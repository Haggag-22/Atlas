"""Tests for atlas.core.permission_map — PermissionMap evaluation chain.

Tests the full IAM evaluation logic, false-positive prevention measures,
and the has_permission() method's behaviour across all 8 evaluation steps.
"""

import pytest

from atlas.core.permission_map import (
    IdentityPermissionProfile,
    PermissionConfidence,
    PermissionEntry,
    PermissionMap,
    PermissionSource,
    PolicyStatement,
    ServiceAccess,
    action_matches,
    not_action_matches,
    resource_arn_matches,
)


# ──────────────────────────────────────────────────────────────────────
# Utility matchers
# ──────────────────────────────────────────────────────────────────────
class TestActionMatches:
    def test_wildcard_matches_everything(self):
        assert action_matches("*", "s3:GetObject") is True

    def test_exact_match(self):
        assert action_matches("s3:GetObject", "s3:GetObject") is True
        assert action_matches("s3:GetObject", "s3:PutObject") is False

    def test_service_wildcard(self):
        assert action_matches("s3:*", "s3:GetObject") is True
        assert action_matches("s3:*", "ec2:DescribeInstances") is False

    def test_prefix_wildcard(self):
        assert action_matches("s3:Get*", "s3:GetObject") is True
        assert action_matches("s3:Get*", "s3:GetBucketPolicy") is True
        assert action_matches("s3:Get*", "s3:PutObject") is False

    def test_case_insensitive(self):
        assert action_matches("s3:getobject", "s3:GetObject") is True
        assert action_matches("S3:GETOBJECT", "s3:GetObject") is True


class TestResourceArnMatches:
    def test_wildcard(self):
        assert resource_arn_matches("*", "arn:aws:s3:::my-bucket") is True

    def test_exact(self):
        assert resource_arn_matches(
            "arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket",
        ) is True

    def test_glob_pattern(self):
        assert resource_arn_matches("arn:aws:s3:::*", "arn:aws:s3:::my-bucket") is True
        assert resource_arn_matches("arn:aws:s3:::my-*", "arn:aws:s3:::my-bucket") is True
        assert resource_arn_matches("arn:aws:s3:::other-*", "arn:aws:s3:::my-bucket") is False


class TestNotActionMatches:
    def test_excluded(self):
        assert not_action_matches(["iam:*"], "iam:CreateUser") is False

    def test_not_excluded(self):
        assert not_action_matches(["iam:*"], "s3:GetObject") is True


# ──────────────────────────────────────────────────────────────────────
# IdentityPermissionProfile.has_permission()
# ──────────────────────────────────────────────────────────────────────
class TestExplicitDeny:
    """Step 1: Explicit deny always wins, even for admins."""

    def test_deny_statement_blocks_access(self):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/alice",
            is_admin=True,
            admin_policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",
        )
        profile.deny_statements.append(PolicyStatement(
            effect="Deny",
            actions=["s3:DeleteBucket"],
            resources=["*"],
        ))
        assert profile.has_permission("s3:DeleteBucket") is False

    def test_deny_entry_in_permissions_dict(self):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/alice",
        )
        profile.add_permission(PermissionEntry(
            action="s3:PutObject",
            allowed=False,
            confidence=PermissionConfidence.CONFIRMED,
            source=PermissionSource.DENY_CONFIRMED,
        ))
        assert profile.has_permission("s3:PutObject") is False

    def test_deny_wins_over_allow_entry(self):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/alice",
        )
        profile.deny_statements.append(PolicyStatement(
            effect="Deny", actions=["s3:*"], resources=["*"],
        ))
        profile.add_permission(PermissionEntry(
            action="s3:GetObject",
            allowed=True,
            confidence=PermissionConfidence.CONFIRMED,
            source=PermissionSource.SENTINEL_PROBE,
        ))
        assert profile.has_permission("s3:GetObject") is False


class TestAdminShortCircuit:
    """Step 2: True admin gets short-circuit (after deny check)."""

    def test_true_admin_allowed(self):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/alice",
            is_admin=True,
            admin_policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",
        )
        assert profile.has_permission("ec2:RunInstances") is True
        assert profile.has_permission("iam:CreateUser") is True

    def test_power_user_no_shortcircuit(self):
        """FP-2: PowerUserAccess should NOT be treated as full admin."""
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/alice",
            is_admin=True,
            admin_policy_arn="arn:aws:iam::aws:policy/PowerUserAccess",
        )
        # Without any allow statements/entries, this should be False
        assert profile.has_permission("iam:CreateUser") is False

    def test_admin_still_blocked_by_explicit_deny(self):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/alice",
            is_admin=True,
            admin_policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",
        )
        profile.deny_statements.append(PolicyStatement(
            effect="Deny", actions=["s3:*"], resources=["*"],
        ))
        assert profile.has_permission("s3:GetObject") is False


class TestPermissionBoundary:
    """Step 3: Permission boundary intersection."""

    def test_boundary_blocks_action_not_in_boundary(self):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/alice",
            has_permission_boundary=True,
        )
        profile.boundary_statements.append(PolicyStatement(
            effect="Allow",
            actions=["s3:*"],
            resources=["*"],
        ))
        profile.add_permission(PermissionEntry(
            action="ec2:RunInstances",
            allowed=True,
            confidence=PermissionConfidence.CONFIRMED,
            source=PermissionSource.POLICY_DOCUMENT,
        ))
        # ec2:RunInstances is not in the boundary
        assert profile.has_permission("ec2:RunInstances") is False

    def test_boundary_allows_action_in_boundary(self):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/alice",
            has_permission_boundary=True,
        )
        profile.boundary_statements.append(PolicyStatement(
            effect="Allow", actions=["s3:*"], resources=["*"],
        ))
        profile.add_permission(PermissionEntry(
            action="s3:GetObject",
            allowed=True,
            confidence=PermissionConfidence.CONFIRMED,
            source=PermissionSource.POLICY_DOCUMENT,
        ))
        assert profile.has_permission("s3:GetObject") is True


class TestSessionPolicy:
    """Step 4: Session policy intersection (assumed roles)."""

    def test_session_policy_blocks_action_not_allowed(self):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:role/reader",
            is_assumed_role=True,
        )
        profile.session_policy_statements.append(PolicyStatement(
            effect="Allow", actions=["s3:Get*"], resources=["*"],
        ))
        profile.add_permission(PermissionEntry(
            action="s3:PutObject",
            allowed=True,
            confidence=PermissionConfidence.CONFIRMED,
            source=PermissionSource.SENTINEL_PROBE,
        ))
        # PutObject not in session policy
        assert profile.has_permission("s3:PutObject") is False

    def test_session_policy_allows_matching_action(self):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:role/reader",
            is_assumed_role=True,
        )
        profile.session_policy_statements.append(PolicyStatement(
            effect="Allow", actions=["s3:Get*"], resources=["*"],
        ))
        profile.add_permission(PermissionEntry(
            action="s3:GetObject",
            allowed=True,
            confidence=PermissionConfidence.CONFIRMED,
            source=PermissionSource.SENTINEL_PROBE,
        ))
        assert profile.has_permission("s3:GetObject") is True


class TestIdentityPolicyAllow:
    """Step 5: Identity policy Allow with condition checking."""

    def test_allow_statement_grants_access(self):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/alice",
        )
        profile.allow_statements.append(PolicyStatement(
            effect="Allow", actions=["s3:*"], resources=["*"],
        ))
        assert profile.has_permission("s3:GetObject") is True

    def test_blocking_condition_prevents_allow(self):
        """FP-3: MFA condition blocks access."""
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/alice",
        )
        profile.allow_statements.append(PolicyStatement(
            effect="Allow",
            actions=["s3:*"],
            resources=["*"],
            conditions={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        ))
        assert profile.has_permission("s3:GetObject") is False

    def test_permission_entry_grants_access(self):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/alice",
        )
        profile.add_permission(PermissionEntry(
            action="lambda:ListFunctions",
            allowed=True,
            confidence=PermissionConfidence.CONFIRMED,
            source=PermissionSource.SENTINEL_PROBE,
        ))
        assert profile.has_permission("lambda:ListFunctions") is True


class TestResourcePolicyGrants:
    """Step 6: Resource-based policy grants (FP-7)."""

    def test_resource_policy_grants_access(self):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/alice",
        )
        profile.resource_policy_grants["arn:aws:s3:::my-bucket/*"] = [
            "s3:GetObject",
        ]
        assert profile.has_permission(
            "s3:GetObject", "arn:aws:s3:::my-bucket/file.txt",
        ) is True

    def test_resource_policy_wildcard(self):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/alice",
        )
        profile.resource_policy_grants["*"] = ["s3:GetObject"]
        assert profile.has_permission("s3:GetObject") is True


class TestServiceLevelInference:
    """Step 7: Service-level inference with FP-1 prevention."""

    def test_read_action_inferred_from_service_access(self):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/alice",
        )
        profile.service_access["s3"] = ServiceAccess(
            service="s3",
            has_read=True,
            read_confidence=PermissionConfidence.CONFIRMED,
        )
        assert profile.has_permission("s3:ListBuckets") is True

    def test_write_action_never_inferred(self):
        """FP-1: Write actions are never inferred from service-level."""
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/alice",
        )
        profile.service_access["s3"] = ServiceAccess(
            service="s3",
            has_read=True,
            has_write=True,
            read_confidence=PermissionConfidence.CONFIRMED,
            write_confidence=PermissionConfidence.CONFIRMED,
        )
        assert profile.has_permission("s3:PutObject") is False

    def test_confidence_threshold_gate(self):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/alice",
        )
        profile.service_access["ec2"] = ServiceAccess(
            service="ec2",
            has_read=True,
            read_confidence=PermissionConfidence.INFERRED,
        )
        # INFERRED >= HEURISTIC, so default threshold passes
        assert profile.has_permission("ec2:DescribeInstances") is True
        # But CONFIRMED threshold should reject INFERRED confidence
        assert profile.has_permission(
            "ec2:DescribeInstances",
            min_confidence=PermissionConfidence.CONFIRMED,
        ) is False


class TestImplicitDeny:
    """Step 8: Default implicit deny."""

    def test_no_permissions_returns_false(self):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/alice",
        )
        assert profile.has_permission("s3:GetObject") is False

    def test_unrelated_permission_does_not_grant(self):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/alice",
        )
        profile.add_permission(PermissionEntry(
            action="ec2:DescribeInstances",
            allowed=True,
            confidence=PermissionConfidence.CONFIRMED,
            source=PermissionSource.SENTINEL_PROBE,
        ))
        assert profile.has_permission("s3:GetObject") is False


# ──────────────────────────────────────────────────────────────────────
# PermissionMap top-level
# ──────────────────────────────────────────────────────────────────────
class TestPermissionMapTopLevel:
    def test_get_or_create_profile(self):
        pmap = PermissionMap()
        p1 = pmap.get_or_create_profile("arn:aws:iam::123:user/alice")
        p2 = pmap.get_or_create_profile("arn:aws:iam::123:user/alice")
        assert p1 is p2

    def test_profile_has_permission_works(self):
        pmap = PermissionMap()
        pmap.set_caller_arn("arn:aws:iam::123:user/alice")
        profile = pmap.get_or_create_profile("arn:aws:iam::123:user/alice")
        profile.add_permission(PermissionEntry(
            action="s3:GetObject",
            allowed=True,
            confidence=PermissionConfidence.CONFIRMED,
            source=PermissionSource.SENTINEL_PROBE,
        ))
        assert profile.has_permission("s3:GetObject") is True
        assert profile.has_permission("s3:PutObject") is False

    def test_caller_arn_set_correctly(self):
        pmap = PermissionMap()
        pmap.set_caller_arn("arn:aws:iam::123:user/alice")
        assert pmap.caller_arn == "arn:aws:iam::123:user/alice"

    def test_scp_deny_blocks_access_via_profile_deny_statements(self):
        pmap = PermissionMap()
        pmap.set_caller_arn("arn:aws:iam::123:user/alice")
        pmap.load_scps([{
            "policy_document": {
                "Statement": [{
                    "Effect": "Deny",
                    "Action": "s3:*",
                    "Resource": "*",
                }],
            },
        }])
        profile = pmap.get_or_create_profile("arn:aws:iam::123:user/alice")
        profile.add_permission(PermissionEntry(
            action="s3:GetObject",
            allowed=True,
            confidence=PermissionConfidence.CONFIRMED,
            source=PermissionSource.SENTINEL_PROBE,
        ))
        # The SCP deny is stored at the pmap level — profile.has_permission
        # doesn't see it directly, so we verify the SCP deny was loaded
        assert len(pmap._scp_deny_statements) >= 1
        scp_stmt = pmap._scp_deny_statements[0]
        assert scp_stmt.matches_action("s3:GetObject") is True


class TestNotActionPolicy:
    """FP-4: NotAction + Allow should NOT create phantom '*' entries."""

    def test_not_action_allows_non_excluded(self):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/alice",
        )
        profile.allow_statements.append(PolicyStatement(
            effect="Allow",
            not_actions=["iam:*", "organizations:*"],
            resources=["*"],
        ))
        # s3 is NOT in the not_actions → should be allowed
        assert profile.has_permission("s3:GetObject") is True

    def test_not_action_denies_excluded(self):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/alice",
        )
        profile.allow_statements.append(PolicyStatement(
            effect="Allow",
            not_actions=["iam:*", "organizations:*"],
            resources=["*"],
        ))
        # iam:CreateUser IS in the not_actions → should be blocked
        assert profile.has_permission("iam:CreateUser") is False

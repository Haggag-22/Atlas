"""Tests for Tier 1 policy document analysis.

Verifies that PolicyStatement parsing and has_permission() correctly
handles Allow, Deny, NotAction, NotResource, conditions, and resource
scoping from parsed IAM policy documents.
"""

import pytest

from atlas.core.permission_map import (
    IdentityPermissionProfile,
    PermissionConfidence,
    PermissionEntry,
    PermissionSource,
    PolicyStatement,
    action_matches,
    not_action_matches,
    not_resource_matches,
    resource_arn_matches,
)


# ──────────────────────────────────────────────────────────────────────
# PolicyStatement.matches_action
# ──────────────────────────────────────────────────────────────────────
class TestPolicyStatementMatchesAction:
    def test_exact_action(self):
        stmt = PolicyStatement(
            effect="Allow", actions=["s3:GetObject"],
        )
        assert stmt.matches_action("s3:GetObject") is True
        assert stmt.matches_action("s3:PutObject") is False

    def test_wildcard_action(self):
        stmt = PolicyStatement(
            effect="Allow", actions=["s3:*"],
        )
        assert stmt.matches_action("s3:GetObject") is True
        assert stmt.matches_action("ec2:DescribeInstances") is False

    def test_star_matches_everything(self):
        stmt = PolicyStatement(
            effect="Allow", actions=["*"],
        )
        assert stmt.matches_action("s3:GetObject") is True
        assert stmt.matches_action("iam:CreateUser") is True

    def test_prefix_wildcard(self):
        stmt = PolicyStatement(
            effect="Allow", actions=["s3:Get*", "s3:List*"],
        )
        assert stmt.matches_action("s3:GetObject") is True
        assert stmt.matches_action("s3:ListBuckets") is True
        assert stmt.matches_action("s3:PutObject") is False

    def test_not_action(self):
        stmt = PolicyStatement(
            effect="Allow", not_actions=["iam:*", "organizations:*"],
        )
        assert stmt.matches_action("s3:GetObject") is True
        assert stmt.matches_action("iam:CreateUser") is False
        assert stmt.matches_action("organizations:ListAccounts") is False

    def test_empty_actions_and_not_actions(self):
        stmt = PolicyStatement(effect="Allow")
        assert stmt.matches_action("s3:GetObject") is False


# ──────────────────────────────────────────────────────────────────────
# PolicyStatement.matches_resource
# ──────────────────────────────────────────────────────────────────────
class TestPolicyStatementMatchesResource:
    def test_star_resource(self):
        stmt = PolicyStatement(
            effect="Allow", actions=["s3:*"], resources=["*"],
        )
        assert stmt.matches_resource("arn:aws:s3:::my-bucket") is True

    def test_specific_resource(self):
        stmt = PolicyStatement(
            effect="Allow",
            actions=["s3:GetObject"],
            resources=["arn:aws:s3:::my-bucket/*"],
        )
        assert stmt.matches_resource("arn:aws:s3:::my-bucket/file.txt") is True
        assert stmt.matches_resource("arn:aws:s3:::other-bucket/file.txt") is False

    def test_not_resource(self):
        stmt = PolicyStatement(
            effect="Allow",
            actions=["s3:*"],
            not_resources=["arn:aws:s3:::secret-bucket/*"],
        )
        assert stmt.matches_resource("arn:aws:s3:::public-bucket/file.txt") is True
        assert stmt.matches_resource("arn:aws:s3:::secret-bucket/file.txt") is False


# ──────────────────────────────────────────────────────────────────────
# PolicyStatement.has_blocking_conditions
# ──────────────────────────────────────────────────────────────────────
class TestBlockingConditions:
    def test_no_conditions(self):
        stmt = PolicyStatement(effect="Allow", actions=["s3:*"])
        assert stmt.has_blocking_conditions is False

    def test_mfa_condition_blocks(self):
        stmt = PolicyStatement(
            effect="Allow", actions=["s3:*"],
            conditions={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        )
        assert stmt.has_blocking_conditions is True

    def test_source_ip_blocks(self):
        stmt = PolicyStatement(
            effect="Allow", actions=["s3:*"],
            conditions={"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
        )
        assert stmt.has_blocking_conditions is True

    def test_vpce_blocks(self):
        stmt = PolicyStatement(
            effect="Allow", actions=["s3:*"],
            conditions={"StringEquals": {"aws:SourceVpce": "vpce-12345"}},
        )
        assert stmt.has_blocking_conditions is True

    def test_principal_org_id_blocks(self):
        stmt = PolicyStatement(
            effect="Allow", actions=["sts:AssumeRole"],
            conditions={"StringEquals": {"aws:PrincipalOrgID": "o-12345"}},
        )
        assert stmt.has_blocking_conditions is True

    def test_non_blocking_condition_does_not_block(self):
        stmt = PolicyStatement(
            effect="Allow", actions=["s3:*"],
            conditions={"StringEquals": {"s3:prefix": "home/"}},
        )
        assert stmt.has_blocking_conditions is False


# ──────────────────────────────────────────────────────────────────────
# End-to-end: Tier 1 policy → has_permission
# ──────────────────────────────────────────────────────────────────────
class TestTier1PolicyToHasPermission:
    """Simulate what happens when Tier 1 parses a policy document and
    the profile is queried with has_permission."""

    def test_admin_policy(self):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/alice",
            is_admin=True,
            admin_policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",
        )
        assert profile.has_permission("s3:GetObject") is True
        assert profile.has_permission("iam:CreateUser") is True
        assert profile.has_permission("lambda:InvokeFunction") is True

    def test_read_only_policy(self):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/bob",
        )
        profile.allow_statements.append(PolicyStatement(
            effect="Allow",
            actions=["s3:Get*", "s3:List*", "ec2:Describe*"],
            resources=["*"],
        ))
        assert profile.has_permission("s3:GetObject") is True
        assert profile.has_permission("s3:ListBuckets") is True
        assert profile.has_permission("ec2:DescribeInstances") is True
        assert profile.has_permission("s3:PutObject") is False
        assert profile.has_permission("ec2:RunInstances") is False

    def test_power_user_access_policy(self):
        """PowerUserAccess: Allow * except iam:* and organizations:*."""
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/charlie",
        )
        profile.allow_statements.append(PolicyStatement(
            effect="Allow",
            not_actions=["iam:*", "organizations:*"],
            resources=["*"],
        ))
        # Allowed
        assert profile.has_permission("s3:GetObject") is True
        assert profile.has_permission("ec2:RunInstances") is True
        assert profile.has_permission("lambda:InvokeFunction") is True
        # Denied by NotAction
        assert profile.has_permission("iam:CreateUser") is False
        assert profile.has_permission("organizations:ListAccounts") is False

    def test_deny_overrides_allow(self):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/dave",
        )
        profile.allow_statements.append(PolicyStatement(
            effect="Allow", actions=["s3:*"], resources=["*"],
        ))
        profile.deny_statements.append(PolicyStatement(
            effect="Deny",
            actions=["s3:DeleteBucket", "s3:DeleteObject"],
            resources=["*"],
        ))
        assert profile.has_permission("s3:GetObject") is True
        assert profile.has_permission("s3:PutObject") is True
        assert profile.has_permission("s3:DeleteBucket") is False
        assert profile.has_permission("s3:DeleteObject") is False

    def test_resource_scoped_allow(self):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/eve",
        )
        profile.allow_statements.append(PolicyStatement(
            effect="Allow",
            actions=["s3:GetObject", "s3:PutObject"],
            resources=["arn:aws:s3:::my-bucket/*"],
        ))
        # Access to the specified bucket
        assert profile.has_permission(
            "s3:GetObject", "arn:aws:s3:::my-bucket/file.txt",
        ) is True
        # No access to other buckets
        assert profile.has_permission(
            "s3:GetObject", "arn:aws:s3:::other-bucket/file.txt",
        ) is False
        # Wildcard resource query does NOT match a resource-scoped policy
        # (the policy only grants access to a specific bucket)
        assert profile.has_permission("s3:GetObject") is False

    def test_mfa_gated_policy(self):
        """FP-3: MFA condition blocks the attacker."""
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/frank",
        )
        profile.allow_statements.append(PolicyStatement(
            effect="Allow",
            actions=["iam:*"],
            resources=["*"],
            conditions={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        ))
        # MFA-gated → attacker can't satisfy → blocked
        assert profile.has_permission("iam:CreateUser") is False

    def test_mixed_policies_with_boundary(self):
        """Permission boundary intersects with identity policy."""
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/grace",
            has_permission_boundary=True,
        )
        # Identity policy: full S3 + EC2 access
        profile.allow_statements.append(PolicyStatement(
            effect="Allow",
            actions=["s3:*", "ec2:*"],
            resources=["*"],
        ))
        # Boundary: only S3
        profile.boundary_statements.append(PolicyStatement(
            effect="Allow",
            actions=["s3:*"],
            resources=["*"],
        ))
        # S3: allowed (in both identity + boundary)
        assert profile.has_permission("s3:GetObject") is True
        # EC2: denied (not in boundary)
        assert profile.has_permission("ec2:RunInstances") is False

    def test_multiple_allow_statements(self):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/harry",
        )
        profile.allow_statements.append(PolicyStatement(
            effect="Allow", actions=["s3:Get*"], resources=["*"],
        ))
        profile.allow_statements.append(PolicyStatement(
            effect="Allow", actions=["ec2:Describe*"], resources=["*"],
        ))
        assert profile.has_permission("s3:GetObject") is True
        assert profile.has_permission("ec2:DescribeInstances") is True
        assert profile.has_permission("s3:PutObject") is False
        assert profile.has_permission("ec2:RunInstances") is False

"""Tests for brute-force error classification and write inference rules.

Tests the _classify_error helper, _WRITE_INFERENCE_RULES, and
_infer_write_from_read_cluster logic in the PermissionResolverCollector.
"""

import pytest

from atlas.core.permission_map import (
    IdentityPermissionProfile,
    PermissionConfidence,
    PermissionEntry,
    PermissionSource,
)
from atlas.recon.permissions.resolver import (
    _AMBIGUOUS_ERROR_CODES,
    _AUTH_BEFORE_PARAMS_SERVICES,
    _DENY_ERROR_CODES,
    _PARAM_ERROR_CODES,
    _RESOURCE_NOT_FOUND_CODES,
    PermissionResolverCollector,
)


# ──────────────────────────────────────────────────────────────────────
# Error code classification
# ──────────────────────────────────────────────────────────────────────
class TestErrorCodeSets:
    """Verify the error code frozensets contain expected values."""

    def test_deny_codes_contain_access_denied(self):
        assert "AccessDenied" in _DENY_ERROR_CODES
        assert "AccessDeniedException" in _DENY_ERROR_CODES
        assert "UnauthorizedAccess" in _DENY_ERROR_CODES
        assert "UnauthorizedOperation" in _DENY_ERROR_CODES

    def test_deny_codes_contain_token_errors(self):
        assert "InvalidClientTokenId" in _DENY_ERROR_CODES
        assert "ExpiredToken" in _DENY_ERROR_CODES
        assert "ExpiredTokenException" in _DENY_ERROR_CODES

    def test_resource_not_found_codes(self):
        assert "NoSuchBucket" in _RESOURCE_NOT_FOUND_CODES
        assert "NoSuchKey" in _RESOURCE_NOT_FOUND_CODES
        assert "ResourceNotFoundException" in _RESOURCE_NOT_FOUND_CODES
        assert "NoSuchEntity" in _RESOURCE_NOT_FOUND_CODES
        assert "ParameterNotFound" in _RESOURCE_NOT_FOUND_CODES
        assert "DBInstanceNotFoundFault" in _RESOURCE_NOT_FOUND_CODES

    def test_ambiguous_codes(self):
        assert "SubscriptionRequiredException" in _AMBIGUOUS_ERROR_CODES
        assert "Throttling" in _AMBIGUOUS_ERROR_CODES
        assert "ThrottlingException" in _AMBIGUOUS_ERROR_CODES
        assert "UnsupportedOperation" in _AMBIGUOUS_ERROR_CODES

    def test_param_error_codes(self):
        assert "ValidationError" in _PARAM_ERROR_CODES
        assert "ValidationException" in _PARAM_ERROR_CODES
        assert "InvalidParameterValue" in _PARAM_ERROR_CODES
        assert "MissingParameter" in _PARAM_ERROR_CODES
        assert "SerializationException" in _PARAM_ERROR_CODES

    def test_sets_are_disjoint_deny_vs_resource_not_found(self):
        """Deny codes and resource-not-found should not overlap."""
        overlap = _DENY_ERROR_CODES & _RESOURCE_NOT_FOUND_CODES
        assert len(overlap) == 0, f"Overlap: {overlap}"

    def test_sets_are_disjoint_deny_vs_param(self):
        overlap = _DENY_ERROR_CODES & _PARAM_ERROR_CODES
        assert len(overlap) == 0, f"Overlap: {overlap}"


# ──────────────────────────────────────────────────────────────────────
# Auth-before-params service allowlist
# ──────────────────────────────────────────────────────────────────────
class TestAuthBeforeParamsServices:
    """Verify the service allowlist for param-error trust."""

    def test_allowlist_is_frozenset(self):
        assert isinstance(_AUTH_BEFORE_PARAMS_SERVICES, frozenset)

    def test_known_auth_first_services_present(self):
        for svc in ("s3", "iam", "sts", "ec2", "lambda", "rds"):
            assert svc in _AUTH_BEFORE_PARAMS_SERVICES, f"{svc} missing"

    def test_known_param_first_services_absent(self):
        """Services known to validate params before auth must NOT be
        in the allowlist — their param errors are unreliable."""
        for svc in (
            "cloudwatch", "cloudformation", "dynamodb",
            "elasticbeanstalk", "kinesis", "kinesisvideo",
            "ssm", "workdocs",
        ):
            assert svc not in _AUTH_BEFORE_PARAMS_SERVICES, (
                f"{svc} should not be trusted for param-error inference"
            )


# ──────────────────────────────────────────────────────────────────────
# Throttle codes
# ──────────────────────────────────────────────────────────────────────
class TestThrottleCodes:
    def test_throttle_codes_defined(self):
        assert "Throttling" in PermissionResolverCollector._THROTTLE_CODES
        assert "ThrottlingException" in PermissionResolverCollector._THROTTLE_CODES
        assert "RequestLimitExceeded" in PermissionResolverCollector._THROTTLE_CODES
        assert "TooManyRequestsException" in PermissionResolverCollector._THROTTLE_CODES

    def test_throttle_codes_are_frozenset(self):
        assert isinstance(PermissionResolverCollector._THROTTLE_CODES, frozenset)


# ──────────────────────────────────────────────────────────────────────
# Write inference rules
# ──────────────────────────────────────────────────────────────────────
class TestWriteInferenceRules:
    """Test _WRITE_INFERENCE_RULES structure and _infer_write_from_read_cluster."""

    def test_rules_have_correct_shape(self):
        for read_actions, threshold, write_actions in \
                PermissionResolverCollector._WRITE_INFERENCE_RULES:
            assert isinstance(read_actions, list)
            assert isinstance(threshold, int)
            assert isinstance(write_actions, list)
            assert threshold > 0
            assert len(read_actions) >= threshold, (
                f"threshold {threshold} > read_actions count {len(read_actions)}"
            )
            assert len(write_actions) > 0

    def test_s3_inference_rule_exists(self):
        s3_rules = [
            r for r in PermissionResolverCollector._WRITE_INFERENCE_RULES
            if any(a.startswith("s3:") for a in r[0])
        ]
        assert len(s3_rules) >= 1
        read_actions, threshold, write_actions = s3_rules[0]
        assert threshold <= len(read_actions)
        assert "s3:PutObject" in write_actions
        assert "s3:DeleteObject" in write_actions

    def test_ec2_inference_rule_exists(self):
        ec2_rules = [
            r for r in PermissionResolverCollector._WRITE_INFERENCE_RULES
            if any(a.startswith("ec2:") for a in r[0])
        ]
        assert len(ec2_rules) >= 1
        _, _, write_actions = ec2_rules[0]
        assert "ec2:RunInstances" in write_actions

    def test_iam_inference_rule_exists(self):
        iam_rules = [
            r for r in PermissionResolverCollector._WRITE_INFERENCE_RULES
            if any(a.startswith("iam:") for a in r[0])
        ]
        assert len(iam_rules) >= 1
        _, _, write_actions = iam_rules[0]
        assert "iam:CreateAccessKey" in write_actions

    def test_new_service_inference_rules(self):
        """Verify the expanded inference rules for new services."""
        services = set()
        for read_actions, _, _ in PermissionResolverCollector._WRITE_INFERENCE_RULES:
            for a in read_actions:
                services.add(a.split(":")[0])

        # These services should have rules now
        assert "secretsmanager" in services
        assert "kms" in services
        assert "ssm" in services
        assert "rds" in services
        assert "dynamodb" in services
        assert "cloudformation" in services
        assert "sns" in services
        assert "sqs" in services
        assert "logs" in services

    def test_secretsmanager_infers_get_secret_value(self):
        sm_rules = [
            r for r in PermissionResolverCollector._WRITE_INFERENCE_RULES
            if any(a.startswith("secretsmanager:") for a in r[0])
        ]
        assert len(sm_rules) >= 1
        _, _, write_actions = sm_rules[0]
        assert "secretsmanager:GetSecretValue" in write_actions

    def test_kms_infers_decrypt(self):
        kms_rules = [
            r for r in PermissionResolverCollector._WRITE_INFERENCE_RULES
            if any(a.startswith("kms:") for a in r[0])
        ]
        assert len(kms_rules) >= 1
        _, _, write_actions = kms_rules[0]
        assert "kms:Decrypt" in write_actions


class TestInferWriteFromReadCluster:
    """Test the _infer_write_from_read_cluster method directly."""

    @pytest.fixture
    def _collector(self, config, recorder, sample_graph):
        """Create a minimal PermissionResolverCollector for testing."""
        return PermissionResolverCollector(
            session=None,
            config=config,
            graph=sample_graph,
            recorder=recorder,
        )

    def test_s3_reads_above_threshold_infer_writes(self, _collector):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/alice",
        )
        s3_reads = [
            "s3:ListBuckets", "s3:GetBucketPolicy", "s3:GetBucketAcl",
            "s3:GetBucketLocation", "s3:GetPublicAccessBlock",
        ]
        for action in s3_reads:
            profile.add_permission(PermissionEntry(
                action=action,
                allowed=True,
                confidence=PermissionConfidence.CONFIRMED,
                source=PermissionSource.SENTINEL_PROBE,
            ))

        results: dict = {"total": 5, "succeeded": 5, "denied": 0, "errors": 0}
        _collector._infer_write_from_read_cluster(profile, results)

        assert profile.permissions.get("s3:PutObject") is not None
        assert profile.permissions["s3:PutObject"].allowed is True
        assert profile.permissions["s3:PutObject"].confidence == PermissionConfidence.INFERRED

    def test_below_threshold_does_not_infer(self, _collector):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/alice",
        )
        # Only 2 S3 reads — below threshold of 4
        for action in ["s3:ListBuckets", "s3:GetBucketPolicy"]:
            profile.add_permission(PermissionEntry(
                action=action,
                allowed=True,
                confidence=PermissionConfidence.CONFIRMED,
                source=PermissionSource.SENTINEL_PROBE,
            ))

        results: dict = {"total": 2, "succeeded": 2, "denied": 0, "errors": 0}
        _collector._infer_write_from_read_cluster(profile, results)

        assert profile.permissions.get("s3:PutObject") is None

    def test_confirmed_deny_not_overridden(self, _collector):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/alice",
        )
        s3_reads = [
            "s3:ListBuckets", "s3:GetBucketPolicy", "s3:GetBucketAcl",
            "s3:GetBucketLocation", "s3:GetPublicAccessBlock",
        ]
        for action in s3_reads:
            profile.add_permission(PermissionEntry(
                action=action,
                allowed=True,
                confidence=PermissionConfidence.CONFIRMED,
                source=PermissionSource.SENTINEL_PROBE,
            ))
        # Explicitly deny s3:PutObject
        profile.add_permission(PermissionEntry(
            action="s3:PutObject",
            allowed=False,
            confidence=PermissionConfidence.CONFIRMED,
            source=PermissionSource.DENY_CONFIRMED,
        ))

        results: dict = {"total": 5, "succeeded": 5, "denied": 0, "errors": 0}
        _collector._infer_write_from_read_cluster(profile, results)

        # The deny should NOT be overridden
        assert profile.permissions["s3:PutObject"].allowed is False

    def test_multiple_services_inferred_independently(self, _collector):
        profile = IdentityPermissionProfile(
            identity_arn="arn:aws:iam::123:user/alice",
        )
        # S3 reads above threshold
        for action in [
            "s3:ListBuckets", "s3:GetBucketPolicy", "s3:GetBucketAcl",
            "s3:GetBucketLocation",
        ]:
            profile.add_permission(PermissionEntry(
                action=action,
                allowed=True,
                confidence=PermissionConfidence.CONFIRMED,
                source=PermissionSource.SENTINEL_PROBE,
            ))
        # Lambda reads above threshold
        for action in ["lambda:ListFunctions", "lambda:ListLayers"]:
            profile.add_permission(PermissionEntry(
                action=action,
                allowed=True,
                confidence=PermissionConfidence.CONFIRMED,
                source=PermissionSource.SENTINEL_PROBE,
            ))

        results: dict = {"total": 6, "succeeded": 6, "denied": 0, "errors": 0}
        _collector._infer_write_from_read_cluster(profile, results)

        assert profile.permissions.get("s3:PutObject") is not None
        assert profile.permissions.get("lambda:InvokeFunction") is not None

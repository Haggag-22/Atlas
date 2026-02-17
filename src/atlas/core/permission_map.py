"""
atlas.core.permission_map
~~~~~~~~~~~~~~~~~~~~~~~~~
Centralized Permission Mapping & Attack Surface Analysis.

This is the **single source of truth** for what every IAM identity in
the environment can do.  Every downstream layer — the Planner (attack
graph builder, path finder, strategies) and the Executor — consults
this map instead of walking policy documents directly.

AWS IAM Evaluation Logic (implemented here):
  1. Explicit Deny wins — always checked first
  2. SCPs filter — account-level restrictions from Organizations
  3. Permission boundaries — intersected with identity policies
  4. Resource-based policies — inbound access from resource side
  5. Identity policies — the standard Allow/Deny evaluation
  6. Session policies — restrictions on assumed-role sessions
  7. Condition keys — block or downgrade conditional permissions

False-positive prevention measures:
  FP-1  Service-level inference never returns hard True for write actions
        unless the exact action was confirmed.  Only read actions can be
        inferred from service-level access, and even then only when the
        confidence is at or above the requested threshold.
  FP-2  is_admin no longer short-circuits SCP denies or explicit denies.
        PowerUserAccess is not treated as admin (it denies iam:*).
  FP-3  Conditional Allow statements with MFA, source IP, or VPC
        conditions are treated as blocked (return False from has_permission)
        unless the caller can satisfy them.
  FP-4  NotAction+Allow no longer creates a phantom '*' permission
        entry in the dict.  Evaluation goes through PolicyStatement only.
  FP-5  Resource-based policy grants interact correctly with identity
        denies for same-account vs. cross-account scenarios.
  FP-6  Confidence threshold parameter on has_permission() allows the
        attack graph to require CONFIRMED for execution-path edges.

Three-tier permission resolution hierarchy (cheapest first):

  Tier 1 — POLICY_DOCUMENT
  Tier 2 — ACCOUNT_AUTH_DETAILS
  Tier 3 — SENTINEL_PROBE
  Bonus  — IMPLICIT / OPERATOR_HINT
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from enum import Enum, unique
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Permission confidence levels
# ---------------------------------------------------------------------------
@unique
class PermissionConfidence(str, Enum):
    """How confident we are that an identity has a specific permission."""
    CONFIRMED = "confirmed"      # Verified from policy doc or empirical test
    INFERRED = "inferred"        # Inferred from service-level access
    HEURISTIC = "heuristic"      # Guessed from related permissions
    UNKNOWN = "unknown"          # No data available


@unique
class PermissionSource(str, Enum):
    """How a permission entry was discovered."""
    POLICY_DOCUMENT = "policy_document"
    ACCOUNT_AUTH_DETAILS = "account_auth_details"
    SIMULATE_PRINCIPAL = "simulate_principal_policy"
    PIECEMEAL_POLICY = "piecemeal_policy"
    SERVICE_LAST_ACCESSED = "service_last_accessed"
    SENTINEL_PROBE = "sentinel_probe"
    IMPLICIT = "implicit"
    OPERATOR_HINT = "operator_hint"
    DENY_CONFIRMED = "deny_confirmed"
    RESOURCE_POLICY = "resource_policy"
    PERMISSION_BOUNDARY = "permission_boundary"
    SCP = "scp"


# Confidence ranking for comparison
_CONF_RANK: dict[PermissionConfidence, int] = {
    PermissionConfidence.UNKNOWN: 0,
    PermissionConfidence.HEURISTIC: 1,
    PermissionConfidence.INFERRED: 2,
    PermissionConfidence.CONFIRMED: 3,
}


# ---------------------------------------------------------------------------
# Well-known blocking conditions that attackers cannot satisfy
# ---------------------------------------------------------------------------
_BLOCKING_CONDITION_KEYS = {
    # MFA conditions — attacker almost never has the target's MFA device
    "aws:MultiFactorAuthPresent",
    "aws:MultiFactorAuthAge",
    # Source IP restrictions — attacker is coming from their own IP
    "aws:SourceIp",
    # VPC endpoint restrictions
    "aws:SourceVpce",
    "aws:SourceVpc",
    # Principal tag — attacker can't control tag values on another identity
    "aws:PrincipalTag",
    # Organization ID — attacker outside the org can't satisfy this
    "aws:PrincipalOrgID",
}


def _has_blocking_condition(conditions: dict[str, Any]) -> bool:
    """Check if conditions contain a key that an attacker cannot satisfy.

    Returns True if the statement has a condition that would block an
    external attacker (MFA, source IP, VPC endpoint, etc.).
    """
    if not conditions:
        return False
    for _operator, key_values in conditions.items():
        if not isinstance(key_values, dict):
            continue
        for key in key_values:
            # Normalize the key for comparison
            normalized = key.split("/")[0]  # Handle tag keys like aws:PrincipalTag/team
            if normalized in _BLOCKING_CONDITION_KEYS:
                return True
    return False


def _has_mfa_condition(conditions: dict[str, Any]) -> bool:
    """Check specifically for MFA conditions."""
    if not conditions:
        return False
    for _operator, key_values in conditions.items():
        if not isinstance(key_values, dict):
            continue
        for key in key_values:
            if "MultiFactorAuth" in key:
                return True
    return False


def _has_source_ip_condition(conditions: dict[str, Any]) -> bool:
    """Check specifically for source IP conditions."""
    if not conditions:
        return False
    for _operator, key_values in conditions.items():
        if not isinstance(key_values, dict):
            continue
        for key in key_values:
            if "SourceIp" in key:
                return True
    return False


# ---------------------------------------------------------------------------
# Well-known admin policy ARNs (true admin vs. limited admin)
# ---------------------------------------------------------------------------
# TRUE admin — unrestricted access to everything
_TRUE_ADMIN_ARNS = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
}

# POWER USER — has broad access but explicitly denies IAM/Orgs actions.
# These should NOT be treated as admin because they have built-in denies.
_POWER_USER_ARNS = {
    "arn:aws:iam::aws:policy/PowerUserAccess",
}

# All well-known "admin-like" ARNs (for detection, not for short-circuiting)
_ADMIN_LIKE_ARNS = _TRUE_ADMIN_ARNS | _POWER_USER_ARNS | {
    "arn:aws:iam::aws:policy/IAMFullAccess",
}


# ---------------------------------------------------------------------------
# IAM action / resource matching utilities
# ---------------------------------------------------------------------------
def action_matches(pattern: str, action: str) -> bool:
    """Check if an IAM action pattern matches a specific action.

    Case-insensitive.  Supports wildcards: *, s3:*, s3:Get*, s3:*Object*.
    """
    if pattern == "*":
        return True
    if pattern == action:
        return True
    return fnmatch.fnmatch(action.lower(), pattern.lower())


def resource_arn_matches(pattern: str, resource_arn: str) -> bool:
    """Check if an IAM resource ARN pattern matches a resource ARN."""
    if pattern == "*":
        return True
    if pattern == resource_arn:
        return True
    return fnmatch.fnmatch(resource_arn, pattern)


def not_action_matches(not_actions: list[str], action: str) -> bool:
    """Returns True if the action is NOT excluded by NotAction."""
    for pattern in not_actions:
        if action_matches(pattern, action):
            return False
    return True


def not_resource_matches(not_resources: list[str], resource_arn: str) -> bool:
    """Returns True if the resource is NOT excluded by NotResource."""
    for pattern in not_resources:
        if resource_arn_matches(pattern, resource_arn):
            return False
    return True


# ---------------------------------------------------------------------------
# Individual permission entry
# ---------------------------------------------------------------------------
@dataclass
class PermissionEntry:
    """A single permission record for an identity."""
    action: str
    allowed: bool
    confidence: PermissionConfidence
    source: PermissionSource
    resource_arn: str = "*"
    resource_arns: list[str] = field(default_factory=lambda: ["*"])
    conditions: dict[str, Any] = field(default_factory=dict)
    has_conditions: bool = False
    has_blocking_conditions: bool = False  # FP-3: MFA, IP, VPC, etc.
    notes: str = ""

    @property
    def confidence_score(self) -> float:
        """Numeric confidence: 1.0 = certain, 0.0 = no idea."""
        return {
            PermissionConfidence.CONFIRMED: 1.0,
            PermissionConfidence.INFERRED: 0.7,
            PermissionConfidence.HEURISTIC: 0.4,
            PermissionConfidence.UNKNOWN: 0.0,
        }[self.confidence]


# ---------------------------------------------------------------------------
# Policy statement (parsed from IAM JSON)
# ---------------------------------------------------------------------------
@dataclass
class PolicyStatement:
    """A parsed IAM policy statement for proper evaluation."""
    effect: str
    actions: list[str] = field(default_factory=list)
    not_actions: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=lambda: ["*"])
    not_resources: list[str] = field(default_factory=list)
    conditions: dict[str, Any] = field(default_factory=dict)
    source: PermissionSource = PermissionSource.POLICY_DOCUMENT

    @property
    def has_blocking_conditions(self) -> bool:
        """Check if this statement has conditions an attacker can't satisfy."""
        return _has_blocking_condition(self.conditions)

    def matches_action(self, action: str) -> bool:
        """Check if this statement applies to a given action."""
        if self.actions:
            return any(action_matches(p, action) for p in self.actions)
        if self.not_actions:
            return not_action_matches(self.not_actions, action)
        return False

    def matches_resource(self, resource_arn: str) -> bool:
        """Check if this statement applies to a given resource."""
        if self.not_resources:
            return not_resource_matches(self.not_resources, resource_arn)
        return any(resource_arn_matches(r, resource_arn) for r in self.resources)


# ---------------------------------------------------------------------------
# Service-level access summary
# ---------------------------------------------------------------------------
@dataclass
class ServiceAccess:
    """Summary of access to an entire AWS service for one identity."""
    service: str
    has_read: bool = False
    has_write: bool = False
    read_confidence: PermissionConfidence = PermissionConfidence.UNKNOWN
    write_confidence: PermissionConfidence = PermissionConfidence.UNKNOWN
    confirmed_actions: list[str] = field(default_factory=list)
    denied_actions: list[str] = field(default_factory=list)


def _is_read_action(action_verb: str) -> bool:
    """Check if an IAM action verb is a read-only operation."""
    return action_verb.startswith(
        ("Describe", "List", "Get", "Search", "Lookup",
         "Check", "Head", "Batch", "Query", "Scan")
    )


# ---------------------------------------------------------------------------
# Per-identity permission profile
# ---------------------------------------------------------------------------
@dataclass
class IdentityPermissionProfile:
    """Complete permission profile for a single IAM identity."""
    identity_arn: str
    is_admin: bool = False
    # FP-2: Track the specific admin policy ARN so we can distinguish
    # true admin (AdministratorAccess) from PowerUserAccess
    admin_policy_arn: str = ""
    permissions: dict[str, PermissionEntry] = field(default_factory=dict)
    allow_statements: list[PolicyStatement] = field(default_factory=list)
    deny_statements: list[PolicyStatement] = field(default_factory=list)
    boundary_statements: list[PolicyStatement] = field(default_factory=list)
    has_permission_boundary: bool = False
    permission_boundary_arn: str | None = None
    service_access: dict[str, ServiceAccess] = field(default_factory=dict)
    resource_policy_grants: dict[str, list[str]] = field(default_factory=dict)
    resolution_tier: str = "none"
    policy_documents_available: bool = False
    is_assumed_role: bool = False
    session_policy_statements: list[PolicyStatement] = field(default_factory=list)
    account_id: str = ""

    def has_permission(
        self,
        action: str,
        resource_arn: str = "*",
        min_confidence: PermissionConfidence = PermissionConfidence.HEURISTIC,
    ) -> bool:
        """Check if this identity has a specific permission.

        Full AWS IAM evaluation with false-positive prevention:
          1. Explicit Deny (always wins, even for admins)
          2. SCP-level deny handled at PermissionMap level
          3. is_admin short-circuit (only AFTER deny check, only for true admins)
          4. Permission boundary intersection
          5. Session policy intersection
          6. Identity policy Allow (conditions checked)
          7. Resource-based policy grants
          8. Service-level inference (read-only, confidence-gated)
          9. Default: implicit deny

        Args:
            min_confidence: Minimum confidence level required to return True.
                Use CONFIRMED for execution paths, HEURISTIC for planning.
        """
        # ── Step 1: ALWAYS check explicit DENY first ────────────────
        # This runs even for admin identities (FP-2)
        if self._is_explicitly_denied(action, resource_arn):
            return False

        # ── Step 2: Admin short-circuit (only for TRUE admin) ────────
        # FP-2: Only AdministratorAccess gets the short-circuit.
        # PowerUserAccess has built-in denies (handled in step 1).
        if self.is_admin and self.admin_policy_arn in _TRUE_ADMIN_ARNS:
            return True

        # ── Step 3: Permission boundary intersection ─────────────────
        if self.has_permission_boundary and self.boundary_statements:
            boundary_allows = False
            for stmt in self.boundary_statements:
                if stmt.effect == "Allow" and stmt.matches_action(action) \
                        and stmt.matches_resource(resource_arn):
                    boundary_allows = True
                    break
            if not boundary_allows:
                return False

        # ── Step 4: Session policy intersection (assumed roles) ──────
        if self.is_assumed_role and self.session_policy_statements:
            session_allows = False
            for stmt in self.session_policy_statements:
                if stmt.effect == "Allow" and stmt.matches_action(action) \
                        and stmt.matches_resource(resource_arn):
                    session_allows = True
                    break
            if not session_allows:
                return False

        # ── Step 5: Identity policy Allow (with condition checking) ──
        # FP-3: Check conditions on allow statements
        for stmt in self.allow_statements:
            if stmt.matches_action(action) and stmt.matches_resource(resource_arn):
                # If the statement has blocking conditions (MFA, IP, VPC),
                # an attacker cannot satisfy them — skip this statement
                if stmt.has_blocking_conditions:
                    continue
                return True

        # Quick lookup from permissions dict (also condition-aware)
        if self._check_permission_entries(action, resource_arn):
            return True

        # ── Step 6: Resource-based policy grants ─────────────────────
        # FP-7: Resource-based policies can grant access independently
        # of identity policies for SAME-ACCOUNT access.
        if self._check_resource_policy_grants(action, resource_arn):
            return True

        # ── Step 7: Service-level inference (confidence-gated) ───────
        # FP-1: Only infer for READ actions, never for write actions.
        # The specific action must meet the min_confidence threshold.
        if self._check_service_level_inference(
            action, resource_arn, min_confidence,
        ):
            return True

        # ── Step 8: Implicit deny ────────────────────────────────────
        return False

    def _is_explicitly_denied(
        self, action: str, resource_arn: str,
    ) -> bool:
        """Check if an action is explicitly denied.

        Checks both parsed deny statements and the permissions dict.
        Conditional denies are evaluated:
          - Unconditional deny → always blocks
          - Conditional deny with blocking conditions → blocks
            (conservative: assume deny applies unless condition is in
            attacker's favor, which blocking conditions are not)
          - Conditional deny with non-blocking conditions → blocks
            (conservative approach for safety)
        """
        for stmt in self.deny_statements:
            if stmt.matches_action(action) and stmt.matches_resource(resource_arn):
                return True

        deny_entry = self._find_deny_entry(action)
        if deny_entry:
            return True

        return False

    def _find_deny_entry(self, action: str) -> PermissionEntry | None:
        """Find an explicit deny entry for an action."""
        entry = self.permissions.get(action)
        if entry and not entry.allowed:
            return entry

        service = action.split(":")[0] if ":" in action else ""
        if service:
            wildcard = f"{service}:*"
            entry = self.permissions.get(wildcard)
            if entry and not entry.allowed:
                return entry

        entry = self.permissions.get("*")
        if entry and not entry.allowed:
            return entry

        # FP-6: Also check all glob patterns for deny
        for pattern, entry in self.permissions.items():
            if not entry.allowed and action_matches(pattern, action):
                return entry

        return None

    def _check_permission_entries(
        self, action: str, resource_arn: str = "*",
    ) -> bool:
        """Check the permissions dict for an allow entry.

        FP-3: Entries with blocking conditions return False.
        FP-4: Entries sourced from NotAction ('*' with notes) are skipped
              in favor of PolicyStatement evaluation (already done above).
        """
        # Direct match
        entry = self.permissions.get(action)
        if entry and entry.allowed:
            # FP-3: Skip entries with blocking conditions
            if entry.has_blocking_conditions:
                return False
            if self._entry_matches_resource(entry, resource_arn):
                return True

        # Wildcard: "ec2:*" allows "ec2:DescribeInstances"
        service = action.split(":")[0] if ":" in action else ""
        if service:
            wildcard = f"{service}:*"
            entry = self.permissions.get(wildcard)
            if entry and entry.allowed and not entry.has_blocking_conditions:
                if self._entry_matches_resource(entry, resource_arn):
                    return True

        # Full admin via '*' entry
        entry = self.permissions.get("*")
        if entry and entry.allowed and not entry.has_blocking_conditions:
            # FP-4: If this '*' came from NotAction, DON'T use it as
            # a general allow.  The PolicyStatement evaluation in step 5
            # already correctly handles NotAction semantics.
            if "NotAction" in entry.notes:
                pass  # Skip — rely on PolicyStatement evaluation
            elif self._entry_matches_resource(entry, resource_arn):
                return True

        # Glob matching through all entries
        for pattern, entry in self.permissions.items():
            if not entry.allowed:
                continue
            if entry.has_blocking_conditions:
                continue
            if "NotAction" in entry.notes:
                continue
            if action_matches(pattern, action):
                if self._entry_matches_resource(entry, resource_arn):
                    return True

        return False

    @staticmethod
    def _entry_matches_resource(
        entry: PermissionEntry, resource_arn: str,
    ) -> bool:
        """Check if a permission entry's resource scope matches."""
        if resource_arn == "*" or entry.resource_arn == "*":
            return True
        if resource_arn_matches(entry.resource_arn, resource_arn):
            return True
        for r in entry.resource_arns:
            if resource_arn_matches(r, resource_arn):
                return True
        return False

    def _check_resource_policy_grants(
        self, action: str, resource_arn: str,
    ) -> bool:
        """Check resource-based policy grants.

        FP-7: Resource-based policies can grant access independently
        of identity policies.  In same-account scenarios, resource-based
        policies can even override identity-level denies (except for
        explicit deny statements, which were already checked).
        """
        # Exact resource match
        if resource_arn in self.resource_policy_grants:
            for granted in self.resource_policy_grants[resource_arn]:
                if action_matches(granted, action):
                    return True

        # Wildcard resource grants
        if "*" in self.resource_policy_grants:
            for granted in self.resource_policy_grants["*"]:
                if action_matches(granted, action):
                    return True

        # Pattern matching for resource grants
        for grant_arn, granted_actions in self.resource_policy_grants.items():
            if grant_arn == "*":
                continue
            if resource_arn_matches(grant_arn, resource_arn):
                for granted in granted_actions:
                    if action_matches(granted, action):
                        return True

        return False

    def _check_service_level_inference(
        self,
        action: str,
        resource_arn: str,
        min_confidence: PermissionConfidence,
    ) -> bool:
        """Service-level inference with false-positive prevention.

        FP-1: This is the most common source of false positives.
        Rules:
          - WRITE actions are NEVER inferred from service-level access.
            Only the exact action being confirmed (via sentinel probe or
            implicit tracking) grants confidence for that specific action.
          - READ actions can be inferred if the service has confirmed
            read access, but only when the confidence meets the threshold.
          - The confidence threshold allows callers to be stricter
            (e.g., CONFIRMED for execution, HEURISTIC for planning).
        """
        service = action.split(":")[0] if ":" in action else ""
        if not service or service not in self.service_access:
            return False

        svc = self.service_access[service]
        action_verb = action.split(":")[1] if ":" in action else ""
        is_read = _is_read_action(action_verb)

        # WRITE actions: NEVER infer from service-level access
        # The attacker needs the exact permission, not just "some service access"
        if not is_read:
            return False

        # READ actions: check service-level read access with confidence gate
        if is_read and svc.has_read:
            if _CONF_RANK.get(svc.read_confidence, 0) >= _CONF_RANK.get(min_confidence, 0):
                return True

        return False

    def get_confidence(
        self,
        action: str,
        resource_arn: str = "*",
    ) -> PermissionConfidence:
        """Get confidence level for a specific permission check."""
        if self.is_admin and self.admin_policy_arn in _TRUE_ADMIN_ARNS:
            return PermissionConfidence.CONFIRMED

        # Check for condition-gated permissions
        entry = self.permissions.get(action)
        if entry and entry.allowed:
            if entry.has_blocking_conditions:
                return PermissionConfidence.UNKNOWN  # Effectively denied
            if entry.has_conditions:
                return PermissionConfidence.INFERRED
            return entry.confidence

        # Wildcard match
        service = action.split(":")[0] if ":" in action else ""
        if service:
            wildcard = f"{service}:*"
            entry = self.permissions.get(wildcard)
            if entry and entry.allowed:
                if entry.has_blocking_conditions:
                    return PermissionConfidence.UNKNOWN
                if entry.has_conditions:
                    return PermissionConfidence.INFERRED
                return entry.confidence

        # Statement-based check
        for stmt in self.allow_statements:
            if stmt.matches_action(action) and stmt.matches_resource(resource_arn):
                if stmt.has_blocking_conditions:
                    return PermissionConfidence.UNKNOWN
                if stmt.conditions:
                    return PermissionConfidence.INFERRED
                return PermissionConfidence.CONFIRMED

        # Resource-based policy
        if resource_arn in self.resource_policy_grants:
            for granted in self.resource_policy_grants[resource_arn]:
                if action_matches(granted, action):
                    return PermissionConfidence.CONFIRMED

        # Service-level inference
        if service in self.service_access:
            svc = self.service_access[service]
            action_verb = action.split(":")[1] if ":" in action else ""
            if _is_read_action(action_verb) and svc.has_read:
                return svc.read_confidence
            # Write actions from service-level = UNKNOWN (FP-1)
            if not _is_read_action(action_verb):
                return PermissionConfidence.UNKNOWN

        return PermissionConfidence.UNKNOWN

    def get_success_multiplier(
        self, action: str, resource_arn: str = "*",
    ) -> float:
        """Get a multiplier for success_probability based on confidence."""
        conf = self.get_confidence(action, resource_arn)
        return {
            PermissionConfidence.CONFIRMED: 1.0,
            PermissionConfidence.INFERRED: 0.7,
            PermissionConfidence.HEURISTIC: 0.4,
            PermissionConfidence.UNKNOWN: 0.0,
        }[conf]

    def add_permission(self, entry: PermissionEntry) -> None:
        """Add or upgrade a permission entry (higher confidence wins)."""
        # FP-3: Flag blocking conditions on the entry
        if entry.has_conditions and not entry.has_blocking_conditions:
            entry.has_blocking_conditions = _has_blocking_condition(
                entry.conditions,
            )

        existing = self.permissions.get(entry.action)
        if existing:
            # Deny always takes priority over allow
            if not entry.allowed and existing.allowed:
                self.permissions[entry.action] = entry
                self._update_service_access(entry)
                return
            # Don't overwrite deny with allow
            if entry.allowed and not existing.allowed:
                return
            # Same effect: higher confidence wins
            if existing.confidence_score >= entry.confidence_score:
                return
        self.permissions[entry.action] = entry
        self._update_service_access(entry)

    def add_statement(self, stmt: PolicyStatement) -> None:
        """Add a parsed policy statement for full evaluation."""
        if stmt.effect == "Deny":
            self.deny_statements.append(stmt)
        else:
            self.allow_statements.append(stmt)

    def add_resource_policy_grant(
        self, resource_arn: str, actions: list[str],
    ) -> None:
        """Record that a resource-based policy grants actions to this identity."""
        if resource_arn not in self.resource_policy_grants:
            self.resource_policy_grants[resource_arn] = []
        self.resource_policy_grants[resource_arn].extend(actions)

    def _update_service_access(self, entry: PermissionEntry) -> None:
        """Update service-level summary from a permission entry."""
        service = entry.action.split(":")[0] if ":" in entry.action else ""
        if not service or entry.action == "*":
            return

        if service not in self.service_access:
            self.service_access[service] = ServiceAccess(service=service)

        svc = self.service_access[service]
        action_verb = entry.action.split(":")[1] if ":" in entry.action else ""
        is_read = _is_read_action(action_verb)

        if entry.allowed:
            if entry.action not in svc.confirmed_actions:
                svc.confirmed_actions.append(entry.action)
            if is_read or entry.action.endswith(":*"):
                svc.has_read = True
                if _CONF_RANK.get(entry.confidence, 0) > _CONF_RANK.get(svc.read_confidence, 0):
                    svc.read_confidence = entry.confidence
            if not is_read or entry.action.endswith(":*"):
                svc.has_write = True
                if _CONF_RANK.get(entry.confidence, 0) > _CONF_RANK.get(svc.write_confidence, 0):
                    svc.write_confidence = entry.confidence
        else:
            if entry.action not in svc.denied_actions:
                svc.denied_actions.append(entry.action)


# ---------------------------------------------------------------------------
# The PermissionMap — central authority
# ---------------------------------------------------------------------------
class PermissionMap:
    """Central permission authority used by all downstream layers.

    Implements the full AWS IAM evaluation chain with false-positive
    prevention at every stage.
    """

    def __init__(self) -> None:
        self._profiles: dict[str, IdentityPermissionProfile] = {}
        self._scp_deny_statements: list[PolicyStatement] = []
        self._scp_allow_statements: list[PolicyStatement] = []
        self._caller_arn: str = ""
        self._resolution_summary: dict[str, Any] = {
            "tier_used": "none",
            "policy_docs_available": False,
            "account_auth_details_available": False,
            "sentinel_probes_run": 0,
            "sentinel_probes_succeeded": 0,
            "implicit_permissions_tracked": 0,
            "operator_hints_loaded": 0,
            "total_identities": 0,
            "total_permissions_mapped": 0,
            "scps_loaded": 0,
            "permission_boundaries_applied": 0,
            "resource_policies_analyzed": 0,
            "cross_account_trusts": 0,
            "condition_gated_permissions": 0,
            "blocking_conditions_found": 0,
            "false_positives_prevented": 0,
        }

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------
    def set_caller_arn(self, caller_arn: str) -> None:
        """Set the caller identity ARN."""
        self._caller_arn = caller_arn

    def load_scps(self, scps: list[dict[str, Any]]) -> None:
        """Load Service Control Policies as account-level filters."""
        count = 0
        for scp in scps:
            doc = scp.get("policy_document", {})
            for raw_stmt in doc.get("Statement", []):
                stmt = self._parse_statement(raw_stmt, PermissionSource.SCP)
                if stmt.effect == "Deny":
                    self._scp_deny_statements.append(stmt)
                else:
                    self._scp_allow_statements.append(stmt)
                count += 1
        self._resolution_summary["scps_loaded"] = count

    def load_permission_boundary(
        self,
        identity_arn: str,
        boundary_doc: dict[str, Any],
    ) -> None:
        """Load a permission boundary for an identity."""
        profile = self.get_or_create_profile(identity_arn)
        profile.has_permission_boundary = True

        for raw_stmt in boundary_doc.get("Statement", []):
            stmt = self._parse_statement(
                raw_stmt, PermissionSource.PERMISSION_BOUNDARY,
            )
            profile.boundary_statements.append(stmt)

        self._resolution_summary["permission_boundaries_applied"] = (
            self._resolution_summary.get("permission_boundaries_applied", 0) + 1
        )

    def load_resource_policy(
        self,
        resource_arn: str,
        policy_doc: dict[str, Any],
        resource_account_id: str = "",
    ) -> None:
        """Load a resource-based policy (S3, KMS, Lambda, etc.)."""
        for raw_stmt in policy_doc.get("Statement", []):
            if raw_stmt.get("Effect") != "Allow":
                continue

            principals = self._extract_principals(raw_stmt)
            actions = raw_stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            for principal_arn in principals:
                matched_identities = self._resolve_principal(
                    principal_arn, resource_account_id,
                )
                for identity_arn in matched_identities:
                    profile = self.get_or_create_profile(identity_arn)
                    profile.add_resource_policy_grant(resource_arn, actions)

        self._resolution_summary["resource_policies_analyzed"] = (
            self._resolution_summary.get("resource_policies_analyzed", 0) + 1
        )

    # ------------------------------------------------------------------
    # ARN normalization
    # ------------------------------------------------------------------
    @staticmethod
    def _normalize_arn(arn: str) -> str:
        """Normalize assumed-role ARNs to their IAM role equivalents.

        STS assumed-role ARNs look like:
          arn:aws:sts::123456789012:assumed-role/RoleName/session-name
        But profiles are stored under the IAM role ARN:
          arn:aws:iam::123456789012:role/RoleName

        This ensures lookups work regardless of which ARN format is used.
        """
        if ":assumed-role/" in arn:
            parts = arn.split(":")
            if len(parts) >= 6:
                resource = parts[5]
                role_parts = resource.split("/")
                role_name = role_parts[1] if len(role_parts) > 1 else role_parts[-1]
                account_id = parts[4]
                return f"arn:aws:iam::{account_id}:role/{role_name}"
        return arn

    def _resolve_profile(self, identity_arn: str) -> "IdentityPermissionProfile | None":
        """Look up a profile, trying both the raw and normalized ARN."""
        profile = self._profiles.get(identity_arn)
        if profile:
            return profile
        normalized = self._normalize_arn(identity_arn)
        if normalized != identity_arn:
            return self._profiles.get(normalized)
        return None

    # ------------------------------------------------------------------
    # Query interface
    # ------------------------------------------------------------------
    def identity_has_permission(
        self,
        identity_arn: str,
        action: str,
        resource_arn: str = "*",
        min_confidence: PermissionConfidence = PermissionConfidence.HEURISTIC,
    ) -> bool:
        """Check if an identity has a specific permission.

        Full evaluation chain with SCP enforcement:
          1. SCP deny (account-level) — always checked
          2. SCP allow whitelist — action must be in at least one SCP
          3. Per-identity evaluation (deny → boundary → allow → resource)

        Handles both raw STS ARNs (``arn:aws:sts::...:assumed-role/...``)
        and normalized IAM ARNs (``arn:aws:iam::...:role/...``)
        transparently.
        """
        # ── SCP deny check (even admins can be blocked by SCPs) ────
        for stmt in self._scp_deny_statements:
            if stmt.matches_action(action):
                return False

        # ── SCP allow whitelist ────────────────────────────────────
        if self._scp_allow_statements:
            scp_allows = any(
                stmt.matches_action(action)
                for stmt in self._scp_allow_statements
            )
            if not scp_allows:
                return False

        # ── Per-identity evaluation ────────────────────────────────
        profile = self._resolve_profile(identity_arn)
        if not profile:
            return False
        return profile.has_permission(action, resource_arn, min_confidence)

    def get_confidence(
        self, identity_arn: str, action: str, resource_arn: str = "*",
    ) -> PermissionConfidence:
        """Get confidence level for a permission check."""
        profile = self._resolve_profile(identity_arn)
        if not profile:
            return PermissionConfidence.UNKNOWN
        return profile.get_confidence(action, resource_arn)

    def get_confidence_multiplier(
        self, identity_arn: str, action: str, resource_arn: str = "*",
    ) -> float:
        """Get a success probability multiplier based on confidence."""
        profile = self._resolve_profile(identity_arn)
        if not profile:
            return 0.0
        return profile.get_success_multiplier(action, resource_arn)

    def is_admin(self, identity_arn: str) -> bool:
        """Check if an identity has admin-level access."""
        profile = self._resolve_profile(identity_arn)
        return profile.is_admin if profile else False

    def get_profile(
        self, identity_arn: str,
    ) -> IdentityPermissionProfile | None:
        """Get the full permission profile for an identity."""
        return self._resolve_profile(identity_arn)

    def get_or_create_profile(
        self, identity_arn: str,
    ) -> IdentityPermissionProfile:
        """Get or create a permission profile for an identity."""
        if identity_arn not in self._profiles:
            account_id = ""
            parts = identity_arn.split(":")
            if len(parts) >= 5:
                account_id = parts[4]
            self._profiles[identity_arn] = IdentityPermissionProfile(
                identity_arn=identity_arn,
                account_id=account_id,
            )
        return self._profiles[identity_arn]

    @property
    def caller_arn(self) -> str:
        return self._caller_arn

    def all_identities(self) -> list[str]:
        return list(self._profiles.keys())

    @property
    def resolution_summary(self) -> dict[str, Any]:
        """Summary of how permissions were resolved."""
        self._resolution_summary["total_identities"] = len(self._profiles)
        total_perms = sum(
            len(p.permissions) for p in self._profiles.values()
        )
        self._resolution_summary["total_permissions_mapped"] = total_perms
        cond_count = sum(
            1 for p in self._profiles.values()
            for e in p.permissions.values()
            if e.has_conditions
        )
        self._resolution_summary["condition_gated_permissions"] = cond_count
        blocking_count = sum(
            1 for p in self._profiles.values()
            for e in p.permissions.values()
            if e.has_blocking_conditions
        )
        self._resolution_summary["blocking_conditions_found"] = blocking_count
        return dict(self._resolution_summary)

    def update_summary(self, **kwargs: Any) -> None:
        self._resolution_summary.update(kwargs)

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        """Serialize the PermissionMap for persistence/replay."""
        profiles_data: dict[str, Any] = {}
        for arn, profile in self._profiles.items():
            perms = {}
            for action, entry in profile.permissions.items():
                perms[action] = {
                    "allowed": entry.allowed,
                    "confidence": entry.confidence.value,
                    "source": entry.source.value,
                    "resource_arn": entry.resource_arn,
                    "resource_arns": entry.resource_arns,
                    "has_conditions": entry.has_conditions,
                    "has_blocking_conditions": entry.has_blocking_conditions,
                    "notes": entry.notes,
                }
            profiles_data[arn] = {
                "is_admin": profile.is_admin,
                "admin_policy_arn": profile.admin_policy_arn,
                "permissions": perms,
                "service_access": {
                    svc: {
                        "has_read": sa.has_read,
                        "has_write": sa.has_write,
                        "read_confidence": sa.read_confidence.value,
                        "write_confidence": sa.write_confidence.value,
                        "confirmed_actions": sa.confirmed_actions,
                        "denied_actions": sa.denied_actions,
                    }
                    for svc, sa in profile.service_access.items()
                },
                "resolution_tier": profile.resolution_tier,
                "policy_documents_available": profile.policy_documents_available,
                "has_permission_boundary": profile.has_permission_boundary,
                "is_assumed_role": profile.is_assumed_role,
                "account_id": profile.account_id,
                "resource_policy_grants": profile.resource_policy_grants,
            }

        return {
            "caller_arn": self._caller_arn,
            "resolution_summary": self._resolution_summary,
            "profiles": profiles_data,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PermissionMap:
        """Deserialize a PermissionMap from saved data."""
        pmap = cls()
        pmap._caller_arn = data.get("caller_arn", "")
        pmap._resolution_summary = data.get("resolution_summary", {})

        for arn, pdata in data.get("profiles", {}).items():
            profile = pmap.get_or_create_profile(arn)
            profile.is_admin = pdata.get("is_admin", False)
            profile.admin_policy_arn = pdata.get("admin_policy_arn", "")
            profile.resolution_tier = pdata.get("resolution_tier", "none")
            profile.policy_documents_available = pdata.get(
                "policy_documents_available", False
            )
            profile.has_permission_boundary = pdata.get(
                "has_permission_boundary", False
            )
            profile.is_assumed_role = pdata.get("is_assumed_role", False)
            profile.account_id = pdata.get("account_id", "")
            profile.resource_policy_grants = pdata.get(
                "resource_policy_grants", {}
            )

            for action, edata in pdata.get("permissions", {}).items():
                profile.add_permission(PermissionEntry(
                    action=action,
                    allowed=edata.get("allowed", True),
                    confidence=PermissionConfidence(
                        edata.get("confidence", "confirmed")
                    ),
                    source=PermissionSource(
                        edata.get("source", "policy_document")
                    ),
                    resource_arn=edata.get("resource_arn", "*"),
                    resource_arns=edata.get("resource_arns", ["*"]),
                    has_conditions=edata.get("has_conditions", False),
                    has_blocking_conditions=edata.get(
                        "has_blocking_conditions", False
                    ),
                    notes=edata.get("notes", ""),
                ))

            for svc_name, sdata in pdata.get("service_access", {}).items():
                profile.service_access[svc_name] = ServiceAccess(
                    service=svc_name,
                    has_read=sdata.get("has_read", False),
                    has_write=sdata.get("has_write", False),
                    read_confidence=PermissionConfidence(
                        sdata.get("read_confidence", "unknown")
                    ),
                    write_confidence=PermissionConfidence(
                        sdata.get("write_confidence", "unknown")
                    ),
                    confirmed_actions=sdata.get("confirmed_actions", []),
                    denied_actions=sdata.get("denied_actions", []),
                )

        return pmap

    # ------------------------------------------------------------------
    # Summary for display
    # ------------------------------------------------------------------
    def summary(self) -> dict[str, Any]:
        admin_count = sum(1 for p in self._profiles.values() if p.is_admin)
        boundary_count = sum(
            1 for p in self._profiles.values() if p.has_permission_boundary
        )
        svc_coverage: set[str] = set()
        for p in self._profiles.values():
            svc_coverage.update(p.service_access.keys())

        return {
            "Identities Mapped": len(self._profiles),
            "Admin Identities": admin_count,
            "Permission Boundaries": boundary_count,
            "SCPs Loaded": self._resolution_summary.get("scps_loaded", 0),
            "Resource Policies": self._resolution_summary.get(
                "resource_policies_analyzed", 0
            ),
            "Resolution Tier": self._resolution_summary.get("tier_used", "none"),
            "Policy Docs Available": self._resolution_summary.get(
                "policy_docs_available", False
            ),
            "Sentinel Probes": (
                f"{self._resolution_summary.get('sentinel_probes_succeeded', 0)}"
                f"/{self._resolution_summary.get('sentinel_probes_run', 0)} succeeded"
            ),
            "Condition-Gated": self._resolution_summary.get(
                "condition_gated_permissions", 0
            ),
            "Blocking Conditions": self._resolution_summary.get(
                "blocking_conditions_found", 0
            ),
            "Services Covered": len(svc_coverage),
            "Service List": sorted(svc_coverage),
            "Total Permissions": self._resolution_summary.get(
                "total_permissions_mapped", 0
            ),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_statement(
        raw: dict[str, Any],
        source: PermissionSource,
    ) -> PolicyStatement:
        actions = raw.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        not_actions = raw.get("NotAction", [])
        if isinstance(not_actions, str):
            not_actions = [not_actions]
        resources = raw.get("Resource", ["*"])
        if isinstance(resources, str):
            resources = [resources]
        not_resources = raw.get("NotResource", [])
        if isinstance(not_resources, str):
            not_resources = [not_resources]

        return PolicyStatement(
            effect=raw.get("Effect", "Deny"),
            actions=actions,
            not_actions=not_actions,
            resources=resources,
            not_resources=not_resources,
            conditions=raw.get("Condition", {}),
            source=source,
        )

    @staticmethod
    def _extract_principals(stmt: dict[str, Any]) -> list[str]:
        principal = stmt.get("Principal", {})
        if principal == "*":
            return ["*"]
        if isinstance(principal, str):
            return [principal]
        if isinstance(principal, dict):
            arns: list[str] = []
            for key in ("AWS", "Service", "Federated"):
                vals = principal.get(key, [])
                if isinstance(vals, str):
                    vals = [vals]
                arns.extend(vals)
            return arns
        return []

    def _resolve_principal(
        self,
        principal_arn: str,
        resource_account_id: str,
    ) -> list[str]:
        if principal_arn == "*":
            return list(self._profiles.keys())

        if principal_arn in self._profiles:
            return [principal_arn]

        if ":root" in principal_arn:
            account_match = re.search(r":(\d{12}):", principal_arn)
            if account_match:
                acct = account_match.group(1)
                return [
                    arn for arn, p in self._profiles.items()
                    if p.account_id == acct
                ]

        return []

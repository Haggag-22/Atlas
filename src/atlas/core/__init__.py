"""atlas.core — Shared types, models, configuration, safety, and telemetry."""

from atlas.core.config import AtlasConfig
from atlas.core.graph import EnvironmentGraph
from atlas.core.models import (
    ActionResult,
    AttackEdge,
    AttackPlan,
    BackupPlan,
    CloudFormationStack,
    DetectionProfile,
    EBSSnapshot,
    EnvironmentMetadata,
    GuardrailState,
    IAMRole,
    IAMUser,
    KMSKey,
    LoggingState,
    PlannedAction,
    ProtectedResource,
    RDSInstance,
    SecretsManagerSecret,
    SSMParameter,
)
from atlas.core.permission_map import (
    PermissionConfidence,
    PermissionEntry,
    PermissionMap,
    PermissionSource,
    PolicyStatement,
)
from atlas.core.safety import SafetyGate
from atlas.core.telemetry import TelemetryRecorder
from atlas.core.types import (
    ActionStatus,
    EdgeType,
    Layer,
    NodeType,
    NoiseLevel,
    OperationPhase,
    Strategy,
)

"""Built-in technique plugins."""

from atlas.plugins.registry import register_plugin
from atlas.plugins.techniques.identity_discovery import IdentityDiscoveryPlugin
from atlas.plugins.techniques.permission_enumeration import PermissionEnumerationPlugin
from atlas.plugins.techniques.role_trust_analysis import RoleTrustAnalysisPlugin
from atlas.plugins.techniques.s3_enumeration import S3EnumerationPlugin
from atlas.plugins.techniques.security_group_enumeration import SecurityGroupEnumerationPlugin
from atlas.plugins.techniques.iam_policy_simulation import IAMPolicySimulationPlugin


def register_builtin_plugins() -> None:
    """Register all built-in technique plugins."""
    register_plugin(IdentityDiscoveryPlugin())
    register_plugin(PermissionEnumerationPlugin())
    register_plugin(RoleTrustAnalysisPlugin())
    register_plugin(S3EnumerationPlugin())
    register_plugin(SecurityGroupEnumerationPlugin())
    register_plugin(IAMPolicySimulationPlugin())

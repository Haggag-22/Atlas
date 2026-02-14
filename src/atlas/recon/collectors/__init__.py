"""atlas.recon.collectors — Individual AWS data collectors."""

from atlas.recon.collectors.backup import BackupCollector
from atlas.recon.collectors.guardrail import GuardrailCollector
from atlas.recon.collectors.identity import IdentityCollector
from atlas.recon.collectors.logging_config import LoggingConfigCollector
from atlas.recon.collectors.permission_resolver import PermissionResolverCollector
from atlas.recon.collectors.policy import PolicyCollector
from atlas.recon.collectors.resource import ResourceCollector
from atlas.recon.collectors.trust import TrustCollector

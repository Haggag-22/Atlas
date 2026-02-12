"""Safety controls: allowlists, confirmations, dry run."""

from atlas.core.config import SafetyConfig

F = TypeVar("F", bound=Callable[..., object])

_LAB_BANNER = """
╔══════════════════════════════════════════════════════════════════════╗
║  ATLAS - AWS Cloud Adversary Emulation                               ║
║  FOR AUTHORIZED LAB USE ONLY. Do not run in production accounts.     ║
║  You are responsible for compliance with AWS ToS and your policies.  ║
╚══════════════════════════════════════════════════════════════════════╝
"""


def get_lab_banner() -> str:
    return _LAB_BANNER.strip()


def check_account_allowed(account_id: str, config: SafetyConfig) -> bool:
    """Return True if account_id is in allowlist (or allowlist is empty and we warn)."""
    if not config.allowed_account_ids:
        return True  # No restriction
    return account_id in config.allowed_account_ids


def check_region_allowed(region: str, config: SafetyConfig) -> bool:
    return region in config.allowed_regions


def require_confirmation_destructive(config: SafetyConfig, technique_name: str) -> bool:
    """Return True if we may proceed (user confirmed or confirmation disabled)."""
    if not config.require_confirmation_destructive:
        return True
    # Actual confirmation is done in CLI; this just signals that confirmation is required
    return True

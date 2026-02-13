"""
atlas.executor.session
~~~~~~~~~~~~~~~~~~~~~~
AWS session management with credential chain tracking.

Manages the lifecycle of AWS credentials as the executor pivots
between identities.  Tracks the full provenance chain:
  initial_key → assumed_role_A → assumed_role_B

This chain is critical for:
  - Blast radius analysis
  - Rollback ordering
  - Telemetry correlation
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import aioboto3
import structlog

from atlas.core.config import AWSConfig

logger = structlog.get_logger(__name__)


@dataclass
class CredentialEntry:
    """A single set of credentials in the chain."""
    identity_arn: str
    access_key_id: str = ""
    session_token: str | None = None
    expiration: str | None = None
    source: str = ""      # how we got these creds ("initial", "assume_role", "create_key")
    parent_arn: str = ""   # identity that obtained these creds
    obtained_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )

    @property
    def is_expired(self) -> bool:
        if not self.expiration:
            return False
        try:
            exp = datetime.fromisoformat(self.expiration.replace("Z", "+00:00"))
            return datetime.now(timezone.utc) > exp
        except (ValueError, TypeError):
            return False


class SessionManager:
    """Manages credential chains and creates sessions for each identity."""

    def __init__(self, initial_config: AWSConfig) -> None:
        self._initial_config = initial_config
        self._chain: list[CredentialEntry] = []
        self._current: CredentialEntry | None = None

    @property
    def current_identity(self) -> str:
        """ARN of the identity we're currently operating as."""
        return self._current.identity_arn if self._current else ""

    @property
    def chain_depth(self) -> int:
        """How many credential pivots deep we are."""
        return len(self._chain)

    @property
    def credential_chain(self) -> list[dict[str, str]]:
        """Full provenance chain as a list of dicts."""
        return [
            {
                "identity": e.identity_arn,
                "source": e.source,
                "parent": e.parent_arn,
                "obtained_at": e.obtained_at,
            }
            for e in self._chain
        ]

    def set_initial_identity(self, arn: str) -> None:
        """Record the initial identity (from STS GetCallerIdentity)."""
        entry = CredentialEntry(
            identity_arn=arn,
            source="initial",
        )
        self._chain = [entry]
        self._current = entry
        logger.info("session_initial_identity", arn=arn)

    def add_assumed_role(
        self,
        *,
        role_arn: str,
        access_key_id: str,
        secret_access_key: str,
        session_token: str,
        expiration: str = "",
    ) -> None:
        """Record an assumed role and update current session."""
        parent = self._current.identity_arn if self._current else ""
        entry = CredentialEntry(
            identity_arn=role_arn,
            access_key_id=access_key_id,
            session_token=session_token,
            expiration=expiration,
            source="assume_role",
            parent_arn=parent,
        )
        # Store the secret key securely (in memory only, never serialized)
        entry._secret_key = secret_access_key  # type: ignore[attr-defined]
        self._chain.append(entry)
        self._current = entry
        logger.info("session_role_assumed", role=role_arn, depth=self.chain_depth)

    def add_access_key(
        self,
        *,
        user_arn: str,
        access_key_id: str,
        secret_access_key: str,
    ) -> None:
        """Record a newly created access key."""
        parent = self._current.identity_arn if self._current else ""
        entry = CredentialEntry(
            identity_arn=user_arn,
            access_key_id=access_key_id,
            source="create_key",
            parent_arn=parent,
        )
        entry._secret_key = secret_access_key  # type: ignore[attr-defined]
        self._chain.append(entry)
        self._current = entry
        logger.info("session_key_added", user=user_arn, depth=self.chain_depth)

    def get_current_session(self) -> aioboto3.Session:
        """Create an aioboto3 session for the current identity."""
        if not self._current or self._current.source == "initial":
            return self._get_initial_session()

        # Use assumed role or created key credentials
        secret = getattr(self._current, "_secret_key", "")
        return aioboto3.Session(
            aws_access_key_id=self._current.access_key_id,
            aws_secret_access_key=secret,
            aws_session_token=self._current.session_token,
            region_name=self._initial_config.region,
        )

    def revert_to_previous(self) -> bool:
        """Pop the current credential and revert to the previous one.

        Returns False if we're already at the initial identity.
        """
        if len(self._chain) <= 1:
            return False
        self._chain.pop()
        self._current = self._chain[-1]
        logger.info("session_reverted", identity=self._current.identity_arn)
        return True

    def _get_initial_session(self) -> aioboto3.Session:
        kwargs: dict[str, Any] = {}
        if self._initial_config.profile:
            kwargs["profile_name"] = self._initial_config.profile
        if self._initial_config.region:
            kwargs["region_name"] = self._initial_config.region
        if self._initial_config.access_key_id:
            kwargs["aws_access_key_id"] = self._initial_config.access_key_id
            kwargs["aws_secret_access_key"] = self._initial_config.secret_access_key
            if self._initial_config.session_token:
                kwargs["aws_session_token"] = self._initial_config.session_token
        return aioboto3.Session(**kwargs)

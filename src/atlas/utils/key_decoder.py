"""
atlas.utils.key_decoder
~~~~~~~~~~~~~~~~~~~~~~~
Decode AWS account IDs from access key IDs.

Two methods:
  1. **Offline decoding** (preferred): Extract the account ID directly from
     the access key ID using base32 decoding and bit-shifting.  This requires
     NO API calls, generates NO CloudTrail events, and works for keys created
     after March 29, 2019 (those with the 5th character >= 'Q').

  2. **API-based** (``sts:GetAccessKeyInfo``): Calls the STS API to resolve
     the account ID.  This is logged in CloudTrail but ONLY in the caller's
     account — NOT the target's account.

Original research:
  - Aidan Steele: AWS Access Key ID Formats
  - Tal Be'ery: A short note on AWS KEY ID (bit-shifting method)

Key format:
  - Characters 1-4: Prefix (AKIA = long-lived, ASIA = temporary)
  - Characters 5-12: Encode the AWS account ID (base32, big-endian)
  - Character 13: Encodes the least-significant bit of the account ID
  - Characters 14-20: Random / opaque

Valid character set: ABCDEFGHIJKLMNOPQRSTUVWXYZ234567 (base32)
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# ── Key prefix classifications ──────────────────────────────────────
KEY_PREFIXES: dict[str, str] = {
    "AKIA": "Long-lived IAM user access key",
    "ASIA": "Temporary security credentials (STS)",
    "ABIA": "AWS STS service bearer token",
    "ACCA": "Context-specific credential",
    "AROA": "IAM role unique ID (not an access key)",
    "AIDA": "IAM user unique ID (not an access key)",
    "AIPA": "EC2 instance profile ID",
    "ANSA": "Service-specific unique ID",
    "APKA": "Public key ID",
    "ANPA": "Managed policy unique ID",
    "ANVA": "Version in a managed policy",
    "AGPA": "IAM group unique ID",
    "ASCA": "Certificate unique ID",
}


@dataclass(frozen=True)
class KeyInfo:
    """Decoded information from an AWS access key ID."""

    access_key_id: str
    prefix: str
    prefix_description: str
    account_id: str | None          # None if decoding fails (old-format key)
    is_temporary: bool              # ASIA = temporary (STS)
    is_long_lived: bool             # AKIA = long-lived (IAM user)
    is_new_format: bool             # post-March-2019 (5th char >= 'Q')
    decode_method: str              # "offline" | "api" | "failed"


def decode_account_id(access_key_id: str) -> str | None:
    """Decode the AWS account ID from an access key ID (offline, no API call).

    Returns the 12-digit account ID string, or None if the key is in the
    old format (pre-March 2019) and cannot be decoded offline.

    This function generates ZERO API calls and ZERO CloudTrail events.
    """
    if len(access_key_id) < 16:
        return None

    # Only keys with 5th character >= 'Q' use the new encoding
    if access_key_id[4] < "Q":
        return None

    try:
        trimmed = access_key_id[4:]  # Remove prefix (AKIA/ASIA/etc.)
        # Pad to a multiple of 8 for base32 decoding
        padded = trimmed + "=" * ((8 - len(trimmed) % 8) % 8)
        decoded = base64.b32decode(padded.upper())
        # First 6 bytes encode the account ID
        raw_bytes = decoded[:6]
        z = int.from_bytes(raw_bytes, byteorder="big", signed=False)
        mask = int.from_bytes(
            binascii.unhexlify(b"7fffffffff80"),
            byteorder="big",
            signed=False,
        )
        account_id = (z & mask) >> 7
        return f"{account_id:012d}"
    except Exception:
        return None


def classify_key(access_key_id: str) -> KeyInfo:
    """Classify an access key ID and extract all available information.

    Performs offline decoding only (no API calls).
    """
    prefix = access_key_id[:4] if len(access_key_id) >= 4 else access_key_id
    prefix_desc = KEY_PREFIXES.get(prefix, "Unknown prefix")
    is_new = len(access_key_id) >= 5 and access_key_id[4] >= "Q"

    account_id = decode_account_id(access_key_id)

    return KeyInfo(
        access_key_id=access_key_id,
        prefix=prefix,
        prefix_description=prefix_desc,
        account_id=account_id,
        is_temporary=prefix == "ASIA",
        is_long_lived=prefix == "AKIA",
        is_new_format=is_new,
        decode_method="offline" if account_id else "failed",
    )


async def get_access_key_info_api(
    session: Any,
    access_key_id: str,
) -> str | None:
    """Use sts:GetAccessKeyInfo to resolve the account ID via API.

    NOTE: This call is logged in CloudTrail ONLY in the CALLER's account,
    not in the target account.  Safe for red team use when calling from
    your own account.
    """
    try:
        async with session.client("sts") as sts:
            resp = await sts.get_access_key_info(AccessKeyId=access_key_id)
            return resp.get("Account")
    except Exception as exc:
        logger.debug(
            "get_access_key_info_failed",
            key_id=access_key_id[:8] + "...",
            error=str(exc),
        )
        return None


def decode_multiple_keys(
    access_key_ids: list[str],
) -> dict[str, KeyInfo]:
    """Decode account IDs for multiple access key IDs (offline, batch).

    Returns a dict mapping access_key_id -> KeyInfo.
    """
    return {kid: classify_key(kid) for kid in access_key_ids}


def identify_cross_account_keys(
    access_key_ids: list[str],
    expected_account_id: str,
) -> list[KeyInfo]:
    """Find access keys that belong to a DIFFERENT account than expected.

    Useful for scope validation and cross-account credential discovery.
    """
    results: list[KeyInfo] = []
    for kid in access_key_ids:
        info = classify_key(kid)
        if info.account_id and info.account_id != expected_account_id:
            results.append(info)
    return results

"""Sealed miner-provider credentials for the generic confidential room.

The room holds a private sealing key bound to its approved image.  A miner seals
a provider descriptor to its matching public key, so the owner and validator
handle only ciphertext.  The descriptor is bound to the miner's submitted agent
bundle before a profile receives it.
"""

from __future__ import annotations

import json
import re

from room.dstack import get_client
from room.profile import MinerInferenceCredential

SEALING_KEY_PATH = "kata/sealing"
_CREDENTIAL_VERSION = 1
_CREDENTIAL_FIELDS = frozenset({"version", "provider", "api_key", "bundle_binding"})
_PROVIDER_PATTERN = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


def sealing_privkey() -> bytes:
    """The room's private sealing key -- bound to this image, never leaves the room."""
    return get_client().get_key(SEALING_KEY_PATH).decode_key()


def resolve_miner_credential(
    sealed_param: str = "", *, required: bool = True
) -> MinerInferenceCredential | None:
    """Decrypt and validate one miner credential inside the room.

    A room deliberately has no deploy-time provider-key fallback.  ``required``
    is false only for an intentionally inference-free submission; it returns
    ``None`` instead of substituting an operator credential.
    """
    sealed = sealed_param.strip()
    if not sealed:
        if not required:
            return None
        raise RuntimeError(
            "no sealed miner credential for this run (there is no plaintext fallback)"
        )
    try:
        plaintext = _decrypt(sealed)
    except Exception as exc:  # noqa: BLE001 - cryptographic library errors must not escape
        raise RuntimeError("sealed miner credential could not be decrypted") from exc
    return _parse_credential(plaintext)


def _decrypt(sealed: str) -> str:
    from ecies import decrypt as ecies_decrypt

    return ecies_decrypt(sealing_privkey(), bytes.fromhex(sealed)).decode("utf-8")


def _parse_credential(plaintext: str) -> MinerInferenceCredential:
    """Parse the versioned plaintext without ever echoing a miner API key."""

    try:
        payload = json.loads(plaintext)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("sealed miner credential has an invalid format") from exc
    if not isinstance(payload, dict) or set(payload) != _CREDENTIAL_FIELDS:
        raise RuntimeError("sealed miner credential has an invalid format")
    if payload.get("version") != _CREDENTIAL_VERSION:
        raise RuntimeError("sealed miner credential uses an unsupported version")
    provider = payload.get("provider")
    api_key = payload.get("api_key")
    bundle_binding = payload.get("bundle_binding")
    if not isinstance(provider, str) or not _PROVIDER_PATTERN.fullmatch(provider):
        raise RuntimeError("sealed miner credential has an invalid provider")
    if (
        not isinstance(api_key, str)
        or not api_key
        or len(api_key) > 8192
        or any(ord(character) < 32 for character in api_key)
    ):
        raise RuntimeError("sealed miner credential has an invalid API key")
    if not isinstance(bundle_binding, str) or not _SHA256_PATTERN.fullmatch(bundle_binding):
        raise RuntimeError("sealed miner credential has an invalid bundle binding")
    return MinerInferenceCredential(
        provider=provider,
        api_key=api_key,
        bundle_binding=bundle_binding,
    )

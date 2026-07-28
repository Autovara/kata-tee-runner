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
from room.ids import PROVIDER_ID_REGEX
from room.profile import (
    CREDENTIAL_VERSION_MULTI_KEY,
    CREDENTIAL_VERSION_SINGLE_KEY,
    CredentialSpec,
    MinerCredentialSet,
    MinerInferenceCredential,
)

SEALING_KEY_PATH = "kata/sealing"
_CREDENTIAL_VERSION = CREDENTIAL_VERSION_SINGLE_KEY
_CREDENTIAL_FIELDS = frozenset({"version", "provider", "api_key", "bundle_binding"})
_CREDENTIAL_SET_FIELDS = frozenset(
    {"version", "credential_profile", "credentials", "bundle_binding"}
)
_PROVIDER_PATTERN = re.compile(PROVIDER_ID_REGEX + r"\Z")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")

#: A key shorter than this is a placeholder rather than a credential.  The upper bound matches the
#: single-key parser so neither shape accepts something the other would refuse.
MIN_KEY_CHARS = 16
MAX_KEY_CHARS = 8192


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


def resolve_sealed_credential(
    sealed_param: str = "", *, spec: CredentialSpec, required: bool = True
):
    """Decrypt and validate a sealed payload against the contract the loaded profile declares.

    This is the one entry point the server uses.  Dispatching on the *profile's* declared version --
    rather than on whatever version the payload claims -- is what makes the two shapes mutually
    unreachable: a room running a single-key profile will not parse a multi-key payload no matter
    how it is labelled, and a room running a multi-key profile will not accept a single key.

    Returns ``MinerInferenceCredential`` for version 1 and ``MinerCredentialSet`` for version 2.

    Version 1 is delegated to :func:`resolve_miner_credential` unchanged rather than reimplemented
    here.  That is deliberate: the single-key path is deployed and carrying real money, so the
    strongest available evidence that multi-key sealing did not disturb it is that its code and its
    tests are untouched.
    """
    if spec.version != CREDENTIAL_VERSION_MULTI_KEY:
        return resolve_miner_credential(sealed_param, required=required)

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
    return _parse_credential_set(plaintext, spec=spec)


def _decrypt(sealed: str) -> str:
    from ecies import decrypt as ecies_decrypt

    return ecies_decrypt(sealing_privkey(), bytes.fromhex(sealed)).decode("utf-8")


def _parse_credential_set(plaintext: str, *, spec: CredentialSpec) -> MinerCredentialSet:
    """Parse a multi-key payload without ever echoing a miner API key.

    Every message raised here reaches a miner's pull request, the room's logs and -- via the failure
    envelope -- an attestation.  So each one names the *field* and never the value, and the caller
    that reports it upstream reduces it further to a reason code.
    """

    try:
        payload = json.loads(plaintext)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("sealed miner credential has an invalid format") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("sealed miner credential has an invalid format")

    # VERSION FIRST.  A single-key payload also fails the field-set check below, but on a message
    # that does not tell a miner what they actually did, which was seal with the wrong tool.
    if payload.get("version") != CREDENTIAL_VERSION_MULTI_KEY:
        raise RuntimeError(
            "sealed miner credential uses an unsupported version; this room requires a "
            "multi-credential payload"
        )
    if set(payload) != _CREDENTIAL_SET_FIELDS:
        raise RuntimeError("sealed miner credential has an invalid format")

    if payload.get("credential_profile") != spec.credential_profile:
        # Sealed for a different lane's policy.  Spending it here would run a contestant under
        # rules it never agreed to, and would bill it for the privilege.
        raise RuntimeError("sealed miner credential is not for this room's credential profile")

    bundle_binding = payload.get("bundle_binding")
    if not isinstance(bundle_binding, str) or not _SHA256_PATTERN.fullmatch(bundle_binding):
        raise RuntimeError("sealed miner credential has an invalid bundle binding")

    credentials = payload.get("credentials")
    if not isinstance(credentials, dict):
        raise RuntimeError("sealed miner credential has an invalid credential map")

    required = set(spec.required_providers)
    present = set(credentials)
    missing = sorted(required - present)
    if missing:
        raise RuntimeError(
            f"sealed miner credential is missing required provider(s): {', '.join(missing)}"
        )
    unexpected = sorted(present - required)
    if unexpected:
        # Refused rather than ignored: a miner who sealed a fifth key believed it would be spent,
        # and silently dropping it leaves that belief intact until it costs them a duel.
        raise RuntimeError(
            f"sealed miner credential has unexpected provider(s): {', '.join(unexpected)}"
        )

    keys: dict = {}
    for provider in spec.required_providers:
        if not _PROVIDER_PATTERN.fullmatch(provider):
            raise RuntimeError("profile declares an invalid provider id")
        entry = credentials[provider]
        if not isinstance(entry, dict) or set(entry) != {"api_key"}:
            raise RuntimeError(f"sealed credential for {provider} has an invalid format")
        api_key = entry["api_key"]
        if not isinstance(api_key, str):
            raise RuntimeError(f"sealed credential for {provider} has an invalid API key")
        # Length and alphabet only.  Neither branch reports the value, nor its length in a way that
        # narrows it, because this text reaches the miner.
        if not MIN_KEY_CHARS <= len(api_key) <= MAX_KEY_CHARS:
            raise RuntimeError(f"sealed credential for {provider} has an invalid API key length")
        if any(ord(character) < 32 or ord(character) == 127 for character in api_key):
            raise RuntimeError(f"sealed credential for {provider} has an invalid API key")
        keys[provider] = api_key

    return MinerCredentialSet(
        credentials=keys,
        bundle_binding=bundle_binding,
        credential_profile=spec.credential_profile,
    )


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

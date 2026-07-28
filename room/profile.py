"""The one seam a subnet implements to run inside the sealed room.

The room handles sealing, the inference gateway, the sealed network, attestation,
and HTTP endpoints. A subnet profile only says how to fetch its problem and run a
miner agent against it to produce a report.

This is the generic contract; a subnet's implementation lives in the subnet's own package and is
loaded at startup via ``KATA_TEE_PROFILE=<module>:<Class>``."""

import os
from dataclasses import dataclass
from typing import Protocol

# A profile owns the mechanics of starting an untrusted agent container, but all
# profiles should use the same deployment knob for its total wall-clock budget.
# This limits a stuck process; it is deliberately not a model, token, call, or
# retry budget.
AGENT_EXECUTION_TIMEOUT_ENV = "KATA_TEE_AGENT_EXECUTION_TIMEOUT_SECONDS"
DEFAULT_AGENT_EXECUTION_TIMEOUT_SECONDS = 840


def resolve_agent_execution_timeout_seconds() -> float:
    """Return the configured total agent-process timeout for a TEE profile.

    Fail closed on a malformed value so a deployment typo is visible before an
    untrusted candidate gets an unexpectedly long execution allowance.
    """

    raw = os.environ.get(AGENT_EXECUTION_TIMEOUT_ENV, "").strip()
    if not raw:
        return float(DEFAULT_AGENT_EXECUTION_TIMEOUT_SECONDS)
    try:
        timeout = float(raw)
    except ValueError as exc:
        raise RuntimeError(f"{AGENT_EXECUTION_TIMEOUT_ENV} must be a positive number") from exc
    if timeout <= 0:
        raise RuntimeError(f"{AGENT_EXECUTION_TIMEOUT_ENV} must be a positive number")
    return timeout


@dataclass(frozen=True)
class TeeJobResult:
    """The profile result that the generic room binds into its TEE attestation."""

    report: dict
    provenance: dict[str, object]


@dataclass(frozen=True)
class MinerInferenceCredential:
    """A miner-owned provider credential decrypted only inside the sealed room.

    ``provider`` is an opaque, allowlisted route identifier.  ``api_key`` and
    ``bundle_binding`` are never returned by the room or included in attestation
    provenance.  Binding the credential to the submitted agent bundle prevents a
    validator from replaying a public ciphertext with a different agent to reveal
    the miner's key.
    """

    provider: str
    api_key: str
    bundle_binding: str

    def __repr__(self) -> str:
        # The default dataclass repr would print the key.  A secret-bearing object that renders
        # itself is a secret in every log line that ever catches an exception holding one.
        return f"MinerInferenceCredential(provider={self.provider!r}, api_key=<redacted>)"

    __str__ = __repr__


@dataclass(frozen=True)
class MinerCredentialSet:
    """Several miner-owned provider credentials, decrypted only inside the sealed room.

    The version-1 shape above carries exactly one key, which fits a subnet whose evaluation is a
    single inference call.  A subnet whose evaluation spends against several independent providers
    -- search, scraping, summarisation, judging -- cannot express that as one key, and a run that
    discovers the second provider is missing has already spent real money on the first.

    So the whole set is sealed together and validated up front.  *Which* providers make up the set
    is not this module's business: the room stays subnet-blind, and the profile declares its own
    ``required_providers``.  The room enforces exactly that set, no more and no less.

    Like the single credential, this object never leaves the room and never renders its values.
    """

    credentials: dict
    bundle_binding: str
    credential_profile: str

    def __repr__(self) -> str:
        return (
            f"MinerCredentialSet(providers={sorted(self.credentials)!r}, "
            f"credential_profile={self.credential_profile!r}, keys=<redacted>)"
        )

    __str__ = __repr__

    def key(self, provider: str) -> str:
        """The key for one provider.  Callers are trusted in-room code only."""
        if provider not in self.credentials:
            raise RuntimeError(f"no sealed credential for provider {provider!r}")
        return self.credentials[provider]

    @property
    def providers(self) -> tuple:
        return tuple(sorted(self.credentials))


#: Sealed-payload versions.  A profile that declares neither gets version 1, because that is what
#: every profile predating multi-key sealing used and silently re-interpreting those payloads under
#: a new schema is precisely the failure this versioning exists to prevent.  A new profile that
#: forgets to declare a version therefore fails loudly at its first credential -- "this room expects
#: one key, you sealed four" -- rather than scoring something under rules nobody chose.
CREDENTIAL_VERSION_SINGLE_KEY = 1
CREDENTIAL_VERSION_MULTI_KEY = 2


@dataclass(frozen=True)
class CredentialSpec:
    """What a profile requires of a sealed credential payload.

    This is the whole of what the room knows about a subnet's credentials.  It is deliberately data
    rather than code: the base image must be able to enforce a subnet's requirements without
    containing that subnet's name.
    """

    version: int = CREDENTIAL_VERSION_SINGLE_KEY
    #: For version 2: the exact provider set, and the profile string the sealed payload must carry.
    #: Empty for version 1, whose payload names a single provider the gateway routes on instead.
    required_providers: tuple = ()
    credential_profile: str = ""


def credential_spec_for(profile) -> CredentialSpec:
    """The credential contract a loaded profile declares.

    Reads attributes rather than requiring a method so existing single-key profiles -- which live in
    other repositories and predate this -- keep working untouched.
    """
    version = int(getattr(profile, "credential_version", CREDENTIAL_VERSION_SINGLE_KEY))
    if version == CREDENTIAL_VERSION_SINGLE_KEY:
        return CredentialSpec(version=version)
    if version != CREDENTIAL_VERSION_MULTI_KEY:
        raise RuntimeError(f"profile declares unsupported credential_version {version!r}")

    providers = tuple(getattr(profile, "required_providers", ()) or ())
    credential_profile = str(getattr(profile, "credential_profile", "") or "")
    if not providers:
        raise RuntimeError(
            "a multi-key profile must declare required_providers; the room enforces the set the "
            "profile names and has no subnet-specific default to fall back to"
        )
    if len(set(providers)) != len(providers):
        raise RuntimeError("profile declares a duplicate provider in required_providers")
    if not credential_profile:
        raise RuntimeError(
            "a multi-key profile must declare credential_profile so a payload sealed for another "
            "lane's policy is refused rather than spent"
        )
    return CredentialSpec(
        version=version,
        required_providers=providers,
        credential_profile=credential_profile,
    )


class TeeJobProfile(Protocol):
    #: project_key that selects the no-docker plumbing stub (local tests).
    fixture_project: str

    #: Optional. Omit (or set 1) for a single sealed key; set 2 to receive a MinerCredentialSet, and
    #: then also declare ``required_providers`` and ``credential_profile``. See CredentialSpec.
    credential_version: int
    required_providers: tuple
    credential_profile: str

    def run(
        self,
        *,
        project_key: str,
        credential: MinerInferenceCredential | MinerCredentialSet | None,
        bundle_root: str | None,
        job_id: str,
        bundle_sha256: str,
    ) -> TeeJobResult:
        """Run the miner's agent for ``project_key`` inside the room and return its report (a
        JSON-able dict) and immutable execution provenance.  The generic room has already bounded
        and extracted ``bundle_root`` and verified any credential's binding before this method is
        called.  Talks only to the in-room gateway for inference. ``fixture_project`` selects a
        lightweight stub."""
        ...

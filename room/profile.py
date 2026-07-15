"""The one seam a subnet implements to run inside the sealed room.

The room handles sealing, the inference gateway, the sealed network, attestation,
and HTTP endpoints. A subnet profile only says how to fetch its problem and run a
miner agent against it to produce a report.

This is the generic contract; a subnet's implementation lives in the subnet's own package and is
loaded at startup via ``KATA_TEE_PROFILE=<module>:<Class>``."""

from dataclasses import dataclass
from typing import Protocol


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


class TeeJobProfile(Protocol):
    #: project_key that selects the no-docker plumbing stub (local tests).
    fixture_project: str

    def run(
        self,
        *,
        project_key: str,
        credential: MinerInferenceCredential | None,
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

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


class TeeJobProfile(Protocol):
    #: project_key that selects the no-docker plumbing stub (local tests).
    fixture_project: str

    def run(
        self,
        *,
        project_key: str,
        sealed_key: str,
        bundle_b64: str,
        job_id: str,
        bundle_sha256: str,
    ) -> TeeJobResult:
        """Run the miner's agent for ``project_key`` inside the room and return its report (a
        JSON-able dict) and immutable execution provenance. Talks only to the in-room gateway for
        inference. ``fixture_project`` selects a lightweight stub."""
        ...

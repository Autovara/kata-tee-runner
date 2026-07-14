"""The ONE seam a subnet implements to run inside the sealed room. The room handles sealing, the
relay + sealed network, attestation, and the HTTP endpoints; a subnet profile only says how to
fetch its problem and run the miner's agent against it to produce a report.

This is the generic contract; a subnet's implementation lives in the subnet's own package and is
loaded at startup via ``KATA_TEE_PROFILE=<module>:<Class>``."""

from typing import Protocol


class TeeJobProfile(Protocol):
    #: project_key that selects the no-docker plumbing stub (local tests).
    fixture_project: str

    def run(self, *, project_key: str, sealed_key: str, bundle_b64: str) -> dict:
        """Run the miner's agent for ``project_key`` inside the room and return its report (a
        JSON-able dict). Talks only to the in-room relay for inference. ``fixture_project`` selects
        a lightweight stub."""
        ...

"""A trivial in-repo TeeJobProfile for the plumbing test — proves the room runs any subnet's
profile with no subnet-specific code in the base."""

from room.profile import TeeJobResult


class FakeProfile:
    fixture_project = "fixture-project"

    def image(self, project_key: str) -> str:
        return f"registry.example/{project_key}:latest"

    def run(
        self, *, project_key: str, sealed_key: str = "", bundle_b64: str = "",
        job_id: str, bundle_sha256: str,
    ) -> TeeJobResult:
        return TeeJobResult(
            report={"findings": [project_key]},
            provenance={
                "profile": "fake",
                "project_image": f"registry.example/{project_key}@sha256:fake",
                "pinned_model": "fake",
                "job_id": job_id,
            },
        )

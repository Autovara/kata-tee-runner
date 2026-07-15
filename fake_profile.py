"""A trivial in-repo TeeJobProfile for the plumbing test — proves the room runs any subnet's
profile with no subnet-specific code in the base."""

from room.profile import MinerInferenceCredential, TeeJobResult


class FakeProfile:
    fixture_project = "fixture-project"

    def image(self, project_key: str) -> str:
        return f"registry.example/{project_key}:latest"

    def run(
        self,
        *,
        project_key: str,
        credential: MinerInferenceCredential | None = None,
        bundle_root: str | None = None,
        job_id: str,
        bundle_sha256: str,
    ) -> TeeJobResult:
        return TeeJobResult(
            report={
                "findings": [project_key],
                "credential_provider": credential.provider if credential else None,
                "bundle_received": bundle_root is not None,
            },
            provenance={
                "profile": "fake",
                "project_image": f"registry.example/{project_key}@sha256:fake",
                "inference_policy": "fixture",
                "job_id": job_id,
            },
        )

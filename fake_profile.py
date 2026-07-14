"""A trivial in-repo TeeJobProfile for the plumbing test — proves the room runs any subnet's
profile with no subnet-specific code in the base."""


class FakeProfile:
    fixture_project = "fixture-project"

    def image(self, project_key: str) -> str:
        return f"registry.example/{project_key}:latest"

    def run(self, *, project_key: str, sealed_key: str = "", bundle_b64: str = "") -> dict:
        return {"findings": [project_key]}

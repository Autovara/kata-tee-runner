from __future__ import annotations

import json
from pathlib import Path

import pytest

from room import sealing
from room.bundle import credential_bundle_binding


def _credential(**changes) -> str:
    payload = {
        "version": 1,
        "provider": "openrouter",
        "api_key": "miner-secret-key",
        "bundle_binding": "a" * 64,
    }
    payload.update(changes)
    return json.dumps(payload)


def test_resolve_miner_credential_is_versioned_and_does_not_echo_key(monkeypatch) -> None:
    monkeypatch.setattr(sealing, "_decrypt", lambda _sealed: _credential())
    credential = sealing.resolve_miner_credential("ciphertext")
    assert credential is not None
    assert credential.provider == "openrouter"
    assert credential.api_key == "miner-secret-key"


@pytest.mark.parametrize(
    "payload",
    [
        "not json",
        _credential(provider="Invalid Provider"),
        _credential(bundle_binding="wrong"),
        _credential(api_key=""),
        _credential(unexpected="value"),
    ],
)
def test_resolve_miner_credential_rejects_invalid_descriptors_without_key_leak(
    monkeypatch, payload
) -> None:
    monkeypatch.setattr(sealing, "_decrypt", lambda _sealed: payload)
    with pytest.raises(RuntimeError) as error:
        sealing.resolve_miner_credential("ciphertext")
    assert "miner-secret-key" not in str(error.value)


def test_inference_free_submission_has_no_platform_fallback() -> None:
    assert sealing.resolve_miner_credential(required=False) is None
    with pytest.raises(RuntimeError, match="no sealed miner credential"):
        sealing.resolve_miner_credential()


def test_credential_binding_ignores_transient_local_artifacts(tmp_path: Path) -> None:
    bundle = tmp_path / "submission"
    bundle.mkdir()
    (bundle / "agent.py").write_text("def agent_main(): pass\n", encoding="utf-8")
    expected = credential_bundle_binding(bundle)

    cache = bundle / "__pycache__"
    cache.mkdir()
    (cache / "agent.cpython-313.pyc").write_bytes(b"compiled-agent")
    (bundle / "helper.pyo").write_bytes(b"optimized-agent")
    git_dir = bundle / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")

    assert credential_bundle_binding(bundle) == expected

from __future__ import annotations

import json

import pytest

from room import sealing


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

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import kata_seal
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


def test_credential_binding_includes_submission_metadata(tmp_path: Path) -> None:
    bundle = tmp_path / "submission"
    bundle.mkdir()
    (bundle / "agent.py").write_text("def agent_main(): pass\n", encoding="utf-8")
    (bundle / "submission.json").write_text('{"submission_id":"first"}\n', encoding="utf-8")
    initial = credential_bundle_binding(bundle)

    (bundle / "submission.json").write_text('{"submission_id":"second"}\n', encoding="utf-8")

    assert credential_bundle_binding(bundle) != initial


def test_kata_seal_rejects_a_blank_api_key_before_contacting_the_room(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("TEST_PROVIDER_KEY", "   ")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "kata_seal.py",
            "--room",
            "https://room.example",
            "--provider",
            "akashml",
            "--key-env",
            "TEST_PROVIDER_KEY",
            # A REAL directory. This passed `./submission` when single-key sealing was its own
            # program, which failed on the blank key only because the bundle was not checked until
            # later. The merged tool applies the multi-key rule to both contracts -- every local
            # check before any secret is read -- so a bogus bundle is now reported first, and this
            # test would have been asserting the argument order rather than the blank-key refusal.
            "--bundle",
            str(tmp_path),
            # Likewise. Single-key sealing used to load the key -- including PROMPTING for it --
            # and only then check --measurement. The merged tool validates every argument before
            # reading any secret, so a miner is no longer asked for a credential and then told
            # their command was malformed.
            "--measurement",
            "a" * 64,
        ],
    )

    with pytest.raises(SystemExit, match="must not be empty"):
        kata_seal.main()


def test_kata_seal_checks_the_bundle_before_reading_any_key(monkeypatch) -> None:
    """No secret is read, and no room contacted, until the arguments are known-good."""
    monkeypatch.setenv("TEST_PROVIDER_KEY", "miner-key-value-0123456789")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "kata_seal.py",
            "--room", "https://room.example",
            "--provider", "akashml",
            "--key-env", "TEST_PROVIDER_KEY",
            "--bundle", "./does-not-exist",
            "--no-verify",
        ],
    )
    with pytest.raises(SystemExit, match="is not a directory"):
        kata_seal.main()


def test_kata_seal_requires_an_approved_measurement_before_contacting_room(
    monkeypatch,
) -> None:
    monkeypatch.setenv("TEST_PROVIDER_KEY", "miner-key")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "kata_seal.py",
            "--room",
            "https://room.example",
            "--provider",
            "akashml",
            "--key-env",
            "TEST_PROVIDER_KEY",
            "--bundle",
            "./submission",
        ],
    )
    monkeypatch.setattr(
        kata_seal,
        "fetch_pubkey",
        lambda _room: pytest.fail("must reject before contacting the room"),
    )

    with pytest.raises(SystemExit, match="--measurement"):
        kata_seal.main()


@pytest.mark.parametrize(
    "room",
    [
        "https://:password@room.example",
        "https://room.example?redirect=https://evil.example",
        "https://room.example#fragment",
    ],
)
def test_kata_seal_rejects_ambiguous_room_urls(room: str) -> None:
    with pytest.raises(SystemExit, match="without embedded credentials"):
        kata_seal.fetch_pubkey(room)


def test_kata_seal_http_client_refuses_redirects() -> None:
    assert (
        kata_seal._RejectRedirects().redirect_request(
            None, None, 307, "redirect", {}, "https://evil.example"
        )
        is None
    )


def test_kata_seal_key_file_must_be_private_and_regular(
    monkeypatch, tmp_path: Path
) -> None:
    exposed = tmp_path / "provider-key"
    exposed.write_text("miner-key\n", encoding="utf-8")
    exposed.chmod(0o644)
    with pytest.raises(SystemExit, match="group/other"):
        kata_seal.load_api_key(key_env="", key_file=str(exposed))

    exposed.chmod(0o600)
    assert kata_seal.load_api_key(key_env="", key_file=str(exposed)) == "miner-key"


def test_kata_seal_quote_must_bind_the_published_key(monkeypatch) -> None:
    pubkey = "02" + "11" * 32
    report = SimpleNamespace(mr_config_id=b"\x01" + b"\xaa" * 32, report_data=b"\x00" * 64)
    parsed = SimpleNamespace(report=report, is_tdx=lambda: True)

    async def collateral(_url, _raw):
        return object()

    fake_qvl = SimpleNamespace(
        PHALA_PCCS_URL="https://pccs.example",
        parse_quote=lambda _raw: parsed,
        get_collateral=collateral,
        verify=lambda _raw, _collateral, _now: SimpleNamespace(status="OK"),
    )
    monkeypatch.setitem(sys.modules, "dcap_qvl", fake_qvl)

    with pytest.raises(SystemExit, match="does not bind"):
        kata_seal.verify_room("00", pubkey, "aa" * 32)


def test_kata_seal_accepts_only_a_bound_approved_current_tdx_quote(monkeypatch) -> None:
    pubkey = "02" + "11" * 32
    binding = kata_seal.hashlib.sha256(
        b"kata-sealing-pubkey:" + bytes.fromhex(pubkey)
    ).digest()
    report = SimpleNamespace(
        mr_config_id=b"\x01" + b"\xaa" * 32,
        report_data=binding + b"\x00" * 32,
    )
    parsed = SimpleNamespace(report=report, is_tdx=lambda: True)

    async def collateral(_url, _raw):
        return object()

    fake_qvl = SimpleNamespace(
        PHALA_PCCS_URL="https://pccs.example",
        parse_quote=lambda _raw: parsed,
        get_collateral=collateral,
        verify=lambda _raw, _collateral, _now: SimpleNamespace(
            status="SW_HARDENING_NEEDED"
        ),
    )
    monkeypatch.setitem(sys.modules, "dcap_qvl", fake_qvl)

    assert kata_seal.verify_room("00", pubkey, "aa" * 32) == (
        "aa" * 32,
        "SW_HARDENING_NEEDED",
    )

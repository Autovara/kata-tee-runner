"""Plumbing test for the subnet-blind sealed-room server: it loads whatever profile
KATA_TEE_PROFILE names (here the in-repo FakeProfile) and runs the same attestation-bound /run flow
— proving the base names no subnet. Mirrors the binding assertions any subnet runner is held to,
and covers the /run request authentication (room.auth)."""

import hashlib
import json
import time

import pytest

from room import auth
from room.attest import bind_and_quote, binding_payload, canonical
from room.sealing import resolve_inference_key
from room.server import PROFILE, app


def _post_run(body: dict, *, signature: str | None = "__valid__"):
    """POST /run with a valid HMAC signature by default; pass signature=None to omit it, or a string
    to force a specific (e.g. wrong) signature."""
    body = {
        "issued_at": int(time.time()),
        "expires_at": int(time.time()) + 60,
        "bundle_sha256": "ab" * 32,
        **body,
    }
    raw = json.dumps(body).encode()
    headers = {"Content-Type": "application/json"}
    if signature == "__valid__":
        headers[auth.SIGNATURE_HEADER] = auth.sign(raw)
    elif signature is not None:
        headers[auth.SIGNATURE_HEADER] = signature
    return app.test_client().post("/run", data=raw, headers=headers)


def test_profile_is_loaded_generically_from_env():
    assert type(PROFILE).__name__ == "FakeProfile"


def test_health():
    assert app.test_client().get("/health").get_json() == {"ok": True}


def test_bind_and_quote_binds_answer_project_and_nonce():
    report = {"findings": ["f1"]}
    nonce = b"\x02" * 16
    provenance = {"profile": "fake", "project_image": "image@sha256:test"}
    answer_hash, binding_hash, report_data, quote = bind_and_quote(
        report, nonce, "proj-a", bundle_sha256="ab" * 32, provenance=provenance,
    )
    assert answer_hash == hashlib.sha256(canonical(report)).digest()
    assert binding_hash == hashlib.sha256(
        canonical(binding_payload(report=report, bundle_sha256="ab" * 32, provenance=provenance))
    ).digest()
    assert report_data == hashlib.sha256(nonce + b"proj-a" + binding_hash).digest()
    assert quote.quote


def test_run_uses_the_loaded_profile_and_binds():
    nonce = "cc" * 16
    resp = _post_run({"nonce": nonce, "project_key": "proj-x"})
    data = resp.get_json()
    assert resp.status_code == 200
    assert data["report"] == {"findings": ["proj-x"]}
    binding_hash = hashlib.sha256(canonical(binding_payload(
        report={"findings": ["proj-x"]}, bundle_sha256="ab" * 32,
        provenance=data["provenance"],
    ))).digest()
    report_data = hashlib.sha256(bytes.fromhex(nonce) + b"proj-x" + binding_hash).digest()
    assert data["report_data_sha256"] == report_data.hex()
    assert data["quote"] == "fake-quote:" + report_data.hex()


def test_run_rejects_non_hex_nonce():
    assert _post_run({"nonce": "zz", "project_key": "proj-x"}).status_code == 400


def test_run_rejects_replay():
    body = {"nonce": "de" * 16, "project_key": "proj-x"}
    assert _post_run(body).status_code == 200
    assert _post_run(body).status_code == 409


def test_run_rejects_expired_request():
    now = int(time.time())
    assert _post_run({
        "nonce": "ef" * 16, "project_key": "proj-x", "issued_at": now - 120,
        "expires_at": now - 60,
    }).status_code == 400


def test_pull_test_is_disabled_by_default():
    assert app.test_client().post("/pull-test").status_code == 404


def test_inference_free_profile_never_receives_a_fallback_key():
    assert resolve_inference_key(required=False) == ""
    with pytest.raises(RuntimeError, match="no sealed inference key"):
        resolve_inference_key()


def test_run_rejects_unsigned_request():
    # No signature header -> 401. This is the fix for the key-exfil vuln: an attacker can't invoke
    # /run (so can't have a victim's sealed key decrypted into their agent).
    assert _post_run({"nonce": "cc" * 16, "project_key": "proj-x"}, signature=None).status_code == 401


def test_run_rejects_bad_signature():
    assert _post_run({"nonce": "cc" * 16, "project_key": "proj-x"}, signature="deadbeef").status_code == 401


def test_run_rejects_tampered_body_after_signing():
    # A signature is over the exact bytes; changing the body invalidates it.
    raw = json.dumps({"nonce": "cc" * 16, "project_key": "proj-x"}).encode()
    sig = auth.sign(raw)
    tampered = raw.replace(b"proj-x", b"proj-EVIL")
    resp = app.test_client().post(
        "/run", data=tampered,
        headers={"Content-Type": "application/json", auth.SIGNATURE_HEADER: sig},
    )
    assert resp.status_code == 401


def test_run_fails_closed_when_secret_unconfigured(monkeypatch):
    monkeypatch.delenv(auth.AUTH_SECRET_ENV, raising=False)
    resp = _post_run({"nonce": "cc" * 16, "project_key": "proj-x"}, signature=None)
    assert resp.status_code == 503

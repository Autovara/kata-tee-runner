"""Plumbing test for the subnet-blind sealed-room server: it loads whatever profile
KATA_TEE_PROFILE names (here the in-repo FakeProfile) and runs the same attestation-bound /run flow
— proving the base names no subnet. Mirrors the binding assertions any subnet runner is held to,
and covers the /run request authentication (room.auth)."""

import hashlib
import json

from room import auth
from room.attest import bind_and_quote, canonical
from room.server import PROFILE, app


def _post_run(body: dict, *, signature: str | None = "__valid__"):
    """POST /run with a valid HMAC signature by default; pass signature=None to omit it, or a string
    to force a specific (e.g. wrong) signature."""
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
    answer_hash, report_data, quote = bind_and_quote(report, nonce, "proj-a")
    assert answer_hash == hashlib.sha256(canonical(report)).digest()
    assert report_data == hashlib.sha256(nonce + b"proj-a" + answer_hash).digest()
    assert quote.quote


def test_run_uses_the_loaded_profile_and_binds():
    nonce = "cc" * 16
    resp = _post_run({"nonce": nonce, "project_key": "proj-x"})
    data = resp.get_json()
    assert resp.status_code == 200
    assert data["report"] == {"findings": ["proj-x"]}
    answer_hash = hashlib.sha256(canonical({"findings": ["proj-x"]})).digest()
    report_data = hashlib.sha256(bytes.fromhex(nonce) + b"proj-x" + answer_hash).digest()
    assert data["report_data_sha256"] == report_data.hex()
    assert data["quote"] == "fake-quote:" + report_data.hex()


def test_run_rejects_non_hex_nonce():
    assert _post_run({"nonce": "zz", "project_key": "proj-x"}).status_code == 400


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

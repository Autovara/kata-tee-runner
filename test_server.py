"""Plumbing test for the subnet-blind sealed-room server: it loads whatever profile
KATA_TEE_PROFILE names (here the in-repo FakeProfile) and runs the same attestation-bound /run flow
— proving the base names no subnet. Mirrors the binding assertions any subnet runner is held to."""

import hashlib

from room.attest import bind_and_quote, canonical
from room.server import PROFILE, app


def test_profile_is_loaded_generically_from_env():
    # The base imported no subnet; it loaded the profile named by KATA_TEE_PROFILE.
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
    resp = app.test_client().post(
        "/run", json={"nonce": nonce, "project_key": "proj-x"}
    )
    data = resp.get_json()
    assert resp.status_code == 200
    # The report came from the loaded profile (FakeProfile echoes the project_key).
    assert data["report"] == {"findings": ["proj-x"]}
    answer_hash = hashlib.sha256(canonical({"findings": ["proj-x"]})).digest()
    report_data = hashlib.sha256(bytes.fromhex(nonce) + b"proj-x" + answer_hash).digest()
    assert data["report_data_sha256"] == report_data.hex()
    assert data["quote"] == "fake-quote:" + report_data.hex()


def test_run_rejects_non_hex_nonce():
    resp = app.test_client().post("/run", json={"nonce": "zz", "project_key": "proj-x"})
    assert resp.status_code == 400

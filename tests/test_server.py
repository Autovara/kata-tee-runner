"""Plumbing test for the subnet-blind sealed-room server: it loads whatever profile
KATA_TEE_PROFILE names (here the in-repo FakeProfile) and runs the same attestation-bound /run flow
— proving the base names no subnet. Mirrors the binding assertions any subnet runner is held to,
and covers the /run request authentication (room.auth)."""

import hashlib
import json
import time
from pathlib import Path

import pytest
from fake_profile import FakeMultiKeyProfile
from helpers import bundle_b64, bundle_binding, post_run

from room import auth, sealing
from room import server as server_module
from room.attest import bind_and_quote, binding_payload, canonical
from room.bundle import credential_bundle_binding
from room.profile import (
    CREDENTIAL_FAILURE_ATTESTED_ZERO,
    MinerCredentialSet,
    MinerInferenceCredential,
    credential_spec_for,
)
from room.server import CREDENTIAL_SPEC, PROFILE, app


def test_profile_is_loaded_generically_from_env():
    assert type(PROFILE).__name__ == "FakeProfile"


def test_health():
    assert app.test_client().get("/health").get_json() == {"ok": True}


def test_bind_and_quote_binds_answer_project_and_nonce():
    report = {"findings": ["f1"]}
    nonce = b"\x02" * 16
    provenance = {"profile": "fake", "project_image": "image@sha256:test"}
    answer_hash, binding_hash, report_data, quote = bind_and_quote(
        report,
        nonce,
        "proj-a",
        bundle_sha256="ab" * 32,
        provenance=provenance,
    )
    assert answer_hash == hashlib.sha256(canonical(report)).digest()
    assert (
        binding_hash
        == hashlib.sha256(
            canonical(
                binding_payload(report=report, bundle_sha256="ab" * 32, provenance=provenance)
            )
        ).digest()
    )
    assert report_data == hashlib.sha256(nonce + b"proj-a" + binding_hash).digest()
    assert quote.quote


def test_run_uses_the_loaded_profile_and_binds():
    nonce = "cc" * 16
    resp = post_run({"nonce": nonce, "project_key": "proj-x"})
    data = resp.get_json()
    assert resp.status_code == 200
    assert data["report"] == {
        "findings": ["proj-x"],
        "credential_provider": None,
        "bundle_received": False,
    }
    binding_hash = hashlib.sha256(
        canonical(
            binding_payload(
                report={
                    "findings": ["proj-x"],
                    "credential_provider": None,
                    "bundle_received": False,
                },
                bundle_sha256="ab" * 32,
                provenance=data["provenance"],
            )
        )
    ).digest()
    report_data = hashlib.sha256(bytes.fromhex(nonce) + b"proj-x" + binding_hash).digest()
    assert data["report_data_sha256"] == report_data.hex()
    assert data["quote"] == "fake-quote:" + report_data.hex()


def test_run_rejects_non_hex_nonce():
    assert post_run({"nonce": "zz", "project_key": "proj-x"}).status_code == 400


def test_run_rejects_replay():
    body = {"nonce": "de" * 16, "project_key": "proj-x"}
    assert post_run(body).status_code == 200
    assert post_run(body).status_code == 409


def test_run_rejects_expired_request():
    now = int(time.time())
    assert (
        post_run(
            {
                "nonce": "ef" * 16,
                "project_key": "proj-x",
                "issued_at": now - 120,
                "expires_at": now - 60,
            }
        ).status_code
        == 400
    )


def test_pull_test_is_disabled_by_default():
    assert app.test_client().post("/pull-test").status_code == 404


def test_run_binds_a_decrypted_credential_to_the_exact_agent_bundle(monkeypatch, tmp_path: Path):
    from room import server

    bundle_root = tmp_path / "bundle"
    bundle_root.mkdir()
    (bundle_root / "agent.py").write_text("def agent_main(): pass\n", encoding="utf-8")
    binding = credential_bundle_binding(bundle_root)
    credential = MinerInferenceCredential(
        provider="openrouter",
        api_key="private-miner-key",
        bundle_binding=binding,
    )
    monkeypatch.setattr(server.sealing, "resolve_miner_credential", lambda *_a, **_k: credential)
    files = {"agent.py": "def agent_main(): pass\n"}
    bundle = bundle_b64(files)

    response = post_run(
        {
            "nonce": "aa" * 16,
            "project_key": "proj-x",
            "sealed_key": "ciphertext-visible-to-validator-only",
            "bundle": bundle,
            "bundle_sha256": binding,
        }
    )

    assert response.status_code == 200
    assert response.get_json()["report"]["credential_provider"] == "openrouter"
    assert "private-miner-key" not in response.get_data(as_text=True)


def test_run_rejects_credential_replayed_with_a_substituted_agent(monkeypatch, tmp_path: Path):
    from room import server

    original = tmp_path / "original"
    original.mkdir()
    (original / "agent.py").write_text("safe agent\n", encoding="utf-8")
    credential = MinerInferenceCredential(
        provider="chutes",
        api_key="private-miner-key",
        bundle_binding=credential_bundle_binding(original),
    )
    monkeypatch.setattr(server.sealing, "resolve_miner_credential", lambda *_a, **_k: credential)
    files = {"agent.py": "malicious exfiltration agent\n"}
    substituted_bundle = bundle_b64(files)

    response = post_run(
        {
            "nonce": "bb" * 16,
            "project_key": "proj-x",
            "sealed_key": "public-ciphertext",
            "bundle": substituted_bundle,
            "bundle_sha256": bundle_binding(tmp_path, files),
        }
    )

    assert response.status_code == 400
    assert "not bound to this candidate bundle" in response.get_json()["error"]


def test_run_rejects_a_digest_that_does_not_match_the_executed_bundle(tmp_path: Path):
    files = {"agent.py": "def agent_main(): return {'ok': True}\n"}
    response = post_run(
        {
            "nonce": "bc" * 16,
            "project_key": "proj-x",
            "bundle": bundle_b64(files),
            "bundle_sha256": "ab" * 32,
        }
    )

    assert bundle_binding(tmp_path, files) != "ab" * 32
    assert response.status_code == 400
    assert "does not match the submitted candidate bundle" in response.get_json()["error"]


def test_run_rejects_unsigned_request():
    # No signature header -> 401. This is the fix for the key-exfil vuln: an attacker can't invoke
    # /run (so can't have a victim's sealed key decrypted into their agent).
    assert (
        post_run({"nonce": "cc" * 16, "project_key": "proj-x"}, signature=None).status_code == 401
    )


def test_run_rejects_bad_signature():
    assert (
        post_run({"nonce": "cc" * 16, "project_key": "proj-x"}, signature="deadbeef").status_code
        == 401
    )


def test_run_rejects_tampered_body_after_signing():
    # A signature is over the exact bytes; changing the body invalidates it.
    raw = json.dumps({"nonce": "cc" * 16, "project_key": "proj-x"}).encode()
    sig = auth.sign(raw)
    tampered = raw.replace(b"proj-x", b"proj-EVIL")
    resp = app.test_client().post(
        "/run",
        data=tampered,
        headers={"Content-Type": "application/json", auth.SIGNATURE_HEADER: sig},
    )
    assert resp.status_code == 401


def test_run_fails_closed_when_secret_unconfigured(monkeypatch):
    monkeypatch.delenv(auth.AUTH_SECRET_ENV, raising=False)
    resp = post_run({"nonce": "cc" * 16, "project_key": "proj-x"}, signature=None)
    assert resp.status_code == 503


def test_profile_failure_is_identified_as_infrastructure(monkeypatch):
    def fail_run(**_kwargs):
        raise RuntimeError("Docker daemon refused the container")

    monkeypatch.setattr(server_module.PROFILE, "run", fail_run)
    response = post_run({"nonce": "a9" * 16, "project_key": "proj-x"})

    assert response.status_code == 500
    assert response.get_json()["error_kind"] == "infrastructure"
    assert "Docker daemon refused" in response.get_json()["error"]


# --- the multi-key credential contract ---------------------------------------------------------
#
# Merged from test_server_multi_key.py. Splitting the server's tests by CREDENTIAL VERSION put two
# copies of the same request helpers in two files and made "which file tests /run?" have two
# answers. These exercise the same server, so they live with it.


SECRET = "miner-secret-key-value-0123456789"
PROVIDERS = ("alpha", "beta", "gamma", "delta")


@pytest.fixture
def multi_key(monkeypatch):
    """Swap the loaded profile in place rather than reloading the module.

    Reloading ``room.server`` would rebind a Flask app other test modules already hold, making the
    suite order-dependent -- a flaky test is worse than an unwritten one.
    """
    profile = FakeMultiKeyProfile()
    monkeypatch.setattr(server_module, "PROFILE", profile)
    monkeypatch.setattr(server_module, "CREDENTIAL_SPEC", credential_spec_for(profile))
    return profile


@pytest.fixture
def participant_funded_single_key(monkeypatch):
    """Single-key payload shape with contestant-owned failure semantics (the SN60 contract)."""

    class _Profile:
        credential_failure_mode = CREDENTIAL_FAILURE_ATTESTED_ZERO

    profile = _Profile()
    monkeypatch.setattr(server_module, "CREDENTIAL_SPEC", credential_spec_for(profile))
    return profile


def _credential_set(binding: str) -> MinerCredentialSet:
    return MinerCredentialSet(
        credentials={name: f"{SECRET}-{name}" for name in PROVIDERS},
        bundle_binding=binding,
        credential_profile="fake-multi-key-v1",
    )


def _run_with(monkeypatch, tmp_path, *, credential, nonce):
    files = {"agent.py": "safe agent\n"}
    monkeypatch.setattr(
        sealing, "resolve_sealed_credential", lambda *_a, **_k: credential
    )
    return post_run(
        {
            "nonce": nonce,
            "project_key": "proj-x",
            "sealed_key": "public-ciphertext",
            "bundle": bundle_b64(files),
            "bundle_sha256": bundle_binding(tmp_path, files),
        }
    )


# ---- the profile's contract is read at load ----------------------------------------------------

def test_a_multi_key_profile_declares_its_own_provider_set() -> None:
    """The base enforces what the profile declares and contains no lane's provider list, which is
    what keeps one image serving every lane."""
    spec = credential_spec_for(FakeMultiKeyProfile())
    assert spec.version == 2
    assert spec.required_providers == PROVIDERS
    assert spec.credential_profile == "fake-multi-key-v1"


def test_the_default_profile_still_has_the_single_key_contract() -> None:
    assert CREDENTIAL_SPEC.version == 1


# ---- the happy path ----------------------------------------------------------------------------

def test_a_bound_credential_set_reaches_the_profile(multi_key, monkeypatch, tmp_path) -> None:
    files = {"agent.py": "safe agent\n"}
    binding = bundle_binding(tmp_path, files)
    response = _run_with(
        monkeypatch, tmp_path, credential=_credential_set(binding), nonce="e1" * 16
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["report"]["credential_providers"] == sorted(PROVIDERS)
    assert body["report"]["bundle_received"] is True


# ---- the attested failure envelope --------------------------------------------------------------

def _assert_is_attested_failure(body: dict, *, reason: str) -> None:
    """The envelope must be verifiable exactly like a successful run, or it is not evidence."""
    assert body["report"]["status"] == "credential_failure"
    assert body["report"]["reason"] == reason
    assert body["quote"], "a failure envelope without a quote is not evidence"
    # The quote must actually cover THIS report -- recompute the binding the way a validator does.
    expected = canonical(
        binding_payload(
            report=body["report"],
            bundle_sha256=body["bundle_sha256"],
            provenance=body["provenance"],
        )
    )
    import hashlib

    assert body["binding_sha256"] == hashlib.sha256(expected).hexdigest()
    assert body["quote"].endswith(body["report_data_sha256"])


def test_an_unreadable_credential_returns_an_attested_failure(
    multi_key, monkeypatch, tmp_path
) -> None:
    def _raise(*_args, **_kwargs):
        raise RuntimeError("sealed miner credential could not be decrypted")

    monkeypatch.setattr(sealing, "resolve_sealed_credential", _raise)
    files = {"agent.py": "safe agent\n"}
    response = post_run(
        {
            "nonce": "c1" * 16,
            "project_key": "proj-x",
            "sealed_key": "garbage",
            "bundle": bundle_b64(files),
            "bundle_sha256": bundle_binding(tmp_path, files),
        }
    )
    assert response.status_code == 200, "a bare 4xx is not evidence a validator can verify"
    _assert_is_attested_failure(response.get_json(), reason="unreadable")


def test_a_participant_funded_single_key_failure_is_also_attested(
    participant_funded_single_key, monkeypatch, tmp_path
) -> None:
    """Ownership, not payload version, decides whether a bad key is a contestant zero."""

    def _raise(*_args, **_kwargs):
        raise RuntimeError("sealed miner credential could not be decrypted")

    monkeypatch.setattr(sealing, "resolve_sealed_credential", _raise)
    files = {"agent.py": "safe agent\n"}
    response = post_run(
        {
            "nonce": "d1" * 16,
            "project_key": "proj-x",
            "sealed_key": "garbage",
            "bundle": bundle_b64(files),
            "bundle_sha256": bundle_binding(tmp_path, files),
        }
    )
    assert response.status_code == 200
    _assert_is_attested_failure(response.get_json(), reason="unreadable")


def test_a_missing_credential_returns_an_attested_failure(
    multi_key, monkeypatch, tmp_path
) -> None:
    """A miner-funded run with nothing to fund it. Attested for the same reason: it zeroes the
    contestant, so it has to be provable."""
    response = _run_with(monkeypatch, tmp_path, credential=None, nonce="c2" * 16)
    assert response.status_code == 200
    _assert_is_attested_failure(response.get_json(), reason="absent")


def test_a_credential_bound_to_another_bundle_returns_an_attested_failure(
    multi_key, monkeypatch, tmp_path
) -> None:
    """The replay defence: a host that took a miner's public ciphertext and ran it against a
    different agent gets a refusal it cannot pass off as the miner's own failure to answer."""
    response = _run_with(
        monkeypatch, tmp_path, credential=_credential_set("f" * 64), nonce="c3" * 16
    )
    assert response.status_code == 200
    _assert_is_attested_failure(response.get_json(), reason="not_bound_to_bundle")


def test_a_failure_envelope_has_the_same_shape_as_a_success(
    multi_key, monkeypatch, tmp_path
) -> None:
    """One verification path for both, so a validator cannot end up treating "no evidence" and
    "evidence of failure" as the same thing."""
    files = {"agent.py": "safe agent\n"}
    binding = bundle_binding(tmp_path, files)
    ok = _run_with(
        monkeypatch, tmp_path, credential=_credential_set(binding), nonce="c4" * 16
    ).get_json()
    failed = _run_with(monkeypatch, tmp_path, credential=None, nonce="c5" * 16).get_json()
    assert set(ok) == set(failed)


def test_a_failure_envelope_never_contains_a_key(multi_key, monkeypatch, tmp_path) -> None:
    """It is attested, published and read by anyone who verifies the duel."""
    def _raise(*_args, **_kwargs):
        raise RuntimeError("sealed credential for alpha has an invalid API key")

    monkeypatch.setattr(sealing, "resolve_sealed_credential", _raise)
    files = {"agent.py": "safe agent\n"}
    response = post_run(
        {
            "nonce": "c6" * 16,
            "project_key": "proj-x",
            "sealed_key": "garbage",
            "bundle": bundle_b64(files),
            "bundle_sha256": bundle_binding(tmp_path, files),
        }
    )
    assert SECRET not in json.dumps(response.get_json())


# ---- a validator-side mistake is still an error, not a contestant's failure ----------------------

def test_a_wrong_bundle_digest_is_still_a_plain_error(multi_key, monkeypatch, tmp_path) -> None:
    """The validator supplies bundle_sha256. Attesting "the contestant's credentials failed" when
    the *validator* sent the wrong digest would zero a miner for someone else's mistake."""
    files = {"agent.py": "safe agent\n"}
    monkeypatch.setattr(
        sealing,
        "resolve_sealed_credential",
        lambda *_a, **_k: _credential_set(bundle_binding(tmp_path, files)),
    )
    response = post_run(
        {
            "nonce": "c7" * 16,
            "project_key": "proj-x",
            "sealed_key": "public-ciphertext",
            "bundle": bundle_b64(files),
            "bundle_sha256": "ab" * 32,
        }
    )
    assert response.status_code == 400
    assert "does not match" in response.get_json()["error"]


# ---- operator-funded credentials still fail as infrastructure -----------------------------------


def test_an_operator_funded_single_key_profile_returns_a_plain_error(
    monkeypatch, tmp_path
) -> None:
    """The default legacy profile does not assign credential faults to a contestant."""

    def _raise(*_args, **_kwargs):
        raise RuntimeError("sealed miner credential could not be decrypted")

    monkeypatch.setattr(sealing, "resolve_miner_credential", _raise)
    files = {"agent.py": "safe agent\n"}
    response = post_run(
        {
            "nonce": "c8" * 16,
            "project_key": "proj-x",
            "sealed_key": "garbage",
            "bundle": bundle_b64(files),
            "bundle_sha256": bundle_binding(tmp_path, files),
        }
    )
    assert response.status_code == 400
    assert "could not be decrypted" in response.get_json()["error"]

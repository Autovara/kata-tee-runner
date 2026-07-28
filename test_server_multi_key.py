"""The room's behaviour when a multi-key profile is loaded, and the attested failure envelope.

The envelope is the part that matters. Under a miner-funded policy a credential fault scores that
contestant **zero**, so the room must return *evidence* of the fault rather than an HTTP error. A
bare 4xx could be produced by anything on the path -- a proxy, a network, a host that would rather
one side lost -- and a promotion decision resting on one is a decision resting on nothing. A
quote-bound report cannot be forged by the host that relays it.

Under the single-key policy the lane funds inference, a credential fault is the operator's problem
rather than a contestant's, and a plain 400 is the honest answer. Both behaviours are asserted here,
because the risk is that adding the first quietly changed the second.
"""

from __future__ import annotations

import json
import tarfile
import time
from base64 import b64encode
from io import BytesIO
from pathlib import Path
from tarfile import TarFile

import pytest

from fake_profile import FakeMultiKeyProfile
from room import auth, sealing
from room import server as server_module
from room.attest import binding_payload, canonical
from room.bundle import credential_bundle_binding
from room.profile import MinerCredentialSet, credential_spec_for

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


def _post_run(body: dict):
    body = {
        "issued_at": int(time.time()),
        "expires_at": int(time.time()) + 60,
        "bundle_sha256": "ab" * 32,
        **body,
    }
    raw = json.dumps(body).encode()
    headers = {"Content-Type": "application/json", auth.SIGNATURE_HEADER: auth.sign(raw)}
    return server_module.app.test_client().post("/run", data=raw, headers=headers)


def _bundle_b64(files: dict[str, str]) -> str:
    buffer = BytesIO()
    with TarFile.open(fileobj=buffer, mode="w:gz") as archive:
        for relative, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(relative)
            info.size = len(data)
            archive.addfile(info, BytesIO(data))
    return b64encode(buffer.getvalue()).decode()


def _bundle_binding(tmp_path: Path, files: dict[str, str]) -> str:
    root = tmp_path / "binding"
    root.mkdir(exist_ok=True)
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return credential_bundle_binding(root)


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
    return _post_run(
        {
            "nonce": nonce,
            "project_key": "proj-x",
            "sealed_key": "public-ciphertext",
            "bundle": _bundle_b64(files),
            "bundle_sha256": _bundle_binding(tmp_path, files),
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
    assert server_module.CREDENTIAL_SPEC.version == 1


# ---- the happy path ----------------------------------------------------------------------------

def test_a_bound_credential_set_reaches_the_profile(multi_key, monkeypatch, tmp_path) -> None:
    files = {"agent.py": "safe agent\n"}
    binding = _bundle_binding(tmp_path, files)
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
    response = _post_run(
        {
            "nonce": "c1" * 16,
            "project_key": "proj-x",
            "sealed_key": "garbage",
            "bundle": _bundle_b64(files),
            "bundle_sha256": _bundle_binding(tmp_path, files),
        }
    )
    assert response.status_code == 200, "a bare 4xx is not evidence a validator can verify"
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
    binding = _bundle_binding(tmp_path, files)
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
    response = _post_run(
        {
            "nonce": "c6" * 16,
            "project_key": "proj-x",
            "sealed_key": "garbage",
            "bundle": _bundle_b64(files),
            "bundle_sha256": _bundle_binding(tmp_path, files),
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
        lambda *_a, **_k: _credential_set(_bundle_binding(tmp_path, files)),
    )
    response = _post_run(
        {
            "nonce": "c7" * 16,
            "project_key": "proj-x",
            "sealed_key": "public-ciphertext",
            "bundle": _bundle_b64(files),
            "bundle_sha256": "ab" * 32,
        }
    )
    assert response.status_code == 400
    assert "does not match" in response.get_json()["error"]


# ---- the single-key policy is unchanged ----------------------------------------------------------

def test_a_single_key_profile_still_returns_a_plain_error(monkeypatch, tmp_path) -> None:
    """No `multi_key` fixture: the default single-key profile is loaded. There the lane funds
    inference, so a credential fault is the operator's problem and a 400 is the honest answer."""
    def _raise(*_args, **_kwargs):
        raise RuntimeError("sealed miner credential could not be decrypted")

    monkeypatch.setattr(sealing, "resolve_miner_credential", _raise)
    files = {"agent.py": "safe agent\n"}
    response = _post_run(
        {
            "nonce": "c8" * 16,
            "project_key": "proj-x",
            "sealed_key": "garbage",
            "bundle": _bundle_b64(files),
            "bundle_sha256": _bundle_binding(tmp_path, files),
        }
    )
    assert response.status_code == 400
    assert "could not be decrypted" in response.get_json()["error"]

from __future__ import annotations

import json
from pathlib import Path

import pytest

from room import sealing
from room.bundle import credential_bundle_binding
from room.profile import (
    CredentialSpec,
    MinerCredentialSet,
    MinerInferenceCredential,
    credential_spec_for,
)


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


# --- the multi-key credential contract ------------------------------------------------------
#
# Merged from test_sealing_multi.py. Both files tested room-side credential resolution; the
# split was by credential VERSION, which meant "where are the sealing tests?" had two answers
# and the version-crossing cases -- a v1 payload offered to a v2 profile and back -- sat in
# whichever file their author happened to open.


SECRET = "miner-secret-key-value-0123456789"
PROVIDERS = ("alpha", "beta", "gamma", "delta")

V2_SPEC = CredentialSpec(
    version=2, required_providers=PROVIDERS, credential_profile="fake-multi-key-v1"
)
V1_SPEC = CredentialSpec(version=1)


def _v2_payload(**changes) -> str:
    payload = {
        "version": 2,
        "credential_profile": "fake-multi-key-v1",
        "credentials": {name: {"api_key": f"{SECRET}-{name}"} for name in PROVIDERS},
        "bundle_binding": "a" * 64,
    }
    payload.update(changes)
    return json.dumps(payload)


def _v1_payload() -> str:
    return json.dumps(
        {
            "version": 1,
            "provider": "alpha",
            "api_key": SECRET,
            "bundle_binding": "a" * 64,
        }
    )


def _resolve(monkeypatch, payload: str, *, spec: CredentialSpec = V2_SPEC):
    monkeypatch.setattr(sealing, "_decrypt", lambda _sealed: payload)
    return sealing.resolve_sealed_credential("ciphertext", spec=spec)


# ---- the happy path ---------------------------------------------------------------------------

def test_a_complete_credential_set_resolves(monkeypatch) -> None:
    credential = _resolve(monkeypatch, _v2_payload())
    assert isinstance(credential, MinerCredentialSet)
    # Sorted rather than in declaration order, so the repr and the report are stable.
    assert credential.providers == tuple(sorted(PROVIDERS))
    assert credential.key("alpha") == f"{SECRET}-alpha"
    assert credential.bundle_binding == "a" * 64


def test_an_absent_credential_still_has_no_platform_fallback() -> None:
    assert sealing.resolve_sealed_credential(spec=V2_SPEC, required=False) is None
    with pytest.raises(RuntimeError, match="no sealed miner credential"):
        sealing.resolve_sealed_credential(spec=V2_SPEC)


# ---- the two shapes cannot be confused for one another ----------------------------------------

def test_a_single_key_payload_cannot_be_read_as_a_credential_set(monkeypatch) -> None:
    """And the message says *version*, not "unknown field", so a miner learns they used the wrong
    sealing tool rather than that their JSON was odd."""
    monkeypatch.setattr(sealing, "_decrypt", lambda _sealed: _v1_payload())
    with pytest.raises(RuntimeError, match="unsupported version") as error:
        sealing.resolve_sealed_credential("ciphertext", spec=V2_SPEC)
    assert SECRET not in str(error.value)


def test_a_credential_set_cannot_reach_a_single_key_profile(monkeypatch) -> None:
    """THE exit-gate property. A room running a single-key profile must not spend a four-key
    payload, however it is labelled -- dispatch is on what the PROFILE declares, never on what the
    payload claims."""
    monkeypatch.setattr(sealing, "_decrypt", lambda _sealed: _v2_payload())
    with pytest.raises(RuntimeError) as error:
        sealing.resolve_sealed_credential("ciphertext", spec=V1_SPEC)
    assert SECRET not in str(error.value)


def test_a_credential_set_labelled_version_one_is_still_refused(monkeypatch) -> None:
    """Belt and braces: even a payload that lies about its version does not cross over."""
    with pytest.raises(RuntimeError, match="unsupported version"):
        _resolve(monkeypatch, _v2_payload(version=1))


def test_the_single_key_path_still_returns_a_single_key_credential(monkeypatch) -> None:
    monkeypatch.setattr(sealing, "_decrypt", lambda _sealed: _v1_payload())
    credential = sealing.resolve_sealed_credential("ciphertext", spec=V1_SPEC)
    assert isinstance(credential, MinerInferenceCredential)
    assert credential.provider == "alpha"


# ---- the set must be exactly what the profile declared -----------------------------------------

@pytest.mark.parametrize("missing", PROVIDERS)
def test_every_declared_provider_is_required(monkeypatch, missing: str) -> None:
    """Enforced up front because a run that discovers the fourth key is absent has already spent
    the miner's money on the first three."""
    payload = json.loads(_v2_payload())
    del payload["credentials"][missing]
    with pytest.raises(RuntimeError, match=f"missing required provider.*{missing}"):
        _resolve(monkeypatch, json.dumps(payload))


def test_an_undeclared_provider_is_refused_not_ignored(monkeypatch) -> None:
    """A miner who sealed a fifth key believed it would be spent. Dropping it silently leaves that
    belief intact until it costs them a duel."""
    payload = json.loads(_v2_payload())
    payload["credentials"]["epsilon"] = {"api_key": SECRET}
    with pytest.raises(RuntimeError, match="unexpected provider.*epsilon"):
        _resolve(monkeypatch, json.dumps(payload))


def test_a_set_sealed_for_another_lanes_profile_is_refused(monkeypatch) -> None:
    """Spending it would run a contestant under rules it never agreed to, and bill it for that."""
    with pytest.raises(RuntimeError, match="credential profile"):
        _resolve(monkeypatch, _v2_payload(credential_profile="some-other-lane-v1"))


# ---- malformed input fails closed --------------------------------------------------------------

@pytest.mark.parametrize(
    "payload",
    [
        "not json",
        json.dumps([1, 2, 3]),
        _v2_payload(bundle_binding="wrong"),
        _v2_payload(bundle_binding="A" * 64),
        _v2_payload(credentials="not-an-object"),
        _v2_payload(extra="value"),
    ],
)
def test_a_malformed_payload_is_refused(monkeypatch, payload: str) -> None:
    with pytest.raises(RuntimeError):
        _resolve(monkeypatch, payload)


@pytest.mark.parametrize(
    "bad_key",
    ["", "short", "x" * (sealing.MAX_KEY_CHARS + 1), "has\nnewline", "has\x00null", "tab\there"],
)
def test_an_unusable_key_is_refused(monkeypatch, bad_key: str) -> None:
    payload = json.loads(_v2_payload())
    payload["credentials"]["beta"] = {"api_key": bad_key}
    with pytest.raises(RuntimeError, match="beta"):
        _resolve(monkeypatch, json.dumps(payload))


@pytest.mark.parametrize(
    "entry", [{"api_key": 5}, {"api_key": SECRET, "extra": 1}, "flat-string", None]
)
def test_a_credential_entry_must_be_exactly_an_api_key(monkeypatch, entry) -> None:
    payload = json.loads(_v2_payload())
    payload["credentials"]["gamma"] = entry
    with pytest.raises(RuntimeError, match="gamma"):
        _resolve(monkeypatch, json.dumps(payload))


# ---- no key reaches a log, an exception or a repr ----------------------------------------------

@pytest.mark.parametrize(
    "payload",
    [
        _v2_payload(credential_profile="wrong"),
        _v2_payload(bundle_binding="wrong"),
        _v2_payload(extra="value"),
        _v2_payload(version=7),
        _v1_payload(),
    ],
)
def test_no_rejection_message_ever_contains_a_key(monkeypatch, payload: str) -> None:
    """These messages are logged, attested, and shown to a miner in a pull request."""
    with pytest.raises(RuntimeError) as error:
        _resolve(monkeypatch, payload)
    assert SECRET not in str(error.value)
    assert SECRET not in repr(error.value)


def test_a_resolved_credential_set_never_renders_its_keys(monkeypatch) -> None:
    credential = _resolve(monkeypatch, _v2_payload())
    for rendered in (repr(credential), str(credential), f"{credential}", f"{credential!r}"):
        assert SECRET not in rendered
    assert "alpha" in repr(credential)  # providers are safe, and are what an operator needs


def test_the_single_key_credential_also_never_renders_its_key() -> None:
    """It did before this change: the default dataclass repr printed api_key, so any traceback
    holding one wrote a miner's key into the log."""
    credential = MinerInferenceCredential(
        provider="alpha", api_key=SECRET, bundle_binding="a" * 64
    )
    for rendered in (repr(credential), str(credential), f"{credential}"):
        assert SECRET not in rendered


def test_an_unknown_provider_lookup_names_no_key(monkeypatch) -> None:
    credential = _resolve(monkeypatch, _v2_payload())
    with pytest.raises(RuntimeError, match="omega") as error:
        credential.key("omega")
    assert SECRET not in str(error.value)


# ---- the profile's declaration is validated at boot, not on the first duel ----------------------

class _Profile:
    def __init__(self, **attributes):
        for name, value in attributes.items():
            setattr(self, name, value)


def test_a_profile_that_declares_nothing_gets_the_single_key_contract() -> None:
    """Every profile predating this lives in another repository and declares nothing. Silently
    re-reading their payloads under a new schema is exactly what the versioning prevents."""
    from room.profile import CREDENTIAL_FAILURE_HTTP_ERROR

    spec = credential_spec_for(_Profile())
    assert spec.version == 1
    assert spec.credential_failure_mode == CREDENTIAL_FAILURE_HTTP_ERROR


@pytest.mark.parametrize(
    ("attributes", "expected"),
    [
        ({"credential_version": 2, "credential_profile": "p"}, "required_providers"),
        ({"credential_version": 2, "required_providers": ("a", "b")}, "credential_profile"),
        (
            {
                "credential_version": 2,
                "required_providers": ("a", "a"),
                "credential_profile": "p",
            },
            "duplicate provider",
        ),
        ({"credential_version": 3}, "unsupported credential_version"),
        ({"credential_failure_mode": "score_everyone_full_marks"}, "credential_failure_mode"),
    ],
)
def test_an_incoherent_profile_declaration_fails_at_load(attributes, expected: str) -> None:
    """At load, so a deployment mistake shows up when the room boots rather than partway through
    the first duel it is asked to judge."""
    with pytest.raises(RuntimeError, match=expected):
        credential_spec_for(_Profile(**attributes))


def test_a_well_formed_multi_key_declaration_is_accepted() -> None:
    from room.profile import CREDENTIAL_FAILURE_ATTESTED_ZERO

    spec = credential_spec_for(
        _Profile(
            credential_version=2,
            required_providers=PROVIDERS,
            credential_profile="fake-multi-key-v1",
        )
    )
    assert spec.version == 2
    assert spec.required_providers == PROVIDERS  # the SPEC keeps the declared order
    assert spec.credential_failure_mode == CREDENTIAL_FAILURE_ATTESTED_ZERO


def test_a_single_key_profile_can_declare_participant_owned_credentials() -> None:
    from room.profile import CREDENTIAL_FAILURE_ATTESTED_ZERO

    spec = credential_spec_for(
        _Profile(credential_failure_mode=CREDENTIAL_FAILURE_ATTESTED_ZERO)
    )
    assert spec.version == 1
    assert spec.credential_failure_mode == CREDENTIAL_FAILURE_ATTESTED_ZERO

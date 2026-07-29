"""The multi-key sealer CLI.

Two properties carry the weight here, and both are about what happens on a miner's own machine
before anything is uploaded:

* **A key is never a command-line value.** Command lines are world-readable in the process list on
  a shared machine, and they land in shell history. Only an environment variable name, a 0600 file,
  or a hidden prompt is accepted.
* **A partial set is never written.** A set short one key seals fine, uploads fine, and fails
  partway through a scored run -- after the miner has already paid for the providers that did work.
  Catching it here costs nothing; catching it there costs a duel.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import kata_seal
import kata_seal as sealer

PROVIDERS = ("alpha", "beta", "gamma", "delta")
KEY = "miner-secret-key-value-0123456789"


def _argv(monkeypatch, *extra: str) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "kata_seal.py",
            "--room",
            "https://room.example",
            "--credential-profile",
            "fake-multi-key-v1",
            "--providers",
            ",".join(PROVIDERS),
            "--bundle",
            ".",
            *extra,
        ],
    )


# ---- provider list parsing -----------------------------------------------------------------------

def test_a_valid_provider_list_parses() -> None:
    assert sealer.parse_providers(" alpha, beta ,gamma ") == ("alpha", "beta", "gamma")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", "at least one"),
        (" , ", "at least one"),
        ("alpha,alpha", "must not repeat"),
        ("Alpha", "lowercase"),
        ("has space", "lowercase"),
        ("9leading", "lowercase"),
    ],
)
def test_a_bad_provider_list_is_refused(raw: str, expected: str) -> None:
    with pytest.raises(SystemExit, match=expected):
        sealer.parse_providers(raw)


@pytest.mark.parametrize("argument", ["noequals", "=value", "provider=", " = "])
def test_a_malformed_key_source_is_refused(argument: str) -> None:
    with pytest.raises(SystemExit, match="provider=value"):
        sealer.parse_key_source(argument, flag="--key-env")


# ---- the set must be complete before anything is sealed ---

def test_a_complete_set_is_collected(monkeypatch) -> None:
    for provider in PROVIDERS:
        monkeypatch.setenv(f"{provider.upper()}_KEY", f"{KEY}-{provider}")
    keys = sealer.collect_keys(
        PROVIDERS,
        key_envs={p: f"{p.upper()}_KEY" for p in PROVIDERS},
        key_files={},
    )
    assert sorted(keys) == sorted(PROVIDERS)


def test_a_key_source_for_an_undeclared_provider_is_refused() -> None:
    with pytest.raises(SystemExit, match="not in --providers"):
        sealer.collect_keys(PROVIDERS, key_envs={"epsilon": "E"}, key_files={})


def test_a_provider_with_two_key_sources_is_refused() -> None:
    """Ambiguous: which one did the miner mean to spend? Guessing risks sealing a stale key."""
    with pytest.raises(SystemExit, match="both --key-env and --key-file"):
        sealer.collect_keys(PROVIDERS, key_envs={"alpha": "A"}, key_files={"alpha": "/tmp/a"})


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", "must not be empty"),
        ("short", "characters"),
        ("x" * (sealer.MAX_KEY_CHARS + 1), "characters"),
        ("has\nnewline-and-enough-length-here", "control character"),
    ],
)
def test_a_key_the_room_would_refuse_is_caught_locally(
    monkeypatch, value: str, expected: str
) -> None:
    """Mirrors the room's own validation. The alternative is an attested zero on a scored duel for
    a key the miner could have fixed in a second."""
    monkeypatch.setenv("ALPHA_KEY", value)
    with pytest.raises(SystemExit, match=expected):
        sealer.collect_keys(("alpha",), key_envs={"alpha": "ALPHA_KEY"}, key_files={})


def test_a_missing_key_prompts_rather_than_seals_a_partial_set(monkeypatch) -> None:
    prompted: list[str] = []

    def _prompt(message: str) -> str:
        prompted.append(message)
        return f"{KEY}-prompted"

    monkeypatch.setattr(sealer.getpass, "getpass", _prompt)
    monkeypatch.setenv("ALPHA_KEY", f"{KEY}-alpha")
    keys = sealer.collect_keys(PROVIDERS, key_envs={"alpha": "ALPHA_KEY"}, key_files={})
    assert len(keys) == len(PROVIDERS)
    assert len(prompted) == 3
    assert all("alpha" not in message for message in prompted)


# ---- no key ever appears as a command-line value ---

def test_the_cli_offers_no_way_to_pass_a_key_as_a_value() -> None:
    """A regression guard on the interface itself: adding a plausible-looking --key would put every
    miner's credential into the process list on a shared machine."""
    options = {
        action.option_strings[0]
        for action in sealer.build_parser()._actions
        if action.option_strings
    }
    assert "--key" not in options
    assert {"--key-env", "--key-file"} <= options


# ---- output is atomic and private ---

def test_the_ciphertext_is_written_privately(tmp_path: Path) -> None:
    target = tmp_path / "bundle" / "sealed_inference_key"
    sealer.write_atomically(target, "deadbeef")
    assert target.read_text(encoding="utf-8") == "deadbeef"
    assert target.stat().st_mode & 0o077 == 0, "the ciphertext must not be group/world readable"


def test_a_failed_write_leaves_the_previous_file_intact(monkeypatch, tmp_path: Path) -> None:
    """A half-written ciphertext looks like a submitted credential. The miner finds out it was
    truncated when their duel comes back zeroed."""
    target = tmp_path / "sealed_inference_key"
    target.write_text("previous-ciphertext", encoding="utf-8")

    def _boom(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(kata_seal.os, "replace", _boom)
    with pytest.raises(OSError, match="disk full"):
        sealer.write_atomically(target, "new-ciphertext")

    assert target.read_text(encoding="utf-8") == "previous-ciphertext"
    leftovers = [p.name for p in tmp_path.iterdir() if p.name.startswith(".kata-seal-")]
    assert not leftovers, "a failed seal must not leave a temporary behind"


def test_an_interrupted_write_also_cleans_up(monkeypatch, tmp_path: Path) -> None:
    """KeyboardInterrupt is not an Exception. Catching only Exception would leave the temporary."""
    target = tmp_path / "sealed_inference_key"

    def _boom(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(kata_seal.os, "replace", _boom)
    with pytest.raises(KeyboardInterrupt):
        sealer.write_atomically(target, "new-ciphertext")
    assert not list(tmp_path.iterdir())


# ---- local checks happen before the room is contacted ---

def test_a_bad_measurement_is_rejected_before_contacting_the_room(monkeypatch, tmp_path) -> None:
    _argv(monkeypatch)
    monkeypatch.setattr(
        sealer, "fetch_pubkey", lambda _room: pytest.fail("must reject before contacting the room")
    )
    with pytest.raises(SystemExit, match="--measurement"):
        sealer.main()


def test_an_incomplete_set_is_rejected_before_contacting_the_room(
    monkeypatch, tmp_path: Path
) -> None:
    """Ordering matters: the room learns nothing about a submission that was never going to work."""
    monkeypatch.setattr(
        sealer, "fetch_pubkey", lambda _room: pytest.fail("must reject before contacting the room")
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "kata_seal.py",
            "--room",
            "https://room.example",
            "--credential-profile",
            "fake-multi-key-v1",
            "--providers",
            ",".join(PROVIDERS),
            "--bundle",
            str(tmp_path),
            "--measurement",
            "a" * 64,
            "--key-env",
            "epsilon=SOME_KEY",
        ],
    )
    with pytest.raises(SystemExit, match="not in --providers"):
        sealer.main()


def test_a_missing_bundle_directory_is_rejected(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "kata_seal.py",
            "--room",
            "https://room.example",
            "--credential-profile",
            "fake-multi-key-v1",
            "--providers",
            "alpha",
            "--bundle",
            str(tmp_path / "nope"),
            "--measurement",
            "a" * 64,
        ],
    )
    with pytest.raises(SystemExit, match="is not a directory"):
        sealer.main()


# ---- end to end, against the room's own parser ---

def test_the_sealed_payload_is_exactly_what_the_room_accepts(
    monkeypatch, tmp_path: Path
) -> None:
    """THE cross-component check. The sealer and the room's parser are in different files and were
    written at different times; nothing but this asserts they agree on the payload."""
    from room import sealing
    from room.profile import CredentialSpec

    bundle = tmp_path / "submission"
    bundle.mkdir()
    (bundle / "agent.py").write_text("def agent_main(): pass\n", encoding="utf-8")

    for provider in PROVIDERS:
        monkeypatch.setenv(f"{provider.upper()}_KEY", f"{KEY}-{provider}")

    captured: dict[str, str] = {}

    class _FakeEcies:
        @staticmethod
        def encrypt(_pubkey: str, payload: bytes) -> bytes:
            captured["payload"] = payload.decode()
            return b"\xde\xad\xbe\xef"

    monkeypatch.setitem(sys.modules, "ecies", _FakeEcies)
    monkeypatch.setattr(
        sealer,
        "fetch_pubkey",
        lambda _room: {"pubkey": "02" + "11" * 32, "quote": "quote"},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "kata_seal.py",
            "--room",
            "https://room.example",
            "--credential-profile",
            "fake-multi-key-v1",
            "--providers",
            ",".join(PROVIDERS),
            "--bundle",
            str(bundle),
            "--no-verify",
            *[f"--key-env={p}={p.upper()}_KEY" for p in PROVIDERS],
        ],
    )
    sealer.main()

    # The room parses the sealer's own output, with no hand-written fixture in between.
    monkeypatch.setattr(sealing, "_decrypt", lambda _sealed: captured["payload"])
    resolved = sealing.resolve_sealed_credential(
        "ciphertext",
        spec=CredentialSpec(
            version=2,
            required_providers=PROVIDERS,
            credential_profile="fake-multi-key-v1",
        ),
    )
    assert resolved.providers == tuple(sorted(PROVIDERS))
    assert resolved.key("gamma") == f"{KEY}-gamma"

    # ...and the binding it sealed is the one the room recomputes from the same bundle.
    from room.bundle import credential_bundle_binding

    assert resolved.bundle_binding == credential_bundle_binding(bundle)

    written = (bundle / "sealed_inference_key").read_text(encoding="utf-8")
    assert written == "deadbeef"
    assert json.loads(captured["payload"])["version"] == 2


def test_the_written_ciphertext_is_excluded_from_its_own_binding(tmp_path: Path) -> None:
    """It cannot commit to itself. Everything else must, so editing the agent after sealing
    invalidates the credential and forces a reseal."""
    from room.bundle import SEALED_CREDENTIAL_FILENAME, credential_bundle_binding

    bundle = tmp_path / "submission"
    bundle.mkdir()
    (bundle / "agent.py").write_text("def agent_main(): pass\n", encoding="utf-8")
    before = credential_bundle_binding(bundle)

    sealer.write_atomically(bundle / SEALED_CREDENTIAL_FILENAME, "deadbeef")
    assert credential_bundle_binding(bundle) == before

    (bundle / "agent.py").write_text("def agent_main(): exfiltrate()\n", encoding="utf-8")
    assert credential_bundle_binding(bundle) != before


# --- one tool, two contracts: choosing between them ----------------------------------------------
#
# Single-key and multi-key sealing used to be two programs. Merging them removed a whole class of
# drift -- one parser, one set of flags -- and introduced exactly one new risk: picking the wrong
# contract. The room dispatches on the sealed payload's version, so a version-1 credential where the
# lane wants version 2 is refused mid-duel, and a credential failure scores zero. The mode is
# therefore never inferred, and every way of getting it wrong is diagnosed by name.


def _run(monkeypatch, argv: list[str]):
    monkeypatch.setattr(sys, "argv", ["kata_seal.py", *argv])
    return kata_seal.main


def test_naming_no_contract_is_refused(monkeypatch, tmp_path: Path) -> None:
    """Not defaulting to either. A default here is a silent choice of credential format."""
    with pytest.raises(SystemExit):
        _run(monkeypatch, ["--room", "https://r.example", "--bundle", str(tmp_path)])()


def test_naming_both_contracts_is_refused(monkeypatch, tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        _run(monkeypatch, [
            "--room", "https://r.example", "--provider", "alpha",
            "--providers", "alpha,beta", "--bundle", str(tmp_path),
        ])()


def test_the_multi_key_flag_form_in_single_key_mode_is_diagnosed_by_name(
    monkeypatch, tmp_path: Path
) -> None:
    """Left alone this would look up an environment variable literally named
    'alpha=ALPHA_KEY', find nothing, and report an empty key."""
    with pytest.raises(SystemExit, match="multi-key form"):
        _run(monkeypatch, [
            "--room", "https://r.example", "--provider", "alpha",
            "--key-env", "alpha=ALPHA_KEY",
            "--bundle", str(tmp_path), "--measurement", "a" * 64,
        ])()


def test_the_bare_flag_form_in_multi_key_mode_is_diagnosed(monkeypatch, tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="provider=value"):
        _run(monkeypatch, [
            "--room", "https://r.example", "--providers", "alpha,beta",
            "--credential-profile", "p", "--key-env", "ALPHA_KEY",
            "--bundle", str(tmp_path), "--measurement", "a" * 64,
        ])()


def test_a_credential_profile_in_single_key_mode_is_refused(monkeypatch, tmp_path: Path) -> None:
    """It has no place in a version-1 payload, so accepting and ignoring it would let a miner
    believe they had sealed the multi-key contract."""
    with pytest.raises(SystemExit, match="belongs to multi-key mode"):
        _run(monkeypatch, [
            "--room", "https://r.example", "--provider", "alpha",
            "--credential-profile", "p",
            "--bundle", str(tmp_path), "--measurement", "a" * 64,
        ])()


def test_repeating_a_key_flag_in_single_key_mode_is_refused(monkeypatch, tmp_path: Path) -> None:
    """The flag is repeatable for the multi-key contract; silently taking the last one in
    single-key mode would seal a key the miner did not choose."""
    with pytest.raises(SystemExit, match="once in single-key mode"):
        _run(monkeypatch, [
            "--room", "https://r.example", "--provider", "alpha",
            "--key-env", "A_KEY", "--key-env", "B_KEY",
            "--bundle", str(tmp_path), "--measurement", "a" * 64,
        ])()


# --- the single-key contract ---------------------------------------------------------------
#
# Moved from test_sealing.py, which held CLI tests and room-side credential-resolution tests under
# one name. Two tools became one; these are that tool's tests, all of them, in one place.


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

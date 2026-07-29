"""Security invariants of the sealed room, stated plainly and asserted.

Recorded BEFORE the refactor moves TEE code. The room executes untrusted agents and holds miners'
decrypted credentials in memory, so every property below is one that, if lost, is not a bug that
shows up as an error -- it shows up as a room that still returns 200.
"""

from __future__ import annotations

import pytest

from room import auth


def _with_secret(monkeypatch, secret: str = "s" * 64) -> None:
    monkeypatch.setenv(auth.AUTH_SECRET_ENV, secret)


# ---- INVARIANT: an unauthenticated caller cannot invoke a run ---

def test_a_room_with_no_shared_secret_is_not_configured(monkeypatch):
    """Fail closed. A room that treated "no secret" as "no auth required" would accept a run from
    anyone who found the URL -- and the URL is public, because /health must be."""
    monkeypatch.delenv(auth.AUTH_SECRET_ENV, raising=False)
    assert auth.is_configured() is False


def test_a_tampered_body_does_not_verify(monkeypatch):
    _with_secret(monkeypatch)
    body = b'{"job":"pool-1"}'
    signature = auth.sign(body)
    assert auth.verify(body, signature) is True
    assert auth.verify(body + b" ", signature) is False
    assert auth.verify(body, signature[:-1] + ("0" if signature[-1] != "0" else "1")) is False


def test_a_signature_from_a_different_secret_does_not_verify(monkeypatch):
    body = b'{"job":"pool-1"}'
    _with_secret(monkeypatch, "a" * 64)
    foreign = auth.sign(body)
    _with_secret(monkeypatch, "b" * 64)
    assert auth.verify(body, foreign) is False


# ---- INVARIANT: a signed request is short-lived and single-use ---

def test_an_expired_request_is_refused():
    """Bounds how long a captured request stays useful."""
    now = 1_000_000
    problem = auth.validate_request_window(
        {auth.ISSUED_AT_FIELD: now - 10_000, auth.EXPIRES_AT_FIELD: now - 9_000}, now=now)
    assert problem and "expired" in problem


def test_a_request_from_the_future_is_refused():
    now = 1_000_000
    problem = auth.validate_request_window(
        {auth.ISSUED_AT_FIELD: now + 10_000, auth.EXPIRES_AT_FIELD: now + 10_100}, now=now)
    assert problem and "future" in problem


def test_a_request_may_not_outlive_the_room_policy():
    now = 1_000_000
    lifetime = auth.request_lifetime_seconds()
    problem = auth.validate_request_window(
        {auth.ISSUED_AT_FIELD: now, auth.EXPIRES_AT_FIELD: now + lifetime + 60}, now=now)
    assert problem and "lifetime" in problem


def test_a_request_without_a_window_is_refused():
    assert auth.validate_request_window({}) is not None


def test_a_valid_window_is_accepted():
    """Without this the four refusals above would pass on a validator that rejected everything."""
    now = 1_000_000
    assert auth.validate_request_window(
        {auth.ISSUED_AT_FIELD: now, auth.EXPIRES_AT_FIELD: now + 60}, now=now) is None


def test_a_nonce_cannot_be_reused():
    """Signature validity alone is not enough: a captured request replays perfectly."""
    guard = auth.ReplayGuard()
    now = 1_000_000
    assert guard.reserve("a" * 32, expires_at=now + 60, now=now) is True
    assert guard.reserve("a" * 32, expires_at=now + 60, now=now) is False


def test_the_replay_store_is_bounded():
    """An unbounded nonce store is a memory-exhaustion path reachable by anyone who can sign."""
    guard = auth.ReplayGuard(max_entries=4)
    now = 1_000_000
    for index in range(50):
        assert guard.reserve(f"{index:032x}", expires_at=now + 60, now=now) is True
    # Bounded: the oldest entries were evicted rather than retained forever.
    assert len(guard._seen) <= 4


# ---- INVARIANT: diagnostics are off unless deliberately enabled ---

@pytest.mark.parametrize("value", [None, "", "0", "false", "no", "off", "maybe"])
def test_the_diagnostic_endpoint_is_absent_unless_explicitly_enabled(monkeypatch, value):
    """404, not 403: an endpoint that announces itself is an endpoint worth attacking. Only an
    explicit affirmative enables it -- "off" and "maybe" must not read as true."""
    from room import server

    if value is None:
        monkeypatch.delenv("KATA_ROOM_ENABLE_DIAGNOSTICS", raising=False)
    else:
        monkeypatch.setenv("KATA_ROOM_ENABLE_DIAGNOSTICS", value)
    response = server.app.test_client().post("/pull-test", json={})
    assert response.status_code == 404, value


def test_the_diagnostic_endpoint_still_demands_auth_when_enabled(monkeypatch):
    """Enabling diagnostics must not also disable authentication."""
    from room import server

    monkeypatch.setenv("KATA_ROOM_ENABLE_DIAGNOSTICS", "1")
    monkeypatch.delenv(auth.AUTH_SECRET_ENV, raising=False)
    response = server.app.test_client().post("/pull-test", json={})
    assert response.status_code == 503


# ---- INVARIANT: a sealed credential is written atomically, at 0600, by BOTH CLIs ---
#
# `kata_seal.py` used a plain `open(...).write()`. Two consequences, both silent:
#
#   * an interrupted seal left a TRUNCATED credential, which fails later on a scored duel rather
#     than at the moment the miner sealed it;
#   * the file took the caller's umask instead of 0600.
#
# `kata_seal_multi.py` already did it correctly. The two tools now share one writer, so the
# behaviour cannot diverge again -- which is the point of sharing it rather than copying the fix.

def test_both_sealing_tools_use_the_same_writer():
    import kata_seal
    import kata_seal_multi

    assert kata_seal_multi.write_atomically is kata_seal.write_atomically


def test_a_sealed_credential_is_written_owner_only(tmp_path):
    import stat

    import kata_seal

    target = tmp_path / "sealed_inference_key"
    kata_seal.write_atomically(target, "deadbeef")
    mode = stat.S_IMODE(target.stat().st_mode)
    assert mode == 0o600, f"sealed credential is {oct(mode)}, expected 0o600"


def test_a_failed_seal_leaves_the_previous_credential_intact(tmp_path, monkeypatch):
    """A miner re-sealing after editing their agent must not lose the working credential to a
    half-written replacement."""
    import kata_seal

    target = tmp_path / "sealed_inference_key"
    target.write_text("previous", encoding="utf-8")

    def _boom(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(kata_seal.os, "replace", _boom)
    with pytest.raises(OSError):
        kata_seal.write_atomically(target, "replacement")
    assert target.read_text(encoding="utf-8") == "previous"
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".kata-seal-")]

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

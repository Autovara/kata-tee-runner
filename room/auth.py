"""Request authentication for the room's privileged endpoint (/run).

/run runs a caller-supplied agent and injects a decrypted inference key into it, so it MUST only be
callable by the trusted validator. We require an HMAC-SHA256 signature over the exact request body,
keyed by a shared secret (``KATA_ROOM_AUTH_SECRET``) the validator and the room both hold (delivered
to the room the same sealed way as other secrets). An attacker who replays a miner's public sealed
key cannot forge the signature, so the room won't decrypt it into their agent.

Fail closed: if the secret is not configured, /run refuses to serve.
"""

import hmac
import os
import threading
import time
from collections import OrderedDict
from hashlib import sha256

AUTH_SECRET_ENV = "KATA_ROOM_AUTH_SECRET"
SIGNATURE_HEADER = "X-Kata-Signature"
ISSUED_AT_FIELD = "issued_at"
EXPIRES_AT_FIELD = "expires_at"
DEFAULT_MAX_REQUEST_LIFETIME_SECONDS = 1_200
DEFAULT_MAX_CLOCK_SKEW_SECONDS = 30
DEFAULT_MAX_REPLAY_ENTRIES = 8_192


def _secret() -> bytes:
    return os.environ.get(AUTH_SECRET_ENV, "").strip().encode()


def is_configured() -> bool:
    return bool(_secret())


def sign(body: bytes, secret: bytes | None = None) -> str:
    """HMAC-SHA256 hex of ``body`` (the raw request bytes) under the shared secret."""
    return hmac.new(secret if secret is not None else _secret(), body, sha256).hexdigest()


def verify(body: bytes, signature: str) -> bool:
    """True iff ``signature`` is a valid HMAC of ``body`` under the configured secret.

    Constant-time compare; false when no secret is configured (fail closed) or the header is absent.
    """
    secret = _secret()
    if not secret:
        return False
    return hmac.compare_digest(sign(body, secret), (signature or "").strip())


def request_lifetime_seconds() -> int:
    raw = os.environ.get("KATA_ROOM_MAX_REQUEST_LIFETIME_SECONDS", "").strip()
    try:
        value = int(raw) if raw else DEFAULT_MAX_REQUEST_LIFETIME_SECONDS
    except ValueError:
        value = DEFAULT_MAX_REQUEST_LIFETIME_SECONDS
    return max(1, value)


def request_clock_skew_seconds() -> int:
    raw = os.environ.get("KATA_ROOM_MAX_CLOCK_SKEW_SECONDS", "").strip()
    try:
        value = int(raw) if raw else DEFAULT_MAX_CLOCK_SKEW_SECONDS
    except ValueError:
        value = DEFAULT_MAX_CLOCK_SKEW_SECONDS
    return max(0, value)


def validate_request_window(payload: dict[str, object], *, now: int | None = None) -> str | None:
    """Validate the short-lived signed-request claims before a run is reserved."""
    try:
        issued_at = int(payload[ISSUED_AT_FIELD])
        expires_at = int(payload[EXPIRES_AT_FIELD])
    except (KeyError, TypeError, ValueError):
        return f"request must include integer {ISSUED_AT_FIELD} and {EXPIRES_AT_FIELD}"
    current = int(time.time()) if now is None else now
    skew = request_clock_skew_seconds()
    if issued_at > current + skew:
        return "request issued_at is too far in the future"
    if expires_at <= issued_at:
        return "request expires_at must be after issued_at"
    if expires_at - issued_at > request_lifetime_seconds():
        return "request lifetime exceeds the room policy"
    if expires_at < current - skew:
        return "request has expired"
    return None


class ReplayGuard:
    """A bounded, thread-safe single-use nonce store for signed room requests."""

    def __init__(self, *, max_entries: int = DEFAULT_MAX_REPLAY_ENTRIES) -> None:
        self._max_entries = max_entries
        self._seen: OrderedDict[str, int] = OrderedDict()
        self._lock = threading.Lock()

    def reserve(self, nonce_hex: str, *, expires_at: int, now: int | None = None) -> bool:
        current = int(time.time()) if now is None else now
        with self._lock:
            while self._seen:
                oldest_nonce, oldest_expiry = next(iter(self._seen.items()))
                if oldest_expiry >= current:
                    break
                self._seen.pop(oldest_nonce)
            if nonce_hex in self._seen:
                return False
            self._seen[nonce_hex] = expires_at
            while len(self._seen) > self._max_entries:
                self._seen.popitem(last=False)
            return True

    def clear(self) -> None:
        with self._lock:
            self._seen.clear()


REPLAY_GUARD = ReplayGuard()

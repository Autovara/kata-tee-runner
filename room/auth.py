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
from hashlib import sha256

AUTH_SECRET_ENV = "KATA_ROOM_AUTH_SECRET"
SIGNATURE_HEADER = "X-Kata-Signature"


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

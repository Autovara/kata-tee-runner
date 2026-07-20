"""Shared identifier grammars for the sealed room.

The allowlisted-provider id grammar is a security-relevant contract: the sealer
(``kata_seal``), the credential validator (``room.sealing``), and the gateway route
parser (``room.inference_gateway``) must all agree on what a valid provider id is.
Keeping the one regex here stops those copies from silently drifting apart.
"""

# A lowercase, dash/underscore provider id of 1..64 chars, e.g. "openrouter".
PROVIDER_ID_REGEX = r"[a-z][a-z0-9_-]{0,63}"

"""The confidential-VM client shared by sealing and attestation.

The SDK requires the dstack socket at construction time.  Create one client on
first TEE operation rather than at import time so an unauthenticated ``/health``
probe remains available while the room is starting.
"""

from functools import lru_cache

from dstack_sdk import DstackClient


@lru_cache
def get_client() -> DstackClient:
    """Return the process-wide dstack client when a TEE operation needs it."""
    return DstackClient()

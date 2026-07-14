"""Sealed-key handling (generic). The room holds a private sealing key bound to its image; a miner
seals their inference key to the matching public key, so the owner only ever handles ciphertext."""

import os

from room.dstack import client

SEALING_KEY_PATH = "kata/sealing"


def sealing_privkey() -> bytes:
    """The room's private sealing key -- bound to this image, never leaves the room."""
    return client.get_key(SEALING_KEY_PATH).decode_key()


def resolve_inference_key(sealed_param: str = "") -> str:
    """The miner's inference key. Prefer a per-request sealed blob (so ONE room can serve many
    candidates, each with its own key), then a deploy-time SEALED_INFERENCE_KEY, then a plaintext
    env var (test only). Sealed blobs are decrypted INSIDE the room; the owner only handled the
    ciphertext."""
    sealed = (sealed_param or os.environ.get("SEALED_INFERENCE_KEY", "")).strip()
    if sealed:
        from ecies import decrypt as ecies_decrypt

        return ecies_decrypt(sealing_privkey(), bytes.fromhex(sealed)).decode()
    return os.environ.get("INFERENCE_API_KEY", "")

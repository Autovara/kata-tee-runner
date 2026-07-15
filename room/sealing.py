"""Sealed-key handling (generic). The room holds a private sealing key bound to its image; a miner
seals their inference key to the matching public key, so the owner only ever handles ciphertext."""

from room.dstack import get_client

SEALING_KEY_PATH = "kata/sealing"


def sealing_privkey() -> bytes:
    """The room's private sealing key -- bound to this image, never leaves the room."""
    return get_client().get_key(SEALING_KEY_PATH).decode_key()


def resolve_inference_key(sealed_param: str = "", *, required: bool = True) -> str:
    """Decrypt the miner's per-request key inside the room.

    A room deliberately has no deploy-time key fallback: a supplied ciphertext is always owned by
    the candidate being evaluated. ``required=False`` is only for a deliberately inference-free
    agent; it returns an empty credential rather than substituting an operator key.
    """
    sealed = sealed_param.strip()
    if not sealed:
        if not required:
            return ""
        raise RuntimeError(
            "no sealed inference key for this run (a sealed key is required; there is no plaintext "
            "fallback)"
        )
    from ecies import decrypt as ecies_decrypt

    return ecies_decrypt(sealing_privkey(), bytes.fromhex(sealed)).decode()

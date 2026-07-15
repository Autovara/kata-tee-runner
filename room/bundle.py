"""Bounded extraction for a signed candidate bundle inside a TEE room."""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import os
import tarfile
from pathlib import Path

DEFAULT_MAX_COMPRESSED_BYTES = 512 * 1024
DEFAULT_MAX_EXTRACTED_BYTES = 256 * 1024
DEFAULT_MAX_FILES = 16
SEALED_CREDENTIAL_FILENAME = "sealed_inference_key"
_BUNDLE_BINDING_DOMAIN = b"kata-miner-credential-bundle-v1\0"
_TRANSIENT_BUNDLE_DIRS = frozenset({".git", "__pycache__"})
_TRANSIENT_BUNDLE_SUFFIXES = frozenset({".pyc", ".pyo"})


def _positive_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        value = int(raw) if raw else default
    except ValueError:
        value = default
    return max(1, value)


def extract_submission_bundle(bundle_b64: str, destination: Path) -> None:
    """Decode and extract a Kata-sized bundle without allowing a tar bomb."""
    if not bundle_b64:
        raise RuntimeError("TEE run is missing its candidate bundle")
    max_compressed = _positive_env(
        "KATA_ROOM_MAX_COMPRESSED_BUNDLE_BYTES", DEFAULT_MAX_COMPRESSED_BYTES
    )
    max_extracted = _positive_env(
        "KATA_ROOM_MAX_EXTRACTED_BUNDLE_BYTES", DEFAULT_MAX_EXTRACTED_BYTES
    )
    max_files = _positive_env("KATA_ROOM_MAX_BUNDLE_FILES", DEFAULT_MAX_FILES)
    # Base64 has at most 4/3 expansion.  Reject before allocating an unbounded string payload.
    if len(bundle_b64) > ((max_compressed + 2) // 3) * 4:
        raise RuntimeError("candidate bundle exceeds the compressed-size policy")
    try:
        raw = base64.b64decode(bundle_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RuntimeError("candidate bundle is not valid base64") from exc
    if len(raw) > max_compressed:
        raise RuntimeError("candidate bundle exceeds the compressed-size policy")
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            members = archive.getmembers()
            regular = [member for member in members if member.isfile()]
            if len(regular) > max_files:
                raise RuntimeError("candidate bundle exceeds the file-count policy")
            if sum(member.size for member in regular) > max_extracted:
                raise RuntimeError("candidate bundle exceeds the extracted-size policy")
            destination.mkdir(parents=True, exist_ok=False)
            archive.extractall(destination, filter="data")
    except (tarfile.TarError, OSError) as exc:
        raise RuntimeError("candidate bundle is not a safe gzip tar archive") from exc


def credential_bundle_binding(bundle_root: Path) -> str:
    """Return the stable hash to which a miner seals a provider credential.

    The public ciphertext file is intentionally excluded so the miner can hash
    the bundle before creating it. Generated Python caches and VCS metadata are
    excluded too: subnet packers do not transmit them, and they must not make a
    valid credential fail merely because a miner ran the agent locally. Every
    submitted executable bundle file is included, making a ciphertext unusable
    with a substituted agent or helper file.
    """

    if not bundle_root.is_dir():
        raise RuntimeError("credential binding requires an extracted bundle directory")
    digest = hashlib.sha256(_BUNDLE_BINDING_DOMAIN)
    for path in sorted(bundle_root.rglob("*")):
        if path.is_dir():
            continue
        if not path.is_file() or path.is_symlink():
            raise RuntimeError("credential binding accepts regular bundle files only")
        relative = path.relative_to(bundle_root).as_posix()
        if _exclude_from_credential_binding(relative):
            continue
        encoded_path = relative.encode("utf-8")
        content = path.read_bytes()
        digest.update(len(encoded_path).to_bytes(4, "big"))
        digest.update(encoded_path)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _exclude_from_credential_binding(relative_path: str) -> bool:
    """Keep credential hashing aligned with the submission bundle sent to a room."""
    path = Path(relative_path)
    return (
        relative_path == SEALED_CREDENTIAL_FILENAME
        or path.suffix in _TRANSIENT_BUNDLE_SUFFIXES
        or any(part in _TRANSIENT_BUNDLE_DIRS for part in path.parts)
    )

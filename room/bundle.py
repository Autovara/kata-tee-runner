"""Bounded extraction for a signed candidate bundle inside a TEE room."""

from __future__ import annotations

import base64
import binascii
import io
import os
import tarfile
from pathlib import Path

DEFAULT_MAX_COMPRESSED_BYTES = 512 * 1024
DEFAULT_MAX_EXTRACTED_BYTES = 256 * 1024
DEFAULT_MAX_FILES = 16


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

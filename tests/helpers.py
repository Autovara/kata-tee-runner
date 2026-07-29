"""Shared test helpers for the sealed room.

These three lived in both server test modules. ``bundle_b64`` was byte-identical; the other two
shared a NAME while differing -- one ``_post_run`` supported an explicit signature and one did not,
and one ``_bundle_binding`` tolerated an existing directory. Same name, different behaviour, in two
files a reader would reasonably assume agreed.

The versions kept here are the permissive ones, which are supersets of both.
"""

from __future__ import annotations

import json
import tarfile
import time
from base64 import b64encode
from io import BytesIO
from pathlib import Path
from tarfile import TarFile

from room import auth
from room.bundle import credential_bundle_binding
from room.server import app


def post_run(body: dict, *, signature: str | None = "__valid__"):
    """POST /run with a valid HMAC signature by default; pass signature=None to omit it, or a
    string to force a specific (e.g. wrong) signature."""
    body = {
        "issued_at": int(time.time()),
        "expires_at": int(time.time()) + 60,
        "bundle_sha256": "ab" * 32,
        **body,
    }
    raw = json.dumps(body).encode()
    headers = {"Content-Type": "application/json"}
    if signature == "__valid__":
        headers[auth.SIGNATURE_HEADER] = auth.sign(raw)
    elif signature is not None:
        headers[auth.SIGNATURE_HEADER] = signature
    return app.test_client().post("/run", data=raw, headers=headers)


def bundle_b64(files: dict[str, str]) -> str:
    buffer = BytesIO()
    with TarFile.open(fileobj=buffer, mode="w:gz") as archive:
        for relative, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(relative)
            info.size = len(data)
            archive.addfile(info, BytesIO(data))
    return b64encode(buffer.getvalue()).decode()


def bundle_binding(tmp_path: Path, files: dict[str, str]) -> str:
    root = tmp_path / "binding"
    root.mkdir(exist_ok=True)
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return credential_bundle_binding(root)

"""The generic sealed-room HTTP service — subnet-blind.

The room handles sealing, the miner-funded inference gateway, the sealed network,
attestation, and these endpoints. The subnet-specific execution is a *profile*
(implements ``room.profile.TeeJobProfile``)
loaded at startup from ``KATA_TEE_PROFILE=<module>:<Class>`` — so this base names no subnet. A
subnet image sets that environment variable and adds its profile module.

Two modes on /run, chosen by project_key:
  * project_key == profile.fixture_project  -> the profile's no-docker plumbing stub.
  * any real project_key                    -> the profile pulls + runs the problem in the room.

Both return: the answer (report) + an attestation quote whose report-data BINDS the answer +
project + round nonce.

Deployment secrets arrive as sealed environment variables (delivered to the
attested room; never hardcoded):
  GHCR_USER, GHCR_TOKEN  -- registry login to pull the private problem image

Each miner's provider credential is instead supplied as ``sealed_key`` in its
signed ``/run`` request. The room decrypts it only for that job, verifies that
it is bound to the submitted agent bundle, and passes it to the subnet profile;
it is never a runner-wide environment variable.
"""

import binascii
import hashlib
import hmac
import importlib
import json
import os
import re
import tempfile
import traceback
from pathlib import Path

from flask import Flask, jsonify, request

from room import auth, sealing
from room.attest import bind_and_quote
from room.bundle import credential_bundle_binding, extract_submission_bundle
from room.dstack import get_client
from room.inference_network import docker, ghcr_login
from room.profile import TeeJobResult

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = int(
    os.environ.get("KATA_ROOM_MAX_REQUEST_BYTES", str(1024 * 1024))
)


def load_profile():
    """Load the subnet's TeeJobProfile from ``KATA_TEE_PROFILE=<module>:<Class>``.

    Keeping this out of the base image's code is what makes the room subnet-blind: a subnet's image
    sets ``KATA_TEE_PROFILE=<module>:<Class>`` and adds that profile module.
    """
    spec = os.environ.get("KATA_TEE_PROFILE", "").strip()
    if ":" not in spec:
        raise RuntimeError(
            "KATA_TEE_PROFILE must be '<module>:<Class>' naming the subnet's TeeJobProfile."
        )
    module_name, class_name = spec.split(":", 1)
    return getattr(importlib.import_module(module_name), class_name)()


PROFILE = load_profile()


@app.get("/health")
def health():
    return jsonify(ok=True)


@app.get("/pubkey")
def pubkey():
    """Publish the room's sealing PUBLIC key (bound into a quote) so a miner can encrypt their
    inference key to it. The miner verifies the quote is the approved image, then seals to this key
    -- and the owner only ever handles the resulting ciphertext."""
    try:
        from coincurve import PublicKey

        sk = sealing.sealing_privkey()
        pk = PublicKey.from_secret(sk).format(compressed=True).hex()
        rd = hashlib.sha256(b"kata-sealing-pubkey:" + bytes.fromhex(pk)).digest()
        q = get_client().get_quote(rd)
        return jsonify(pubkey=pk, quote=q.quote, event_log=q.event_log)
    except Exception as exc:  # noqa: BLE001
        return jsonify(error=str(exc), where=traceback.format_exc()[-1200:]), 500


@app.post("/pull-test")
def pull_test():
    """Private diagnostic for a registry pull; disabled unless explicitly enabled."""
    if os.environ.get("KATA_ROOM_ENABLE_DIAGNOSTICS", "").lower() not in {
        "1",
        "true",
        "yes",
    }:
        return jsonify(error="diagnostics are disabled"), 404
    if not auth.is_configured():
        return jsonify(error=f"room auth is not configured (set {auth.AUTH_SECRET_ENV})"), 503
    raw = request.get_data()
    if not auth.verify(raw, request.headers.get(auth.SIGNATURE_HEADER, "")):
        return jsonify(error="unauthorized"), 401
    try:
        body = json.loads(raw) if raw else {}
        project_key = body.get("project_key", "")
        if not project_key:
            return jsonify(error="body must contain project_key"), 400
        ghcr_login()
        image = PROFILE.image(project_key)
        proc = docker(["pull", image])
        if proc.returncode != 0:
            return jsonify(ok=False, image=image, error=proc.stderr[:600]), 502
        digest = docker(["inspect", "--format", "{{index .RepoDigests 0}}", image]).stdout.strip()
        return jsonify(ok=True, image=image, digest=digest)
    except Exception as exc:  # noqa: BLE001
        return jsonify(ok=False, error=str(exc), where=traceback.format_exc()[-1200:]), 500


@app.route("/run", methods=["POST"])
def run():
    # /run runs a caller-supplied agent with a decrypted key injected, so it is authenticated and
    # POST-only. Fail closed if no shared secret is configured; reject a missing/invalid signature.
    if not auth.is_configured():
        return jsonify(error=f"room auth is not configured (set {auth.AUTH_SECRET_ENV})"), 503
    raw = request.get_data()
    if not auth.verify(raw, request.headers.get(auth.SIGNATURE_HEADER, "")):
        return jsonify(error="unauthorized"), 401
    try:
        return _run(raw)
    except Exception as exc:  # noqa: BLE001 - surface the real cause
        return jsonify(error=str(exc), where=traceback.format_exc()[-1500:]), 500


def _run(raw: bytes):
    # Parse the SAME bytes the signature covered (Kata passes each candidate's sealed key per run).
    try:
        body = json.loads(raw) if raw else {}
    except ValueError:
        return jsonify(error="body must be JSON"), 400
    if not isinstance(body, dict):
        return jsonify(error="body must be a JSON object"), 400
    window_error = auth.validate_request_window(body)
    if window_error:
        return jsonify(error=window_error), 400
    nonce_hex = body.get("nonce", "")
    project_key = body.get("project_key", PROFILE.fixture_project)
    sealed_key = body.get("sealed_key", "")
    bundle_b64 = body.get("bundle", "")  # base64 tar.gz of the miner's agent bundle
    bundle_sha256 = body.get("bundle_sha256", "")
    try:
        nonce = binascii.unhexlify(nonce_hex)
    except (binascii.Error, ValueError):
        return jsonify(error="nonce must be hex"), 400
    if not (8 <= len(nonce) <= 32):
        return jsonify(error="nonce must be 8..32 bytes of hex"), 400
    if not isinstance(bundle_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", bundle_sha256):
        return jsonify(error="bundle_sha256 must be a lowercase SHA-256 hex digest"), 400
    if not auth.REPLAY_GUARD.reserve(
        nonce_hex,
        expires_at=int(body[auth.EXPIRES_AT_FIELD]),
    ):
        return jsonify(error="nonce already used"), 409

    try:
        credential = sealing.resolve_miner_credential(sealed_key, required=False)
    except RuntimeError as exc:
        return jsonify(error=str(exc)), 400
    if credential is not None and not bundle_b64:
        return jsonify(error="a sealed miner credential requires a candidate bundle"), 400

    with tempfile.TemporaryDirectory() as directory:
        bundle_root: Path | None = None
        if bundle_b64:
            bundle_root = Path(directory) / "bundle"
            try:
                extract_submission_bundle(bundle_b64, bundle_root)
                actual_binding = credential_bundle_binding(bundle_root)
            except RuntimeError as exc:
                return jsonify(error=str(exc)), 400
            if credential is not None and not hmac.compare_digest(
                credential.bundle_binding, actual_binding
            ):
                return (
                    jsonify(error="sealed miner credential is not bound to this candidate bundle"),
                    400,
                )
        result = PROFILE.run(
            project_key=project_key,
            credential=credential,
            bundle_root=str(bundle_root) if bundle_root is not None else None,
            job_id=nonce_hex,
            bundle_sha256=bundle_sha256,
        )
    if not isinstance(result, TeeJobResult):
        raise RuntimeError("TEE profile returned an invalid result; expected TeeJobResult")

    answer_hash, binding_hash, report_data, quote = bind_and_quote(
        result.report,
        nonce,
        project_key,
        bundle_sha256=bundle_sha256,
        provenance=result.provenance,
    )
    return jsonify(
        nonce=nonce_hex,
        project_key=project_key,
        report=result.report,
        bundle_sha256=bundle_sha256,
        provenance=result.provenance,
        answer_sha256=answer_hash.hex(),
        binding_sha256=binding_hash.hex(),
        report_data_sha256=report_data.hex(),
        quote=quote.quote,
        event_log=quote.event_log,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True)

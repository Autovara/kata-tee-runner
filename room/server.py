"""The generic sealed-room HTTP service — subnet-blind.

The room handles sealing, the model-pinning relay + sealed network, attestation, and these
endpoints. The subnet-specific execution is a *profile* (implements ``room.profile.TeeJobProfile``)
loaded at startup from ``KATA_TEE_PROFILE=<module>:<Class>`` — so this base names no subnet. A
subnet image sets that env and adds its profile module (see kata-tee-runner-plan §2).

Two modes on /run, chosen by project_key:
  * project_key == profile.fixture_project  -> the profile's no-docker plumbing stub.
  * any real project_key                    -> the profile pulls + runs the problem in the room.

Both return: the answer (report) + an attestation quote whose report-data BINDS the answer +
project + round nonce.

Secrets arrive as sealed env vars (delivered to the attested room; NEVER hardcoded):
  GHCR_USER, GHCR_TOKEN  -- registry login to pull the private problem image
  INFERENCE_API_KEY      -- the miner's sealed inference key
"""

import binascii
import hashlib
import importlib
import os
import traceback

from flask import Flask, jsonify, request

from room import sealing
from room.attest import bind_and_quote
from room.dstack import client
from room.relay_net import docker, ghcr_login

app = Flask(__name__)


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
        q = client.get_quote(rd)
        return jsonify(pubkey=pk, quote=q.quote, event_log=q.event_log)
    except Exception as exc:  # noqa: BLE001
        return jsonify(error=str(exc), where=traceback.format_exc()[-1200:]), 500


@app.get("/pull-test")
def pull_test():
    """Confirm the room can log into the registry and pull a private problem image."""
    try:
        project_key = request.args.get("project_key", "")
        if not project_key:
            return jsonify(error="pass ?project_key=<a real project key>"), 400
        ghcr_login()
        image = PROFILE.image(project_key)
        proc = docker(["pull", image])
        if proc.returncode != 0:
            return jsonify(ok=False, image=image, error=proc.stderr[:600]), 502
        digest = docker(["inspect", "--format", "{{index .RepoDigests 0}}", image]).stdout.strip()
        return jsonify(ok=True, image=image, digest=digest)
    except Exception as exc:  # noqa: BLE001
        return jsonify(ok=False, error=str(exc), where=traceback.format_exc()[-1200:]), 500


@app.route("/run", methods=["GET", "POST"])
def run():
    try:
        return _run()
    except Exception as exc:  # noqa: BLE001 - surface the real cause
        return jsonify(error=str(exc), where=traceback.format_exc()[-1500:]), 500


def _run():
    # GET (manual testing) or POST (Kata passes each candidate's sealed key per request).
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        nonce_hex = body.get("nonce", "")
        project_key = body.get("project_key", PROFILE.fixture_project)
        sealed_key = body.get("sealed_key", "")
        bundle_b64 = body.get("bundle", "")  # base64 tar.gz of the miner's agent bundle
    else:
        nonce_hex = request.args.get("nonce", "")
        project_key = request.args.get("project_key", PROFILE.fixture_project)
        sealed_key = request.args.get("sealed_key", "")
        bundle_b64 = ""
    try:
        nonce = binascii.unhexlify(nonce_hex)
    except (binascii.Error, ValueError):
        return jsonify(error="nonce must be hex"), 400
    if not (8 <= len(nonce) <= 32):
        return jsonify(error="nonce must be 8..32 bytes of hex"), 400

    report = PROFILE.run(project_key=project_key, sealed_key=sealed_key, bundle_b64=bundle_b64)

    answer_hash, report_data, quote = bind_and_quote(report, nonce, project_key)
    return jsonify(
        nonce=nonce_hex,
        project_key=project_key,
        report=report,
        answer_sha256=answer_hash.hex(),
        report_data_sha256=report_data.hex(),
        quote=quote.quote,
        event_log=quote.event_log,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True)

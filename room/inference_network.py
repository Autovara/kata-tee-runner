"""Inference gateway, sealed agent network, and image-registry login helpers.

Agents run on an internal Docker network and can reach only the in-room inference
gateway. The gateway forwards their unchanged miner-funded requests to configured
provider routes; it does not impose a model, token, call, retry, or cost policy.
"""

import os
import socket
import subprocess
import sys
import time

from room.inference_gateway import make_job_route_token

GHCR = "ghcr.io"
INF_NET = "kata-inf-net"
INFERENCE_GATEWAY_ALIAS = "kata-inference-gateway"
INFERENCE_GATEWAY_PORT = "8000"

_logged_in = False
_gateway_process = None
_inference_network_ready = False


def docker(args, stdin=None, timeout=300):
    return subprocess.run(
        ["docker", *args], input=stdin, capture_output=True, text=True, timeout=timeout
    )


def ghcr_login():
    """Log the room's Docker daemon into GHCR using its sealed token."""
    global _logged_in
    if _logged_in:
        return
    user = os.environ.get("GHCR_USER", "")
    token = os.environ.get("GHCR_TOKEN", "")
    if not user or not token:
        raise RuntimeError("GHCR_USER / GHCR_TOKEN not set (needed to pull the problem image)")
    process = docker(["login", GHCR, "-u", user, "--password-stdin"], stdin=token)
    if process.returncode != 0:
        raise RuntimeError(f"ghcr login failed: {process.stderr[:300]}")
    _logged_in = True


def start_inference_gateway_once():
    """Start the built-in miner-funded gateway on the runner container."""
    global _gateway_process
    if _gateway_process is not None and _gateway_process.poll() is None:
        return
    _gateway_process = subprocess.Popen(
        [sys.executable, "-m", "room.inference_gateway"],
        env={
            **os.environ,
            "KATA_INFERENCE_GATEWAY_HOST": "0.0.0.0",
            "KATA_INFERENCE_GATEWAY_PORT": INFERENCE_GATEWAY_PORT,
        },
    )
    time.sleep(1.0)  # Let it bind before the first agent call.


def _docker_already_exists(process) -> bool:
    """Whether a docker command failed only because the object already exists."""
    return "already exists" in (process.stderr or "").lower()


def _require_internal_network(name: str) -> None:
    """Fail closed unless ``name`` is an internal (egress-blocked) Docker network.

    An agent runs on this network carrying the miner's decrypted inference key. If a
    network with this name already exists but is NOT internal (created without
    ``--internal``, e.g. a leftover or a misconfiguration), the agent could reach the
    public internet with that key. Refuse to proceed rather than run on it.
    """
    inspect = docker(["network", "inspect", "-f", "{{.Internal}}", name])
    if inspect.returncode != 0:
        raise RuntimeError(
            f"could not inspect inference network {name!r}: {inspect.stderr[:300]}"
        )
    if inspect.stdout.strip().lower() != "true":
        raise RuntimeError(
            f"inference network {name!r} is not internal (Internal={inspect.stdout.strip()!r}); "
            "refusing to run an agent with its inference key on a network that can reach "
            "the internet"
        )


def ensure_inference_network_once():
    """Create the egress-blocked network on which an agent can reach only the gateway.

    Fails closed: the network must exist AND be internal before any agent runs on it.
    """
    global _inference_network_ready
    if _inference_network_ready:
        return
    create = docker(["network", "create", "--internal", INF_NET])
    if create.returncode != 0 and not _docker_already_exists(create):
        raise RuntimeError(
            f"failed to create internal inference network {INF_NET!r}: {create.stderr[:300]}"
        )
    # Even when the network already existed, verify it is internal -- never trust a
    # pre-existing network of this name to be egress-blocked.
    _require_internal_network(INF_NET)
    own_container = socket.gethostname()
    connect = docker(
        [
            "network",
            "connect",
            "--alias",
            INFERENCE_GATEWAY_ALIAS,
            INF_NET,
            own_container,
        ]
    )
    # Tolerate the gateway already being attached; fail on any other connect error so
    # the gateway is guaranteed reachable on the sealed network before agents run.
    if connect.returncode != 0 and not _docker_already_exists(connect):
        raise RuntimeError(
            f"failed to connect the inference gateway to {INF_NET!r}: {connect.stderr[:300]}"
        )
    _inference_network_ready = True


def inference_gateway_url(job_id: str, provider: str) -> str:
    """Return the signed, provider-bound gateway URL for one agent job.

    The route token contains no API key. It prevents an untrusted agent from
    switching the encrypted credential to another allowlisted provider.
    """
    route = make_job_route_token(job_id, provider)
    return f"http://{INFERENCE_GATEWAY_ALIAS}:{INFERENCE_GATEWAY_PORT}/j/{route}"

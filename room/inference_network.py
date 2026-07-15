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


def ensure_inference_network_once():
    """Create the egress-blocked network on which an agent can reach only the gateway."""
    global _inference_network_ready
    if _inference_network_ready:
        return
    docker(["network", "create", "--internal", INF_NET])  # Ignore already-exists failures.
    own_container = socket.gethostname()
    docker(
        [
            "network",
            "connect",
            "--alias",
            INFERENCE_GATEWAY_ALIAS,
            INF_NET,
            own_container,
        ]
    )
    _inference_network_ready = True


def inference_gateway_url() -> str:
    """Return the only provider-facing URL available inside an agent container."""
    return f"http://{INFERENCE_GATEWAY_ALIAS}:{INFERENCE_GATEWAY_PORT}"

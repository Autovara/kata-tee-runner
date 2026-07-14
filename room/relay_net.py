"""Model-pinning relay + sealed internal network + image-registry login (generic). The agent runs
on an internal network where it can reach ONLY the in-room relay, which pins the model and forwards
to the provider with the miner's key -- so inference is real and fair with no direct internet."""

import os
import socket
import subprocess
import sys
import time

GHCR = "ghcr.io"
INF_NET = "kata-inf-net"
RELAY_ALIAS = "kata-relay"
RELAY_PORT = "8000"

_logged_in = False
_relay_proc = None
_inf_net_ready = False


def docker(args, stdin=None, timeout=300):
    return subprocess.run(
        ["docker", *args], input=stdin, capture_output=True, text=True, timeout=timeout
    )


def ghcr_login():
    """Log the room's docker into GHCR using the sealed token. Idempotent."""
    global _logged_in
    if _logged_in:
        return
    user = os.environ.get("GHCR_USER", "")
    token = os.environ.get("GHCR_TOKEN", "")
    if not user or not token:
        raise RuntimeError("GHCR_USER / GHCR_TOKEN not set (needed to pull the problem image)")
    proc = docker(["login", GHCR, "-u", user, "--password-stdin"], stdin=token)
    if proc.returncode != 0:
        raise RuntimeError(f"ghcr login failed: {proc.stderr[:300]}")
    _logged_in = True


def start_relay_once():
    """Run the model-pinning relay as a background process in this container (port 8000). Config
    (provider/model/pinning) comes from the room's env, which the relay inherits."""
    global _relay_proc
    if _relay_proc is not None and _relay_proc.poll() is None:
        return
    _relay_proc = subprocess.Popen(
        [sys.executable, "/app/relay.py"],
        env={**os.environ, "KATA_RELAY_HOST": "0.0.0.0", "KATA_RELAY_PORT": RELAY_PORT},
    )
    time.sleep(1.0)  # let it bind before the first agent call


def ensure_relay_net_once():
    """A sealed internal network on which the agent can reach ONLY the relay (this container,
    aliased). No direct internet for the agent -> the pinned model is enforced."""
    global _inf_net_ready
    if _inf_net_ready:
        return
    docker(["network", "create", "--internal", INF_NET])  # ignore "already exists"
    own = socket.gethostname()  # this runner's container id
    docker(["network", "connect", "--alias", RELAY_ALIAS, INF_NET, own])  # ignore if already
    _inf_net_ready = True


def relay_url() -> str:
    """The URL the agent uses to reach the in-room relay (on the sealed net)."""
    return f"http://{RELAY_ALIAS}:{RELAY_PORT}"

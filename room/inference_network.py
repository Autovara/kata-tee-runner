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


def _network_endpoint_ids(name: str) -> list[str]:
    """Full container IDs currently attached to network ``name`` (empty on any error)."""
    inspect = docker(
        ["network", "inspect", "-f", "{{range $id, $cfg := .Containers}}{{$id}}\n{{end}}", name]
    )
    if inspect.returncode != 0:
        return []
    return [line.strip() for line in inspect.stdout.splitlines() if line.strip()]


def _reset_inference_network() -> None:
    """Tear ``kata-inf-net`` down and recreate it so ONLY the current runner holds the alias.

    The network is internal and PERSISTS on the daemon across runner-container restarts (it is
    created here at runtime, not by compose). After the runner container restarts, the endpoint of
    the previous, now-dead runner instance can linger on the network still holding the
    ``kata-inference-gateway`` alias -- so an agent's DNS lookup resolves to a dead address, every
    inference call fails at connect, and the room used to return a silent, zero-scoring empty
    report. Force-disconnect every lingering endpoint, remove the network, and recreate it, so the
    live runner is the sole holder of the gateway alias.
    """
    for endpoint_id in _network_endpoint_ids(INF_NET):
        docker(["network", "disconnect", "-f", INF_NET, endpoint_id])  # best effort
    docker(["network", "rm", INF_NET])  # best effort; tolerate "not found"
    create = docker(["network", "create", "--internal", INF_NET])
    if create.returncode != 0 and not _docker_already_exists(create):
        raise RuntimeError(
            f"failed to create internal inference network {INF_NET!r}: {create.stderr[:300]}"
        )
    # Never trust a pre-existing network of this name to be egress-blocked.
    _require_internal_network(INF_NET)
    own_container = socket.gethostname()
    connect = docker(
        ["network", "connect", "--alias", INFERENCE_GATEWAY_ALIAS, INF_NET, own_container]
    )
    if connect.returncode != 0 and not _docker_already_exists(connect):
        raise RuntimeError(
            f"failed to connect the inference gateway to {INF_NET!r}: {connect.stderr[:300]}"
        )


def _verify_gateway_reachable() -> None:
    """Fail closed unless a throwaway container on the sealed network can reach the gateway.

    This proves the exact path a real agent uses -- DNS-resolve ``kata-inference-gateway`` on
    ``kata-inf-net`` and connect to it -- BEFORE any miner-funded agent runs. Without it a stale
    endpoint or a dead gateway is invisible: the agent's calls fail silently, the room returns an
    empty report, and the miner is scored 0 while never being charged. Refuse the run instead.
    """
    # Probe from the runner's OWN image (a locally-present python image) so the sealed, egress-less
    # network need not pull anything and we depend on no compose-only variable.
    own_container = socket.gethostname()
    inspect = docker(["inspect", "-f", "{{.Image}}", own_container])
    image = inspect.stdout.strip() if inspect.returncode == 0 else ""
    if not image:
        raise RuntimeError(
            "could not resolve the runner image to self-test inference-gateway reachability: "
            f"{(inspect.stderr or '').strip()[:200]}"
        )
    url = f"http://{INFERENCE_GATEWAY_ALIAS}:{INFERENCE_GATEWAY_PORT}/healthz"
    probe = docker(
        [
            "run", "--rm", "--network", INF_NET, "--entrypoint", "python", image, "-c",
            "import urllib.request,sys;"
            f"sys.exit(0 if urllib.request.urlopen({url!r}, timeout=10).status == 200 else 1)",
        ],
        timeout=90,
    )
    if probe.returncode != 0:
        raise RuntimeError(
            "inference gateway is NOT reachable on the sealed network via alias "
            f"{INFERENCE_GATEWAY_ALIAS!r}: {(probe.stderr or probe.stdout or '').strip()[:300]}. "
            "Refusing to run an agent whose inference would silently fail and score the miner 0."
        )


def ensure_inference_network_once():
    """Guarantee an egress-blocked network on which an agent can actually reach the gateway.

    Fails closed on two counts: the network must be internal (no miner-key exfiltration), AND the
    gateway must be provably reachable on it (no silent zero-score). Runs once per runner process --
    i.e. once per (re)start, which is exactly when stale network state from a dead prior runner
    exists.
    """
    global _inference_network_ready
    if _inference_network_ready:
        return
    _reset_inference_network()
    _verify_gateway_reachable()
    _inference_network_ready = True


def inference_gateway_url(job_id: str, provider: str) -> str:
    """Return the signed, provider-bound gateway URL for one agent job.

    The route token contains no API key. It prevents an untrusted agent from
    switching the encrypted credential to another allowlisted provider.
    """
    route = make_job_route_token(job_id, provider)
    return f"http://{INFERENCE_GATEWAY_ALIAS}:{INFERENCE_GATEWAY_PORT}/j/{route}"

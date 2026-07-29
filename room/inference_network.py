"""Inference gateway, sealed agent network, and image-registry login helpers.

Agents run on an internal Docker network and can reach only the in-room inference
gateway. The gateway forwards their unchanged miner-funded requests to configured
provider routes; it does not impose a model, token, call, retry, or cost policy.
"""

import os
import re
import socket
import subprocess
import sys
import time

from room.inference_gateway import make_job_route_token

GHCR = "ghcr.io"
INF_NET = "kata-inf-net"
INFERENCE_GATEWAY_ALIAS = "kata-inference-gateway"
INFERENCE_GATEWAY_PORT = "8000"
# A per-job agent container is named ``kata-sn60-<hex>`` or ``kata-sn22-<hex>`` by its profile.
# Runner containers have longer compose-generated names and can never match this anchored pattern.
_AGENT_CONTAINER_RE = re.compile(r"^kata-(?:sn22|sn60)-[0-9a-f]{12,64}(?:-stage)?$")
_AGENT_VOLUME_RE = re.compile(
    r"^kata-(?:sn22|sn60)-[0-9a-f]{12,64}-(?:bundle|output)$"
)

_logged_in = False
_gateway_process = None
_inference_network_ready = False


def docker(args, stdin=None, timeout=300, *, stdout=None, stderr=None):
    options = {"stdout": stdout, "stderr": stderr}
    if stdout is None and stderr is None:
        options = {"capture_output": True}
    return subprocess.run(
        ["docker", *args], input=stdin, text=True, timeout=timeout, **options
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


def cleanup_stale_agent_containers() -> None:
    """Remove leftover per-job agent containers and volumes from interrupted runs.

    The SN60 and SN22 profiles remove each agent container in ``finally``, but a room crash between
    ``create`` and cleanup can leave one behind. Stopped ones otherwise accumulate on the persistent
    daemon across runner restarts, and a lingering one can keep a stale ``kata-inf-net`` endpoint.
    This runs at runner start, when no agent is running. Runner containers never match the anchored,
    hex-only agent pattern, so they are never touched.
    """
    listed = docker(["ps", "-a", "--format", "{{.Names}}"])
    if listed.returncode != 0:
        return
    for name in listed.stdout.split():
        if _AGENT_CONTAINER_RE.fullmatch(name.strip()):
            docker(["rm", "-f", name.strip()])  # best effort
    volumes = docker(["volume", "ls", "--format", "{{.Name}}"])
    if volumes.returncode != 0:
        return
    for name in volumes.stdout.split():
        if _AGENT_VOLUME_RE.fullmatch(name.strip()):
            docker(["volume", "rm", "-f", name.strip()])  # best effort


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
    cleanup_stale_agent_containers()  # drop crashed leftovers (and any stale endpoint they hold)
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


# ---- the trusted broker -------------------------------------------------------------------------
#
# The gateway above runs as a SUBPROCESS, which is exactly why it cannot be the broker: a subprocess
# has no way to reach the decrypted keys in the /run handler's memory, so the key has to travel to
# whoever makes the call -- and for the gateway that is the agent. The broker instead runs on a
# thread inside the runner process, holds the keys itself, and hands the agent a capability.

BROKER_PORT = "8100"
_broker_server = None
_broker_thread = None
_broker_network_ready = False


def start_broker_once(broker):
    """Serve ``broker`` on the sealed network, in this process. Idempotent."""
    global _broker_server, _broker_thread
    if _broker_server is not None:
        return _broker_server
    import threading

    from room.broker import build_broker_server

    _broker_server = build_broker_server(broker, "0.0.0.0", int(BROKER_PORT))
    _broker_thread = threading.Thread(
        target=_broker_server.serve_forever, daemon=True, name="kata-broker"
    )
    _broker_thread.start()
    return _broker_server


def stop_broker():
    """Shut the broker's listener down. Used at batch completion and by tests."""
    global _broker_server, _broker_thread, _broker_network_ready
    if _broker_server is not None:
        _broker_server.shutdown()
        _broker_server.server_close()
        _broker_server = None
    if _broker_thread is not None:
        _broker_thread.join(timeout=10)
        _broker_thread = None
    _broker_network_ready = False


def broker_url() -> str:
    """The base URL an agent is given. A host and a port -- the agent appends nothing but an
    operation NAME, and the broker refuses any name it does not recognise."""
    return f"http://{INFERENCE_GATEWAY_ALIAS}:{BROKER_PORT}"


def _verify_broker_reachable() -> None:
    """Fail closed unless a throwaway container on the sealed network can reach the broker.

    Same reasoning as the gateway probe: without it, a stale network endpoint makes every agent call
    fail at connect, the room returns an empty report, and the contestant is scored zero for the
    room's own misconfiguration. Refuse the run instead.
    """
    own_container = socket.gethostname()
    inspect = docker(["inspect", "-f", "{{.Image}}", own_container])
    image = inspect.stdout.strip() if inspect.returncode == 0 else ""
    if not image:
        raise RuntimeError(
            "could not resolve the runner image to self-test broker reachability: "
            f"{(inspect.stderr or '').strip()[:200]}"
        )
    url = f"{broker_url()}/healthz"
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
            "the trusted broker is NOT reachable on the sealed network via alias "
            f"{INFERENCE_GATEWAY_ALIAS!r}: {(probe.stderr or probe.stdout or '').strip()[:300]}. "
            "Refusing to run an agent whose calls would silently fail and score it 0."
        )


def ensure_broker_network_once(broker):
    """An egress-blocked network on which an agent can reach the broker and nothing else.

    Fails closed on both counts: the network must be internal (so a compromised agent has no path
    off it), and the broker must be provably reachable on it (so a silent zero is impossible).
    """
    global _broker_network_ready
    server = start_broker_once(broker)
    if _broker_network_ready:
        return server
    _reset_inference_network()
    _verify_broker_reachable()
    _broker_network_ready = True
    return server

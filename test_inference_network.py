"""The sealed agent network must be internal AND the gateway provably reachable on it.

An agent runs on kata-inf-net carrying the miner's decrypted inference key, so a pre-existing
NON-internal network of that name would let it egress with the key. And a stale endpoint left by a
dead prior runner (the persistent internal network survives runner restarts) makes the
kata-inference-gateway alias resolve to a dead address, so the agent's inference silently fails and
the miner is scored 0. ensure_inference_network_once() must reset the network to a clean state and
then PROVE reachability, failing closed on either count.
"""

import types

import pytest

import room.inference_network as inf


def _proc(returncode=0, stdout="", stderr=""):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def _is_endpoint_list(args):
    return args[:2] == ["network", "inspect"] and "Containers" in args[3]


def _is_internal_check(args):
    return args[:2] == ["network", "inspect"] and "Internal" in args[3]


def _install_fake_docker(monkeypatch, responder, *, image="ghcr.io/x/runner@sha256:abc"):
    calls = []

    def fake_docker(args, stdin=None, timeout=300):
        calls.append(args)
        return responder(args)

    monkeypatch.setattr(inf, "docker", fake_docker)
    monkeypatch.setattr(inf, "_inference_network_ready", False)
    monkeypatch.setattr(inf.socket, "gethostname", lambda: "runner-container")
    if image is None:
        monkeypatch.delenv("KATA_SN60_RUNNER_IMAGE", raising=False)
    else:
        monkeypatch.setenv("KATA_SN60_RUNNER_IMAGE", image)
    return calls


def _healthy_responder(*, endpoints="", internal="true", probe_rc=0, image="sha256:runnerimg",
                       container_names=""):
    def responder(args):
        if args[:2] == ["ps", "-a"]:  # stale-agent-container cleanup listing
            return _proc(stdout=container_names)
        if _is_endpoint_list(args):
            return _proc(stdout=endpoints)
        if _is_internal_check(args):
            return _proc(stdout=internal + "\n")
        if args[:2] == ["inspect", "-f"]:  # resolve the runner's own image for the probe
            return _proc(returncode=0 if image else 1, stdout=(image + "\n") if image else "")
        if args[:1] == ["run"]:  # the reachability probe
            return _proc(returncode=probe_rc, stderr="" if probe_rc == 0 else "connection refused")
        return _proc()  # ps/disconnect / rm / create / connect all succeed

    return responder


def test_stale_agent_containers_removed_but_runner_untouched(monkeypatch):
    names = "\n".join([
        "kata-sn60-ac8715c964e6100011122",   # leftover agent container -> remove
        "kata-sn60-deadbeefdeadbeef0011",    # another leftover -> remove
        "dstack-kata-sn60-runner-1",         # the RUNNER -> must NOT be removed
        "some-other-container",
    ])
    calls = _install_fake_docker(monkeypatch, _healthy_responder(container_names=names))
    inf.ensure_inference_network_once()
    removed = [a[-1] for a in calls if a[:2] == ["rm", "-f"]]
    assert "kata-sn60-ac8715c964e6100011122" in removed
    assert "kata-sn60-deadbeefdeadbeef0011" in removed
    assert "dstack-kata-sn60-runner-1" not in removed
    assert "some-other-container" not in removed


def test_clean_reset_and_reachable_marks_ready(monkeypatch):
    calls = _install_fake_docker(monkeypatch, _healthy_responder())
    inf.ensure_inference_network_once()
    assert inf._inference_network_ready is True
    # it recreated the network and verified it is internal, then probed reachability
    assert ["network", "rm", inf.INF_NET] in calls
    assert ["network", "create", "--internal", inf.INF_NET] in calls
    assert any(a[:2] == ["network", "inspect"] and "Internal" in a[3] for a in calls)
    assert any(a[:1] == ["run"] for a in calls)


def test_stale_endpoint_is_force_disconnected_before_recreate(monkeypatch):
    stale = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    calls = _install_fake_docker(monkeypatch, _healthy_responder(endpoints=stale + "\n"))
    inf.ensure_inference_network_once()
    assert ["network", "disconnect", "-f", inf.INF_NET, stale] in calls
    assert inf._inference_network_ready is True


def test_unreachable_gateway_fails_closed(monkeypatch):
    # network resets fine and is internal, but the reachability probe cannot reach the gateway.
    _install_fake_docker(monkeypatch, _healthy_responder(probe_rc=1))
    with pytest.raises(RuntimeError, match="NOT reachable"):
        inf.ensure_inference_network_once()
    assert inf._inference_network_ready is False  # never runs an agent with dead inference


def test_non_internal_network_is_rejected(monkeypatch):
    # rm failed to clear it and create says already-exists; the internal check then fails closed.
    def responder(args):
        if _is_endpoint_list(args):
            return _proc(stdout="")
        if args[:2] == ["network", "create"]:
            return _proc(returncode=1, stderr="network with name kata-inf-net already exists")
        if _is_internal_check(args):
            return _proc(stdout="false\n")
        if args[:1] == ["run"]:
            pytest.fail("must not probe/run on a non-internal network")
        return _proc()

    _install_fake_docker(monkeypatch, responder)
    with pytest.raises(RuntimeError, match="not internal"):
        inf.ensure_inference_network_once()
    assert inf._inference_network_ready is False


def test_create_failure_that_is_not_already_exists_raises(monkeypatch):
    def responder(args):
        if _is_endpoint_list(args):
            return _proc(stdout="")
        if args[:2] == ["network", "create"]:
            return _proc(returncode=1, stderr="permission denied talking to docker daemon")
        return _proc()

    _install_fake_docker(monkeypatch, responder)
    with pytest.raises(RuntimeError, match="failed to create internal inference network"):
        inf.ensure_inference_network_once()
    assert inf._inference_network_ready is False


def test_unresolvable_runner_image_cannot_self_test(monkeypatch):
    # docker inspect of the runner's own container fails -> cannot build the probe -> fail closed.
    _install_fake_docker(monkeypatch, _healthy_responder(image=""))
    with pytest.raises(RuntimeError, match="could not resolve the runner image"):
        inf.ensure_inference_network_once()
    assert inf._inference_network_ready is False


# ---- the same guarantees for the trusted broker ---
#
# The broker replaces the gateway for miner-funded lanes and the failure modes are identical: a
# non-internal network lets a compromised agent egress, and an unreachable broker makes every call
# fail at connect -- which used to look like "the contestant found nothing" and score it zero.


def _fake_broker():
    from room.broker import Broker

    return Broker([])


def test_broker_network_is_rejected_when_not_internal(monkeypatch):
    """The agent no longer carries a key, but it does carry a capability and whatever it scraped.
    A network that can reach the internet is still an exfiltration path."""
    _install_fake_docker(monkeypatch, _healthy_responder(internal="false"))
    monkeypatch.setattr(inf, "_broker_network_ready", False)
    monkeypatch.setattr(inf, "start_broker_once", lambda _broker: None)

    with pytest.raises(RuntimeError, match="not internal"):
        inf.ensure_broker_network_once(_fake_broker())


def test_an_unreachable_broker_fails_closed(monkeypatch):
    """Refusing the run beats returning an empty report: an empty report is scored, and the
    contestant is scored zero for the room's own misconfiguration."""
    _install_fake_docker(monkeypatch, _healthy_responder(probe_rc=1))
    monkeypatch.setattr(inf, "_broker_network_ready", False)
    monkeypatch.setattr(inf, "start_broker_once", lambda _broker: None)

    with pytest.raises(RuntimeError, match="broker is NOT reachable"):
        inf.ensure_broker_network_once(_fake_broker())


def test_a_healthy_broker_network_is_prepared_once(monkeypatch):
    calls = _install_fake_docker(monkeypatch, _healthy_responder())
    monkeypatch.setattr(inf, "_broker_network_ready", False)
    monkeypatch.setattr(inf, "start_broker_once", lambda _broker: None)

    broker = _fake_broker()
    inf.ensure_broker_network_once(broker)
    prepared = len(calls)
    inf.ensure_broker_network_once(broker)

    assert len(calls) == prepared, "the network was prepared twice"


def test_the_broker_url_names_a_host_and_a_port_and_nothing_else():
    """The agent appends only an operation NAME to this. If it carried a path the agent could
    manipulate, the broker's operation allowlist would be one string-join away from irrelevant."""
    from urllib.parse import urlsplit

    parsed = urlsplit(inf.broker_url())
    assert parsed.scheme == "http"          # inside the sealed network; there is no CA in a room
    assert parsed.netloc == f"{inf.INFERENCE_GATEWAY_ALIAS}:{inf.BROKER_PORT}"
    assert parsed.path == ""
    assert not parsed.query and not parsed.fragment

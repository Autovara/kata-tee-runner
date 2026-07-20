"""The sealed agent network must be internal before any agent runs on it.

An agent runs on kata-inf-net carrying the miner's decrypted inference key, so a
pre-existing NON-internal network of that name would let it egress with the key.
ensure_inference_network_once() must fail closed in that case.
"""

import types

import pytest

import room.inference_network as inf


def _proc(returncode=0, stdout="", stderr=""):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def _install_fake_docker(monkeypatch, responder):
    calls = []

    def fake_docker(args, stdin=None, timeout=300):
        calls.append(args)
        return responder(args)

    monkeypatch.setattr(inf, "docker", fake_docker)
    monkeypatch.setattr(inf, "_inference_network_ready", False)
    monkeypatch.setattr(inf.socket, "gethostname", lambda: "runner-container")
    return calls


def test_fresh_internal_network_is_created_and_connected(monkeypatch):
    def responder(args):
        if args[:2] == ["network", "create"]:
            return _proc()  # created
        if args[:2] == ["network", "inspect"]:
            return _proc(stdout="true\n")  # internal
        if args[:2] == ["network", "connect"]:
            return _proc()
        return _proc()

    calls = _install_fake_docker(monkeypatch, responder)
    inf.ensure_inference_network_once()
    assert inf._inference_network_ready is True
    assert ["network", "inspect", "-f", "{{.Internal}}", inf.INF_NET] in calls


def test_preexisting_non_internal_network_is_rejected(monkeypatch):
    def responder(args):
        if args[:2] == ["network", "create"]:
            return _proc(returncode=1, stderr="network with name kata-inf-net already exists")
        if args[:2] == ["network", "inspect"]:
            return _proc(stdout="false\n")  # NOT internal -> must fail closed
        if args[:2] == ["network", "connect"]:
            pytest.fail("must not connect an agent path to a non-internal network")
        return _proc()

    _install_fake_docker(monkeypatch, responder)
    with pytest.raises(RuntimeError, match="not internal"):
        inf.ensure_inference_network_once()
    assert inf._inference_network_ready is False  # never marked ready


def test_preexisting_internal_network_with_gateway_already_attached_is_ok(monkeypatch):
    def responder(args):
        if args[:2] == ["network", "create"]:
            return _proc(returncode=1, stderr="network with name kata-inf-net already exists")
        if args[:2] == ["network", "inspect"]:
            return _proc(stdout="true\n")
        if args[:2] == ["network", "connect"]:
            return _proc(returncode=1, stderr="endpoint with name runner-container already exists in network")
        return _proc()

    _install_fake_docker(monkeypatch, responder)
    inf.ensure_inference_network_once()  # tolerates already-exists on both create and connect
    assert inf._inference_network_ready is True


def test_create_failure_that_is_not_already_exists_raises(monkeypatch):
    def responder(args):
        if args[:2] == ["network", "create"]:
            return _proc(returncode=1, stderr="permission denied talking to docker daemon")
        return _proc()

    _install_fake_docker(monkeypatch, responder)
    with pytest.raises(RuntimeError, match="failed to create internal inference network"):
        inf.ensure_inference_network_once()
    assert inf._inference_network_ready is False

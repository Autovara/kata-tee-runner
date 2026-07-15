from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from room import inference_network
from room.inference_gateway import (
    GatewayConfigurationError,
    build_server,
    resolve_direct_route,
    resolve_proxy_upstream,
    resolve_timeout,
)


class RecordingProvider(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        self.server.records.append(  # type: ignore[attr-defined]
            {
                "path": self.path,
                "headers": {key.lower(): value for key, value in self.headers.items()},
                "body": body,
            }
        )
        if self.headers.get("X-Upstream-Boom") == "yes":
            self._reply(502, {"detail": "provider boom"})
            return
        self._reply(200, {"ok": True}, extra_header=("X-Provider", "yes"))

    def _reply(self, status: int, payload: dict, extra_header=None) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if extra_header:
            self.send_header(*extra_header)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        return


@pytest.fixture
def gateway_and_provider(monkeypatch):
    provider = ThreadingHTTPServer(("127.0.0.1", 0), RecordingProvider)
    provider.records = []  # type: ignore[attr-defined]
    provider.daemon_threads = True
    threading.Thread(target=provider.serve_forever, daemon=True).start()
    monkeypatch.setenv(
        "KATA_INFERENCE_GATEWAY_UPSTREAM",
        f"http://127.0.0.1:{provider.server_address[1]}",
    )
    gateway = build_server("127.0.0.1", 0)
    threading.Thread(target=gateway.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{gateway.server_address[1]}", provider
    finally:
        gateway.shutdown()
        provider.shutdown()


def post(url: str, body: bytes, headers: dict[str, str] | None = None):
    request = Request(url, data=body, method="POST", headers=headers or {})
    with urlopen(request, timeout=10) as response:
        return (
            response.status,
            response.read(),
            {key.lower(): value for key, value in response.headers.items()},
        )


def test_proxy_route_is_optional_and_has_no_provider_default(monkeypatch) -> None:
    monkeypatch.delenv("KATA_INFERENCE_GATEWAY_UPSTREAM", raising=False)
    assert resolve_proxy_upstream() is None
    monkeypatch.setenv("KATA_INFERENCE_GATEWAY_UPSTREAM", "http://provider:8000/")
    assert resolve_proxy_upstream() == "http://provider:8000"


def test_timeout_is_transport_configuration_not_inference_policy(monkeypatch) -> None:
    monkeypatch.setenv("KATA_INFERENCE_GATEWAY_TIMEOUT", "12.5")
    assert resolve_timeout() == 12.5
    monkeypatch.setenv("KATA_INFERENCE_GATEWAY_TIMEOUT", "invalid")
    assert resolve_timeout() == 900.0


def test_direct_route_requires_explicit_prefixes_and_endpoint(monkeypatch) -> None:
    monkeypatch.setenv("KATA_INFERENCE_GATEWAY_DIRECT_KEY_PREFIXES", "miner-")
    monkeypatch.delenv("KATA_INFERENCE_GATEWAY_DIRECT_UPSTREAM", raising=False)

    with pytest.raises(GatewayConfigurationError, match="must be configured together"):
        resolve_direct_route("miner-key")


def test_gateway_forwards_miner_request_and_key_unchanged(gateway_and_provider) -> None:
    base, provider = gateway_and_provider
    body = json.dumps(
        {
            "model": "miner/provider-model",
            "messages": [{"role": "user", "content": "audit"}],
            "temperature": 0.7,
            "seed": 42,
            "max_tokens": 123_456,
        }
    ).encode()

    status, _, response_headers = post(
        base + "/inference",
        body,
        {"Content-Type": "application/json", "x-inference-api-key": "miner-key"},
    )

    assert status == 200
    assert response_headers["x-provider"] == "yes"
    assert len(provider.records) == 1
    record = provider.records[0]
    assert record["path"] == "/inference"
    assert record["body"] == body
    assert record["headers"]["x-inference-api-key"] == "miner-key"


def test_job_alias_is_private_to_the_room_and_query_is_preserved(
    gateway_and_provider,
) -> None:
    base, provider = gateway_and_provider
    post(
        base + "/j/private-job-1/inference?trace=1",
        b"{}",
        {"x-inference-api-key": "miner-key"},
    )

    assert provider.records[0]["path"] == "/inference?trace=1"


def test_gateway_rejects_a_missing_miner_key_before_any_provider_call(
    gateway_and_provider,
) -> None:
    base, provider = gateway_and_provider

    with pytest.raises(HTTPError) as error:
        post(base + "/inference", b"{}")

    assert error.value.code == 401
    assert provider.records == []


def test_gateway_uses_a_direct_route_without_rewriting_the_request(
    gateway_and_provider, monkeypatch
) -> None:
    base, proxy_provider = gateway_and_provider
    direct_provider = ThreadingHTTPServer(("127.0.0.1", 0), RecordingProvider)
    direct_provider.records = []  # type: ignore[attr-defined]
    direct_provider.daemon_threads = True
    threading.Thread(target=direct_provider.serve_forever, daemon=True).start()
    monkeypatch.setenv("KATA_INFERENCE_GATEWAY_DIRECT_KEY_PREFIXES", "direct-")
    monkeypatch.setenv(
        "KATA_INFERENCE_GATEWAY_DIRECT_UPSTREAM",
        f"http://127.0.0.1:{direct_provider.server_address[1]}/v1/chat/completions",
    )
    monkeypatch.setenv("KATA_INFERENCE_GATEWAY_DIRECT_AUTH_HEADER", "X-API-Key")
    monkeypatch.setenv("KATA_INFERENCE_GATEWAY_DIRECT_AUTH_VALUE_TEMPLATE", "Token {api_key}")
    body = json.dumps({"model": "miner/model", "messages": [], "max_tokens": 99999}).encode()
    try:
        post(base + "/inference", body, {"x-inference-api-key": "direct-secret"})
    finally:
        direct_provider.shutdown()

    assert proxy_provider.records == []
    record = direct_provider.records[0]
    assert record["path"] == "/v1/chat/completions"
    assert record["headers"]["x-api-key"] == "Token direct-secret"
    assert "x-inference-api-key" not in record["headers"]
    assert record["body"] == body


def test_gateway_rejects_requests_when_no_matching_provider_route_exists(
    monkeypatch,
) -> None:
    monkeypatch.delenv("KATA_INFERENCE_GATEWAY_UPSTREAM", raising=False)
    monkeypatch.delenv("KATA_INFERENCE_GATEWAY_DIRECT_KEY_PREFIXES", raising=False)
    monkeypatch.delenv("KATA_INFERENCE_GATEWAY_DIRECT_UPSTREAM", raising=False)
    gateway = build_server("127.0.0.1", 0)
    threading.Thread(target=gateway.serve_forever, daemon=True).start()
    try:
        with pytest.raises(HTTPError) as error:
            post(
                f"http://127.0.0.1:{gateway.server_address[1]}/inference",
                b"{}",
                {"x-inference-api-key": "miner-key"},
            )
        assert error.value.code == 502
    finally:
        gateway.shutdown()


def test_gateway_blocks_non_inference_routes(gateway_and_provider) -> None:
    base, provider = gateway_and_provider

    with pytest.raises(HTTPError) as error:
        post(base + "/metrics/reset", b"{}")

    assert error.value.code == 404
    assert provider.records == []


def test_health_is_local_and_does_not_contact_the_provider(
    gateway_and_provider,
) -> None:
    base, provider = gateway_and_provider

    with urlopen(base + "/healthz", timeout=10) as response:
        payload = json.loads(response.read())

    assert payload == {"status": "ok", "service": "miner-inference-gateway"}
    assert provider.records == []


def test_gateway_passes_provider_http_errors_through(gateway_and_provider) -> None:
    base, _provider = gateway_and_provider

    with pytest.raises(HTTPError) as error:
        post(
            base + "/inference",
            b"{}",
            {"X-Upstream-Boom": "yes", "x-inference-api-key": "miner-key"},
        )

    assert error.value.code == 502


def test_runner_starts_the_built_in_gateway_module(monkeypatch) -> None:
    commands: list[tuple[list[str], dict]] = []

    class Process:
        def poll(self):
            return None

    def fake_popen(command, **kwargs):
        commands.append((command, kwargs))
        return Process()

    monkeypatch.setattr(inference_network.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(inference_network.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(inference_network, "_gateway_process", None)

    inference_network.start_inference_gateway_once()

    assert commands[0][0] == [inference_network.sys.executable, "-m", "room.inference_gateway"]
    assert commands[0][1]["env"]["KATA_INFERENCE_GATEWAY_PORT"] == "8000"

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from room import auth, inference_network
from room.inference_gateway import (
    GatewayConfigurationError,
    build_server,
    make_job_route_token,
    resolve_provider_routes,
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


def _routes(provider_url: str) -> str:
    return json.dumps(
        {
            "openrouter": {
                "upstream": f"{provider_url}/openrouter/chat/completions",
            },
            "chutes": {
                "upstream": f"{provider_url}/chutes/chat/completions",
                "auth_header": "X-API-Key",
                "auth_value_template": "Token {api_key}",
                "headers": {"X-Route-Owner": "miner"},
            },
            "akashml": {
                "upstream": f"{provider_url}/akashml/chat/completions",
            },
        }
    )


@pytest.fixture
def gateway_and_provider(monkeypatch):
    monkeypatch.setenv(auth.AUTH_SECRET_ENV, "room-test-secret")
    provider = ThreadingHTTPServer(("127.0.0.1", 0), RecordingProvider)
    provider.records = []  # type: ignore[attr-defined]
    provider.daemon_threads = True
    threading.Thread(target=provider.serve_forever, daemon=True).start()
    provider_url = f"http://127.0.0.1:{provider.server_address[1]}"
    monkeypatch.setenv("KATA_INFERENCE_GATEWAY_PROVIDER_ROUTES_JSON", _routes(provider_url))
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


def inference_url(base: str, provider: str, job_id: str = "a" * 32) -> str:
    return f"{base}/j/{make_job_route_token(job_id, provider)}/inference"


def test_provider_routes_are_explicit_and_operator_configured(monkeypatch) -> None:
    monkeypatch.delenv("KATA_INFERENCE_GATEWAY_PROVIDER_ROUTES_JSON", raising=False)
    with pytest.raises(GatewayConfigurationError, match="must configure at least one provider"):
        resolve_provider_routes()

    monkeypatch.setenv(
        "KATA_INFERENCE_GATEWAY_PROVIDER_ROUTES_JSON",
        json.dumps({"bad provider": {"upstream": "https://provider.example/v1/chat/completions"}}),
    )
    with pytest.raises(GatewayConfigurationError, match="provider route names"):
        resolve_provider_routes()


def test_timeout_is_transport_configuration_not_inference_policy(monkeypatch) -> None:
    monkeypatch.setenv("KATA_INFERENCE_GATEWAY_TIMEOUT", "12.5")
    assert resolve_timeout() == 12.5
    monkeypatch.setenv("KATA_INFERENCE_GATEWAY_TIMEOUT", "invalid")
    assert resolve_timeout() == 180.0


def test_gateway_routes_each_signed_job_to_its_sealed_provider(gateway_and_provider) -> None:
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
        inference_url(base, "openrouter"),
        body,
        {"Content-Type": "application/json", "x-inference-api-key": "openrouter-key"},
    )
    assert status == 200
    assert response_headers["x-provider"] == "yes"

    status, _, _ = post(
        inference_url(base, "chutes", "b" * 32),
        body,
        {
            "Authorization": "Bearer attacker-supplied-value",
            "Content-Type": "application/json",
            "x-inference-api-key": "chutes-key",
        },
    )
    assert status == 200

    assert [record["path"] for record in provider.records] == [
        "/openrouter/chat/completions",
        "/chutes/chat/completions",
    ]
    openrouter, chutes = provider.records
    assert openrouter["body"] == body
    assert openrouter["headers"]["authorization"] == "Bearer openrouter-key"
    assert "x-inference-api-key" not in openrouter["headers"]
    assert chutes["body"] == body
    assert chutes["headers"]["x-api-key"] == "Token chutes-key"
    assert chutes["headers"]["x-route-owner"] == "miner"
    assert "authorization" not in chutes["headers"]


def test_gateway_does_not_allow_an_agent_to_change_its_provider(gateway_and_provider) -> None:
    base, provider = gateway_and_provider
    route = make_job_route_token("c" * 32, "openrouter")
    tampered = route.replace("~openrouter~", "~akashml~")

    with pytest.raises(HTTPError) as error:
        post(
            f"{base}/j/{tampered}/inference",
            b"{}",
            {"x-inference-api-key": "miner-key"},
        )

    assert error.value.code == 403
    assert provider.records == []


def test_gateway_rejects_a_missing_miner_key_before_provider_call(gateway_and_provider) -> None:
    base, provider = gateway_and_provider
    with pytest.raises(HTTPError) as error:
        post(inference_url(base, "akashml"), b"{}")
    assert error.value.code == 401
    assert provider.records == []


def test_gateway_rejects_a_provider_not_enabled_by_the_operator(gateway_and_provider) -> None:
    base, provider = gateway_and_provider
    with pytest.raises(HTTPError) as error:
        post(
            inference_url(base, "other-provider"),
            b"{}",
            {"x-inference-api-key": "miner-key"},
        )
    assert error.value.code == 502
    assert provider.records == []


def test_gateway_blocks_unsigned_or_non_inference_routes(gateway_and_provider) -> None:
    base, provider = gateway_and_provider
    for path in ("/inference", "/j/not-a-token/inference", "/metrics/reset"):
        with pytest.raises(HTTPError) as error:
            post(base + path, b"{}", {"x-inference-api-key": "miner-key"})
        assert error.value.code == 403
    assert provider.records == []


def test_health_is_local_and_does_not_contact_the_provider(gateway_and_provider) -> None:
    base, provider = gateway_and_provider
    with urlopen(base + "/healthz", timeout=10) as response:
        payload = json.loads(response.read())
    assert payload == {"status": "ok", "service": "miner-inference-gateway"}
    assert provider.records == []


def test_gateway_passes_provider_http_errors_through(gateway_and_provider) -> None:
    base, _provider = gateway_and_provider
    with pytest.raises(HTTPError) as error:
        post(
            inference_url(base, "openrouter"),
            b"{}",
            {"X-Upstream-Boom": "yes", "x-inference-api-key": "miner-key"},
        )
    assert error.value.code == 502


def test_inference_network_creates_a_signed_provider_bound_url(monkeypatch) -> None:
    monkeypatch.setenv(auth.AUTH_SECRET_ENV, "room-test-secret")
    url = inference_network.inference_gateway_url("d" * 32, "akashml")
    assert url.startswith("http://kata-inference-gateway:8000/j/")
    assert "~akashml~" in url


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

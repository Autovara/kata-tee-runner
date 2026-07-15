"""Allowlisted multi-provider gateway for miner-funded confidential execution.

An untrusted agent runs on an internal Docker network with no public egress. It
can call only a signed per-job ``/j/<route>/inference`` endpoint with its own
provider key.  The route is derived inside the room from the miner's encrypted
credential descriptor, so an agent cannot select a different provider or an
arbitrary destination.

Provider routes are deployment configuration, not miner input.  The gateway is
subnet-neutral: it does not select models, meter tokens, limit calls, or pay
for inference; it only sends an unchanged request to an allowlisted route with
the miner's own credential.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import sys
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from room import auth

DEFAULT_TIMEOUT_SECONDS = 900

PROVIDER_ROUTES_ENV = "KATA_INFERENCE_GATEWAY_PROVIDER_ROUTES_JSON"
TIMEOUT_ENV = "KATA_INFERENCE_GATEWAY_TIMEOUT"

DEFAULT_AUTH_HEADER = "Authorization"
DEFAULT_AUTH_VALUE_TEMPLATE = "Bearer {api_key}"

HEALTH_PATH = "/healthz"
_PROVIDER_PATTERN = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_JOB_ROUTE_PATTERN = re.compile(
    r"/j/(?P<job_id>[0-9a-f]{16,64})~(?P<provider>[a-z][a-z0-9_-]{0,63})~"
    r"(?P<signature>[0-9a-f]{64})/inference\Z"
)
_HEADER_NAME_PATTERN = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+\Z")

_SKIP_REQUEST_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
    "authorization",
    "x-inference-api-key",
    "x-inference-provider",
}
_SKIP_RESPONSE_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
}


class GatewayConfigurationError(Exception):
    """The deployment has no valid route for the requested provider."""


class GatewayAuthorizationError(Exception):
    """The request did not carry a valid room-generated provider route."""


@dataclass(frozen=True)
class ProviderRoute:
    """An operator-approved provider endpoint and its credential transform."""

    upstream: str
    auth_header: str = DEFAULT_AUTH_HEADER
    auth_value_template: str = DEFAULT_AUTH_VALUE_TEMPLATE
    headers: tuple[tuple[str, str], ...] = ()


def _require_provider_id(value: object) -> str:
    if not isinstance(value, str) or not _PROVIDER_PATTERN.fullmatch(value):
        raise GatewayConfigurationError(
            "provider route names must use lowercase letters, digits, _ or -"
        )
    return value


def _validate_header(name: object, value: object) -> tuple[str, str]:
    if not isinstance(name, str) or not _HEADER_NAME_PATTERN.fullmatch(name):
        raise GatewayConfigurationError("provider route has an invalid header name")
    if not isinstance(value, str) or "\r" in value or "\n" in value:
        raise GatewayConfigurationError("provider route has an invalid header value")
    return name, value


def _validate_upstream(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GatewayConfigurationError("provider route requires an upstream URL")
    upstream = value.strip()
    parsed = urlsplit(upstream)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username
        or parsed.password
    ):
        raise GatewayConfigurationError("provider route upstream must be an absolute HTTP(S) URL")
    return upstream


def resolve_provider_routes() -> dict[str, ProviderRoute]:
    """Load only operator-approved provider routes from deployment configuration."""

    raw = os.environ.get(PROVIDER_ROUTES_ENV, "").strip()
    if not raw:
        raise GatewayConfigurationError(
            f"{PROVIDER_ROUTES_ENV} must configure at least one provider"
        )
    try:
        configured = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GatewayConfigurationError(f"{PROVIDER_ROUTES_ENV} must be a JSON object") from exc
    if not isinstance(configured, dict) or not configured:
        raise GatewayConfigurationError(f"{PROVIDER_ROUTES_ENV} must be a non-empty JSON object")

    routes: dict[str, ProviderRoute] = {}
    for provider, route in configured.items():
        provider_id = _require_provider_id(provider)
        if not isinstance(route, dict):
            raise GatewayConfigurationError(f"provider route {provider_id!r} must be an object")
        unknown = set(route) - {"upstream", "auth_header", "auth_value_template", "headers"}
        if unknown:
            raise GatewayConfigurationError(
                f"provider route {provider_id!r} has unsupported fields"
            )
        auth_header = route.get("auth_header", DEFAULT_AUTH_HEADER)
        _validate_header(auth_header, "")
        template = route.get("auth_value_template", DEFAULT_AUTH_VALUE_TEMPLATE)
        if not isinstance(template, str) or "{api_key}" not in template:
            raise GatewayConfigurationError(
                f"provider route {provider_id!r} auth_value_template must contain {{api_key}}"
            )
        raw_headers = route.get("headers", {})
        if not isinstance(raw_headers, dict):
            raise GatewayConfigurationError(
                f"provider route {provider_id!r} headers must be an object"
            )
        headers = tuple(_validate_header(name, value) for name, value in raw_headers.items())
        routes[provider_id] = ProviderRoute(
            upstream=_validate_upstream(route.get("upstream")),
            auth_header=auth_header,
            auth_value_template=template,
            headers=headers,
        )
    return routes


def resolve_timeout() -> float:
    """Return a network transport timeout, not an inference-budget limit."""

    raw = os.environ.get(TIMEOUT_ENV, "").strip()
    if raw:
        try:
            timeout = float(raw)
        except ValueError:
            return float(DEFAULT_TIMEOUT_SECONDS)
        if timeout > 0:
            return timeout
    return float(DEFAULT_TIMEOUT_SECONDS)


def make_job_route_token(job_id: str, provider: str) -> str:
    """Make the provider-bound route token passed to an untrusted agent.

    The token reveals no API key.  Its signature prevents the agent from changing
    the provider name or using the gateway as an arbitrary allowlisted proxy.
    """

    if not re.fullmatch(r"[0-9a-f]{16,64}", job_id):
        raise ValueError("job id must be 16..64 lowercase hexadecimal characters")
    provider_id = _require_provider_id(provider)
    if not auth.is_configured():
        raise RuntimeError("room auth is not configured; cannot create inference route")
    payload = _route_payload(job_id, provider_id)
    return f"{job_id}~{provider_id}~{auth.sign(payload)}"


def _route_payload(job_id: str, provider: str) -> bytes:
    return f"kata-inference-route-v1:{job_id}:{provider}".encode("ascii")


def _provider_from_route(path: str) -> str:
    match = _JOB_ROUTE_PATTERN.fullmatch(path)
    if match is None or not auth.is_configured():
        raise GatewayAuthorizationError("a valid signed job inference route is required")
    job_id = match.group("job_id")
    provider = match.group("provider")
    signature = match.group("signature")
    expected = auth.sign(_route_payload(job_id, provider))
    if not hmac.compare_digest(signature, expected):
        raise GatewayAuthorizationError("a valid signed job inference route is required")
    return provider


class MinerInferenceGatewayHandler(BaseHTTPRequestHandler):
    """Forward only a job-bound miner inference request to an allowlisted route."""

    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        if urlsplit(self.path).path == HEALTH_PATH:
            self._send_json(200, {"status": "ok", "service": "miner-inference-gateway"})
            return
        self._send_json(404, {"status": "error", "detail": "Only gateway health is available."})

    def do_POST(self) -> None:
        parsed = urlsplit(self.path)
        try:
            provider = _provider_from_route(parsed.path)
        except GatewayAuthorizationError as error:
            self._read_body()
            self._send_json(403, {"status": "error", "detail": str(error)})
            return
        self._forward(provider)

    def _forward(self, provider: str) -> None:
        body = self._read_body()
        api_key = self.headers.get("x-inference-api-key", "").strip()
        if not api_key:
            self._send_json(
                401,
                {"status": "error", "detail": "A miner inference API key is required."},
            )
            return
        try:
            route = resolve_provider_routes().get(provider)
            if route is None:
                raise GatewayConfigurationError("the sealed credential provider is not enabled")
            request = self._build_provider_request(
                api_key=api_key,
                body=body,
                route=route,
                request_headers=self._safe_request_headers(),
            )
        except GatewayConfigurationError as error:
            self._send_json(502, {"status": "error", "detail": str(error)})
            return
        try:
            with urlopen(request, timeout=resolve_timeout()) as response:
                self._relay_response(response.status, response.headers.items(), response.read())
        except HTTPError as error:
            self._relay_response(error.code, error.headers.items(), error.read())
        except URLError as error:
            self._send_json(
                502,
                {"status": "error", "detail": f"gateway could not reach provider: {error.reason}"},
            )

    def _safe_request_headers(self) -> dict[str, str]:
        return {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in _SKIP_REQUEST_HEADERS
        }

    def _build_provider_request(
        self,
        *,
        api_key: str,
        body: bytes,
        route: ProviderRoute,
        request_headers: dict[str, str],
    ) -> Request:
        protected_headers = {route.auth_header.lower()}
        protected_headers.update(name.lower() for name, _ in route.headers)
        headers = {
            key: value
            for key, value in request_headers.items()
            if key.lower() not in protected_headers
        }
        headers.setdefault("Content-Type", "application/json")
        for name, value in route.headers:
            headers[name] = value
        headers[route.auth_header] = self._render_auth_value(route.auth_value_template, api_key)
        return Request(route.upstream, data=body if body else None, headers=headers, method="POST")

    @staticmethod
    def _render_auth_value(template: str, api_key: str) -> str:
        try:
            rendered = template.format(api_key=api_key)
        except (IndexError, KeyError, ValueError) as error:
            raise GatewayConfigurationError(
                "provider auth_value_template must use {api_key}"
            ) from error
        if "\r" in rendered or "\n" in rendered:
            raise GatewayConfigurationError(
                "provider auth_value_template produced an invalid value"
            )
        return rendered

    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        return self.rfile.read(length) if length > 0 else b""

    def _relay_response(self, status: int, header_items, body: bytes) -> None:
        self.send_response(status)
        for key, value in header_items:
            if key.lower() not in _SKIP_RESPONSE_HEADERS:
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _send_json(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        # Requests can contain source code and miner credentials.
        return


def build_server(host: str, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), MinerInferenceGatewayHandler)
    server.daemon_threads = True
    return server


def main() -> int:
    host = os.environ.get("KATA_INFERENCE_GATEWAY_HOST", "0.0.0.0")
    port = int(os.environ.get("KATA_INFERENCE_GATEWAY_PORT", "8000"))
    server = build_server(host, port)
    print(f"Miner-funded inference gateway listening on {host}:{port}", file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

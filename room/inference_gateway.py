"""Generic miner-funded inference gateway for confidential runner profiles.

An untrusted agent runs on an internal Docker network with no public egress. It
can call only this gateway's ``/inference`` endpoint with its own provider key.
The gateway forwards the request unchanged to an operator-configured provider
route. It is deliberately subnet- and provider-neutral:

* it never selects a model or alters request controls;
* it never meters, budgets, or pays for inference;
* it never embeds provider names, API-key prefixes, or subnet endpoints.

The enclosing TEE profile supplies the per-job ``/j/<id>/inference`` alias. The
gateway strips that local correlation id before forwarding the request.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

DEFAULT_TIMEOUT_SECONDS = 900

UPSTREAM_ENV = "KATA_INFERENCE_GATEWAY_UPSTREAM"
TIMEOUT_ENV = "KATA_INFERENCE_GATEWAY_TIMEOUT"
DIRECT_KEY_PREFIXES_ENV = "KATA_INFERENCE_GATEWAY_DIRECT_KEY_PREFIXES"
DIRECT_UPSTREAM_ENV = "KATA_INFERENCE_GATEWAY_DIRECT_UPSTREAM"
DIRECT_AUTH_HEADER_ENV = "KATA_INFERENCE_GATEWAY_DIRECT_AUTH_HEADER"
DIRECT_AUTH_VALUE_TEMPLATE_ENV = "KATA_INFERENCE_GATEWAY_DIRECT_AUTH_VALUE_TEMPLATE"

DEFAULT_DIRECT_AUTH_HEADER = "Authorization"
DEFAULT_DIRECT_AUTH_VALUE_TEMPLATE = "Bearer {api_key}"

INFERENCE_PATH = "/inference"
HEALTH_PATH = "/healthz"
_JOB_INFERENCE_PATH = re.compile(r"/j/[^/?]{1,256}/inference\Z")

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
    """The runner has no valid route for a miner-funded inference request."""


@dataclass(frozen=True)
class DirectProviderRoute:
    """A direct provider endpoint and the header used to carry the miner key."""

    upstream: str
    auth_header: str = DEFAULT_DIRECT_AUTH_HEADER
    auth_value_template: str = DEFAULT_DIRECT_AUTH_VALUE_TEMPLATE


def _split_csv(value: str | None) -> list[str]:
    return [part.strip() for part in (value or "").split(",") if part.strip()]


def _key_matches(api_key: str, prefixes: list[str]) -> bool:
    return any(prefix == "*" or api_key.startswith(prefix) for prefix in prefixes)


def resolve_proxy_upstream() -> str | None:
    """Return the optional generic proxy route, with no subnet-specific default."""
    value = os.environ.get(UPSTREAM_ENV, "").strip().rstrip("/")
    return value or None


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


def resolve_direct_route(api_key: str) -> DirectProviderRoute | None:
    """Return the configured direct route when its prefix allowlist matches.

    A profile may use an OpenAI-compatible proxy route, a direct provider route,
    or both. Direct routing always requires both an endpoint and explicit key
    prefixes; use ``*`` only when every miner key should use that provider.
    """
    prefixes = _split_csv(os.environ.get(DIRECT_KEY_PREFIXES_ENV))
    upstream = os.environ.get(DIRECT_UPSTREAM_ENV, "").strip()
    if bool(prefixes) != bool(upstream):
        raise GatewayConfigurationError(
            f"{DIRECT_KEY_PREFIXES_ENV} and {DIRECT_UPSTREAM_ENV} must be configured together"
        )
    if not prefixes or not _key_matches(api_key, prefixes):
        return None
    return DirectProviderRoute(
        upstream=upstream,
        auth_header=os.environ.get(DIRECT_AUTH_HEADER_ENV, "").strip()
        or DEFAULT_DIRECT_AUTH_HEADER,
        auth_value_template=os.environ.get(DIRECT_AUTH_VALUE_TEMPLATE_ENV, "").strip()
        or DEFAULT_DIRECT_AUTH_VALUE_TEMPLATE,
    )


class MinerInferenceGatewayHandler(BaseHTTPRequestHandler):
    """Forward only miner-funded inference requests from the sealed network."""

    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        if urlsplit(self.path).path == HEALTH_PATH:
            self._send_json(200, {"status": "ok", "service": "miner-inference-gateway"})
            return
        self._send_json(404, {"status": "error", "detail": "Only gateway health is available."})

    def do_POST(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == INFERENCE_PATH:
            upstream_path = INFERENCE_PATH + (f"?{parsed.query}" if parsed.query else "")
        elif _JOB_INFERENCE_PATH.fullmatch(parsed.path):
            upstream_path = INFERENCE_PATH + (f"?{parsed.query}" if parsed.query else "")
        else:
            self._read_body()
            self._send_json(
                404,
                {"status": "error", "detail": "Only POST /inference is allowed."},
            )
            return
        self._forward(upstream_path)

    def _forward(self, upstream_path: str) -> None:
        body = self._read_body()
        api_key = self.headers.get("x-inference-api-key", "").strip()
        if not api_key:
            # Never permit an empty miner key to trigger a provider fallback.
            self._send_json(
                401,
                {"status": "error", "detail": "A miner inference API key is required."},
            )
            return
        try:
            request = self._build_provider_request(
                api_key=api_key,
                body=body,
                upstream_path=upstream_path,
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
                {
                    "status": "error",
                    "detail": f"gateway could not reach provider: {error.reason}",
                },
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
        upstream_path: str,
        request_headers: dict[str, str],
    ) -> Request:
        direct_route = resolve_direct_route(api_key)
        if direct_route is not None:
            headers = {
                key: value
                for key, value in request_headers.items()
                if key.lower() not in {"x-inference-api-key", direct_route.auth_header.lower()}
            }
            headers.setdefault("Content-Type", "application/json")
            headers[direct_route.auth_header] = self._render_auth_value(
                direct_route.auth_value_template,
                api_key,
            )
            return Request(
                direct_route.upstream,
                data=body if body else None,
                headers=headers,
                method="POST",
            )

        proxy_upstream = resolve_proxy_upstream()
        if proxy_upstream is None:
            raise GatewayConfigurationError(
                "No provider route is configured: set "
                f"{UPSTREAM_ENV} or a matching {DIRECT_KEY_PREFIXES_ENV}/{DIRECT_UPSTREAM_ENV}."
            )
        headers = dict(request_headers)
        headers["x-inference-api-key"] = api_key
        return Request(
            proxy_upstream + upstream_path,
            data=body if body else None,
            headers=headers,
            method="POST",
        )

    @staticmethod
    def _render_auth_value(template: str, api_key: str) -> str:
        if "{api_key}" not in template:
            raise GatewayConfigurationError(
                f"{DIRECT_AUTH_VALUE_TEMPLATE_ENV} must include {{api_key}}"
            )
        try:
            return template.format(api_key=api_key)
        except (IndexError, KeyError, ValueError) as error:
            raise GatewayConfigurationError(
                f"{DIRECT_AUTH_VALUE_TEMPLATE_ENV} must use {{api_key}}"
            ) from error

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
        # Inference requests can contain source code and miner credentials.
        return


def build_server(host: str, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), MinerInferenceGatewayHandler)
    server.daemon_threads = True
    return server


def main() -> int:
    host = os.environ.get("KATA_INFERENCE_GATEWAY_HOST", "0.0.0.0")
    port = int(os.environ.get("KATA_INFERENCE_GATEWAY_PORT", "8000"))
    server = build_server(host, port)
    destination = resolve_proxy_upstream() or "configured direct provider routes"
    print(
        f"Miner-funded inference gateway listening on {host}:{port} -> {destination}",
        file=sys.stderr,
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

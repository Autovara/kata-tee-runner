from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler

from room.bounded_http import BoundedThreadingHTTPServer


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    started = threading.Event()

    def setup(self) -> None:
        super().setup()
        type(self).started.set()

    def do_GET(self) -> None:  # noqa: N802
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        return


def _request(port: int) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
        client.sendall(b"GET / HTTP/1.1\r\nHost: room\r\nConnection: close\r\n\r\n")
        chunks = []
        while chunk := client.recv(4096):
            chunks.append(chunk)
        return b"".join(chunks)


def test_slow_connections_have_a_deadline_and_cannot_create_unbounded_threads():
    _Handler.started.clear()
    server = BoundedThreadingHTTPServer(
        ("127.0.0.1", 0),
        _Handler,
        max_connections=1,
        connection_timeout_seconds=0.2,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]

    stalled = socket.create_connection(("127.0.0.1", port), timeout=2)
    stalled.sendall(b"GET / HTTP/1.1\r\nHost: room\r\n")
    assert _Handler.started.wait(timeout=2)

    overloaded = _request(port)
    assert b"503 Service Unavailable" in overloaded
    assert b'{"error":"server is at capacity"}' in overloaded

    # The incomplete request is evicted by the read deadline and releases its only slot.
    stalled.settimeout(2)
    assert stalled.recv(4096) == b""
    assert b"200 OK" in _request(port)

    stalled.close()
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)

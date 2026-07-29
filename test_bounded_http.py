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


def _serve(**kwargs):
    server = BoundedThreadingHTTPServer(("127.0.0.1", 0), _Handler, **kwargs)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, server.server_address[1]


def _stop(server, thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def test_a_stalled_connection_is_evicted_by_its_deadline_and_frees_its_slot():
    """The deadline, on its own.

    This used to be one test that ALSO probed the at-capacity refusal inside the same 0.2s window.
    That could not hold: the two properties are in direct conflict. The refusal needs the stalled
    connection to still be holding the only slot; the deadline exists to take that slot away. So any
    pause longer than the deadline between them -- a loaded host, a GC pause, a scheduler that does
    not run the probe thread promptly -- turned the expected 503 into a 200 and failed the run.

    It presented as a flake: it passed 6/6 in isolation and failed under ./smoke.sh, which runs
    while both lanes are firing rounds. The cause was the assertion order, not the server.

    Nothing here now races. The deadline is the only thing being measured, so it is allowed to take
    as long as it takes.
    """
    _Handler.started.clear()
    server, thread, port = _serve(max_connections=1, connection_timeout_seconds=0.2)
    try:
        stalled = socket.create_connection(("127.0.0.1", port), timeout=2)
        stalled.sendall(b"GET / HTTP/1.1\r\nHost: room\r\n")
        assert _Handler.started.wait(timeout=2)

        # Waiting on the RELEASE, not on the socket close. The two are not the same event and their
        # order is fixed the wrong way round: the socket is closed inside process_request_thread and
        # the slot is released in that method's `finally`, strictly afterwards. So `recv() == b""`
        # is observable BEFORE the slot is free, and a request sent on that signal can legitimately
        # be refused.
        stalled.settimeout(2)
        assert stalled.recv(4096) == b""
        assert server.wait_for_release(at_least=1, timeout=5), (
            f"the evicted connection never released its slot; release_count={server.release_count}"
        )

        # And the freed slot is genuinely reusable -- an eviction that leaked its slot would leave
        # the room serving nothing while reporting itself healthy.
        assert b"200 OK" in _request(port)
        stalled.close()
    finally:
        _stop(server, thread)


# ---- the release signal itself ---
#
# `wait_for_release` exists so a caller can wait on a connection slot actually becoming free. It is
# observability only, but a test that waits on a broken signal is worse than one that sleeps: it
# looks deterministic and is not. So the signal gets its own coverage.


def test_a_fresh_server_has_released_nothing():
    server, thread, _ = _serve(max_connections=1)
    try:
        assert server.release_count == 0
    finally:
        _stop(server, thread)


def test_waiting_for_a_release_that_never_comes_reports_failure():
    """It must return False rather than block forever, or a broken server hangs its caller instead
    of failing it."""
    server, thread, _ = _serve(max_connections=1)
    try:
        assert server.wait_for_release(at_least=1, timeout=0.2) is False
    finally:
        _stop(server, thread)


def test_a_served_request_releases_its_slot():
    server, thread, port = _serve(max_connections=1)
    try:
        assert b"200 OK" in _request(port)
        assert server.wait_for_release(at_least=1, timeout=2)
        assert server.release_count == 1
    finally:
        _stop(server, thread)


def test_a_refused_request_releases_nothing():
    """The 503 path refuses at ADMISSION -- `process_request` returns before acquiring a slot -- so
    it has nothing to release.

    Pinned because getting this backwards is easy and silent: a caller that expected the rejection
    to count would wait for a release that can never arrive, and would blame the server.
    """
    _Handler.started.clear()
    server, thread, port = _serve(max_connections=1, connection_timeout_seconds=5)
    try:
        stalled = socket.create_connection(("127.0.0.1", port), timeout=2)
        stalled.sendall(b"GET / HTTP/1.1\r\nHost: room\r\n")
        assert _Handler.started.wait(timeout=2)

        overloaded = _request(port)
        assert b"503 Service Unavailable" in overloaded
        assert b'{"error":"server is at capacity"}' in overloaded
        # The refusal is complete, and it released nothing; the stalled connection still holds the
        # only slot and has not timed out yet.
        assert server.release_count == 0
        stalled.close()
    finally:
        _stop(server, thread)

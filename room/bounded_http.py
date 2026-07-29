"""Resource-bounded HTTP serving for endpoints reachable by untrusted agents."""

from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Type

DEFAULT_MAX_CONNECTIONS = 32
DEFAULT_CONNECTION_TIMEOUT_SECONDS = 15.0

_OVERLOADED_BODY = b'{"error":"server is at capacity"}'
_OVERLOADED_RESPONSE = b"".join(
    (
        b"HTTP/1.1 503 Service Unavailable\r\n",
        b"Content-Type: application/json\r\n",
        f"Content-Length: {len(_OVERLOADED_BODY)}\r\n".encode("ascii"),
        b"Connection: close\r\n",
        b"\r\n",
        _OVERLOADED_BODY,
    )
)


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """A thread-per-connection server with hard connection and I/O bounds.

    ``ThreadingHTTPServer`` otherwise creates a thread for every accepted socket. An untrusted
    client can hold each thread forever by sending an incomplete header or body. This server admits
    only a fixed number of connections and puts a deadline on every socket operation, so resource
    use and recovery time remain bounded.
    """

    daemon_threads = True
    request_queue_size = DEFAULT_MAX_CONNECTIONS

    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler: Type[BaseHTTPRequestHandler],
        *,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        connection_timeout_seconds: float = DEFAULT_CONNECTION_TIMEOUT_SECONDS,
    ) -> None:
        if max_connections <= 0:
            raise ValueError("max_connections must be positive")
        if connection_timeout_seconds <= 0:
            raise ValueError("connection_timeout_seconds must be positive")
        self.max_connections = max_connections
        self.connection_timeout_seconds = connection_timeout_seconds
        self._connection_slots = threading.BoundedSemaphore(max_connections)
        # Observability only: nothing in the serving path branches on these. They exist because a
        # slot becoming free is otherwise UNOBSERVABLE from outside.
        #
        # A client cannot detect it: the socket is closed inside `process_request_thread`, and the
        # slot is released in that method's `finally`, strictly afterwards. So a peer that sees its
        # connection close and immediately reconnects can still be refused -- correctly. Anything
        # that needs to know a slot is actually available has to wait on the release itself, and a
        # sleep would only turn a deterministic ordering into a probabilistic one.
        self._released = threading.Condition()
        self._release_count = 0
        super().__init__(server_address, request_handler)

    @property
    def release_count(self) -> int:
        """How many connection slots have been released since the server started."""
        with self._released:
            return self._release_count

    def wait_for_release(self, *, at_least: int, timeout: float) -> bool:
        """Block until ``release_count`` reaches ``at_least``. False on timeout.

        ``timeout`` bounds the wait so a broken server fails the caller instead of hanging; it is
        not what the caller is waiting ON, which is the release itself.
        """
        deadline = time.monotonic() + timeout
        with self._released:
            while self._release_count < at_least:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._released.wait(remaining)
            return True

    def _note_release(self) -> None:
        with self._released:
            self._release_count += 1
            self._released.notify_all()

    def get_request(self) -> tuple[socket.socket, object]:
        request, client_address = super().get_request()
        request.settimeout(self.connection_timeout_seconds)
        return request, client_address

    def process_request(self, request: socket.socket, client_address: object) -> None:
        if not self._connection_slots.acquire(blocking=False):
            self._reject_overloaded(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._connection_slots.release()
            self._note_release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: object) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()
            self._note_release()

    def _reject_overloaded(self, request: socket.socket) -> None:
        try:
            request.sendall(_OVERLOADED_RESPONSE)
        except OSError:
            pass
        finally:
            self.shutdown_request(request)

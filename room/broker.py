"""The trusted credential broker: the agent asks, the broker spends, the key never moves.

**What this replaces.** The existing gateway (:mod:`room.inference_gateway`) forwards one unchanged
request to one allowlisted route, and the agent supplies the key in a header. That is a coherent
design when the agent legitimately holds its own credential -- but it means the key is in the
agent container's environment, and an agent is code written by a stranger. ``env``,
``/proc/self/environ``, ``argv``, a crash dump, an exception body: any one and the credential is
gone.

The inversion here is the whole point. **The decrypted keys live in the trusted runner's memory and
are never handed out.** The agent gets a *capability* -- an unguessable, short-lived token bound to
one job and one role -- and asks the broker to perform a named, reviewed operation. The broker
injects the right key server-side, calls a fixed route, and returns provider data. A capability is
worth exactly the calls it has left, and it is worthless the moment the job ends.

**Why the base image still names no subnet.** The broker is a frame: capabilities, roles, quotas,
recording, refusal. The *operations* -- what "web-search" means, which host it reaches, what a valid
input looks like -- are declared by the loaded profile as :class:`OperationSpec` values. So the base
enforces the rules without knowing a single provider, and a second lane needs no change here.

**The two roles never mix.** An agent capability cannot invoke an evaluator operation. If it
could, an agent could ask the judge to grade its own work, or spend the evaluator's reserved quota.
That is enforced twice on purpose -- by role comparison, and by evaluator operations not being
exposed on the HTTP surface at all -- because a single check protecting something this valuable is a
single check away from being wrong.

**Every refusal is the same refusal.** A caller that could tell "unknown operation" from "wrong
role" from "quota exhausted" from "expired capability" could map the room's state one probe at a
time. It cannot.
"""

from __future__ import annotations

import json
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlsplit

from room.bounded_http import BoundedThreadingHTTPServer

#: Capability tokens are opaque and fixed-shape, so a parser that accepted anything else would be a
#: place to smuggle structure into a log line or a path.
CAPABILITY_PREFIX = "kcap_"
CAPABILITY_RE = re.compile(r"^kcap_[0-9a-f]{32}$")

CAPABILITY_HEADER = "x-kata-capability"

ROLE_AGENT = "agent"
ROLE_EVALUATOR = "evaluator"
ROLES = (ROLE_AGENT, ROLE_EVALUATOR)

#: The single refusal. See the module docstring: a specific one is a probe oracle.
DENIED = "the broker refused the request"

#: One request and one response. Bounded on BYTES before anything is parsed, because decoding a
#: 500 MB document is a denial of service while it is still being decoded.
MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

DEFAULT_CAPABILITY_TTL_SECONDS = 900.0


class BrokerDenied(Exception):
    """The request was refused. The message never names state the caller may not observe."""


class BrokerConfigurationError(Exception):
    """A profile declared an operation set the broker cannot serve."""


@dataclass(frozen=True)
class OperationSpec:
    """One reviewed provider operation, declared by the loaded profile.

    ``handler`` receives ``(api_key, payload)`` and returns a JSON-able dict. It is the only place a
    key is touched, and it is the profile's job to make sure the route, host, model and actor id are
    *fixed inside it* rather than read out of ``payload``. The broker enforces that a caller may
    invoke the operation at all; it cannot enforce that a badly-written handler ignores its input.
    """

    name: str
    role: str
    provider: str
    handler: object
    #: Per-capability call ceiling for this operation.
    max_calls: int = 32
    #: Evaluator operations are never reachable over HTTP, only in-process. Defence in depth: the
    #: role check below already refuses them, and this means a leaked evaluator token would still
    #: not be spendable by anything that can only reach the network.
    http_exposed: bool = True

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", self.name or ""):
            raise BrokerConfigurationError("operation names must be lowercase, digits or dashes")
        if self.role not in ROLES:
            raise BrokerConfigurationError(f"operation {self.name!r} has an unknown role")
        if not callable(self.handler):
            raise BrokerConfigurationError(f"operation {self.name!r} has no handler")
        if self.max_calls <= 0:
            raise BrokerConfigurationError(f"operation {self.name!r} has no calls")
        if self.role == ROLE_EVALUATOR and self.http_exposed:
            raise BrokerConfigurationError(
                f"operation {self.name!r} is an evaluator operation and must not be exposed over "
                f"HTTP; the untrusted agent reaches the broker only over the network"
            )


@dataclass(frozen=True)
class Capability:
    """A short-lived grant: one job, one role, until T."""

    token: str
    job_id: str
    role: str
    expires_at: float

    def as_public(self) -> dict:
        """What a caller is told. Note there is no key and no provider name here."""
        return {"capability": self.token, "role": self.role, "expires_at": self.expires_at}

    def __repr__(self) -> str:
        # A capability is not a secret the way a key is, but it IS bearer authority for the job's
        # remaining quota, so it does not belong in a traceback either.
        return f"Capability(job_id={self.job_id!r}, role={self.role!r}, token=<redacted>)"

    __str__ = __repr__


@dataclass
class _Job:
    """One contestant's live broker state. Everything here dies when the job ends."""

    job_id: str
    #: provider -> api_key. The ONLY place these exist outside the sealing parser.
    credentials: dict
    contestant: str = ""
    capabilities: dict = field(default_factory=dict)
    #: (token, operation) -> count
    calls: dict = field(default_factory=dict)
    #: Append-only observations: provider, phase, task, status. Never content, never a key.
    records: list = field(default_factory=list)

    def __repr__(self) -> str:
        return f"_Job(job_id={self.job_id!r}, providers={sorted(self.credentials)!r})"

    __str__ = __repr__


class Broker:
    """Holds decrypted keys for live jobs and performs reviewed operations on their behalf.

    One instance serves the runner process. Jobs are opened and closed around each contestant, so
    two contestants' credentials never coexist longer than the overlap of their runs, and a
    capability from a finished job is dead rather than merely out of quota.
    """

    def __init__(self, operations, *,
                 capability_ttl_seconds: float = DEFAULT_CAPABILITY_TTL_SECONDS, clock=None):
        specs = tuple(operations)
        names = [spec.name for spec in specs]
        if len(set(names)) != len(names):
            raise BrokerConfigurationError("operation names must be unique")
        self._operations = {spec.name: spec for spec in specs}
        self._capability_ttl_seconds = capability_ttl_seconds
        self._clock = clock
        # Billing is a read-modify-write over shared counters and the HTTP server is threaded, so
        # one lock around the whole dispatch is the version of correct that is obviously correct.
        self._lock = threading.Lock()
        self._jobs: dict[str, _Job] = {}
        self._tokens: dict[str, str] = {}   # token -> job_id

    def _now(self) -> float:
        return float(self._clock()) if callable(self._clock) else time.monotonic()

    # ---- job lifecycle ---------------------------------------------------------------------

    def open_job(self, job_id: str, credentials: dict, *, contestant: str = "") -> None:
        """Register one contestant's decrypted keys for the duration of its run."""
        if not re.fullmatch(r"[0-9a-f]{16,64}", job_id or ""):
            raise BrokerConfigurationError("job id must be 16..64 lowercase hexadecimal characters")
        with self._lock:
            if job_id in self._jobs:
                raise BrokerConfigurationError(f"job {job_id} is already open")
            self._jobs[job_id] = _Job(
                job_id=job_id, credentials=dict(credentials), contestant=contestant
            )

    def close_job(self, job_id: str) -> dict:
        """End the job: every capability dies and the keys are overwritten, then dropped.

        Returns the job's recorded provider statuses -- the one thing that outlives it, and it
        carries no key and no content.

        Overwriting before dropping is not superstition about the garbage collector; it is that the
        string objects may live in a heap page that ends up in a core dump, and a dump taken after a
        job is a dump that should not still contain that contestant's credentials.
        """
        with self._lock:
            job = self._jobs.pop(job_id, None)
            if job is None:
                return {"records": []}
            for token in list(job.capabilities):
                self._tokens.pop(token, None)
            job.capabilities.clear()
            for provider in list(job.credentials):
                job.credentials[provider] = ""
            job.credentials.clear()
            return {"records": list(job.records)}

    def close(self) -> None:
        """End every job. Used at batch completion, and on the way out of an error."""
        for job_id in list(self._jobs):
            self.close_job(job_id)

    # ---- capabilities -----------------------------------------------------------------------

    def issue(self, job_id: str, *, role: str) -> Capability:
        """Mint one capability for a live job.

        The token is random rather than derived from the job's identity: a derived token is
        guessable by anyone who knows the inputs, and the agent knows most of them.
        """
        if role not in ROLES:
            raise BrokerConfigurationError(f"unknown role {role!r}")
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise BrokerConfigurationError(f"job {job_id} is not open")
            token = CAPABILITY_PREFIX + secrets.token_hex(16)
            capability = Capability(
                token=token, job_id=job_id, role=role,
                expires_at=self._now() + self._capability_ttl_seconds,
            )
            job.capabilities[token] = capability
            self._tokens[token] = job_id
            return capability

    def _authorize(self, token: object) -> tuple[_Job, Capability]:
        """Validate a presented token. Every refusal is deliberately identical."""
        if not isinstance(token, str) or not CAPABILITY_RE.fullmatch(token):
            raise BrokerDenied(DENIED)
        job_id = self._tokens.get(token)
        if job_id is None:
            raise BrokerDenied(DENIED)
        job = self._jobs.get(job_id)
        if job is None:
            raise BrokerDenied(DENIED)
        capability = job.capabilities.get(token)
        if capability is None or self._now() > capability.expires_at:
            raise BrokerDenied(DENIED)
        return job, capability

    # ---- dispatch ----------------------------------------------------------------------------

    def dispatch(self, token: object, operation: object, payload: object, *,
                 over_http: bool = False) -> dict:
        """Authorize one operation, spend the job's key on it, and return provider data.

        The order matters. Authorization and the role check come first, so an agent probing for
        evaluator operations never reaches a handler and never spends anything. Billing happens
        BEFORE the call, because the provider charges whether or not the room survives to record it.
        """
        with self._lock:
            job, capability = self._authorize(token)
            if not isinstance(operation, str):
                raise BrokerDenied(DENIED)
            spec = self._operations.get(operation)
            if spec is None:
                raise BrokerDenied(DENIED)
            # THE role check. An agent capability may not invoke an evaluator operation: it could
            # otherwise ask the judge to grade its own work, or drain the evaluator's quota.
            if spec.role != capability.role:
                raise BrokerDenied(DENIED)
            if over_http and not spec.http_exposed:
                raise BrokerDenied(DENIED)
            if not isinstance(payload, dict):
                raise BrokerDenied(DENIED)

            key = (token, spec.name)
            if job.calls.get(key, 0) >= spec.max_calls:
                raise BrokerDenied(DENIED)
            api_key = job.credentials.get(spec.provider)
            if not api_key:
                raise BrokerDenied(DENIED)
            job.calls[key] = job.calls.get(key, 0) + 1
            task_id = payload.get("task_id")
            handler = spec.handler

        # OUTSIDE the lock: a provider call takes seconds, and holding the lock across it would
        # serialise every other capability in the room behind one slow upstream.
        status = "error"
        try:
            result = handler(api_key, payload)
            status = "ok"
        except BrokerDenied:
            self._record(job, spec, task_id, "denied")
            raise
        except Exception as exc:  # noqa: BLE001 - a provider fault must not leak its internals
            self._record(job, spec, task_id, _classify(exc))
            # The message is fixed. A provider error body can contain the request, and the request
            # was built with the key in a header.
            raise BrokerDenied(DENIED) from exc
        self._record(job, spec, task_id, status)
        if not isinstance(result, dict):
            raise BrokerDenied(DENIED)
        return result

    def _record(self, job: _Job, spec: OperationSpec, task_id: object, status: str) -> None:
        """Provider, phase, task and status. Never content, never a key."""
        with self._lock:
            job.records.append({
                "contestant": job.contestant,
                "task_id": str(task_id) if isinstance(task_id, (str, int)) else "",
                "provider": spec.provider,
                "phase": spec.role,
                "operation": spec.name,
                "status": status,
            })

    def quota(self, token: object) -> dict:
        """What this capability has left, per operation it may actually invoke.

        Free, and it consumes nothing: an agent that cannot see its own quota either wastes it or
        hoards it, and both make the measurement about planning rather than answer quality.

        It reports only the operations this capability's ROLE may invoke -- otherwise the free,
        always-available operation would be an inventory of the evaluator's surface.
        """
        with self._lock:
            job, capability = self._authorize(token)
            return {
                "role": capability.role,
                "operations": {
                    spec.name: {
                        "used": job.calls.get((capability.token, spec.name), 0),
                        "max_calls": spec.max_calls,
                        "remaining": max(
                            0, spec.max_calls - job.calls.get((capability.token, spec.name), 0)
                        ),
                    }
                    for spec in self._operations.values()
                    if spec.role == capability.role
                },
            }

    def records(self, job_id: str) -> list:
        with self._lock:
            job = self._jobs.get(job_id)
            return list(job.records) if job else []


def _classify(exc: Exception) -> str:
    """A coarse provider-status bucket for the record. Derived from the exception TYPE and, for an
    HTTP error, its numeric code -- never from its message, which can quote the request."""
    code = getattr(exc, "code", None)
    if isinstance(code, int):
        if 200 <= code < 300:
            return "ok"
        if code == 402:
            return "payment_required"
        if code in (401, 403):
            return "unauthorized"
        if code == 429:
            return "rate_limited"
        if 400 <= code < 500:
            return "bad_request"
        return "provider_error"
    return "unreachable"


# ---- the HTTP surface the untrusted agent reaches ------------------------------------------------

class BrokerHandler(BaseHTTPRequestHandler):
    """``POST /v1/op/<name>`` and ``GET /v1/quota``. Nothing else exists."""

    protocol_version = "HTTP/1.1"
    broker: Broker | None = None

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's interface
        path = urlsplit(self.path).path
        if path == "/healthz":
            self._send(200, {"status": "ok", "service": "kata-broker"})
            return
        if path == "/v1/quota":
            try:
                self._send(200, self.broker.quota(self._capability()))
            except BrokerDenied:
                self._send(403, {"error": DENIED})
            return
        self._send(404, {"error": DENIED})

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        body = self._read_body()
        if body is None:
            # Oversized. Refused rather than treated as an empty payload: silently dropping the
            # arguments would run the operation -- and bill it -- with nothing in it.
            self._send(403, {"error": DENIED})
            return
        if not path.startswith("/v1/op/"):
            self._send(404, {"error": DENIED})
            return
        operation = path[len("/v1/op/"):]
        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except (UnicodeDecodeError, ValueError):
            self._send(400, {"error": DENIED})
            return
        try:
            result = self.broker.dispatch(
                self._capability(), operation, payload, over_http=True
            )
        except BrokerDenied:
            # 403 for every refusal, whatever the cause. See the module docstring.
            self._send(403, {"error": DENIED})
            return
        self._send(200, result)

    def _capability(self) -> str:
        return (self.headers.get(CAPABILITY_HEADER) or "").strip()

    def _read_body(self) -> bytes | None:
        """The request body, or ``None`` if it announced more than the ceiling.

        Bounded on the announced LENGTH before a single byte is buffered: reading 500 MB in order
        to discover it is too large is the denial of service the limit exists to prevent.
        """
        if self.headers.get("Transfer-Encoding"):
            return None
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) > 1:
            return None
        try:
            length = int(lengths[0]) if lengths else 0
        except ValueError:
            return None
        if length <= 0:
            return b"" if length == 0 else None
        if length > MAX_REQUEST_BYTES:
            return None
        return self.rfile.read(length)

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")[:MAX_RESPONSE_BYTES]
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        # A request body carries a miner's query and a response carries provider data. Neither
        # belongs in the room's log, and the default handler logs the request line.
        return


def build_broker_server(broker: Broker, host: str, port: int) -> BoundedThreadingHTTPServer:
    """An HTTP server bound to ``broker``, ready for ``serve_forever`` on a thread.

    In-process rather than a subprocess, and that is the crux of the whole design: the decrypted
    keys live in the runner's memory, and a subprocess could not reach them without being handed
    them -- which is the very thing being removed.
    """
    handler = type("_BoundBrokerHandler", (BrokerHandler,), {"broker": broker})
    return BoundedThreadingHTTPServer((host, port), handler)

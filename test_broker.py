"""The trusted broker, against the four properties an untrusted agent must not be able to break.

The agent in these tests is treated as hostile, because it is: it is code written by a stranger,
running with a capability, trying to get more than the capability grants. Every test names the thing
it would achieve if it worked.

The provider names are ``alpha``/``beta``/``gamma``/``delta`` on purpose -- the base image enforces
whatever set a profile declares and knows no lane's providers.
"""

from __future__ import annotations

import json
import socket
import threading
import urllib.error
import urllib.request

import pytest

from room.broker import (
    CAPABILITY_HEADER,
    CAPABILITY_RE,
    DENIED,
    MAX_REQUEST_BYTES,
    ROLE_AGENT,
    ROLE_EVALUATOR,
    Broker,
    BrokerConfigurationError,
    BrokerDenied,
    OperationSpec,
    build_broker_server,
)

KEY_ALPHA = "alpha-secret-key-0123456789abcdef"
KEY_DELTA = "delta-secret-key-0123456789abcdef"
JOB = "0123456789abcdef"

#: Every key that exists in these tests. Used to assert none of them ever comes back out.
ALL_KEYS = (KEY_ALPHA, KEY_DELTA)


def _echo(api_key: str, payload: dict) -> dict:
    """A handler that returns what it was given -- the most hostile plausible handler.

    If the broker's containment depends on handlers being careful, it is not containment. This one
    is careless on purpose, so the tests below measure the broker rather than the handler.
    """
    return {"payload": payload}


def _leaky(api_key: str, payload: dict) -> dict:
    """A handler that tries to hand the key straight back."""
    return {"api_key": api_key}


def _boom(api_key: str, payload: dict) -> dict:
    """A handler whose exception message quotes the key, the way a real provider error body would
    quote the request it was built from."""
    raise RuntimeError(f"upstream rejected Authorization: Bearer {api_key}")


def _operations(handler=_echo, evaluator_handler=_echo):
    return [
        OperationSpec(name="web-search", role=ROLE_AGENT, provider="alpha",
                      handler=handler, max_calls=3),
        OperationSpec(name="final-summary", role=ROLE_AGENT, provider="alpha",
                      handler=handler, max_calls=2),
        OperationSpec(name="judge", role=ROLE_EVALUATOR, provider="delta",
                      handler=evaluator_handler, max_calls=5, http_exposed=False),
    ]


@pytest.fixture
def broker():
    instance = Broker(_operations())
    instance.open_job(JOB, {"alpha": KEY_ALPHA, "delta": KEY_DELTA}, contestant="king")
    yield instance
    instance.close()


@pytest.fixture
def agent(broker):
    return broker.issue(JOB, role=ROLE_AGENT).token


@pytest.fixture
def evaluator(broker):
    return broker.issue(JOB, role=ROLE_EVALUATOR).token


# ---- GATE: a key never leaves the broker --------------------------------------------------------

def test_a_successful_call_returns_provider_data_and_no_key(broker, agent):
    result = broker.dispatch(agent, "web-search", {"query": "x", "task_id": "t1"})
    assert KEY_ALPHA not in json.dumps(result)


def test_a_handler_that_hands_the_key_back_is_the_only_way_it_escapes(broker):
    """Stated plainly because it bounds the claim honestly: the broker cannot stop a handler that
    deliberately returns the key. What it CAN do is be the only place a handler ever sees one, so
    the whole surface is the reviewed operation table rather than every agent ever submitted."""
    leaky = Broker(_operations(handler=_leaky))
    leaky.open_job(JOB, {"alpha": KEY_ALPHA, "delta": KEY_DELTA})
    token = leaky.issue(JOB, role=ROLE_AGENT).token
    assert leaky.dispatch(token, "web-search", {})["api_key"] == KEY_ALPHA
    leaky.close()


def test_a_provider_error_body_never_reaches_the_caller(broker):
    """A real provider quotes the request it rejected, and the request was built with the key in an
    Authorization header. Relaying that verbatim -- which the old gateway did -- hands it back."""
    exploding = Broker(_operations(handler=_boom))
    exploding.open_job(JOB, {"alpha": KEY_ALPHA, "delta": KEY_DELTA})
    token = exploding.issue(JOB, role=ROLE_AGENT).token
    with pytest.raises(BrokerDenied) as raised:
        exploding.dispatch(token, "web-search", {})
    assert KEY_ALPHA not in str(raised.value)
    assert str(raised.value) == DENIED
    exploding.close()


def test_the_recorded_provider_statuses_carry_no_key(broker, agent):
    broker.dispatch(agent, "web-search", {"query": "x", "task_id": "t1"})
    records = broker.records(JOB)
    assert records and all(key not in json.dumps(records) for key in ALL_KEYS)
    assert records[0]["provider"] == "alpha"
    assert records[0]["phase"] == ROLE_AGENT
    assert records[0]["status"] == "ok"


def test_the_quota_reply_carries_no_key(broker, agent):
    assert all(key not in json.dumps(broker.quota(agent)) for key in ALL_KEYS)


def test_no_object_renders_a_key_in_a_traceback(broker, agent):
    """A repr that prints a secret is a secret in every log line that catches an exception."""
    capability = broker.issue(JOB, role=ROLE_AGENT)
    for rendered in (repr(capability), str(capability), f"{capability}"):
        assert "kcap_" not in rendered
    assert all(key not in repr(broker._jobs[JOB]) for key in ALL_KEYS)
    assert all(key not in str(broker._jobs[JOB]) for key in ALL_KEYS)


# ---- GATE: an agent capability cannot reach an evaluator operation ---

def test_an_agent_capability_cannot_invoke_an_evaluator_operation(broker, agent):
    """It could otherwise ask the judge to grade its own work."""
    with pytest.raises(BrokerDenied):
        broker.dispatch(agent, "judge", {"messages": []})


def test_an_agent_capability_cannot_spend_the_evaluator_credential(broker, agent):
    """The delta key funds verification. An agent that could drain it would starve the check that
    is about to be run on its own answer, and then be un-checkable."""
    broker.dispatch(agent, "web-search", {})
    for record in broker.records(JOB):
        assert record["provider"] != "delta"


def test_the_evaluator_operation_is_not_on_the_http_surface_at_all(broker, evaluator):
    """Defence in depth. The role check already refuses an agent; this means even a LEAKED evaluator
    token is unspendable by anything that can only reach the network."""
    assert broker.dispatch(evaluator, "judge", {}, over_http=False)
    with pytest.raises(BrokerDenied):
        broker.dispatch(evaluator, "judge", {}, over_http=True)


def test_declaring_an_evaluator_operation_on_the_http_surface_is_refused():
    """Caught when the profile is loaded rather than when an agent finds it."""
    with pytest.raises(BrokerConfigurationError, match="must not be exposed over HTTP"):
        OperationSpec(name="judge", role=ROLE_EVALUATOR, provider="delta",
                      handler=_echo, http_exposed=True)


def test_quota_lists_only_the_operations_this_role_may_invoke(broker, agent):
    """A free, always-available operation that enumerated the evaluator's surface would be an
    inventory hand-delivered to whoever wants to attack it."""
    assert set(broker.quota(agent)["operations"]) == {"web-search", "final-summary"}


# ---- GATE: an agent cannot select a host, a model or a credential ---

def test_the_credential_comes_from_the_operation_not_the_payload(broker, agent):
    """The whole point of naming an operation instead of a URL. Whatever the agent puts in the
    payload, ``web-search`` spends ``alpha`` -- there is no field it can set to spend ``delta``."""
    hostile = {"provider": "delta", "api_key": "override", "url": "https://evil.test",
               "model": "an-expensive-one", "role": ROLE_EVALUATOR}
    broker.dispatch(agent, "web-search", hostile)
    assert [record["provider"] for record in broker.records(JOB)] == ["alpha"]


def test_an_unknown_operation_is_refused(broker, agent):
    for name in ("", "judge ", "web-search ", "../judge", "WEB-SEARCH", "web-search\n"):
        with pytest.raises(BrokerDenied):
            broker.dispatch(agent, name, {})


def test_a_non_object_payload_is_refused(broker, agent):
    for payload in ("string", 5, None, ["list"]):
        with pytest.raises(BrokerDenied):
            broker.dispatch(agent, "web-search", payload)


# ---- GATE: quotas are the broker's, not the agent's self-report ---

def test_the_quota_is_enforced_per_operation(broker, agent):
    for _ in range(3):
        broker.dispatch(agent, "web-search", {})
    with pytest.raises(BrokerDenied):
        broker.dispatch(agent, "web-search", {})
    # A different operation has its own allowance and is unaffected.
    assert broker.dispatch(agent, "final-summary", {})


def test_an_agent_cannot_talk_its_quota_back_up(broker, agent):
    """Nothing in the payload is consulted when counting. If usage were taken from what the agent
    reported, the honest contestant would be the only one with a limit."""
    for _ in range(3):
        broker.dispatch(agent, "web-search", {"used": 0, "remaining": 999, "max_calls": 10 ** 9})
    with pytest.raises(BrokerDenied):
        broker.dispatch(agent, "web-search", {"used": 0})


def test_a_second_capability_does_not_double_the_allowance(broker, agent):
    """Each capability gets the operation's allowance, so if an agent could MINT one it could
    refresh its quota. It cannot: minting is the room's, taken before the agent starts.

    This test records the consequence honestly -- two capabilities really do carry two allowances --
    so that the containment rests on the agent having no way to obtain a second, not on a belief
    that a second would be worthless.
    """
    assert not hasattr(broker, "issue_from_capability")
    second = broker.issue(JOB, role=ROLE_AGENT).token
    for _ in range(3):
        broker.dispatch(agent, "web-search", {})
    assert broker.dispatch(second, "web-search", {})


def test_both_contestants_get_the_same_allowance(broker):
    """Equal quotas is a fairness property, not a cost control: a duel where one side got more
    calls would measure the room's bookkeeping rather than the two agents."""
    other = "fedcba9876543210"
    broker.open_job(other, {"alpha": KEY_ALPHA, "delta": KEY_DELTA}, contestant="challenger")
    king = broker.quota(broker.issue(JOB, role=ROLE_AGENT).token)
    challenger = broker.quota(broker.issue(other, role=ROLE_AGENT).token)
    assert king == challenger


def test_a_forged_or_malformed_capability_is_refused(broker):
    for token in ("", "kcap_", "kcap_" + "z" * 32, "kcap_" + "0" * 31, "sn22cap_" + "0" * 32,
                  None, 5, "kcap_" + "0" * 32):
        with pytest.raises(BrokerDenied):
            broker.dispatch(token, "web-search", {})


def test_a_capability_expires(broker):
    now = [1000.0]
    timed = Broker(_operations(), capability_ttl_seconds=60.0, clock=lambda: now[0])
    timed.open_job(JOB, {"alpha": KEY_ALPHA, "delta": KEY_DELTA})
    token = timed.issue(JOB, role=ROLE_AGENT).token
    assert timed.dispatch(token, "web-search", {})
    now[0] += 61.0
    with pytest.raises(BrokerDenied):
        timed.dispatch(token, "web-search", {})
    timed.close()


# ---- the job ends, and everything with it ---

def test_closing_a_job_kills_its_capabilities(broker, agent):
    """A capability outliving its job lets a slow agent keep spending after being scored."""
    broker.close_job(JOB)
    with pytest.raises(BrokerDenied):
        broker.dispatch(agent, "web-search", {})


def test_closing_a_job_clears_the_keys(broker, agent):
    """Overwritten before being dropped: a core dump taken after a job should not still contain
    that contestant's credentials."""
    job = broker._jobs[JOB]
    broker.close_job(JOB)
    assert job.credentials == {}
    assert JOB not in broker._jobs


def test_closing_a_job_returns_its_provider_record(broker, agent):
    broker.dispatch(agent, "web-search", {"task_id": "t7"})
    records = broker.close_job(JOB)["records"]
    assert [record["task_id"] for record in records] == ["t7"]


def test_two_contestants_never_share_a_capability(broker):
    other = "fedcba9876543210"
    broker.open_job(other, {"alpha": "other-key-0123456789abcdef", "delta": KEY_DELTA})
    king_token = broker.issue(JOB, role=ROLE_AGENT).token
    broker.close_job(JOB)
    # The other job is untouched by its neighbour ending.
    assert broker.dispatch(broker.issue(other, role=ROLE_AGENT).token, "web-search", {})
    with pytest.raises(BrokerDenied):
        broker.dispatch(king_token, "web-search", {})


def test_a_capability_token_is_unguessable(broker):
    """Derived from the job's identity it would be guessable by anyone who knows the inputs, and the
    agent knows most of them."""
    tokens = {broker.issue(JOB, role=ROLE_AGENT).token for _ in range(50)}
    assert len(tokens) == 50
    assert all(CAPABILITY_RE.fullmatch(token) for token in tokens)


# ---- over real HTTP, which is the only way the agent reaches any of this ---

@pytest.fixture
def served(broker):
    server = build_broker_server(broker, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    yield f"http://{host}:{port}"
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def _call(base: str, path: str, token: str, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        f"{base}{path}", data=data, method="POST" if data is not None else "GET",
        headers={"content-type": "application/json", CAPABILITY_HEADER: token})
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.status, json.loads(response.read().decode())


def test_the_agent_can_perform_its_own_operations_over_http(served, agent):
    status, body = _call(served, "/v1/op/web-search", agent, {"query": "x"})
    assert status == 200
    assert body["payload"]["query"] == "x"


def test_the_agent_cannot_reach_an_evaluator_operation_over_http(served, agent, evaluator):
    """Both with its own capability and with the evaluator's, in case one ever leaks."""
    for token in (agent, evaluator):
        with pytest.raises(urllib.error.HTTPError) as raised:
            _call(served, "/v1/op/judge", token, {})
        assert raised.value.code == 403
        assert KEY_DELTA not in raised.value.read().decode()


def test_every_http_refusal_is_the_same_refusal(served, agent):
    """Unknown operation, wrong role, exhausted quota, forged token: a caller that could tell them
    apart could map the room's state one probe at a time."""
    bodies = set()
    for token, operation in ((agent, "nope"), (agent, "judge"),
                             ("kcap_" + "0" * 32, "web-search"), ("garbage", "web-search")):
        with pytest.raises(urllib.error.HTTPError) as raised:
            _call(served, f"/v1/op/{operation}", token, {})
        assert raised.value.code == 403
        bodies.add(raised.value.read().decode())
    for _ in range(3):
        _call(served, "/v1/op/web-search", agent, {})
    with pytest.raises(urllib.error.HTTPError) as raised:
        _call(served, "/v1/op/web-search", agent, {})
    bodies.add(raised.value.read().decode())
    assert len(bodies) == 1, f"refusals are distinguishable: {bodies}"


def test_quota_is_readable_over_http_and_costs_nothing(served, agent):
    _status, before = _call(served, "/v1/quota", agent)
    _call(served, "/v1/op/web-search", agent, {})
    _status, after = _call(served, "/v1/quota", agent)
    assert before["operations"]["web-search"]["used"] == 0
    assert after["operations"]["web-search"]["used"] == 1


def test_nothing_else_exists_on_the_http_surface(served, agent):
    for path in ("/", "/v1", "/v1/op", "/healthz/../v1/op/judge", "/v1/credentials"):
        try:
            status, _body = _call(served, path, agent)
        except urllib.error.HTTPError as error:
            assert error.code in (403, 404, 501), path
        else:
            assert status == 200 and path == "/healthz", path


def test_an_oversized_request_is_not_buffered(served, agent):
    """Bounded on the ANNOUNCED length before a byte is buffered: decoding a 500 MB document is a
    denial of service while it is still being decoded.

    Sent on a raw socket, announcing an oversized body and then never sending one. That is what
    makes this a test of *not buffering* rather than of the limit alone -- a server that read the
    body before checking would block here waiting for bytes that never arrive, and the recv below
    would time out instead of returning a refusal.

    It also removes a race that failed on CI and passed locally. The previous version used
    ``urllib`` to POST a real 512 KB body. The server refuses on the header and closes without
    draining, which is exactly right, so the client was left writing into a closed socket: whether
    it finished before the RST arrived depended on socket buffer sizes, and on a runner it did not.
    The failure was ``URLError: [Errno 32] Broken pipe`` -- the correct refusal never read.
    """
    host, port = served.removeprefix("http://").split(":")
    with socket.create_connection((host, int(port)), timeout=10) as client:
        client.sendall(
            b"POST /v1/op/web-search HTTP/1.1\r\n"
            b"Host: room\r\n"
            b"Content-Type: application/json\r\n"
            + CAPABILITY_HEADER.encode() + b": " + agent.encode() + b"\r\n"
            + b"Content-Length: " + str(MAX_REQUEST_BYTES * 2).encode() + b"\r\n"
            b"Connection: close\r\n\r\n"
        )
        # Deliberately no body.
        client.settimeout(10)
        response = b""
        while chunk := client.recv(4096):
            response += chunk
    assert b" 403 " in response.split(b"\r\n", 1)[0], response[:200]

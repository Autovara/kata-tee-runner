# `kata-tee-runner` public surfaces

The sealed room's contract with three independent parties: the validator that invokes it, the miner
who seals credentials to it, and the attestation verifier that checks what ran. None of them can be
updated in lockstep with this repository, so every entry below is externally versioned.

## Network endpoints

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `GET /health` | public | liveness; `{"ok":true}` |
| `GET /pubkey` | public | sealing public key **and the attested measurement** |
| `POST /run` | signed HMAC, short-lived | execute one job and return a quote-bound report |
| `POST /pull-test` | signed, diagnostics-gated | registry pull check; off in production |

`/pubkey`'s `measurement` is what a miner's sealing tool verifies before encrypting anything. It is
the single value standing between a miner and sealing keys to a room somebody else controls.

Internal, never published outside the sealed Docker network:

| Endpoint | Purpose |
| --- | --- |
| `GET /healthz` | inference gateway / broker liveness |
| `POST /v1/quota` | broker capability quota |

## CLI surfaces

| Tool | Purpose |
| --- | --- |
| `kata_seal.py` | seal ONE credential to a bundle (v1) |
| `kata_seal_multi.py` | seal a NAMED SET of credentials to a bundle (v2) |

`kata_seal_multi.py` flags — a documented flag the tool does not accept strands a miner at the one
step where they are handling real credentials:

`--room`, `--credential-profile`, `--providers`, `--key-env`, `--key-file`, `--bundle`,
`--measurement`, `--out`, `--no-verify`

## Environment variables

Room: `KATA_ROOM_AUTH_SECRET`, `KATA_ROOM_ENABLE_DIAGNOSTICS`, `KATA_ROOM_MAX_REQUEST_BYTES`,
`KATA_ROOM_MAX_REQUEST_LIFETIME_SECONDS`, `KATA_ROOM_MAX_CLOCK_SKEW_SECONDS`,
`KATA_ROOM_MAX_COMPRESSED_BUNDLE_BYTES`, `KATA_ROOM_MAX_EXTRACTED_BUNDLE_BYTES`,
`KATA_ROOM_MAX_BUNDLE_FILES`, `KATA_TEE_PROFILE`, `KATA_TEE_AGENT_EXECUTION_TIMEOUT_SECONDS`

Inference gateway: `KATA_INFERENCE_GATEWAY_HOST`, `_PORT`, `_TIMEOUT`, `_MAX_ATTEMPTS`,
`_RETRY_BASE_SECONDS`, `_PROVIDER_ROUTES_JSON`, `KATA_INFERENCE_STATUS_DIR`

Registry: `GHCR_USER`, `GHCR_TOKEN` (read-only in production)

## Python surfaces used by subnet profiles

`room.bounded_http.BoundedThreadingHTTPServer` — connection-bounded server. Public members:
`max_connections`, `connection_timeout_seconds`, `release_count`, `wait_for_release(at_least=, timeout=)`.

`release_count` / `wait_for_release` are **observability only**; nothing in the serving path branches
on them. They exist because a connection slot becoming free is otherwise unobservable from outside:
the socket closes inside `process_request_thread` and the slot is released in that method's
`finally`, strictly afterwards. A peer that reconnects on seeing its socket close can still be
refused, correctly.

## Host requirements

`/var/run/dstack.sock` (quote and key derivation) and `/var/run/docker.sock` (running the agent
container inside the room).

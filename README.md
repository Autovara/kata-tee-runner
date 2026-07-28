# kata-tee-runner — the generic sealed-room TEE runner

A "sealed room" (a TEE, or trusted execution environment) is a locked container running on hardware
that can prove what is inside it. This room runs a miner's untrusted agent, lets that agent pay for its
own inference with the miner's sealed API key, and returns a hardware **attestation** that binds the
answer to the exact project and challenge. It seals the miner's provider credential to that miner's exact
submission bundle, runs the agent behind an in-room **miner-funded inference gateway** with no other
internet, and never exposes the plaintext key: the maintainer and validators handle only ciphertext,
and neither pays for inference.

This repo is the **subnet-blind** base. Any subnet reuses it by shipping a small profile, so the room
itself names no subnet. For the SN60 profile and the miner-facing submission guide, see
[kata-sn60](https://github.com/Autovara/kata-sn60).

```
room/                 the generic core
  server.py           /health /pubkey /run; signed diagnostic /pull-test only when enabled
  sealing.py          encrypted miner-provider credential handling
  inference_gateway.py the miner-funded gateway HTTP handler (signed per-job routes)
  inference_network.py starts the gateway, the sealed internal network, and registry login
  attest.py           canonical() + bind_and_quote() (binds report + bundle hash + provenance)
  dstack.py           the confidential-VM client
  profile.py          the TeeJobProfile seam a subnet implements
kata_seal.py verify_run.py                  miner/operator tools
Dockerfile.base       the base image (a subnet builds FROM it)
pyproject.toml        runtime and development dependencies
```

## The profile seam
A subnet implements `room.profile.TeeJobProfile` (`fixture_project`, `image(project_key)`,
`run(*, project_key, credential, bundle_root, job_id, bundle_sha256) -> TeeJobResult`) and points
the room at it. A result contains the JSON report plus immutable execution provenance (profile,
digest-pinned problem image, inference policy, and job id).

```
KATA_TEE_PROFILE=<module>:<Class>     # the subnet's profile module and class
```

A subnet's runner image is `FROM kata-tee-runner` + its profile module + that env. The room starts
the gateway + sealed net, calls the profile's `run`, then binds + quotes the report.

Build both the generic room and every subnet runner from digest-pinned base images. Deploy the final
subnet runner by digest and allowlist its measured TEE image identity; mutable tags are intentionally
rejected by the supplied build/deploy configuration.

## Privileged request contract

`POST /run` is HMAC-authenticated over its exact JSON bytes and requires a one-time nonce,
`issued_at`, `expires_at`, `bundle_sha256`, the candidate bundle, and the miner's sealed credential. The
room accepts only short-lived requests and reserves every nonce before execution, preventing replay.
The quote binds `report`, `bundle_sha256`, and immutable profile provenance to the nonce and project.
Before invoking a profile, the room bounds and extracts the candidate bundle, then verifies the
encrypted descriptor's `bundle_binding` against every submitted bundle file except the ciphertext
itself and transient local files (`__pycache__`, `.pyc`, `.pyo`, and `.git`). A validator therefore
cannot take the public ciphertext from a PR and run it with a substituted agent to expose the key.
Profiles must never fall back to an operator-supplied inference key: the sealed credential in each
request is the sole key source.

## Miner-funded inference routes

`room/inference_gateway.py` is part of this generic runner. A deployment configures a JSON registry
of approved provider routes; a subnet never needs to copy or modify runner security code:

- Set `KATA_INFERENCE_GATEWAY_PROVIDER_ROUTES_JSON` to an object keyed by stable provider ids. Each
  route has an exact `upstream` URL, optional `auth_header`, optional `auth_value_template` containing
  `{api_key}`, and optional fixed `headers`.
- Provider ids are generic. A registry may include `openrouter`, `chutes`, `akashml`, or any other
  provider with a reviewed HTTP endpoint and credential format. The runner does not embed provider
  brands, API-key prefixes, or subnet-specific endpoints.
- A miner seals `{version, provider, api_key, bundle_binding}` locally. `provider` must be an enabled
  registry id; an arbitrary URL is never accepted from the miner.
- For a job, the room gives the agent a signed `INFERENCE_API` route. The agent calls
  `POST $INFERENCE_API/inference` with `x-inference-api-key`. The signed path binds the encrypted
  provider choice, so the agent cannot switch the key to another allowlisted provider.

For example, a deployment could use this shape (fill each exact endpoint from the provider's reviewed
documentation):

```json
{
  "openrouter": {"upstream": "https://<openrouter-chat-endpoint>"},
  "chutes": {"upstream": "https://<chutes-chat-endpoint>"},
  "akashml": {"upstream": "https://<akashml-chat-endpoint>"}
}
```

At least one enabled route is required. A missing miner key, tampered route, or unenabled provider is
rejected before any provider call. The gateway permits only inference traffic from agents; it does
not select models, limit tokens or calls, track cost, or provide a validator-funded fallback. API
billing follows the miner's provider key. TEE/runtime billing remains the deployment platform's
responsibility and must be charged to the miner before it forwards a job to this room.

## Runtime timeouts

Timeouts protect room capacity; they do not constrain a miner's model, tokens, call count, retry
strategy, or provider spending. The production defaults are deliberately ordered:

| Layer | Setting | Default |
| --- | --- | --- |
| One provider request through the gateway | `KATA_INFERENCE_GATEWAY_TIMEOUT` | 180 seconds |
| Whole untrusted agent process (implemented by the subnet profile) | `KATA_TEE_AGENT_EXECUTION_TIMEOUT_SECONDS` | 840 seconds |

An agent should set its own HTTP client timeout slightly above the gateway timeout. The active SN60
contract recommends 195 seconds. A profile must apply the generic total-process setting when it
starts its agent container. This leaves the deployment free to support other subnets without
copying a provider-specific policy into the room.

## Miner sealing command

After verifying the room's `/pubkey` attestation, the miner runs `kata_seal.py` locally. Get the exact
room URL, measurement, and the providers you may use from the subnet's repo (for SN60,
[kata-sn60](https://github.com/Autovara/kata-sn60)):

```bash
uv run --extra seal python kata_seal.py \
  --room https://<approved-room> \
  --provider <provider-id> \
  --key-env <environment-variable-containing-miner-provider-key> \
  --bundle ./submission \
  --measurement <approved-compose-hash>
```

It writes only encrypted ciphertext to `sealed_inference_key`. The miner adds that file to the PR;
the owner and validator see ciphertext, not the key, provider descriptor, or bundle-binding payload.

### Lanes that need several credentials

Some lanes evaluate a submission against several independent providers — search, scraping,
summarisation, judging — and the miner funds all of them. One key cannot express that, and a run
that discovers the second provider is missing has already spent the miner's money on the first. So
the whole set is sealed together, with `kata_seal_multi.py`:

```bash
uv run --extra seal python kata_seal_multi.py \
  --room https://<approved-room> \
  --credential-profile <profile-from-the-subnet-repo> \
  --providers <p1>,<p2>,<p3> \
  --key-env <p1>=<ENV_VAR> --key-env <p2>=<ENV_VAR> --key-env <p3>=<ENV_VAR> \
  --bundle ./submission \
  --measurement <approved-compose-hash>
```

The provider list, the credential profile and the measurement come from the subnet's own repository.
Neither tool accepts a key as a command-line **value** — only the name of an environment variable, a
0600 file, or a hidden prompt — because command lines are world-readable in the process list.

The sealer refuses to write a partial set, and writes the ciphertext atomically at 0600.

## How a profile declares its credential contract

The base image contains no subnet's provider list; a profile declares its own, and the room enforces
exactly what it declares. Omit these attributes and the profile gets the single-key contract above,
which is what every profile predating multi-key sealing used.

```python
class MyProfile:
    credential_version = 2
    required_providers = ("provider-a", "provider-b")
    credential_profile = "my-lane-funding-policy-v1"
```

Dispatch is on what the **profile** declares, never on what a payload claims, so a single-key room
will not spend a multi-key payload and a multi-key room will not accept a single key.

Under a multi-key contract the room answers a credential fault with a **quote-bound
`credential_failure` report** rather than an HTTP error. Where a miner funds their own evaluation, a
credential fault scores them zero — and a bare 4xx is not evidence, since anything on the path could
have produced it. Under the single-key contract the lane funds inference, a credential fault is the
operator's problem rather than a contestant's, and a plain 400 is the honest answer.

## The trusted broker (multi-key lanes)

The gateway above forwards one request to one allowlisted route, and **the agent supplies the key**.
That is coherent when the agent legitimately holds its own credential, but it means a real credential
sits in the environment of code written by a stranger — `os.environ`, `/proc/self/environ`, `argv`, a
crash dump, a provider error body relayed verbatim.

For a lane where the miner funds several providers, the broker inverts that. **The decrypted keys
stay in the runner's memory and are never handed out.** The agent gets a *capability*: an unguessable,
short-lived token bound to one job and one role. It asks for a named operation; the broker injects the
right key server-side, calls a fixed route, and returns provider data.

```text
POST /v1/op/<name>     x-kata-capability: kcap_...
GET  /v1/quota         x-kata-capability: kcap_...
```

The broker runs **in-process on a thread**, not as a subprocess. That is forced by the design: a
subprocess cannot reach the `/run` handler's decrypted credentials without being handed them, which
is the thing being removed.

A profile declares its operations; the base knows no provider names:

```python
from room.broker import Broker, OperationSpec, ROLE_AGENT, ROLE_EVALUATOR

Broker([
    OperationSpec(name="web-search", role=ROLE_AGENT, provider="alpha",
                  handler=my_search, max_calls=64),
    OperationSpec(name="judge", role=ROLE_EVALUATOR, provider="delta",
                  handler=my_judge, max_calls=512, http_exposed=False),
])
```

What the broker guarantees, and what it does not:

- **An agent capability cannot invoke an evaluator operation.** Enforced twice — by role comparison,
  and by evaluator operations not being on the HTTP surface at all. An agent that could reach the
  judge could grade its own work.
- **The credential comes from the operation, never from the payload.** There is no field an agent can
  set to spend a different key, reach a different host, or name a different model.
- **Quotas are the broker's count, not the agent's self-report**, per capability and per operation.
- **Every refusal is byte-identical.** Unknown operation, wrong role, exhausted quota, expired or
  forged token: a caller that could tell them apart could map the room's state one probe at a time.
- **A job's capabilities die with it**, and its keys are overwritten before being dropped — a core
  dump taken afterwards should not still contain that contestant's credentials.
- **It cannot stop a handler that deliberately returns the key.** What it does is make the reviewed
  operation table the only place a handler ever sees one, instead of every agent ever submitted.

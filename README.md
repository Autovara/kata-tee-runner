# kata-tee-runner — the generic sealed-room TEE runner

A "sealed room" (also called a TEE, a trusted execution environment) is a locked container running on
hardware that can prove what is inside it. Here it runs a miner's untrusted agent, lets that agent pay
for its own inference with the miner's sealed API key, and returns a hardware-signed proof of exactly
what it ran. This repo is the generic room; any subnet reuses it by supplying a small profile, so the
room itself knows nothing about a specific subnet. For the SN60 profile, see [`../kata-sn60`](../kata-sn60).

A **subnet-blind** Phala confidential-VM "safe room": it seals a miner's provider credential,
binds it to that miner's exact submission bundle, then runs the agent behind an in-room
**miner-funded inference gateway**. The agent has no direct internet while its own provider key
pays for unchanged inference requests. The room returns the answer plus a
hardware **attestation** whose report-data binds the answer to the project + round nonce. The
maintainer and validator handle only ciphertext; neither receives the plaintext provider key or
provider descriptor, and neither pays for inference.

Any subnet reuses this room by shipping a small **profile** — this base names no subnet.

```
room/                 the generic core
  server.py           /health /pubkey /run; signed diagnostic /pull-test only when enabled
  sealing.py          encrypted miner-provider credential handling
  inference_gateway.py the miner-funded gateway HTTP handler (signed per-job routes)
  inference_network.py starts the gateway, the sealed internal network, and registry login
  attest.py           canonical() + bind_and_quote() (binds report + bundle hash + provenance)
  dstack.py           the confidential-VM client
  profile.py          the TeeJobProfile seam a subnet implements
kata_seal.py step0_check.py verify_run.py   miner/operator tools
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

After verifying the room's `/pubkey` attestation, the miner runs `kata_seal.py` locally:

```bash
python kata_seal.py \
  --room https://<approved-room> \
  --provider openrouter \
  --key <miner-provider-key> \
  --bundle ./submission \
  --measurement <approved-compose-hash>
```

It writes only encrypted ciphertext to `sealed_inference_key`. The miner adds that file to the PR;
the owner and validator see ciphertext, not the key, provider descriptor, or bundle-binding payload.

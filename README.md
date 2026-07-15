# kata-tee-runner — the generic sealed-room TEE runner

A **subnet-blind** Phala confidential-VM "safe room": it seals a miner's inference key, runs the
miner's agent against a pulled problem behind an in-room **model-pinning relay** (so inference is
real and fair, paid by the miner's key, with no direct internet), and returns the answer plus a
hardware **attestation** whose report-data binds the answer to the project + round nonce. The
maintainer never sees the key and never pays for inference.

Any subnet reuses this room by shipping a small **profile** — this base names no subnet.

```
room/                 the generic core
  server.py           /health /pubkey /run; signed diagnostic /pull-test only when enabled
  sealing.py          sealed-key handling
  relay_net.py        model-pinning relay + sealed internal network + registry login
  attest.py           canonical() + bind_and_quote() (binds report + bundle hash + provenance)
  dstack.py           the confidential-VM client
  profile.py          the TeeJobProfile seam a subnet implements
kata_seal.py step0_check.py verify_run.py   miner/operator tools
Dockerfile.base       the base image (a subnet builds FROM it)
```

## The profile seam
A subnet implements `room.profile.TeeJobProfile` (`fixture_project`, `image(project_key)`,
`run(*, project_key, sealed_key, bundle_b64, job_id, bundle_sha256) -> TeeJobResult`) and points
the room at it. A result contains the JSON report plus immutable execution provenance (profile,
digest-pinned problem image, pinned model, and job id).

```
KATA_TEE_PROFILE=<module>:<Class>     # the subnet's profile module and class
```

A subnet's runner image is `FROM kata-tee-runner` + its profile module + that env. The room starts
the relay + sealed net, calls the profile's `run`, then binds + quotes the report.

Build both the generic room and every subnet runner from digest-pinned base images. Deploy the final
subnet runner by digest and allowlist its measured TEE image identity; mutable tags are intentionally
rejected by the supplied build/deploy configuration.

## Privileged request contract

`POST /run` is HMAC-authenticated over its exact JSON bytes and requires a one-time nonce,
`issued_at`, `expires_at`, `bundle_sha256`, the candidate bundle, and the miner's sealed key. The
room accepts only short-lived requests and reserves every nonce before execution, preventing replay.
The quote binds `report`, `bundle_sha256`, and immutable profile provenance to the nonce and project.
Profiles must never fall back to an operator-supplied inference key: the sealed key in each request
is the sole key source. Candidate bundles are bounded before extraction.

See `../KATA-TEE-RUNNER-PLAN.md`. `relay.py` is a vendored generic relay (gitignored; §6).

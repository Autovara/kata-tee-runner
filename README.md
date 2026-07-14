# kata-tee-runner — the generic sealed-room TEE runner

A **subnet-blind** Phala confidential-VM "safe room": it seals a miner's inference key, runs the
miner's agent against a pulled problem behind an in-room **model-pinning relay** (so inference is
real and fair, paid by the miner's key, with no direct internet), and returns the answer plus a
hardware **attestation** whose report-data binds the answer to the project + round nonce. The
maintainer never sees the key and never pays for inference.

Any subnet reuses this room by shipping a small **profile** — this base names no subnet.

```
room/                 the generic core
  server.py           /health /pubkey /pull-test /run ; loads the profile from KATA_TEE_PROFILE
  sealing.py          sealed-key handling
  relay_net.py        model-pinning relay + sealed internal network + registry login
  attest.py           canonical() + bind_and_quote()  (report_data = sha256(nonce+project+answer))
  dstack.py           the confidential-VM client
  profile.py          the TeeJobProfile seam a subnet implements
kata_seal.py step0_check.py verify_run.py   miner/operator tools
Dockerfile.base       the base image (a subnet builds FROM it)
```

## The profile seam
A subnet implements `room.profile.TeeJobProfile` (`fixture_project`, `image(project_key)`,
`run(*, project_key, sealed_key, bundle_b64) -> dict`) and points the room at it:

```
KATA_TEE_PROFILE=<module>:<Class>     # the subnet's profile module and class
```

A subnet's runner image is `FROM kata-tee-runner` + its profile module + that env. The room starts
the relay + sealed net, calls the profile's `run`, then binds + quotes the report.

See `../KATA-TEE-RUNNER-PLAN.md`. `relay.py` is a vendored generic relay (gitignored; §6).

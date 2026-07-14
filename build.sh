#!/usr/bin/env bash
# Build (and optionally push) the generic kata-tee-runner BASE image. A subnet builds its runner
# FROM this base (e.g. kata-sn60/deploy/sn60-runner). Build the base FIRST, then the subnet image.
#
# Usage:
#   ./build.sh v1                 # build docker.io/.../kata-tee-runner:v1
#   ./build.sh v1 --push          # build + push
#   IMAGE=myrepo/tee-runner:v1 RELAY_SRC=/path/to/relay.py ./build.sh v1
set -euo pipefail

TAG="${1:?usage: ./build.sh <tag> [--push]}"
IMAGE="${IMAGE:-docker.io/carloscosimano/kata-tee-runner:${TAG}}"

# relay.py is the vendored model-pinning relay (gitignored). Its de-SN60'd source of truth is a
# §6 follow-up in ../KATA-TEE-RUNNER-PLAN.md; until then it's vendored from the SN60 relay, which a
# subnet image can override with its own. Override RELAY_SRC to vendor a different relay.
RELAY_SRC="${RELAY_SRC:-../kata-sn60/kata_sn60/validator_system/model_relay.py}"
[ -f "$RELAY_SRC" ] || { echo "ERROR: relay source not found at $RELAY_SRC (set RELAY_SRC=)" >&2; exit 1; }
cp "$RELAY_SRC" relay.py
echo "vendored relay.py <- $RELAY_SRC"

docker build -f Dockerfile.base -t "$IMAGE" .
echo "built $IMAGE"
[ "${2:-}" = "--push" ] && docker push "$IMAGE"

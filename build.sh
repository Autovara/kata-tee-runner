#!/usr/bin/env bash
# Build (and optionally push) the generic kata-tee-runner BASE image. A subnet builds its runner
# FROM this base (e.g. kata-sn60/deploy/sn60-runner). Build the base FIRST, then the subnet image.
#
# Usage:
#   PYTHON_BASE=python:3.12-slim@sha256:<digest> ./build.sh v1
#   PYTHON_BASE=python:3.12-slim@sha256:<digest> ./build.sh v1 --push
#   IMAGE=myrepo/tee-runner:v1 RELAY_SRC=/path/to/relay.py PYTHON_BASE=... ./build.sh v1
set -euo pipefail

TAG="${1:?usage: ./build.sh <tag> [--push]}"
IMAGE="${IMAGE:-docker.io/carloscosimano/kata-tee-runner:${TAG}}"
PYTHON_BASE="${PYTHON_BASE:?set PYTHON_BASE to an immutable Python image digest}"
case "$PYTHON_BASE" in
  *@sha256:*) ;;
  *) echo "ERROR: PYTHON_BASE must be an immutable image digest (...@sha256:...)" >&2; exit 1 ;;
esac

# relay.py is the vendored model-pinning relay (gitignored). Its de-SN60'd source of truth is a
# §6 follow-up in ../KATA-TEE-RUNNER-PLAN.md; until then it's vendored from the SN60 relay, which a
# subnet image can override with its own. Override RELAY_SRC to vendor a different relay.
RELAY_SRC="${RELAY_SRC:-../kata-sn60/kata_sn60/validator_system/model_relay.py}"
[ -f "$RELAY_SRC" ] || { echo "ERROR: relay source not found at $RELAY_SRC (set RELAY_SRC=)" >&2; exit 1; }
cp "$RELAY_SRC" relay.py
echo "vendored relay.py <- $RELAY_SRC"

docker build --build-arg PYTHON_BASE="$PYTHON_BASE" -f Dockerfile.base -t "$IMAGE" .
echo "built $IMAGE"
[ "${2:-}" = "--push" ] && docker push "$IMAGE"

#!/usr/bin/env bash
# Build (and optionally push) the generic kata-tee-runner BASE image. A subnet builds its runner
# FROM this base (e.g. kata-sn60/deploy/sn60-runner). Build the base FIRST, then the subnet image.
#
# Usage:
#   PYTHON_BASE=python:3.12-slim@sha256:<digest> ./build.sh v1
#   PYTHON_BASE=python:3.12-slim@sha256:<digest> ./build.sh v1 --push
#   IMAGE=myrepo/tee-runner:v1 GATEWAY_SRC=/path/to/inference_gateway.py PYTHON_BASE=... ./build.sh v1
set -euo pipefail

TAG="${1:?usage: ./build.sh <tag> [--push]}"
IMAGE="${IMAGE:-docker.io/carloscosimano/kata-tee-runner:${TAG}}"
PYTHON_BASE="${PYTHON_BASE:?set PYTHON_BASE to an immutable Python image digest}"
case "$PYTHON_BASE" in
  *@sha256:*) ;;
  *) echo "ERROR: PYTHON_BASE must be an immutable image digest (...@sha256:...)" >&2; exit 1 ;;
esac

# inference_gateway.py is vendored from the shared SN60 implementation until its source moves into
# this generic repository. A subnet may override GATEWAY_SRC with its own gateway implementation.
GATEWAY_SRC="${GATEWAY_SRC:-../kata-sn60/kata_sn60/validator_system/inference_gateway.py}"
[ -f "$GATEWAY_SRC" ] || { echo "ERROR: gateway source not found at $GATEWAY_SRC (set GATEWAY_SRC=)" >&2; exit 1; }
cp "$GATEWAY_SRC" inference_gateway.py
echo "vendored inference_gateway.py <- $GATEWAY_SRC"

docker build --build-arg PYTHON_BASE="$PYTHON_BASE" -f Dockerfile.base -t "$IMAGE" .
echo "built $IMAGE"
[ "${2:-}" = "--push" ] && docker push "$IMAGE"

#!/usr/bin/env bash
# Build (and optionally push) the generic kata-tee-runner base image. A subnet builds its runner
# FROM this base after the base image has been pushed by immutable digest.
#
# Usage:
#   PYTHON_BASE=python:3.12-slim@sha256:<digest> ./build.sh v1
#   PYTHON_BASE=python:3.12-slim@sha256:<digest> ./build.sh v1 --push
set -euo pipefail

TAG="${1:?usage: ./build.sh <tag> [--push]}"
IMAGE="${IMAGE:-docker.io/carloscosimano/kata-tee-runner:${TAG}}"
PYTHON_BASE="${PYTHON_BASE:?set PYTHON_BASE to an immutable Python image digest}"
case "$PYTHON_BASE" in
  *@sha256:*) ;;
  *) echo "ERROR: PYTHON_BASE must be an immutable image digest (...@sha256:...)" >&2; exit 1 ;;
esac

docker build --build-arg PYTHON_BASE="$PYTHON_BASE" -f Dockerfile.base -t "$IMAGE" .
echo "built $IMAGE"
[ "${2:-}" = "--push" ] && docker push "$IMAGE"

#!/usr/bin/env bash
# Build (and optionally push) the generic kata-tee-runner base image. A subnet builds its runner
# FROM this base after the base image has been pushed by immutable digest. Phala rooms use amd64,
# so the build platform is explicit even when the operator's host is a different architecture.
#
# Usage:
#   PYTHON_BASE=python:3.12-slim@sha256:<digest> ./build.sh v1
#   PYTHON_BASE=python:3.12-slim@sha256:<digest> ./build.sh v1 --push
set -euo pipefail

TAG="${1:?usage: ./build.sh <tag> [--push]}"
IMAGE="${IMAGE:-docker.io/carloscosimano/kata-tee-runner:${TAG}}"
PYTHON_BASE="${PYTHON_BASE:?set PYTHON_BASE to an immutable Python image digest}"
PLATFORM="${PLATFORM:-linux/amd64}"
case "$PYTHON_BASE" in
  *@sha256:*) ;;
  *) echo "ERROR: PYTHON_BASE must be an immutable image digest (...@sha256:...)" >&2; exit 1 ;;
esac

case "${2:-}" in
  ""|--push) ;;
  *) echo "ERROR: usage: ./build.sh <tag> [--push]" >&2; exit 1 ;;
esac

case "$PLATFORM" in
  linux/amd64) ;;
  *) echo "ERROR: PLATFORM must be linux/amd64 for Phala rooms" >&2; exit 1 ;;
esac

build_args=(
  --platform "$PLATFORM"
  --build-arg "PYTHON_BASE=$PYTHON_BASE"
  -f Dockerfile.base
  -t "$IMAGE"
)
if [ "${2:-}" = "--push" ]; then
  docker buildx build "${build_args[@]}" --push .
else
  docker buildx build "${build_args[@]}" --load .
fi
echo "built $IMAGE"

#!/usr/bin/env bash
# Build the ESF podman sandbox template image and run its smoke gate.
set -euo pipefail
cd "$(dirname "$0")"

IMAGE="${ESF_TEMPLATE_IMAGE:-localhost/esf-template:debian13-node24}"
NODE_VERSION="${ESF_NODE_VERSION:-24.22.1}"
case "$(uname -m)" in
  x86_64) NODE_ARCH="linux-x64" ;;
  aarch64|arm64) NODE_ARCH="linux-arm64" ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

ESF_PODMAN_STORAGE_ROOT="${ESF_PODMAN_STORAGE_ROOT:-$HOME/.local/share/containers/storage}"
ESF_PODMAN_RUN_ROOT="${ESF_PODMAN_RUN_ROOT:-$HOME/.local/share/containers/runroot}"
ESF_PODMAN_CGROUP_MANAGER="${ESF_PODMAN_CGROUP_MANAGER:-cgroupfs}"
export ESF_PODMAN_STORAGE_ROOT ESF_PODMAN_RUN_ROOT ESF_PODMAN_CGROUP_MANAGER
PODMAN=(podman --root "$ESF_PODMAN_STORAGE_ROOT" --runroot "$ESF_PODMAN_RUN_ROOT" --cgroup-manager "$ESF_PODMAN_CGROUP_MANAGER")

grep -q '^FROM .*@sha256:' Containerfile || { echo "Containerfile FROM is not digest-pinned" >&2; exit 1; }

# Resolve the official checksum for the pinned Node tarball — never
# trust a hardcoded hash to survive a version bump.
SHASUMS="$(curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/SHASUMS256.txt")"
NODE_SHA256="$(printf '%s\n' "$SHASUMS" | awk -v f="node-v${NODE_VERSION}-${NODE_ARCH}.tar.xz" '$2 == f {print $1}')"
[ -n "$NODE_SHA256" ] || { echo "could not resolve sha256 for Node v${NODE_VERSION} ${NODE_ARCH}" >&2; exit 1; }

# Stage the egress CA bundle into the build context. Opt-in operator
# input: set ESF_PROXY_CA_FILE when building behind a TLS-intercepting
# egress proxy; unset = an empty bundle is staged and no CA is baked in.
CA_FILE="${ESF_PROXY_CA_FILE:-}"
if [ -f "$CA_FILE" ]; then cp "$CA_FILE" egress-ca.crt; else : > egress-ca.crt; fi
trap 'rm -f egress-ca.crt' EXIT

"${PODMAN[@]}" build --network host \
  --build-arg "NODE_VERSION=${NODE_VERSION}" \
  --build-arg "NODE_ARCH=${NODE_ARCH}" \
  --build-arg "NODE_SHA256=${NODE_SHA256}" \
  --build-arg "HTTPS_PROXY=${HTTPS_PROXY:-${https_proxy:-}}" \
  --build-arg "HTTP_PROXY=${HTTP_PROXY:-${http_proxy:-}}" \
  -t "$IMAGE" .

ESF_TEMPLATE_IMAGE="$IMAGE" ESF_NODE_VERSION="$NODE_VERSION" ./smoke-gate.sh
echo "built and gated: $IMAGE"

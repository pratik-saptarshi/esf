#!/usr/bin/env bash
# Smoke gate for the ESF podman sandbox template: every probe the
# factory's harnesses depend on, run against the BUILT image, failing
# loudly on the first miss. A green build with a broken runtime is the
# failure this gate exists to catch.
set -euo pipefail

IMAGE="${ESF_TEMPLATE_IMAGE:-localhost/esf-template:debian13-node24}"
NODE_VERSION="${ESF_NODE_VERSION:-24.22.1}"
CLAUDE_CODE_VERSION="${ESF_CLAUDE_CODE_VERSION:-2.1.310}"

ESF_PODMAN_STORAGE_ROOT="${ESF_PODMAN_STORAGE_ROOT:-$HOME/.local/share/containers/storage}"
ESF_PODMAN_RUN_ROOT="${ESF_PODMAN_RUN_ROOT:-$HOME/.local/share/containers/runroot}"
ESF_PODMAN_CGROUP_MANAGER="${ESF_PODMAN_CGROUP_MANAGER:-cgroupfs}"
PODMAN=(podman --root "$ESF_PODMAN_STORAGE_ROOT" --runroot "$ESF_PODMAN_RUN_ROOT" --cgroup-manager "$ESF_PODMAN_CGROUP_MANAGER")
RUN=("${PODMAN[@]}" run --rm --network host "$IMAGE")

fail() { echo "SMOKE-GATE FAIL: $1" >&2; exit 1; }

echo "== base tools =="
"${RUN[@]}" bash -lc 'git --version && python3 --version && bash --version | head -1' || fail "base tools"

echo "== pinned node =="
NODE_OUT="$("${RUN[@]}" bash -lc 'node --version')" || fail "node --version"
[ "$NODE_OUT" = "v${NODE_VERSION}" ] || fail "node version $NODE_OUT != v${NODE_VERSION}"
"${RUN[@]}" bash -lc 'npm --version' >/dev/null || fail "npm --version"

echo "== egress through injected CA =="
"${RUN[@]}" bash -lc 'curl -fsSI https://registry.npmjs.org/ -o /dev/null' || fail "HTTPS to registry.npmjs.org (CA trust or egress broken)"

echo "== claude code (pinned npm install) =="
CLAUDE_OUT="$("${RUN[@]}" bash -lc "npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION} >/dev/null 2>&1 && claude --version")" || fail "claude install/version"
echo "claude: $CLAUDE_OUT"

# codex / opencode are staged by operators from release artifacts;
# when binaries are supplied, they must run on this image.
if [ -n "${ESF_CODEX_BIN:-}" ]; then
  "${PODMAN[@]}" run --rm --network host -v "$ESF_CODEX_BIN:/usr/local/bin/codex:ro" "$IMAGE" bash -lc 'codex --version' || fail "codex --version"
fi
if [ -n "${ESF_OPENCODE_BIN:-}" ]; then
  "${PODMAN[@]}" run --rm --network host -v "$ESF_OPENCODE_BIN:/usr/local/bin/opencode:ro" "$IMAGE" bash -lc 'opencode --version' || fail "opencode --version"
fi

echo "SMOKE-GATE PASS: $IMAGE"

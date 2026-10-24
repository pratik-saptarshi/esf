#!/usr/bin/env bash
# E2E acceptance for the podman sandbox provider.
#
# Proves (no cloud credential): auto-mode recon fails over from a dead
# cube endpoint to podman at worker startup; the full factory pipeline
# completes the credential-free conformance task on the podman
# provider (patch + run.json SUCCEEDED/SUCCESS); no sandboxes leak;
# doctor reports the recon. Does NOT prove model-backed agent runs —
# those remain credential-gated (see the plan, Task 8).
set -euo pipefail
cd "$(dirname "$0")/.."

export PATH="$HOME/sdk/go/bin:$HOME/go/bin:$PATH"
export GOTMPDIR="$HOME/.gotmp"
# make-e2e-repo.sh copies the fixture with tar; as root, tar restores
# recorded ownership, which fails in this host's user namespace (the
# fixture's gid is unmapped). Ownership is irrelevant — the fixture
# script git-inits and commits everything itself — so disable it.
export TAR_OPTIONS="--no-same-owner"
PODMAN="podman --root $HOME/.local/share/containers/storage --runroot $HOME/.local/share/containers/runroot --cgroup-manager=cgroupfs"
IMAGE="localhost/esf-template:debian13-node24"
TEMPORAL_BIN="${TEMPORAL_BIN:-$HOME/workspace/spikes/esf-live-run/bin/temporal}"
# The run workspace holds per-sandbox rootfs copies (~440 MB for the
# template image), which cannot fit the 512 MB /tmp tmpfs on this
# host — keep it on the home filesystem instead.
RUN_DIR="$(mktemp -d "$HOME/.local/share/esf-podman-e2e.XXXXXX")"
RUN_ID="podman-e2e-$(date +%s)"
WORKER_PID=""
TEMPORAL_PID=""
cleanup() {
  [ -n "$WORKER_PID" ] && kill "$WORKER_PID" 2>/dev/null || true
  [ -n "$TEMPORAL_PID" ] && kill "$TEMPORAL_PID" 2>/dev/null || true
  echo "e2e workspace: $RUN_DIR (worker.log, run outputs, doctor.json)"
}
trap cleanup EXIT
fail() { echo "E2E FAIL: $1" >&2; exit 1; }

[ -x "$TEMPORAL_BIN" ] || fail "temporal binary not found at $TEMPORAL_BIN (set TEMPORAL_BIN)"

echo "== build factory + template =="
make build >/dev/null
$PODMAN image exists "$IMAGE" || ./templates/podman/build.sh

echo "== fixture repo =="
# make-e2e-repo.sh takes no target argument: it materialises the
# fixture at testdata/e2e-repo-work/ (gitignored) and prints its path
# and baseline revision (scripts/factory-run-demo.sh is the model).
FIXTURE_OUTPUT="$(./scripts/make-e2e-repo.sh)"
FIXTURE_PATH="$(echo "$FIXTURE_OUTPUT" | sed -n 's/^fixture_path=//p')"
FIXTURE_SHA="$(echo "$FIXTURE_OUTPUT" | sed -n 's/^fixture_sha=//p')"
[ -n "$FIXTURE_PATH" ] && [ -n "$FIXTURE_SHA" ] || fail "could not materialise fixture repo: $FIXTURE_OUTPUT"
echo "   path: $FIXTURE_PATH"
echo "   sha:  $FIXTURE_SHA"

echo "== temporal dev server =="
"$TEMPORAL_BIN" server start-dev --ip 127.0.0.1 --port 7233 \
  --db-filename "$RUN_DIR/temporal.db" --log-level warn >"$RUN_DIR/temporal.log" 2>&1 &
TEMPORAL_PID=$!
for _ in $(seq 1 60); do (echo >/dev/tcp/127.0.0.1/7233) 2>/dev/null && break || sleep 1; done
(echo >/dev/tcp/127.0.0.1/7233) 2>/dev/null || fail "temporal did not come up: $(tail -5 "$RUN_DIR/temporal.log")"

echo "== worker (auto mode: dead cube must fail over to podman) =="
sed -e "s|__HOME__|$HOME|g" -e "s|__RUN_DIR__|$RUN_DIR|g" \
  templates/podman/factory.dev.toml >"$RUN_DIR/factory.toml"
./bin/factory worker --config "$RUN_DIR/factory.toml" >"$RUN_DIR/worker.log" 2>&1 &
WORKER_PID=$!
for _ in $(seq 1 60); do
  grep -q 'factory worker starting' "$RUN_DIR/worker.log" 2>/dev/null && break
  kill -0 "$WORKER_PID" 2>/dev/null || fail "worker exited during startup: $(tail -5 "$RUN_DIR/worker.log")"
  sleep 1
done
grep -q 'factory worker starting' "$RUN_DIR/worker.log" || fail "worker did not start: $(tail -5 "$RUN_DIR/worker.log")"
grep -q 'sandbox.provider=podman' "$RUN_DIR/worker.log" || fail "worker did not select podman: $(grep -i sandbox "$RUN_DIR/worker.log" || true)"

echo "== conformance run =="
# --sandbox-template: a run's sandbox template defaults to
# [cube] template_id, which names a Cube template, not an image; the
# podman provider resolves Spec.Template as the image reference, so
# the run names the template image explicitly (the provider's
# configured image is the same reference).
./bin/factory run --config "$RUN_DIR/factory.toml" --local-path "$FIXTURE_PATH" \
  --rev "$FIXTURE_SHA" --sandbox-template "$IMAGE" \
  --task 'Change the greeting from "hello" to "hello factory". Update the tests appropriately so they pass.' \
  --agent conformance --verification default --run-id "$RUN_ID" --wait \
  || fail "factory run exited non-zero (see $RUN_DIR and worker.log)"

echo "== verdicts =="
RUN_JSON="$(find "$RUN_DIR/data" -name run.json -path "*$RUN_ID*" | head -1)"
[ -n "$RUN_JSON" ] || fail "run.json not found under $RUN_DIR/data"
python3 - "$RUN_JSON" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
assert doc.get("factory_result") == "SUCCEEDED", f"factory_result={doc.get('factory_result')}"
assert doc.get("agent_result") == "SUCCESS", f"agent_result={doc.get('agent_result')}"
print("run.json verdicts ok: factory_result=SUCCEEDED agent_result=SUCCESS")
PY
PATCH_FILE="$(find "$RUN_DIR/data" -path "*$RUN_ID*" -name '*.patch' -type f | head -1)"
[ -n "$PATCH_FILE" ] || fail "patch artifact not found under the run directory"
grep -q 'hello factory' "$PATCH_FILE" || fail "patch does not contain the greeting change: $PATCH_FILE"
echo "patch ok: $PATCH_FILE"

echo "== cleanup + doctor =="
./bin/factory sandboxes --config "$RUN_DIR/factory.toml" | grep -q 'No live sandboxes.' \
  || fail "sandboxes leaked: $(./bin/factory sandboxes --config "$RUN_DIR/factory.toml")"
[ -z "$(ls -A "$RUN_DIR/podman-sandboxes" 2>/dev/null)" ] || fail "podman state dir not empty after the run"
./bin/factory doctor --config "$RUN_DIR/factory.toml" --output json >"$RUN_DIR/doctor.json" 2>/dev/null || true
python3 - "$RUN_DIR/doctor.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
checks = {c["name"]: c["status"] for c in doc["checks"]}
assert checks.get("sandbox_provider") == "ok", f"sandbox_provider={checks.get('sandbox_provider')}"
assert checks.get("podman_reachable") == "ok", f"podman_reachable={checks.get('podman_reachable')}"
print("doctor checks ok: sandbox_provider=ok podman_reachable=ok")
PY

echo "E2E PASS: auto mode selected podman; conformance run SUCCEEDED; patch + run.json verified; no leaked sandboxes"

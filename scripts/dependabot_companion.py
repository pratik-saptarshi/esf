#!/usr/bin/env python3
"""Dependabot companion — regenerates the files a bot bump leaves stale.

Bounded claim: for a Dependabot PR branch, this script regenerates
exactly the companion files a dependency bump desynchronises, and
nothing else:

* ``internal/controlplane/web/package-lock.json`` and
  ``agents/opencode/package-lock.json`` — re-synced from their
  ``package.json`` files with ``npm install --package-lock-only``
  (a partial group bump otherwise leaves ``npm ci`` failing with
  EUSAGE: lock file does not satisfy package.json);
* ``release/inventory.json`` — the dependency records the frozen
  inventory check (``scripts/verify-release-inventory.py``) compares
  against ``go.mod``, both npm lockfiles, and ``uv.lock`` are
  re-derived from those manifests;
* ``internal/releaseinfo/inventory.json`` — the embedded copy, kept
  byte-identical to ``release/inventory.json``.

Safety envelope, enforced before anything is committed:

* only the four companion files may change — any other path in the
  diff refuses the run;
* the diff is capped (default 500 added+deleted lines, override with
  ``ESF_COMPANION_MAX_DIFF_LINES``) — an over-cap regeneration is
  refused, not committed;
* after regeneration the frozen inventory check must pass — if it
  still fails, the changes are restored and nothing is committed;
* a branch whose head is already a companion commit is skipped, so
  each bot push gets at most one companion commit.

Modes:

    dependabot_companion.py --local
        Operate on the current checkout (used per-PR by the sweep and
        directly in tests). Commits with the marker subject on success.

    dependabot_companion.py --sweep
        List open Dependabot PRs via gh, check out each same-repo bot
        branch in a temporary worktree, run --local there, push any
        companion commit back, and label the PR
        ``companions-regenerated``.

The sweep runs from the default branch on a schedule / dispatch (see
``.github/workflows/dependabot-companion.yml``) because workflows
triggered by Dependabot itself receive a read-only token and cannot
push companion commits.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

COMPANION_FILES = {
    "release/inventory.json",
    "internal/releaseinfo/inventory.json",
    "internal/controlplane/web/package-lock.json",
    "agents/opencode/package-lock.json",
}
MARKER_SUBJECT = "chore(companion): regenerate release inventory and lockfiles"
LABEL = "companions-regenerated"
DEFAULT_MAX_DIFF_LINES = 500

# inventory dependencies.frontend key <- npm package name
FRONTEND_PACKAGES = {
    "vite": "vite",
    "lucide": "lucide-react",
    "jsdom": "jsdom",
    "react": "react",
    "tailwind": "tailwindcss",
}
# inventory dependencies key <- go module path (plain version string)
GO_MODULE_VERSIONS = {
    "grpc": "google.golang.org/grpc",
    "otel": "go.opentelemetry.io/otel",
    "sqlite": "modernc.org/sqlite",
    "x_net": "golang.org/x/net",
}
GO_MODULE_FIELDS = {
    "temporal": {
        "go_sdk": "go.temporal.io/sdk",
        "api": "go.temporal.io/api",
    },
}


def parse_go_mod(text):
    """Return {module: version} for every required module."""
    modules = {}
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if line == "require (":
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            line = line[len("require ") :].strip()
        elif not in_block:
            continue
        parts = line.split()
        if len(parts) == 2 and parts[1].startswith("v"):
            modules[parts[0]] = parts[1].removeprefix("v")
    return modules


def lockfile_packages(path):
    data = json.loads(Path(path).read_text())
    return data.get("packages", {})


def derive_inventory(root):
    """Return the inventory dict with dependency records re-derived
    from the tree's manifests (go.mod, npm lockfiles, uv.lock)."""
    root = Path(root)
    inventory = json.loads((root / "release/inventory.json").read_text())
    deps = inventory["dependencies"]

    modules = parse_go_mod((root / "go.mod").read_text())
    for key, module in GO_MODULE_VERSIONS.items():
        if module in modules:
            deps[key] = modules[module]
    for section, fields in GO_MODULE_FIELDS.items():
        for field, module in fields.items():
            if module in modules:
                deps[section][field] = modules[module]
    cube = deps.get("cubesandbox", {})
    sdk_module = "github.com/tencentcloud/CubeSandbox/sdk/go"
    if sdk_module in modules:
        # The inventory records this one with its v prefix (unlike the
        # plain-version fields above); keep the stored form byte-stable
        # so a consistent tree stays a no-op.
        cube["go_sdk"] = "v" + modules[sdk_module]

    web = lockfile_packages(root / "internal/controlplane/web/package-lock.json")
    frontend = deps.get("frontend", {})
    for key, package in FRONTEND_PACKAGES.items():
        entry = web.get(f"node_modules/{package}")
        if entry and "version" in entry:
            frontend[key] = entry["version"]

    agent = lockfile_packages(root / "agents/opencode/package-lock.json")
    opencode = deps.get("opencode", {})
    cli = agent.get("node_modules/@opencode/cli")
    if cli:
        if "version" in cli:
            opencode["version"] = cli["version"]
        if "integrity" in cli:
            opencode["npm_integrity"] = cli["integrity"]
    binary_pkg = opencode.get("linux_amd64_package")
    if binary_pkg:
        binary = agent.get(f"node_modules/{binary_pkg}")
        if binary and "integrity" in binary:
            opencode["linux_amd64_npm_integrity"] = binary["integrity"]

    uv = tomllib.loads((root / "uv.lock").read_text())
    for package in uv.get("package", []):
        if package.get("name") == "dspy":
            deps["dspy"] = package["version"]
    return inventory


def serialize_inventory(inventory):
    # Byte-stable with the repo's existing formatting (indent=2).
    return json.dumps(inventory, indent=2) + "\n"


def sync_inventory(root):
    """Re-derive the inventory and sync the embedded copy.
    Returns True if either file changed."""
    root = Path(root)
    derived = serialize_inventory(derive_inventory(root))
    changed = False
    release = root / "release/inventory.json"
    if release.read_text() != derived:
        release.write_text(derived)
        changed = True
    embedded = root / "internal/releaseinfo/inventory.json"
    if embedded.read_text() != derived:
        embedded.write_text(derived)
        changed = True
    return changed


def sync_lockfiles(root, runner=subprocess.run):
    """Re-sync npm lockfiles from their package.json files."""
    for rel in ("internal/controlplane/web", "agents/opencode"):
        directory = Path(root) / rel
        if (directory / "package.json").exists():
            result = runner(
                ["npm", "install", "--package-lock-only", "--ignore-scripts"],
                cwd=directory,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"npm lockfile sync failed in {rel}: {result.stderr.strip()}"
                )


def git(root, *args, check=True):
    result = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result


def head_is_companion(root):
    subject = git(root, "log", "-1", "--format=%s").stdout.strip()
    return subject.startswith(MARKER_SUBJECT)


def diff_summary(root):
    """Return (changed_files, added_plus_deleted_lines) for tracked
    modifications in the checkout."""
    numstat = git(root, "diff", "--numstat").stdout
    files = set()
    lines = 0
    for line in numstat.splitlines():
        added, deleted, path = line.split("\t", 2)
        files.add(path)
        lines += (0 if added == "-" else int(added)) + (
            0 if deleted == "-" else int(deleted)
        )
    return files, lines


def decide_diff(files, lines, cap):
    """Pure cap/set decision: returns None to accept, or a refusal
    reason string."""
    outside = sorted(set(files) - COMPANION_FILES)
    if outside:
        return f"diff touches non-companion files: {', '.join(outside)}"
    if lines > cap:
        return f"diff of {lines} lines exceeds cap of {cap}"
    return None


def restore_companions(root):
    for rel in COMPANION_FILES:
        git(root, "checkout", "--", rel, check=False)


def opencode_binary_pin_stale(before, after):
    """True if derivation changed the OpenCode release identity
    (version or binary-package integrity). The recorded
    linux_amd64_binary_sha256 belongs to the previous release in that
    case and cannot be re-derived from the manifests — the frozen
    inventory check cannot see it either, because it only compares
    the digest against the equally stale copies in example.toml and
    the Cube template. Such updates are refused for manual
    regeneration."""
    old = before.get("dependencies", {}).get("opencode", {})
    new = after.get("dependencies", {}).get("opencode", {})
    return (
        old.get("version") != new.get("version")
        or old.get("linux_amd64_npm_integrity")
        != new.get("linux_amd64_npm_integrity")
    )


def process_local(root, cap):
    """Run the companion on one checkout. Returns (status, detail)."""
    root = Path(root)
    if head_is_companion(root):
        return "skipped", "head is already a companion commit"
    before = json.loads((root / "release/inventory.json").read_text())
    sync_lockfiles(root)
    sync_inventory(root)
    after = json.loads((root / "release/inventory.json").read_text())
    if opencode_binary_pin_stale(before, after):
        restore_companions(root)
        return (
            "refused",
            "OpenCode bump changes the binary identity "
            f"({before['dependencies']['opencode'].get('version')} -> "
            f"{after['dependencies']['opencode'].get('version')}); "
            "linux_amd64_binary_sha256 cannot be re-derived — "
            "manual regeneration required",
        )
    verify = subprocess.run(
        [sys.executable, str(root / "scripts/verify-release-inventory.py")],
        capture_output=True,
        text=True,
    )
    if verify.returncode != 0:
        restore_companions(root)
        detail = (verify.stderr or verify.stdout).strip().splitlines()
        return "verify-failed", detail[0] if detail else "inventory check failed"
    files, lines = diff_summary(root)
    if not files:
        return "no-changes", "companions already current"
    refusal = decide_diff(files, lines, cap)
    if refusal:
        restore_companions(root)
        return "refused", refusal
    git(root, "add", *sorted(files))
    git(
        root,
        "-c",
        "user.name=esf-dependabot-companion",
        "-c",
        "user.email=dependabot-companion@users.noreply.github.com",
        "commit",
        "-m",
        MARKER_SUBJECT,
        "-m",
        "Regenerated by scripts/dependabot_companion.py for a Dependabot branch:\n"
        "npm lockfiles re-synced from package.json, release inventory records\n"
        "re-derived from go.mod / lockfiles / uv.lock, embedded inventory synced.",
    )
    return "committed", f"{len(files)} files, {lines} diff lines"


def sweep(cap):
    prs = subprocess.run(
        [
            "gh",
            "pr",
            "list",
            "--author",
            "app/dependabot",
            "--state",
            "open",
            "--limit",
            "100",
            "--json",
            "number,headRefName,headRepositoryOwner,isCrossRepository",
        ],
        capture_output=True,
        text=True,
    )
    if prs.returncode != 0:
        print(f"error: gh pr list failed: {prs.stderr.strip()}", file=sys.stderr)
        return 1
    failures = 0
    for pr in json.loads(prs.stdout):
        if pr.get("isCrossRepository"):
            continue
        branch = pr["headRefName"]
        with tempfile.TemporaryDirectory() as tmp:
            worktree = Path(tmp) / "wt"
            fetch = subprocess.run(
                ["git", "fetch", "--quiet", "origin", branch],
                capture_output=True,
                text=True,
            )
            if fetch.returncode != 0:
                print(f"PR #{pr['number']}: fetch failed: {fetch.stderr.strip()}")
                failures += 1
                continue
            subprocess.run(
                ["git", "worktree", "add", "--quiet", str(worktree), "FETCH_HEAD"],
                check=True,
            )
            try:
                try:
                    status, detail = process_local(worktree, cap)
                except Exception as exc:  # one bad branch must not starve the sweep
                    status, detail = "error", f"{type(exc).__name__}: {exc}"
                if status == "committed":
                    push = git(
                        worktree,
                        "push",
                        "origin",
                        f"HEAD:refs/heads/{branch}",
                        check=False,
                    )
                    if push.returncode != 0:
                        status, detail = (
                            "push-failed",
                            push.stderr.strip().splitlines()[-1]
                            if push.stderr.strip()
                            else "git push failed",
                        )
                    else:
                        subprocess.run(
                            [
                                "gh",
                                "pr",
                                "edit",
                                str(pr["number"]),
                                "--add-label",
                                LABEL,
                            ],
                            capture_output=True,
                            text=True,
                        )
            finally:
                subprocess.run(
                    ["git", "worktree", "remove", "--force", str(worktree)],
                    capture_output=True,
                )
            print(f"PR #{pr['number']} ({branch}): {status} — {detail}")
            if status in ("refused", "verify-failed", "push-failed", "error"):
                failures += 1
    return 1 if failures else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--local", action="store_true")
    mode.add_argument("--sweep", action="store_true")
    args = parser.parse_args(argv)
    cap = int(os.environ.get("ESF_COMPANION_MAX_DIFF_LINES", DEFAULT_MAX_DIFF_LINES))
    if args.local:
        status, detail = process_local(Path.cwd(), cap)
        print(f"{status}: {detail}")
        return 0 if status in ("committed", "no-changes", "skipped") else 1
    return sweep(cap)


if __name__ == "__main__":
    raise SystemExit(main())

# ESF podman sandbox template

This directory builds `localhost/esf-template:debian13-node24`, the sandbox
image for ESF's podman provider (`[sandbox] provider = "podman"` or `"auto"`).
The base is **Debian 13 (trixie) slim**, chosen over Ubuntu 24.04 in the
project's base-image evaluation: Debian's toolchain packages are newer (Node
20.19 in the distro vs Ubuntu's 18.19 — still not new enough, see below),
glibc is newer (2.41 vs 2.39), and the support window is longer (full support
to Aug 2028, LTS to Jun 2030, vs Ubuntu standard support to May 2029). The
image carries bash, git, curl, python3, coreutils and ca-certificates, plus a
pinned Node.js — everything the factory's agent harnesses and verification
profiles need inside a sandbox.

The evaluation produced three mitigations, and this template exists to
implement them:

1. **Node is decoupled from the distro.** Current agent CLIs declare a moving
   Node floor (Claude Code already requires `node >= 22`); a frozen distro
   Node drifts below it. The Containerfile therefore installs **no** distro
   `nodejs`/`npm` and instead unpacks the official Node tarball — version
   pinned by `NODE_VERSION` (default v24.22.1) — into `/usr/local`, with the
   tarball's sha256 resolved from the official `SHASUMS256.txt` at build time
   and verified during the build. A version bump can never silently ship an
   unverified binary, and the hash can never go stale in the Containerfile.
2. **Every build is smoke-gated.** `build.sh` runs `smoke-gate.sh` against the
   built image: base tools, the pinned Node (`node --version` must equal the
   pin exactly), one real HTTPS fetch, a pinned `npm install -g
   @anthropic-ai/claude-code` + `claude --version`, and `codex --version` /
   `opencode --version` probes when those binaries are supplied. Any miss
   fails the build loudly — a green build with a broken runtime is the
   failure this gate exists to catch.
3. **The egress-proxy CA is baked into the trust store.** On hosts behind a
   TLS-intercepting egress proxy, in-container HTTPS fails with
   `SELF_SIGNED_CERT_IN_CHAIN` unless the proxy's CA is trusted. `build.sh`
   stages the operator's **full** CA bundle (a bare root CA is not sufficient)
   into the build, and the Containerfile installs it via
   `update-ca-certificates`. Node is pointed at the system store through
   `NODE_EXTRA_CA_CERTS` in `/etc/profile.d/esf.sh`.

## Building

```bash
./templates/podman/build.sh
```

`build.sh` refuses to build unless the Containerfile's `FROM` is
digest-pinned, resolves the Node checksum, stages the CA bundle, builds with
explicit podman flags, then runs the smoke gate. Knobs (all optional):

| Variable | Default | Meaning |
| --- | --- | --- |
| `ESF_TEMPLATE_IMAGE` | `localhost/esf-template:debian13-node24` | Tag for the built image |
| `ESF_NODE_VERSION` | `24.22.1` | Pinned Node version |
| `ESF_CLAUDE_CODE_VERSION` | `2.1.310` | Claude Code version probed by the gate |
| `ESF_PROXY_CA_FILE` | `/run/hatch/egress-tls/ca-bundle.pem` | Full egress CA bundle to bake in; missing file = no CA step |
| `ESF_CODEX_BIN` / `ESF_OPENCODE_BIN` | unset | Host paths to codex/opencode binaries for the gate to probe in-image |
| `ESF_PODMAN_STORAGE_ROOT` | `~/.local/share/containers/storage` | Podman `--root` |
| `ESF_PODMAN_RUN_ROOT` | `~/.local/share/containers/runroot` | Podman `--runroot` |
| `ESF_PODMAN_CGROUP_MANAGER` | `cgroupfs` | Podman `--cgroup-manager` |

When the trixie-slim base moves, re-pin the digest:

```bash
P="podman --root $HOME/.local/share/containers/storage --runroot $HOME/.local/share/containers/runroot --cgroup-manager=cgroupfs"
$P pull docker.io/library/debian:trixie-slim
DIGEST=$($P image inspect docker.io/library/debian:trixie-slim --format '{{.Digest}}')
sed -i "s|^FROM .*|FROM docker.io/library/debian:trixie-slim@${DIGEST}|" templates/podman/Containerfile
```

## Wiring into a factory config

Select the provider and point it at the template image. On this project's
reference host (rootful podman, no network namespaces, no systemd cgroup
manager), the storage/cgroup settings must be explicit — the provider never
relies on ambient podman configuration:

```toml
[sandbox]
provider = "auto"            # or "podman" to require containers

[podman]
image = "localhost/esf-template:debian13-node24"
network = "host"             # this host cannot create network namespaces
cgroup_manager = "cgroupfs"  # no systemd cgroup manager on this host
storage_root = "/home/<user>/.local/share/containers/storage"
run_root = "/home/<user>/.local/share/containers/runroot"
# state_dir = ""             # defaults to <storage.data_dir>/podman-sandboxes
# user = "esf"               # run sandbox commands as the template's esf user
# command_output_bytes = 4194304
# request_timeout = "60s"
```

With `provider = "auto"`, startup probes CubeSandbox first (when configured)
and falls back to podman; with neither reachable it fails closed. Harnesses
configured with `credential_mode = "cube_egress"` are rejected at startup on
the podman provider, by name — they would otherwise fail halfway through a
run at the runtime-network lockdown.

**Runs also need `--sandbox-template`.** Selecting the provider and setting
`[podman] image` is not sufficient on its own: a run's sandbox template
still defaults to `[cube] template_id` — in the `factory run` CLI and again
at sandbox creation — regardless of the selected provider. The podman
provider treats a non-empty run template as the image reference and uses
`[podman] image` only when the run's template is empty, which a defaulted
run never is. Pass the template image on every run, as
`scripts/podman-e2e.sh` does:

```bash
factory run --sandbox-template localhost/esf-template:debian13-node24 ...
```

Without the flag, podman tries to pull the cube `template_id` as an image
and the run fails late, at sandbox creation, with a misleading pull error.
If a cube template ID happened to resolve as an image reference, that image
would be used instead of `[podman] image` — silently the wrong image.

## Execution model, in brief

The provider never uses `podman exec` and never keeps a long-lived container.
`Create` exports the template image and extracts its rootfs to the sandbox's
state directory; each `Execute` is a one-shot `podman run --rm --rootfs`
against that directory, so the **whole filesystem** — including `/usr/local`,
where agent CLIs install — persists across commands. `WriteFile`/`ReadFile`
are host-side operations on the rootfs, with paths validated to stay inside
it. The command's real exit code travels out-of-band: the in-sandbox wrapper
writes it to `/run/esf-exit` in the rootfs and the provider reads it
host-side, so podman's own failure codes (125/126/127) are never mistaken
for the command's. Output is bounded by `command_output_bytes` with the same
semantics as the cube provider (overflow kills the command and reports exit
122 with the `ESF_OUTPUT_LIMIT_EXCEEDED` marker). Capabilities are honest:
the provider advertises no snapshot, clone, suspend, resume, or preview
support, and the factory's optional lifecycle steps degrade to `SKIPPED`
through the existing paths. Because rootfs execution does not apply image
`ENV`/`WORKDIR`/`USER`, the runtime environment lives in
`/etc/profile.d/esf.sh` and the provider runs commands via `/bin/bash -lc`.

## Operational notes

- **State layout.** Each sandbox is `<state_dir>/<id>/` containing `spec.json`
  and the extracted `rootfs/`. Directories are mode 0700 and `spec.json` mode
  0600 — sandbox state is operator-only.
- **Env values ride argv.** Spec and command environment is passed via
  `podman run -e`, which is visible in the host process list while a command
  runs. This is accepted and documented here deliberately: the provider never
  writes env values (or the argv carrying them) to its logs or state files,
  and evidence redaction is unchanged.
- **Non-root execution.** Set `user = "esf"` in `[podman]` to run sandbox
  commands as the template's unprivileged `esf` user (uid 1000) instead of
  root.
- **Destroy and sweeping.** `Destroy` removes the sandbox's state directory
  outright and is idempotent; one-shot containers are `--rm`, so a destroyed
  sandbox leaves nothing behind in `podman ps -a`. A state directory whose
  sandbox is gone from `List` output is orphaned state and can be swept by
  deleting the directory.

## Troubleshooting

- **`overlay on overlay` / storage driver errors** — podman's default
  graphroot sits on a filesystem that cannot host overlay upperdirs. Point
  `storage_root` (and `ESF_PODMAN_STORAGE_ROOT` when building) at a directory
  on a filesystem that can, as the example above does.
- **Network-namespace (`netns`/`setns`) errors** — the host forbids creating
  network namespaces. Set `network = "host"` in `[podman]`; the template
  build already uses `--network host`.
- **Cgroup delegation warning from conmon** — benign on this host: containers
  run, but cgroup resource limits may not enforce. It is not a failure and
  the provider does not treat it as one.
- **Smoke gate fails at the npm registry fetch** with
  `SELF_SIGNED_CERT_IN_CHAIN` — the staged CA file was a bare root CA instead
  of the full bundle. Fix `ESF_PROXY_CA_FILE`, not the gate.

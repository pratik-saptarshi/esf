//go:build integration

package podman

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mitkox/esf/internal/sandbox"
)

func integrationProvider(t *testing.T, mutate func(*Config)) *Provider {
	t.Helper()
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman binary not available")
	}
	cfg := ConfigFromEnv()
	if cfg.Image == "" {
		cfg.Image = "docker.io/library/debian:trixie-slim"
	}
	if cfg.Network == "" {
		cfg.Network = "host"
	}
	if cfg.CgroupManager == "" {
		cfg.CgroupManager = "cgroupfs"
	}
	if cfg.StorageRoot == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		cfg.StorageRoot = filepath.Join(home, ".local", "share", "containers", "storage")
		cfg.RunRoot = filepath.Join(home, ".local", "share", "containers", "runroot")
	}
	cfg.StateDir = t.TempDir()
	if mutate != nil {
		mutate(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestPodmanLifecycleIntegration(t *testing.T) {
	ctx := context.Background()
	p := integrationProvider(t, nil)
	if err := p.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	sb, err := p.Create(ctx, sandbox.Spec{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer p.Destroy(ctx, sb.ID())

	// Whole-rootfs persistence across one-shot runs, including
	// /usr/local/bin (where agent CLIs install) and /workspace.
	exec1, err := sb.Execute(ctx, sandbox.Command{Script: "echo '#!/bin/sh' > /usr/local/bin/esf-it && echo 'echo it-works' >> /usr/local/bin/esf-it && chmod +x /usr/local/bin/esf-it && mkdir -p /workspace && echo persisted > /workspace/note.txt"})
	if err != nil || exec1.ExitCode != 0 {
		t.Fatalf("Execute 1: %+v, %v", exec1, err)
	}
	exec2, err := sb.Execute(ctx, sandbox.Command{Argv: []string{"esf-it"}})
	if err != nil || exec2.ExitCode != 0 || !strings.Contains(exec2.Stdout, "it-works") {
		t.Fatalf("Execute 2 (persisted /usr/local/bin): %+v, %v", exec2, err)
	}
	note, err := sb.ReadFile(ctx, "/workspace/note.txt")
	if err != nil || !strings.Contains(string(note), "persisted") {
		t.Fatalf("ReadFile: %q, %v", note, err)
	}
	// stdin delivery.
	exec3, err := sb.Execute(ctx, sandbox.Command{Argv: []string{"cat"}, Stdin: []byte("hello-stdin")})
	if err != nil || exec3.Stdout != "hello-stdin" {
		t.Fatalf("Execute stdin: %+v, %v", exec3, err)
	}
	// StdinPath delivery (the generic harness prompt mechanism).
	if err := sb.WriteFile(ctx, "/tmp/prompt.txt", []byte("prompt-body")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	exec4, err := sb.Execute(ctx, sandbox.Command{Script: "cat", StdinPath: "/tmp/prompt.txt"})
	if err != nil || exec4.Stdout != "prompt-body" {
		t.Fatalf("Execute StdinPath: %+v, %v", exec4, err)
	}
	// Exit codes propagate exactly.
	exec5, err := sb.Execute(ctx, sandbox.Command{Script: "exit 7"})
	if err != nil || exec5.ExitCode != 7 {
		t.Fatalf("Execute exit 7: %+v, %v", exec5, err)
	}
	// Timeout kills the one-shot container; nothing leaks.
	exec6, err := sb.Execute(ctx, sandbox.Command{Script: "sleep 30", Timeout: time.Second})
	if err != nil || !exec6.TimedOut {
		t.Fatalf("Execute timeout: %+v, %v", exec6, err)
	}
	res, err := p.invoke(ctx, "ps", "-a", "--filter", "name=esf-run-"+sb.ID(), "--format", "{{.Names}}")
	if err != nil || strings.TrimSpace(string(res.Stdout)) != "" {
		t.Fatalf("leaked containers after timeout: %q, %v", res.Stdout, err)
	}
	if err := p.Destroy(ctx, sb.ID()); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if err := p.Destroy(ctx, sb.ID()); err != nil {
		t.Fatalf("Destroy (idempotent): %v", err)
	}
}

// TestPodmanNonRootUserIntegration is the integration regression for
// finding N2: with the documented [podman] user option set to a
// non-root uid, the container must be able to traverse the rootfs and
// execute. Create pre-creates the rootfs at 0700 (and the state dir
// holding spec.json must STAY 0700); extraction must leave the
// rootfs itself at the image's root permissions (0755 for debian).
// The output wrapper also writes /run/esf-exit as the executing user,
// so /run must be user-writable in the extracted rootfs.
func TestPodmanNonRootUserIntegration(t *testing.T) {
	ctx := context.Background()
	p := integrationProvider(t, func(c *Config) { c.User = "1000" })
	sb, err := p.Create(ctx, sandbox.Spec{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer p.Destroy(ctx, sb.ID())

	stateInfo, err := os.Stat(filepath.Join(p.cfg.StateDir, sb.ID()))
	if err != nil {
		t.Fatal(err)
	}
	if got := stateInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("sandbox state dir mode = %o, want 0700 (holds spec.json)", got)
	}
	rootfsInfo, err := os.Stat(filepath.Join(p.cfg.StateDir, sb.ID(), "rootfs"))
	if err != nil {
		t.Fatal(err)
	}
	if got := rootfsInfo.Mode().Perm(); got != 0o755 {
		t.Fatalf("rootfs mode = %o, want 0755 (image root permissions)", got)
	}
	exec, err := sb.Execute(ctx, sandbox.Command{Script: "id -u && echo nonroot-ok"})
	if err != nil || exec.ExitCode != 0 {
		t.Fatalf("Execute as uid 1000: %+v, %v", exec, err)
	}
	if !strings.Contains(exec.Stdout, "1000") || !strings.Contains(exec.Stdout, "nonroot-ok") {
		t.Fatalf("Execute as uid 1000 stdout = %q, want it to contain \"1000\" and \"nonroot-ok\"", exec.Stdout)
	}
}

func TestPodmanOutputLimitIntegration(t *testing.T) {
	ctx := context.Background()
	p := integrationProvider(t, func(c *Config) { c.CommandOutputBytes = 4096 })
	sb, err := p.Create(ctx, sandbox.Spec{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer p.Destroy(ctx, sb.ID())
	exec, err := sb.Execute(ctx, sandbox.Command{Script: "seq 1 200000"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if exec.ExitCode != 122 {
		t.Fatalf("flood exit = %d, want 122", exec.ExitCode)
	}
	if len(exec.Stdout) > 4096 {
		t.Fatalf("stdout len = %d, want <= 4096", len(exec.Stdout))
	}
	if !strings.Contains(exec.Stderr, "ESF_OUTPUT_LIMIT_EXCEEDED") {
		t.Fatalf("stderr lacks truncation marker: %q", exec.Stderr)
	}
}

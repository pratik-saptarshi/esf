package podman

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mitkox/esf/internal/sandbox"
)

// execFake emulates podman for Execute tests: it records argv, honors a
// canned exit file / stdout, and can block until ctx cancellation.
type execFake struct {
	lastArgs   []string
	exitFile   string // contents to write to <rootfs>/run/esf-exit; "" = write nothing
	podmanCode int
	stdout     string
	blockRun   bool
	killed     []string
}

func (f *execFake) Run(ctx context.Context, _ io.Reader, stdout, _ io.Writer, args ...string) (int, error) {
	verb := ""
	for _, a := range args {
		if a == "run" || a == "kill" {
			verb = a
			break
		}
	}
	switch verb {
	case "kill":
		f.killed = append(f.killed, args[len(args)-1])
		return 0, nil
	case "run":
		f.lastArgs = append([]string{}, args...)
		if f.blockRun {
			<-ctx.Done()
			return -1, ctx.Err()
		}
		rootfs := ""
		for i, a := range args {
			if a == "--rootfs" && i+1 < len(args) {
				rootfs = args[i+1]
			}
		}
		if f.exitFile != "" && rootfs != "" {
			_ = os.MkdirAll(filepath.Join(rootfs, "run"), 0o755)
			_ = os.WriteFile(filepath.Join(rootfs, "run", "esf-exit"), []byte(f.exitFile), 0o644)
		}
		io.WriteString(stdout, f.stdout)
		return f.podmanCode, nil
	}
	return 0, nil
}

func testSandbox(t *testing.T, fr *execFake, logBuf *bytes.Buffer) *podmanSandbox {
	t.Helper()
	dir := t.TempDir()
	rootfs := filepath.Join(dir, "rootfs")
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Binary: "podman", Image: "localhost/test:1", StateDir: filepath.Dir(dir)}
	opts := []Option{}
	if logBuf != nil {
		opts = append(opts, WithLogger(slog.New(slog.NewTextHandler(logBuf, nil))))
	}
	p, err := New(cfg, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p.run = fr
	st := sandboxState{ID: "podman-" + strings.Repeat("b", 32), Image: "localhost/test:1", Env: map[string]string{"SPEC_ENV": "spec"}}
	return p.handle(st, dir)
}

func TestExecuteArgvBuiltSafely(t *testing.T) {
	var logBuf bytes.Buffer
	fr := &execFake{exitFile: "0", stdout: "hi\n"}
	sb := testSandbox(t, fr, &logBuf)
	exec, err := sb.Execute(context.Background(), sandbox.Command{
		Argv: []string{"echo", "hello world"},
		Env:  map[string]string{"ESF_TEST_SECRET": "s3cr3t-value", "PLAIN": "x"},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if exec.ExitCode != 0 || exec.Stdout != "hi\n" {
		t.Fatalf("Execution = %+v", exec)
	}
	joined := strings.Join(fr.lastArgs, "\x00")
	if !strings.Contains(joined, "--rootfs\x00"+sb.rootfs) {
		t.Fatalf("argv lacks --rootfs <rootfs>: %q", fr.lastArgs)
	}
	if !strings.Contains(joined, "SPEC_ENV=spec") || !strings.Contains(joined, "PLAIN=x") {
		t.Fatalf("argv lacks merged env: %q", fr.lastArgs)
	}
	payload := fr.lastArgs[len(fr.lastArgs)-1]
	if !strings.Contains(payload, "'hello world'") {
		t.Fatalf("payload does not shell-quote argv: %q", payload)
	}
	if strings.Contains(logBuf.String(), "s3cr3t-value") {
		t.Fatalf("provider logged an env value: %q", logBuf.String())
	}
}

func TestExecuteParsesExitFile(t *testing.T) {
	ctx := context.Background()
	sb := testSandbox(t, &execFake{exitFile: "7"}, nil)
	exec, err := sb.Execute(ctx, sandbox.Command{Argv: []string{"false"}})
	if err != nil || exec.ExitCode != 7 {
		t.Fatalf("exit 7 case: %+v, %v", exec, err)
	}
	sb = testSandbox(t, &execFake{podmanCode: 125}, nil) // no exit file written
	if _, err := sb.Execute(ctx, sandbox.Command{Argv: []string{"true"}}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing exit file: err = %v, want ErrUnavailable", err)
	}
	sb = testSandbox(t, &execFake{exitFile: "abc"}, nil)
	if _, err := sb.Execute(ctx, sandbox.Command{Argv: []string{"true"}}); err == nil {
		t.Fatalf("garbage exit file: err = nil, want error")
	}
}

// exitSymlinkFake emulates a sandboxed command that replaces the exit
// file with a symlink pointing at a host file outside the rootfs
// (Codex finding F1 on PR #4). The wrapper writes the exit code through
// the link inside the sandbox; a host-side read that follows the link
// reads the host file instead.
type exitSymlinkFake struct {
	hostFile string // absolute path of the host file to point the link at
	relative bool   // make the link target relative (../.. escape) instead of absolute
}

func (f *exitSymlinkFake) Run(_ context.Context, _ io.Reader, _, _ io.Writer, args ...string) (int, error) {
	rootfs := ""
	for i, a := range args {
		if a == "--rootfs" && i+1 < len(args) {
			rootfs = args[i+1]
		}
	}
	if rootfs == "" {
		return 0, nil
	}
	target := f.hostFile
	if f.relative {
		rel, err := filepath.Rel(filepath.Join(rootfs, "run"), f.hostFile)
		if err != nil {
			return 0, err
		}
		target = rel
	}
	if err := os.MkdirAll(filepath.Join(rootfs, "run"), 0o755); err != nil {
		return 0, err
	}
	link := filepath.Join(rootfs, "run", "esf-exit")
	_ = os.Remove(link)
	if err := os.Symlink(target, link); err != nil {
		return 0, err
	}
	return 0, nil
}

func TestExecuteExitFileSymlinkDoesNotLeakHostFile(t *testing.T) {
	const marker = "HOST-FILE-MARKER-9f27c1"
	hostFile := filepath.Join(t.TempDir(), "host-secret")
	if err := os.WriteFile(hostFile, []byte(marker+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		relative bool
	}{
		{name: "absolute symlink", relative: false},
		{name: "relative symlink escape", relative: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sb := testSandbox(t, &execFake{}, nil)
			// testSandbox's seam is typed for *execFake; substitute the
			// provider's runner with the symlink-planting fake.
			sb.provider.run = &exitSymlinkFake{hostFile: hostFile, relative: tc.relative}
			_, err := sb.Execute(context.Background(), sandbox.Command{Argv: []string{"true"}})
			if err == nil {
				t.Fatalf("Execute succeeded with a symlinked exit file, want error")
			}
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("error leaked host file contents: %v", err)
			}
		})
	}
}

func TestExecuteTimeoutKillsContainer(t *testing.T) {
	fr := &execFake{blockRun: true}
	sb := testSandbox(t, fr, nil)
	exec, err := sb.Execute(context.Background(), sandbox.Command{Script: "sleep 30", Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !exec.TimedOut || exec.ExitCode != -1 {
		t.Fatalf("Execution = %+v, want TimedOut with ExitCode -1", exec)
	}
	if len(fr.killed) != 1 || !strings.HasPrefix(fr.killed[0], "esf-run-"+sb.id) {
		t.Fatalf("killed = %v, want the esf-run container for this sandbox", fr.killed)
	}
}

func TestExecuteBoundedScriptContract(t *testing.T) {
	script := boundedCommandScript("echo hi", 2048)
	for _, want := range []string{"echo hi", "ESF_OUTPUT_LIMIT_EXCEEDED", "122", "/run/esf-exit", "2048"} {
		if !strings.Contains(script, want) {
			t.Fatalf("boundedCommandScript missing %q:\n%s", want, script)
		}
	}
}

func TestResolveInRootfsRejectsEscape(t *testing.T) {
	rootfs := t.TempDir()
	// usrmerge-style relative symlink inside the rootfs: allowed.
	if err := os.MkdirAll(filepath.Join(rootfs, "usr", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "usr", "bin", "sh"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("usr/bin", filepath.Join(rootfs, "bin")); err != nil {
		t.Fatal(err)
	}
	got, err := resolveInRootfs(rootfs, "/bin/sh")
	if err != nil || got != filepath.Join(rootfs, "usr", "bin", "sh") {
		t.Fatalf("usrmerge resolve = %q, %v", got, err)
	}
	// Relative symlink escaping the rootfs: rejected.
	// The link target here is relative on purpose: resolveInRootfs
	// (pinned by state_test.go's usrmerge/absolute tests) reinterprets
	// absolute targets as rootfs-relative — containment, not escape.
	// A relative target is the actual escape vector, so the link is
	// created with the relative path to the outside directory.
	outside := t.TempDir()
	relEscape, err := filepath.Rel(rootfs, outside)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(relEscape, filepath.Join(rootfs, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveInRootfs(rootfs, "/escape/passwd"); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("symlink escape: err = %v, want ErrInvalidSpec", err)
	}
	// Lexical escapes are contained (paths are rootfs-relative by
	// construction) — the result must stay under rootfs.
	got, err = resolveInRootfs(rootfs, "/../../etc/passwd")
	if err != nil || !isUnder(rootfs, got) {
		t.Fatalf("lexical escape = %q, %v; want a path under rootfs", got, err)
	}
	// Ordinary create path (parents don't exist yet).
	got, err = resolveInRootfs(rootfs, "/workspace/repo/file.txt")
	if err != nil || got != filepath.Join(rootfs, "workspace", "repo", "file.txt") {
		t.Fatalf("create path = %q, %v", got, err)
	}
	if _, err := resolveInRootfs(rootfs, "relative/path"); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("relative path: err = %v, want ErrInvalidSpec", err)
	}
}

func TestWriteReadFileRoundTrip(t *testing.T) {
	ctx := context.Background()
	sb := testSandbox(t, &execFake{}, nil)
	data := []byte("hello factory\n")
	if err := sb.WriteFile(ctx, "/workspace/repo/greeting.txt", data); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	back, err := sb.ReadFile(ctx, "/workspace/repo/greeting.txt")
	if err != nil || !bytes.Equal(back, data) {
		t.Fatalf("ReadFile = %q, %v", back, err)
	}
	if _, err := sb.ReadFile(ctx, "/workspace/missing.txt"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadFile missing: err = %v, want fs.ErrNotExist in chain", err)
	}
	if err := sb.WriteFile(ctx, "", data); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("WriteFile empty path: err = %v, want ErrInvalidSpec", err)
	}
}

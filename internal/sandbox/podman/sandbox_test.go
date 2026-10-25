package podman

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
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

// runBoundedScript executes boundedCommandScript under the host bash
// with TMPDIR pointed at a test-controlled directory and samples the
// total regular-file bytes stored under it while the script runs. It
// returns the script's exit code, its stdout and stderr, the peak
// stored bytes observed mid-run, and the content of the exit-code file
// the script wrote (host /run/esf-exit; "" with checkExit=false when
// that file could not be staged/observed cleanly).
func runBoundedScript(t *testing.T, line string, limit int64) (code int, stdout, stderr string, peak int64, exitFile string, checkExit bool) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	// The script records its exit code at the in-sandbox path
	// /run/esf-exit; on the host that is a real file. Stage it away so
	// the post-run read observes this run only.
	if err := os.Remove(exitFilePath); err == nil || os.IsNotExist(err) {
		checkExit = true
		defer func() { _ = os.Remove(exitFilePath) }()
	}
	tmp := t.TempDir()
	// A wrapper generation that stages capture files at an absolute
	// /tmp template ignores TMPDIR; account for /tmp/esf-* files that
	// appear after the run starts (pre-existing ones are excluded).
	preExisting := map[string]bool{}
	if matches, _ := filepath.Glob("/tmp/esf-*"); true {
		for _, m := range matches {
			preExisting[m] = true
		}
	}
	storedBytes := func() int64 {
		var total int64
		_ = filepath.Walk(tmp, func(_ string, info os.FileInfo, err error) error {
			if err == nil && info.Mode().IsRegular() {
				total += info.Size()
			}
			return nil
		})
		if matches, _ := filepath.Glob("/tmp/esf-*"); true {
			for _, m := range matches {
				if preExisting[m] {
					continue
				}
				if info, err := os.Stat(m); err == nil && info.Mode().IsRegular() {
					total += info.Size()
				}
			}
		}
		return total
	}
	cmd := exec.Command("bash", "-c", boundedCommandScript(line, limit))
	cmd.Dir = tmp
	cmd.Env = append(os.Environ(), "TMPDIR="+tmp)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start wrapper: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.Now().Add(60 * time.Second)
	for {
		if total := storedBytes(); total > peak {
			peak = total
		}
		select {
		case <-done:
			if checkExit {
				if data, err := os.ReadFile(exitFilePath); err == nil {
					exitFile = string(data)
				} else {
					checkExit = false
				}
			}
			return cmd.ProcessState.ExitCode(), outBuf.String(), errBuf.String(), peak, exitFile, checkExit
		case <-time.After(20 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatalf("wrapper script did not finish within 60s (possible FIFO deadlock)")
		}
	}
}

// TestBoundedScriptBoundsStorageWhileRunning is the regression test
// for the post-hoc bounding defect: the capture mechanism must bound
// stored bytes WHILE the command runs, not merely truncate the
// response after it exits. The staged producer emits 1 MiB in total
// (bursts separated by sleeps so mid-run storage can be sampled)
// against a 2048-byte per-stream limit.
func TestBoundedScriptBoundsStorageWhileRunning(t *testing.T) {
	const limit = 2048
	line := `head -c 8192 /dev/zero | tr '\0' 'a'; sleep 2; head -c 8192 /dev/zero | tr '\0' 'a'; sleep 2; head -c 1032192 /dev/zero | tr '\0' 'a'`
	code, stdout, stderr, peak, exitFile, checkExit := runBoundedScript(t, line, limit)
	// Two streams, each hard-capped by its reader at limit+1 stored
	// bytes, plus small slack: the store can never approach the
	// producer's 1 MiB, whatever the exit path.
	const bound = 2*(limit+1) + 256
	if peak > bound {
		t.Fatalf("peak stored bytes during run = %d, want <= %d (limit %d per stream)", peak, bound, limit)
	}
	if code != 122 {
		t.Fatalf("exit code = %d, want 122 on overflow", code)
	}
	if int64(len(stdout)) != limit {
		t.Fatalf("stdout len = %d, want exactly the %d-byte limit", len(stdout), limit)
	}
	if !strings.Contains(stderr, "ESF_OUTPUT_LIMIT_EXCEEDED") {
		t.Fatalf("stderr lacks overflow marker: %q", stderr)
	}
	if checkExit && exitFile != "122" {
		t.Fatalf("exit file = %q, want \"122\"", exitFile)
	}
}

// TestBoundedScriptBehaviorContract pins the wrapper's observable
// contract through real execution: exact-limit output is not overflow,
// one byte over is, and ordinary commands keep their exit code and
// streams untouched.
func TestBoundedScriptBehaviorContract(t *testing.T) {
	const limit = 2048
	t.Run("exact limit is not overflow", func(t *testing.T) {
		code, stdout, stderr, _, exitFile, checkExit := runBoundedScript(t, `head -c 2048 /dev/zero | tr '\0' 'b'`, limit)
		if code != 0 || int64(len(stdout)) != limit || strings.Contains(stderr, "ESF_OUTPUT_LIMIT_EXCEEDED") {
			t.Fatalf("code=%d stdout=%d stderr=%q, want 0/%d/no marker", code, len(stdout), stderr, limit)
		}
		if checkExit && exitFile != "0" {
			t.Fatalf("exit file = %q, want \"0\"", exitFile)
		}
	})
	t.Run("one byte over is overflow", func(t *testing.T) {
		code, stdout, stderr, _, _, _ := runBoundedScript(t, `head -c 2049 /dev/zero | tr '\0' 'b'`, limit)
		if code != 122 || int64(len(stdout)) != limit || !strings.Contains(stderr, "ESF_OUTPUT_LIMIT_EXCEEDED") {
			t.Fatalf("code=%d stdout=%d stderr=%q, want 122/%d/marker", code, len(stdout), stderr, limit)
		}
	})
	t.Run("ordinary command keeps exit code and streams", func(t *testing.T) {
		code, stdout, stderr, _, exitFile, checkExit := runBoundedScript(t, `printf 'hello'; printf 'oops' >&2; exit 7`, limit)
		if code != 7 || stdout != "hello" || stderr != "oops" {
			t.Fatalf("code=%d stdout=%q stderr=%q, want 7/hello/oops", code, stdout, stderr)
		}
		if checkExit && exitFile != "7" {
			t.Fatalf("exit file = %q, want \"7\"", exitFile)
		}
	})
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

// TestResolveInRootfsDeepPlainPath is the regression test for the hop
// budget counting every path component instead of only symlink
// expansions: a path through more than 16 perfectly ordinary
// directories — zero symlinks anywhere — must resolve.
func TestResolveInRootfsDeepPlainPath(t *testing.T) {
	rootfs := t.TempDir()
	deep, path := rootfs, ""
	for i := 1; i <= 18; i++ {
		name := fmt.Sprintf("d%02d", i)
		deep = filepath.Join(deep, name)
		path += "/" + name
	}
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "file.txt"), []byte("deep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := resolveInRootfs(rootfs, path+"/file.txt")
	if err != nil {
		t.Fatalf("resolveInRootfs(19 plain components) = %v, want nil", err)
	}
	if want := filepath.Join(deep, "file.txt"); got != want {
		t.Fatalf("resolveInRootfs(19 plain components) = %q, want %q", got, want)
	}
}

// TestReadWriteFileDeepPath covers the same regression through the
// Sandbox surface: WriteFile creates the deep tree, ReadFile must walk
// every existing component without tripping the symlink budget.
func TestReadWriteFileDeepPath(t *testing.T) {
	ctx := context.Background()
	sb := testSandbox(t, &execFake{}, nil)
	path := ""
	for i := 1; i <= 18; i++ {
		path += fmt.Sprintf("/d%02d", i)
	}
	path += "/file.txt"
	data := []byte("deep\n")
	if err := sb.WriteFile(ctx, path, data); err != nil {
		t.Fatalf("WriteFile deep path: %v", err)
	}
	back, err := sb.ReadFile(ctx, path)
	if err != nil || !bytes.Equal(back, data) {
		t.Fatalf("ReadFile deep path = %q, %v", back, err)
	}
}

// TestResolveInRootfsSymlinkCycleRejected pins what the hop budget is
// actually for: a symlink cycle (a -> b -> a) must still fail with the
// too-many-hops error once the budget counts expansions only.
func TestResolveInRootfsSymlinkCycleRejected(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.Symlink("b", filepath.Join(rootfs, "a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a", filepath.Join(rootfs, "b")); err != nil {
		t.Fatal(err)
	}
	_, err := resolveInRootfs(rootfs, "/a")
	if !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("symlink cycle: err = %v, want ErrInvalidSpec", err)
	}
	if !strings.Contains(err.Error(), "too many symlink hops") {
		t.Fatalf("symlink cycle: err = %v, want too-many-hops message", err)
	}
}

// TestResolveInRootfsLongSymlinkChainRejected pins the budget against
// a finite but over-long chain: 20 symlinks (budget 16) ending at a
// real directory must still fail with the too-many-hops error.
func TestResolveInRootfsLongSymlinkChainRejected(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "real", "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	const links = 20
	for i := links - 1; i >= 0; i-- {
		target := "real"
		if i < links-1 {
			target = fmt.Sprintf("l%02d", i+1)
		}
		if err := os.Symlink(target, filepath.Join(rootfs, fmt.Sprintf("l%02d", i))); err != nil {
			t.Fatal(err)
		}
	}
	_, err := resolveInRootfs(rootfs, "/l00/f.txt")
	if !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("20-link chain: err = %v, want ErrInvalidSpec", err)
	}
	if !strings.Contains(err.Error(), "too many symlink hops") {
		t.Fatalf("20-link chain: err = %v, want too-many-hops message", err)
	}
}

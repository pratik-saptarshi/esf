package podman

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mitkox/esf/internal/sandbox"
)

// exitFilePath is where the in-sandbox wrapper records the command's
// exit code, inside the rootfs so the host can read it after the run.
const exitFilePath = "/run/esf-exit"

type podmanSandbox struct {
	provider *Provider
	id       string
	image    string
	env      map[string]string
	dir      string
	rootfs   string
}

func (s *podmanSandbox) ID() string       { return s.id }
func (s *podmanSandbox) Template() string { return s.image }

func (s *podmanSandbox) Destroy(ctx context.Context) error {
	return s.provider.Destroy(ctx, s.id)
}

func (s *podmanSandbox) Execute(ctx context.Context, cmd sandbox.Command) (sandbox.Execution, error) {
	line, err := sandbox.CommandLine(cmd)
	if err != nil {
		return sandbox.Execution{}, err
	}
	p := s.provider
	// Remove any stale exit file so a missing file after this run is
	// unambiguously a transport failure (decision D5).
	exitHostPath := filepath.Join(s.rootfs, "run", "esf-exit")
	_ = os.Remove(exitHostPath)

	name := fmt.Sprintf("esf-run-%s-%d", s.id, p.seq.Add(1))
	args := p.cfg.baseArgs()
	args = append(args, "run", "--rm", "-i", "--name", name)
	if p.cfg.Network != "" {
		args = append(args, "--network", p.cfg.Network)
	}
	if p.cfg.User != "" {
		args = append(args, "--user", p.cfg.User)
	}
	if cmd.Dir != "" {
		args = append(args, "-w", cmd.Dir)
	}
	for _, kv := range mergedEnv(s.env, cmd.Env) {
		args = append(args, "-e", kv)
	}
	args = append(args, "--rootfs", s.rootfs, "/bin/bash", "-lc", exitFileScript(line))

	runCtx := ctx
	cancel := func() {}
	if cmd.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, cmd.Timeout)
	}
	defer cancel()

	var stdin io.Reader
	if cmd.Stdin != nil {
		stdin = bytes.NewReader(cmd.Stdin)
	}
	started := time.Now()
	var outBuf, errBuf bytes.Buffer
	code, runErr := p.run.Run(runCtx, stdin, &outBuf, &errBuf, args...)
	finished := time.Now()
	exec := sandbox.Execution{
		StartedAt: started, CompletedAt: finished, Duration: finished.Sub(started),
		Stdout: outBuf.String(), Stderr: errBuf.String(),
	}
	if runCtx.Err() != nil {
		// Mirror cube's Execute: distinguish purely by error kind, not by
		// whether cmd.Timeout was set. A caller cancellation is not a
		// timeout even when a timeout was also configured.
		p.killRunContainer(name)
		exec.ExitCode = -1
		if errors.Is(runCtx.Err(), context.Canceled) {
			exec.TimedOut = false
			exec.Stderr = "command cancelled"
			return exec, nil
		}
		exec.TimedOut = true
		exec.Stderr = "command timed out"
		return exec, nil
	}
	if runErr != nil {
		return exec, classify(runErr, errBuf.String())
	}
	_ = code // podman's status is deliberately not the command's; see exitFileScript.
	data, err := os.ReadFile(exitHostPath)
	if err != nil {
		return exec, fmt.Errorf("%w: sandbox %s command did not record an exit code (podman exited %d): %s",
			ErrUnavailable, s.id, code, tailText(errBuf.String()))
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return exec, fmt.Errorf("%w: sandbox %s recorded an unreadable exit code %q", ErrUnavailable, s.id, string(data))
	}
	exec.ExitCode = n
	return exec, nil
}

func (p *Provider) killRunContainer(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = p.invoke(ctx, "kill", name)
}

// exitFileScript wraps a rendered command line so the command's exit
// code is written to exitFilePath before the shell exits with it.
func exitFileScript(line string) string {
	return "mkdir -p /run\n" +
		line + "\n" +
		"esf_exit=$?\n" +
		"printf '%s' \"$esf_exit\" > " + exitFilePath + "\n" +
		"exit \"$esf_exit\"\n"
}

// mergedEnv renders spec env overridden by command env as sorted K=V
// pairs (sorted for deterministic argv in tests and logs).
func mergedEnv(specEnv, cmdEnv map[string]string) []string {
	merged := make(map[string]string, len(specEnv)+len(cmdEnv))
	for k, v := range specEnv {
		merged[k] = v
	}
	for k, v := range cmdEnv {
		merged[k] = v
	}
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+merged[k])
	}
	return out
}

// WriteFile writes data at path inside the sandbox rootfs, creating
// parent directories (mirroring cube's mkdir -p + write). The rootfs is
// host-visible state, so this is a host-side operation (decision D4).
func (s *podmanSandbox) WriteFile(ctx context.Context, path string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%w: write file path is required", ErrInvalidSpec)
	}
	target, err := resolveInRootfs(s.rootfs, path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("create parent directory for %s in sandbox %s: %w", path, s.id, err)
	}
	if err := os.WriteFile(target, data, 0o644); err != nil {
		return fmt.Errorf("write file %s in sandbox %s: %w", path, s.id, err)
	}
	return nil
}

func (s *podmanSandbox) ReadFile(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("%w: read file path is required", ErrInvalidSpec)
	}
	target, err := resolveInRootfs(s.rootfs, path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(target)
	if err != nil {
		return nil, fmt.Errorf("read file %s in sandbox %s: %w", path, s.id, err)
	}
	return data, nil
}

// resolveInRootfs maps an absolute sandbox path to a host path inside
// rootfs, rejecting escapes — including escapes through symlinks already
// present in the rootfs (image content is not fully trusted; see
// extractRootfs). Absolute symlink targets are reinterpreted as
// rootfs-relative, matching how the kernel resolves them under
// `podman run --rootfs` (e.g. usrmerge /bin -> /usr/bin).
func resolveInRootfs(rootfs, path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%w: sandbox path %q must be absolute", ErrInvalidSpec, path)
	}
	current := rootfs
	rest := strings.TrimPrefix(filepath.Clean(path), "/")
	for hops := 0; rest != ""; hops++ {
		if hops > 16 {
			return "", fmt.Errorf("%w: sandbox path %q has too many symlink hops", ErrInvalidSpec, path)
		}
		head, tail, _ := strings.Cut(rest, "/")
		rest = tail
		if head == ".." {
			return "", fmt.Errorf("%w: sandbox path %q escapes the rootfs", ErrInvalidSpec, path)
		}
		next := filepath.Join(current, head)
		fi, err := os.Lstat(next)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				// Remaining components don't exist yet (WriteFile create
				// path): they cannot be symlinks, append verbatim after a
				// final containment check.
				final := filepath.Join(next, rest)
				if !isUnder(rootfs, final) {
					return "", fmt.Errorf("%w: sandbox path %q escapes the rootfs", ErrInvalidSpec, path)
				}
				return final, nil
			}
			return "", fmt.Errorf("stat sandbox path %q: %w", path, err)
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(next)
			if err != nil {
				return "", fmt.Errorf("read sandbox symlink %q: %w", path, err)
			}
			if filepath.IsAbs(target) {
				current = rootfs
				rest = strings.TrimPrefix(filepath.Clean(target), "/") + slashJoin(rest)
			} else {
				resolved := filepath.Join(current, target)
				if !isUnder(rootfs, resolved) {
					return "", fmt.Errorf("%w: sandbox path %q escapes the rootfs via symlink", ErrInvalidSpec, path)
				}
				current = resolved
			}
			continue
		}
		current = next
	}
	if !isUnder(rootfs, current) {
		return "", fmt.Errorf("%w: sandbox path %q escapes the rootfs", ErrInvalidSpec, path)
	}
	return current, nil
}

func slashJoin(rest string) string {
	if rest == "" {
		return ""
	}
	return "/" + rest
}

func isUnder(root, path string) bool {
	return path == root || strings.HasPrefix(path, root+string(os.PathSeparator))
}

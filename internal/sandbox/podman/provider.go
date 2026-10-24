package podman

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mitkox/esf/internal/sandbox"
)

// ProviderName is reported by Provider.Name and recorded in
// sandbox.Info.ProviderID.
const ProviderName = "podman"

// Provider implements sandbox.Provider on podman. Sandboxes are
// directories: <StateDir>/<id>/spec.json + <StateDir>/<id>/rootfs.
type Provider struct {
	cfg Config
	log *slog.Logger
	run runner
	seq atomic.Uint64
}

// Option customizes a Provider.
type Option func(*Provider)

// WithLogger sets the provider logger (default slog.Default()).
func WithLogger(log *slog.Logger) Option {
	return func(p *Provider) {
		if log != nil {
			p.log = log
		}
	}
}

// New validates cfg and returns a Provider. It does not contact podman;
// call Ping for a reachability check (factory's RunWorker does).
func New(cfg Config, opts ...Option) (*Provider, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	p := &Provider{cfg: cfg, log: slog.Default(), run: execRunner{binary: cfg.effectiveBinary()}}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

func (p *Provider) Name() string { return ProviderName }

// Capabilities is deliberately all-false: the one-shot container model
// has no snapshot, clone, suspend, resume, or preview semantics, and the
// factory degrades those features by design when they are absent.
func (p *Provider) Capabilities() sandbox.Capabilities { return sandbox.Capabilities{} }

// Ping mirrors cube's Ping shape: the backend must answer AND the
// configured template image must be present locally.
func (p *Provider) Ping(ctx context.Context) error {
	ctx, cancel := p.opCtx(ctx)
	defer cancel()
	res, err := p.invoke(ctx, "info", "--format", "json")
	if err != nil {
		return fmt.Errorf("%w: podman info: %v", ErrUnavailable, err)
	}
	if res.Code != 0 {
		return classify(fmt.Errorf("podman info exited %d", res.Code), string(res.Stderr))
	}
	return p.imageExists(ctx, p.cfg.Image)
}

func (p *Provider) imageExists(ctx context.Context, image string) error {
	res, err := p.invoke(ctx, "image", "exists", image)
	if err != nil {
		return fmt.Errorf("%w: podman image exists: %v", ErrUnavailable, err)
	}
	if res.Code != 0 {
		return fmt.Errorf("%w: image %s: podman exited %d: %s", ErrTemplateNotFound, image, res.Code, tailText(string(res.Stderr)))
	}
	return nil
}

// ensureImage makes the image available locally, pulling when missing.
func (p *Provider) ensureImage(ctx context.Context, image string) error {
	if err := p.imageExists(ctx, image); err == nil {
		return nil
	}
	res, err := p.invoke(ctx, "pull", image)
	if err != nil {
		return fmt.Errorf("%w: podman pull %s: %v", ErrUnavailable, image, err)
	}
	if res.Code != 0 {
		return classify(fmt.Errorf("podman pull %s exited %d", image, res.Code), string(res.Stderr))
	}
	return nil
}

func (p *Provider) Create(ctx context.Context, spec sandbox.Spec) (sandbox.Sandbox, error) {
	image := strings.TrimSpace(spec.Template)
	if image == "" {
		image = p.cfg.Image
	}
	if image == "" {
		return nil, fmt.Errorf("%w: create requires an image (spec.template or [podman] image)", ErrNotConfigured)
	}
	stateDir, err := p.cfg.effectiveStateDir()
	if err != nil {
		return nil, err
	}
	id, err := newSandboxID()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(stateDir, id)
	rootfs := filepath.Join(dir, "rootfs")
	if err := os.MkdirAll(rootfs, 0o700); err != nil {
		return nil, fmt.Errorf("create sandbox state dir: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(dir)
		}
	}()
	opCtx, cancel := p.opCtx(ctx)
	defer cancel()
	if err := p.materializeRootfs(opCtx, image, id, rootfs); err != nil {
		return nil, err
	}
	st := stateFromSpec(id, image, spec)
	if err := writeState(dir, st); err != nil {
		return nil, err
	}
	ok = true
	p.log.Info("podman sandbox created", "sandbox_id", id, "image", image)
	return p.handle(st, dir), nil
}

// materializeRootfs extracts image's filesystem into rootfs via a
// throwaway container: create -> export -> rm. The container never runs.
func (p *Provider) materializeRootfs(ctx context.Context, image, id, rootfs string) error {
	if err := p.ensureImage(ctx, image); err != nil {
		return err
	}
	name := "esf-create-" + strings.TrimPrefix(id, "podman-")
	res, err := p.invoke(ctx, "create", "--name", name, image)
	if err != nil {
		return fmt.Errorf("%w: podman create: %v", ErrUnavailable, err)
	}
	if res.Code != 0 {
		return classify(fmt.Errorf("podman create exited %d", res.Code), string(res.Stderr))
	}
	defer func() {
		rmCtx, rmCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer rmCancel()
		_, _ = p.invoke(rmCtx, "rm", "-f", name)
	}()
	// Export streams the tar on stdout; write it to a file first so a
	// failed export never leaves a half-extracted rootfs behind.
	tmp, err := os.CreateTemp(filepath.Dir(rootfs), "esf-export-*.tar")
	if err != nil {
		return fmt.Errorf("create export temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	var errBuf strings.Builder
	args := append(append([]string{}, p.cfg.baseArgs()...), "export", name)
	code, runErr := p.run.Run(ctx, nil, tmp, &errBuf, args...)
	if runErr != nil {
		return fmt.Errorf("%w: podman export: %v", ErrUnavailable, runErr)
	}
	if code != 0 {
		return classify(fmt.Errorf("podman export exited %d", code), errBuf.String())
	}
	if _, err := tmp.Seek(0, 0); err != nil {
		return err
	}
	return extractRootfs(tmp, rootfs)
}

func (p *Provider) Reattach(ctx context.Context, id string) (sandbox.Sandbox, error) {
	dir, err := p.sandboxDir(id)
	if err != nil {
		return nil, err
	}
	st, err := readState(dir)
	if err != nil {
		return nil, err
	}
	return p.handle(st, dir), nil
}

// Destroy removes the sandbox's state and rootfs and best-effort removes
// any lingering one-shot containers for it. It is idempotent for
// well-formed IDs (mirroring cube) and rejects malformed IDs before
// touching the filesystem.
func (p *Provider) Destroy(ctx context.Context, id string) error {
	dir, err := p.sandboxDir(id)
	if err != nil {
		return err
	}
	p.sweepRunContainers(ctx, id)
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove sandbox %s state: %w", id, err)
	}
	return nil
}

func (p *Provider) List(ctx context.Context) ([]sandbox.Info, error) {
	stateDir, err := p.cfg.effectiveStateDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list sandbox state dir: %w", err)
	}
	var infos []sandbox.Info
	for _, e := range entries {
		if !e.IsDir() || !validSandboxID(e.Name()) {
			continue
		}
		st, err := readState(filepath.Join(stateDir, e.Name()))
		if err != nil {
			p.log.Warn("skipping unreadable podman sandbox state", "sandbox_id", e.Name(), "error", err)
			continue
		}
		infos = append(infos, sandbox.Info{
			ID: st.ID, ProviderID: ProviderName, State: sandbox.StateRunning,
			Template: st.Image, StartedAt: st.CreatedAt, Metadata: st.Metadata,
		})
	}
	return infos, nil
}

// sweepRunContainers removes containers left behind by Execute calls for
// the sandbox (e.g. after a factory crash). Best-effort by design.
func (p *Provider) sweepRunContainers(ctx context.Context, id string) {
	sweepCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	res, err := p.invoke(sweepCtx, "ps", "-a", "--filter", "name=esf-run-"+id, "--format", "{{.Names}}")
	if err != nil || res.Code != 0 {
		return
	}
	for _, name := range strings.Fields(string(res.Stdout)) {
		_, _ = p.invoke(sweepCtx, "rm", "-f", name)
	}
}

func (p *Provider) sandboxDir(id string) (string, error) {
	if !validSandboxID(id) {
		return "", fmt.Errorf("%w: sandbox id %q", ErrInvalidSpec, id)
	}
	stateDir, err := p.cfg.effectiveStateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(stateDir, id), nil
}

func (p *Provider) handle(st sandboxState, dir string) *podmanSandbox {
	return &podmanSandbox{provider: p, id: st.ID, image: st.Image, env: st.Env, dir: dir, rootfs: filepath.Join(dir, "rootfs")}
}

func (p *Provider) opCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, p.cfg.effectiveRequestTimeout())
}

var _ sandbox.Provider = (*Provider)(nil)

package sandbox

import (
	"context"
	"fmt"
)

// WrapProvider returns a Provider that decorates inner with
// OpenTelemetry spans at the Provider/Sandbox seam (see telemetry.go
// for the contract and the attribute discipline). Existing providers
// are untouched: the decorator wraps any Provider and wraps every
// Sandbox it hands out.
//
// When telemetry is disabled (ESF_OTEL_FILE unset or unusable),
// WrapProvider returns inner itself, so behaviour is identical down
// to the concrete value.
//
// The decorated provider exposes exactly the optional interfaces
// (Suspender, Previewer, Stater) that inner implements — no more —
// because the factory detects optional support by type assertion and
// must keep recording SKIPPED for providers without them. The same
// holds for the decorated sandbox and NetworkUpdater.
func WrapProvider(inner Provider) Provider {
	tel := telemetryFromEnv()
	if tel == nil {
		return inner
	}
	return wrapTracedProvider(inner, tel)
}

// wrapTracedProvider builds the decorated provider, selecting the
// wrapper shape that mirrors inner's optional interfaces.
func wrapTracedProvider(inner Provider, tel *telemetry) Provider {
	tp := &tracedProvider{inner: inner, tel: tel}
	_, suspender := inner.(Suspender)
	_, previewer := inner.(Previewer)
	_, stater := inner.(Stater)
	switch {
	case suspender && previewer && stater:
		return struct {
			Provider
			Suspender
			Previewer
			Stater
		}{tp, tp, tp, tp}
	case suspender && previewer:
		return struct {
			Provider
			Suspender
			Previewer
		}{tp, tp, tp}
	case suspender && stater:
		return struct {
			Provider
			Suspender
			Stater
		}{tp, tp, tp}
	case previewer && stater:
		return struct {
			Provider
			Previewer
			Stater
		}{tp, tp, tp}
	case suspender:
		return struct {
			Provider
			Suspender
		}{tp, tp}
	case previewer:
		return struct {
			Provider
			Previewer
		}{tp, tp}
	case stater:
		return struct {
			Provider
			Stater
		}{tp, tp}
	default:
		// Even the base case goes through an anonymous struct:
		// tracedProvider itself implements the optional interfaces
		// by delegation, and returning it bare would expose them
		// all regardless of what inner supports.
		return struct{ Provider }{tp}
	}
}

// wrapTracedSandbox builds the decorated sandbox, exposing
// NetworkUpdater only when the inner sandbox implements it.
func wrapTracedSandbox(inner Sandbox, tel *telemetry, providerName string) Sandbox {
	ts := &tracedSandbox{inner: inner, tel: tel, provider: providerName}
	if _, ok := inner.(NetworkUpdater); ok {
		return struct {
			Sandbox
			NetworkUpdater
		}{ts, ts}
	}
	// As in wrapTracedProvider, the bare tracedSandbox would expose
	// NetworkUpdater even when the inner sandbox lacks it.
	return struct{ Sandbox }{ts}
}

// tracedProvider decorates a Provider with seam spans. It implements
// the optional lifecycle interfaces by delegation; WrapProvider only
// exposes them when the inner provider implements them, so the
// delegation fallbacks below are unreachable through the public
// wrapper.
type tracedProvider struct {
	inner Provider
	tel   *telemetry
}

func (p *tracedProvider) Name() string { return p.inner.Name() }

func (p *tracedProvider) Capabilities() Capabilities { return p.inner.Capabilities() }

func (p *tracedProvider) Create(ctx context.Context, spec Spec) (Sandbox, error) {
	ctx, rec := p.tel.start(ctx, "create")
	rec.set("provider", p.inner.Name())
	sb, err := p.inner.Create(ctx, spec)
	if err != nil {
		rec.finish(err)
		return nil, err
	}
	rec.set("sandbox_id", sb.ID())
	rec.finish(nil)
	return wrapTracedSandbox(sb, p.tel, p.inner.Name()), nil
}

func (p *tracedProvider) Reattach(ctx context.Context, sandboxID string) (Sandbox, error) {
	ctx, rec := p.tel.start(ctx, "reattach")
	rec.set("provider", p.inner.Name())
	rec.set("sandbox_id", sandboxID)
	sb, err := p.inner.Reattach(ctx, sandboxID)
	if err != nil {
		rec.finish(err)
		return nil, err
	}
	rec.finish(nil)
	return wrapTracedSandbox(sb, p.tel, p.inner.Name()), nil
}

func (p *tracedProvider) Destroy(ctx context.Context, sandboxID string) error {
	ctx, rec := p.tel.start(ctx, "destroy")
	rec.set("provider", p.inner.Name())
	rec.set("sandbox_id", sandboxID)
	err := p.inner.Destroy(ctx, sandboxID)
	rec.finish(err)
	return err
}

func (p *tracedProvider) List(ctx context.Context) ([]Info, error) {
	ctx, rec := p.tel.start(ctx, "list")
	rec.set("provider", p.inner.Name())
	infos, err := p.inner.List(ctx)
	rec.finish(err)
	return infos, err
}

func (p *tracedProvider) Ping(ctx context.Context) error {
	ctx, rec := p.tel.start(ctx, "ping")
	rec.set("provider", p.inner.Name())
	err := p.inner.Ping(ctx)
	rec.finish(err)
	return err
}

// Suspend implements Suspender by delegation, with a span.
func (p *tracedProvider) Suspend(ctx context.Context, sandboxID string) error {
	suspender, ok := p.inner.(Suspender)
	if !ok {
		return fmt.Errorf("sandbox: provider %s does not support suspend", p.inner.Name())
	}
	ctx, rec := p.tel.start(ctx, "suspend")
	rec.set("provider", p.inner.Name())
	rec.set("sandbox_id", sandboxID)
	err := suspender.Suspend(ctx, sandboxID)
	rec.finish(err)
	return err
}

// Resume implements Suspender by delegation, with a span.
func (p *tracedProvider) Resume(ctx context.Context, sandboxID string) error {
	suspender, ok := p.inner.(Suspender)
	if !ok {
		return fmt.Errorf("sandbox: provider %s does not support resume", p.inner.Name())
	}
	ctx, rec := p.tel.start(ctx, "resume")
	rec.set("provider", p.inner.Name())
	rec.set("sandbox_id", sandboxID)
	err := suspender.Resume(ctx, sandboxID)
	rec.finish(err)
	return err
}

// PreviewURL implements Previewer by delegation, with a span. The
// returned URL is never recorded as an attribute.
func (p *tracedProvider) PreviewURL(ctx context.Context, sandboxID string, port int) (string, error) {
	previewer, ok := p.inner.(Previewer)
	if !ok {
		return "", fmt.Errorf("sandbox: provider %s does not support preview", p.inner.Name())
	}
	ctx, rec := p.tel.start(ctx, "preview")
	rec.set("provider", p.inner.Name())
	rec.set("sandbox_id", sandboxID)
	url, err := previewer.PreviewURL(ctx, sandboxID, port)
	rec.finish(err)
	return url, err
}

// SandboxState implements Stater by delegation, with a span. The
// reported state is never recorded as an attribute.
func (p *tracedProvider) SandboxState(ctx context.Context, sandboxID string) (string, error) {
	stater, ok := p.inner.(Stater)
	if !ok {
		return "", fmt.Errorf("sandbox: provider %s does not support state", p.inner.Name())
	}
	ctx, rec := p.tel.start(ctx, "sandbox_state")
	rec.set("provider", p.inner.Name())
	rec.set("sandbox_id", sandboxID)
	state, err := stater.SandboxState(ctx, sandboxID)
	rec.finish(err)
	return state, err
}

// tracedSandbox decorates a Sandbox with seam spans.
type tracedSandbox struct {
	inner    Sandbox
	tel      *telemetry
	provider string
}

func (s *tracedSandbox) ID() string { return s.inner.ID() }

func (s *tracedSandbox) Template() string { return s.inner.Template() }

// Execute records the command's exit code as an attribute. A
// non-zero exit is a result, not a transport failure, so it never
// becomes an ERROR status; only a returned error does. The command
// itself — argv, script, env, stdin — is never recorded.
func (s *tracedSandbox) Execute(ctx context.Context, cmd Command) (Execution, error) {
	ctx, rec := s.tel.start(ctx, "execute")
	rec.set("provider", s.provider)
	rec.set("sandbox_id", s.inner.ID())
	exec, err := s.inner.Execute(ctx, cmd)
	if err != nil {
		rec.finish(err)
		return exec, err
	}
	rec.set("exit_code", int64(exec.ExitCode))
	rec.finish(nil)
	return exec, nil
}

// WriteFile records only the operation; the path and data are never
// recorded.
func (s *tracedSandbox) WriteFile(ctx context.Context, path string, data []byte) error {
	ctx, rec := s.tel.start(ctx, "write_file")
	rec.set("provider", s.provider)
	rec.set("sandbox_id", s.inner.ID())
	err := s.inner.WriteFile(ctx, path, data)
	rec.finish(err)
	return err
}

// ReadFile records only the operation; the path and the returned
// contents are never recorded.
func (s *tracedSandbox) ReadFile(ctx context.Context, path string) ([]byte, error) {
	ctx, rec := s.tel.start(ctx, "read_file")
	rec.set("provider", s.provider)
	rec.set("sandbox_id", s.inner.ID())
	data, err := s.inner.ReadFile(ctx, path)
	rec.finish(err)
	return data, err
}

func (s *tracedSandbox) Destroy(ctx context.Context) error {
	ctx, rec := s.tel.start(ctx, "sandbox_destroy")
	rec.set("provider", s.provider)
	rec.set("sandbox_id", s.inner.ID())
	err := s.inner.Destroy(ctx)
	rec.finish(err)
	return err
}

// UpdateNetwork implements NetworkUpdater by delegation, with a
// span. The network policy is never recorded.
func (s *tracedSandbox) UpdateNetwork(ctx context.Context, network Network) error {
	updater, ok := s.inner.(NetworkUpdater)
	if !ok {
		return fmt.Errorf("sandbox: sandbox %s does not support network updates", s.inner.ID())
	}
	ctx, rec := s.tel.start(ctx, "update_network")
	rec.set("provider", s.provider)
	rec.set("sandbox_id", s.inner.ID())
	err := updater.UpdateNetwork(ctx, network)
	rec.finish(err)
	return err
}

package factory

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mitkox/esf/internal/sandbox"
	"github.com/mitkox/esf/internal/sandbox/cube"
	"github.com/mitkox/esf/internal/sandbox/podman"
)

// stubProvider is a named sandbox.Provider for resolver tests; the
// resolver only reads Name().
type stubProvider struct{ name string }

func (s stubProvider) Name() string { return s.name }
func (s stubProvider) Capabilities() sandbox.Capabilities {
	return sandbox.Capabilities{}
}
func (s stubProvider) Create(context.Context, sandbox.Spec) (sandbox.Sandbox, error) {
	return nil, errors.New("not implemented")
}
func (s stubProvider) Reattach(context.Context, string) (sandbox.Sandbox, error) {
	return nil, errors.New("not implemented")
}
func (s stubProvider) Destroy(context.Context, string) error { return nil }
func (s stubProvider) List(context.Context) ([]sandbox.Info, error) {
	return nil, nil
}
func (s stubProvider) Ping(context.Context) error { return nil }

type fakeProber struct {
	cubeProvider   sandbox.Provider
	cubeDetail     string
	podmanProvider sandbox.Provider
	podmanDetail   string
	hangCube       bool
	calls          []string
}

func (f *fakeProber) Cube(ctx context.Context, _ Config) (sandbox.Provider, ProviderProbe) {
	f.calls = append(f.calls, "cube")
	if f.hangCube {
		<-ctx.Done()
		return nil, ProviderProbe{Provider: ProviderModeCube, Configured: true, Detail: "probe: " + ctx.Err().Error()}
	}
	if f.cubeProvider == nil {
		return nil, ProviderProbe{Provider: ProviderModeCube, Configured: true, Detail: f.cubeDetail}
	}
	return f.cubeProvider, ProviderProbe{Provider: ProviderModeCube, Configured: true, Reachable: true}
}

func (f *fakeProber) Podman(_ context.Context, _ Config) (sandbox.Provider, ProviderProbe) {
	f.calls = append(f.calls, "podman")
	if f.podmanProvider == nil {
		return nil, ProviderProbe{Provider: ProviderModePodman, Configured: true, Detail: f.podmanDetail}
	}
	return f.podmanProvider, ProviderProbe{Provider: ProviderModePodman, Configured: true, Reachable: true}
}

func resolverConfig(mode string) Config {
	return Config{
		Sandbox: SandboxConfig{Provider: mode},
		Cube:    cube.Config{APIURL: "http://127.0.0.1:12088", TemplateID: "tpl-test", ProxyNodeIP: "127.0.0.1", ProxyPortHTTP: 12088, ProxyScheme: "http"},
		Podman:  podman.Config{Image: "localhost/esf-template:debian13-node24"},
	}
}

func TestResolveSandboxProviderExplicitCube(t *testing.T) {
	provider, recon, err := resolveSandboxProvider(context.Background(), resolverConfig(""), nil, &fakeProber{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if recon.Mode != ProviderModeCube || recon.Selected != "cubesandbox" || provider.Name() != "cubesandbox" {
		t.Fatalf("recon = %+v provider = %v", recon, provider)
	}
}

func TestResolveSandboxProviderExplicitPodman(t *testing.T) {
	provider, recon, err := resolveSandboxProvider(context.Background(), resolverConfig("podman"), nil, &fakeProber{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if recon.Mode != ProviderModePodman || recon.Selected != "podman" || provider.Name() != "podman" {
		t.Fatalf("recon = %+v provider = %v", recon, provider)
	}
}

func TestResolveSandboxProviderAutoFallsToPodman(t *testing.T) {
	prober := &fakeProber{cubeDetail: "connection refused", podmanProvider: stubProvider{name: "podman"}}
	provider, recon, err := resolveSandboxProvider(context.Background(), resolverConfig("auto"), nil, prober)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if provider.Name() != "podman" || recon.Selected != "podman" {
		t.Fatalf("selected = %v, recon = %+v", provider, recon)
	}
	if len(recon.Probes) != 2 || recon.Probes[0].Provider != "cubesandbox" || recon.Probes[0].Reachable ||
		recon.Probes[1].Provider != "podman" || !recon.Probes[1].Reachable {
		t.Fatalf("probes = %+v, want cube(failed) then podman(reachable)", recon.Probes)
	}
}

func TestResolveSandboxProviderAutoPrefersCube(t *testing.T) {
	prober := &fakeProber{cubeProvider: stubProvider{name: "cubesandbox"}}
	provider, _, err := resolveSandboxProvider(context.Background(), resolverConfig("auto"), nil, prober)
	if err != nil || provider.Name() != "cubesandbox" {
		t.Fatalf("provider = %v, err = %v", provider, err)
	}
	if len(prober.calls) != 1 || prober.calls[0] != "cube" {
		t.Fatalf("prober calls = %v, want podman never probed when cube works", prober.calls)
	}
}

func TestResolveSandboxProviderAutoFailsClosed(t *testing.T) {
	prober := &fakeProber{cubeDetail: "connection refused", podmanDetail: "image not found"}
	provider, _, err := resolveSandboxProvider(context.Background(), resolverConfig("auto"), nil, prober)
	if err == nil {
		t.Fatal("resolve succeeded with both backends down; want fail-closed error")
	}
	if provider != nil {
		t.Fatalf("provider = %v, want nil on failure (never a silent fake)", provider)
	}
	if !strings.Contains(err.Error(), "cubesandbox") || !strings.Contains(err.Error(), "podman") ||
		!strings.Contains(err.Error(), "connection refused") || !strings.Contains(err.Error(), "image not found") {
		t.Fatalf("error must report BOTH probe outcomes, got: %v", err)
	}
}

func TestResolveSandboxProviderAutoProbeTimeout(t *testing.T) {
	old := probeTimeout
	probeTimeout = 50 * time.Millisecond
	defer func() { probeTimeout = old }()
	prober := &fakeProber{hangCube: true, podmanProvider: stubProvider{name: "podman"}}
	start := time.Now()
	provider, recon, err := resolveSandboxProvider(context.Background(), resolverConfig("auto"), nil, prober)
	if err != nil || provider.Name() != "podman" {
		t.Fatalf("provider = %v, err = %v (a hanging cube endpoint must not wedge resolution)", provider, err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("resolution took %v, want bounded by the probe timeout", elapsed)
	}
	if recon.Probes[0].Detail == "" {
		t.Fatalf("cube probe detail empty, want the timeout recorded: %+v", recon.Probes)
	}
}

// Review Focus 1: cube_egress harnesses must be rejected at startup on
// podman — they would otherwise hard-fail mid-run at the runtime
// network lockdown (which requires sandbox.NetworkUpdater).
func TestResolveSandboxProviderRejectsCubeEgressOnPodman(t *testing.T) {
	cfg := resolverConfig("podman")
	cfg.Harnesses = map[string]HarnessConfig{
		"locked-agent": {CredentialMode: cubeEgressCredentialMode},
	}
	_, _, err := resolveSandboxProvider(context.Background(), cfg, nil, &fakeProber{})
	if err == nil || !strings.Contains(err.Error(), "locked-agent") || !strings.Contains(err.Error(), "cube_egress") {
		t.Fatalf("err = %v, want a startup error naming the harness and cube_egress", err)
	}
	// The same harness on cube is fine.
	cfgCube := resolverConfig("")
	cfgCube.Harnesses = cfg.Harnesses
	if _, _, err := resolveSandboxProvider(context.Background(), cfgCube, nil, &fakeProber{}); err != nil {
		t.Fatalf("cube + cube_egress resolve = %v, want nil", err)
	}
}

func TestNewRuntimeInjectedProviderWins(t *testing.T) {
	cfg := loadConfigBody(t, legacyCubeTOML)
	stub := stubProvider{name: "fake"}
	runtime, err := NewRuntime(context.Background(), RuntimeOptions{Config: cfg, SandboxProvider: stub})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	if runtime.Provider != sandbox.Provider(stub) {
		t.Fatalf("Runtime.Provider = %v, want the injected provider", runtime.Provider)
	}
	if runtime.Recon.Mode != ProviderModeInjected || runtime.Recon.Selected != "fake" {
		t.Fatalf("Runtime.Recon = %+v, want injected/fake", runtime.Recon)
	}
}

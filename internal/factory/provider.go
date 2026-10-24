package factory

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/mitkox/esf/internal/sandbox"
	"github.com/mitkox/esf/internal/sandbox/cube"
	"github.com/mitkox/esf/internal/sandbox/podman"
)

// Provider selection modes for Config.Sandbox.Provider.
const (
	ProviderModeCube     = "cubesandbox"
	ProviderModePodman   = "podman"
	ProviderModeAuto     = "auto"
	ProviderModeInjected = "injected"
)

// ProviderProbe records one backend's reconnaissance outcome.
type ProviderProbe struct {
	Provider   string `json:"provider"`
	Configured bool   `json:"configured"`
	Reachable  bool   `json:"reachable"`
	Detail     string `json:"detail,omitempty"`
}

// ProviderRecon records how the sandbox provider was chosen: the mode,
// the selected provider name, and every probe outcome. Doctor surfaces
// it verbatim (Task 6).
type ProviderRecon struct {
	Mode     string          `json:"mode"`
	Selected string          `json:"selected"`
	Probes   []ProviderProbe `json:"probes,omitempty"`
}

// probeTimeout bounds each auto-mode probe. A cube endpoint that accepts
// TCP and never answers must not wedge worker startup.
var probeTimeout = 10 * time.Second

// sandboxProber abstracts backend construction + Ping so the
// resolution matrix is unit-testable without a live cube or podman.
type sandboxProber interface {
	Cube(ctx context.Context, cfg Config) (sandbox.Provider, ProviderProbe)
	Podman(ctx context.Context, cfg Config) (sandbox.Provider, ProviderProbe)
}

type realProber struct {
	log *slog.Logger
}

// logger returns the prober's logger, falling back to slog.Default()
// when none was supplied — the same normalization resolveSandboxProvider
// applies — so the providers never receive a nil logger option.
func (p realProber) logger() *slog.Logger {
	if p.log != nil {
		return p.log
	}
	return slog.Default()
}

func (p realProber) Cube(ctx context.Context, cfg Config) (sandbox.Provider, ProviderProbe) {
	probe := ProviderProbe{Provider: ProviderModeCube, Configured: cfg.cubeConfigured()}
	provider, err := cube.New(cfg.Cube, cube.WithLogger(p.logger()))
	if err != nil {
		probe.Detail = err.Error()
		return nil, probe
	}
	if err := provider.Ping(ctx); err != nil {
		probe.Detail = err.Error()
		return nil, probe
	}
	probe.Reachable = true
	return provider, probe
}

func (p realProber) Podman(ctx context.Context, cfg Config) (sandbox.Provider, ProviderProbe) {
	probe := ProviderProbe{Provider: ProviderModePodman, Configured: cfg.podmanConfigured()}
	provider, err := podman.New(cfg.Podman, podman.WithLogger(p.logger()))
	if err != nil {
		probe.Detail = err.Error()
		return nil, probe
	}
	if err := provider.Ping(ctx); err != nil {
		probe.Detail = err.Error()
		return nil, probe
	}
	probe.Reachable = true
	return provider, probe
}

// ResolveSandboxProvider selects the sandbox provider for cfg by
// environment reconnaissance:
//
//   - explicit "cubesandbox" / "podman": construct that backend only
//     (reachability stays with the worker startup ping, as before);
//   - "auto": probe cube (configured + Ping), then podman; select the
//     first that answers; if neither does, return one fail-closed error
//     reporting BOTH probe outcomes.
//
// It never falls back to a fake provider.
func ResolveSandboxProvider(ctx context.Context, cfg Config, log *slog.Logger) (sandbox.Provider, ProviderRecon, error) {
	return resolveSandboxProvider(ctx, cfg, log, realProber{log: log})
}

func resolveSandboxProvider(ctx context.Context, cfg Config, log *slog.Logger, prober sandboxProber) (sandbox.Provider, ProviderRecon, error) {
	if log == nil {
		log = slog.Default()
	}
	mode := cfg.SandboxProviderMode()
	recon := ProviderRecon{Mode: mode}
	var selected sandbox.Provider
	switch mode {
	case ProviderModePodman:
		provider, err := podman.New(cfg.Podman, podman.WithLogger(log))
		if err != nil {
			return nil, recon, fmt.Errorf("build podman sandbox provider: %w", err)
		}
		selected = provider
		recon.Probes = append(recon.Probes, ProviderProbe{
			Provider: ProviderModePodman, Configured: cfg.podmanConfigured(),
			Detail: "explicitly selected; reachability is verified by the worker startup ping",
		})
	case ProviderModeAuto:
		if cfg.cubeConfigured() {
			provider, probe := probeWithTimeout(ctx, prober, cfg, ProviderModeCube)
			recon.Probes = append(recon.Probes, probe)
			selected = provider
		} else {
			recon.Probes = append(recon.Probes, ProviderProbe{Provider: ProviderModeCube, Configured: false, Detail: "not configured"})
		}
		if selected == nil && cfg.podmanConfigured() {
			provider, probe := probeWithTimeout(ctx, prober, cfg, ProviderModePodman)
			recon.Probes = append(recon.Probes, probe)
			selected = provider
		} else if selected == nil {
			recon.Probes = append(recon.Probes, ProviderProbe{Provider: ProviderModePodman, Configured: false, Detail: "not configured"})
		}
		if selected == nil {
			parts := make([]string, 0, len(recon.Probes))
			for _, probe := range recon.Probes {
				parts = append(parts, probe.Provider+": "+providerProbeSummary(probe))
			}
			return nil, recon, fmt.Errorf("sandbox provider auto: no usable backend (%s)", strings.Join(parts, "; "))
		}
	default: // ProviderModeCube — pre-feature construction, unchanged.
		provider, err := cube.New(cfg.Cube, cube.WithLogger(log))
		if err != nil {
			return nil, recon, fmt.Errorf("build cubesandbox provider: %w", err)
		}
		selected = provider
		recon.Probes = append(recon.Probes, ProviderProbe{
			Provider: ProviderModeCube, Configured: cfg.cubeConfigured(),
			Detail: "explicitly selected (default); reachability is verified by the worker startup ping",
		})
	}
	recon.Selected = selected.Name()
	// Harnesses with cube-egress credentials depend on provider-managed
	// egress (the runtime network lockdown requires
	// sandbox.NetworkUpdater, which only cubesandbox implements).
	// Reject the combination now, at startup, instead of failing the
	// run halfway through.
	if selected.Name() == podman.ProviderName {
		for name, harness := range cfg.Harnesses {
			if strings.EqualFold(strings.TrimSpace(harness.CredentialMode), cubeEgressCredentialMode) {
				return nil, recon, fmt.Errorf("harness %q uses credential_mode %q, which requires the cubesandbox provider (selected: %s): change the harness credential_mode or select provider %q",
					name, harness.CredentialMode, selected.Name(), ProviderModeCube)
			}
		}
	}
	log.Info("sandbox provider selected", "mode", recon.Mode, "provider", recon.Selected)
	return selected, recon, nil
}

func probeWithTimeout(ctx context.Context, prober sandboxProber, cfg Config, which string) (sandbox.Provider, ProviderProbe) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	if which == ProviderModeCube {
		return prober.Cube(ctx, cfg)
	}
	return prober.Podman(ctx, cfg)
}

// providerProbeSummary condenses one probe outcome for the fail-closed
// auto-mode error. (Named distinctly from hardening_evidence.go's
// probeSummary, which summarizes egress probes.)
func providerProbeSummary(probe ProviderProbe) string {
	if !probe.Configured {
		return "not configured"
	}
	if probe.Detail != "" {
		return probe.Detail
	}
	return "unreachable"
}

package main

import (
	"strings"
	"testing"

	"github.com/mitkox/esf/internal/factory"
	"github.com/mitkox/esf/internal/sandbox/cube"
	"github.com/mitkox/esf/internal/sandbox/podman"
)

func cubeConfigForDoctorTest() cube.Config {
	return cube.Config{APIURL: "http://127.0.0.1:12088", TemplateID: "tpl-test", ProxyNodeIP: "127.0.0.1"}
}

func TestDoctorStructuredReportsSelectedProvider(t *testing.T) {
	cfg := factory.Config{
		Sandbox: factory.SandboxConfig{Provider: "podman"},
		Podman:  podman.Config{Image: "localhost/esf-template:debian13-node24"},
	}
	recon := factory.ProviderRecon{Mode: "podman", Selected: "podman"}
	check := sandboxProviderCheck(cfg, &recon)
	if check.Name != "sandbox_provider" || check.Status != "ok" {
		t.Fatalf("check = %+v, want sandbox_provider/ok", check)
	}
	if !strings.Contains(check.Detail, "podman") || !strings.Contains(check.Detail, "selected=podman") {
		t.Fatalf("detail = %q, want mode and selection reported", check.Detail)
	}
	if got := reachabilityCheckName("podman"); got != "podman_reachable" {
		t.Fatalf("reachabilityCheckName(podman) = %q, want podman_reachable", got)
	}
	// Podman selected but no image configured: fail with the reason.
	broken := sandboxProviderCheck(factory.Config{Sandbox: factory.SandboxConfig{Provider: "podman"}}, nil)
	if broken.Status != "fail" {
		t.Fatalf("broken podman check = %+v, want fail", broken)
	}
	// Auto with neither backend configured: fail.
	none := sandboxProviderCheck(factory.Config{Sandbox: factory.SandboxConfig{Provider: "auto"}}, nil)
	if none.Status != "fail" {
		t.Fatalf("auto/neither check = %+v, want fail", none)
	}
}

func TestDoctorStructuredCubeKeepsLegacyCheck(t *testing.T) {
	cfg := factory.Config{
		Cube: cubeConfigForDoctorTest(),
	}
	check := sandboxProviderCheck(cfg, nil)
	if check.Name != "sandbox_provider" || check.Status != "ok" || !strings.Contains(check.Detail, "cubesandbox") {
		t.Fatalf("check = %+v, want sandbox_provider/ok naming cubesandbox", check)
	}
	if got := reachabilityCheckName("cubesandbox"); got != "cube_reachable" {
		t.Fatalf("reachabilityCheckName(cubesandbox) = %q, want legacy cube_reachable", got)
	}
	if got := reachabilityCheckName("fake"); got != "cube_reachable" {
		t.Fatalf("reachabilityCheckName(fake) = %q, want cube_reachable (legacy default)", got)
	}
}

package factory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadConfigBody(t *testing.T, body string) Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "factory.toml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	return cfg
}

const legacyCubeTOML = `
schema_version = 1
[cube]
api_url = "http://127.0.0.1:12088"
template_id = "tpl-test"
proxy_node_ip = "10.0.0.9"
proxy_scheme = "https"
[hardening]
acknowledge_open_egress = true
`

// A pre-feature config (no provider key, no [podman]) must behave
// exactly as today: cube mode, cube validation authoritative.
func TestConfigProviderDefaultsToCube(t *testing.T) {
	cfg := loadConfigBody(t, legacyCubeTOML)
	if got := cfg.SandboxProviderMode(); got != "cubesandbox" {
		t.Fatalf("SandboxProviderMode = %q, want cubesandbox", got)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate (legacy cube config) = %v, want nil", err)
	}
	// And a legacy config with a broken cube section still fails with
	// the cube error, unchanged. (cube.Config.Validate aggregates its
	// problems into an "invalid cubesandbox configuration" error and
	// never wraps cube.ErrNotConfigured, so the unchanged cube error
	// text is the assertion that pins today's behavior.)
	broken := loadConfigBody(t, "schema_version = 1\n[cube]\ntemplate_id = \"tpl-test\"\n")
	if err := broken.Validate(); err == nil || !strings.Contains(err.Error(), "invalid cubesandbox configuration") {
		t.Fatalf("Validate (legacy broken cube) = %v, want the unchanged cube validation error", err)
	}
}

// provider = "podman" must not require a [cube] section at all — today
// this config fails cube validation unconditionally.
func TestConfigProviderPodmanSkipsCubeValidation(t *testing.T) {
	cfg := loadConfigBody(t, `
schema_version = 1
[sandbox]
provider = "podman"
[podman]
image = "localhost/esf-template:debian13-node24"
[hardening]
acknowledge_open_egress = true
`)
	if got := cfg.SandboxProviderMode(); got != "podman" {
		t.Fatalf("SandboxProviderMode = %q, want podman", got)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate (podman-only config) = %v, want nil", err)
	}
	// But a podman config without an image still fails, from podman.
	broken := loadConfigBody(t, "schema_version = 1\n[sandbox]\nprovider = \"podman\"\n")
	if err := broken.Validate(); err == nil || !strings.Contains(err.Error(), "image") {
		t.Fatalf("Validate (podman, no image) = %v, want image error", err)
	}
}

func TestConfigProviderAutoRequiresOneBackend(t *testing.T) {
	t.Setenv("FACTORY_CUBE_API_URL", "")
	t.Setenv("FACTORY_CUBE_TEMPLATE_ID", "")
	t.Setenv("FACTORY_PODMAN_IMAGE", "")
	cfg := loadConfigBody(t, "schema_version = 1\n[sandbox]\nprovider = \"auto\"\n")
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), `"auto"`) {
		t.Fatalf("Validate (auto, neither backend) = %v, want an error naming auto mode", err)
	}
	// Auto with one configured backend validates.
	ok := loadConfigBody(t, `
schema_version = 1
[sandbox]
provider = "auto"
[podman]
image = "localhost/esf-template:debian13-node24"
[hardening]
acknowledge_open_egress = true
`)
	if err := ok.Validate(); err != nil {
		t.Fatalf("Validate (auto + podman) = %v, want nil", err)
	}
}

func TestConfigProviderUnknownRejected(t *testing.T) {
	cfg := loadConfigBody(t, "schema_version = 1\n[sandbox]\nprovider = \"docker\"\n")
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("Validate (unknown provider) = %v, want a not-supported error", err)
	}
}

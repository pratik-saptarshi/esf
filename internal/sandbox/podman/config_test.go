package podman

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestConfigDefaults(t *testing.T) {
	cfg := ConfigFromEnv()
	if cfg.Binary != "podman" {
		t.Fatalf("Binary = %q, want podman", cfg.Binary)
	}
	if cfg.CommandOutputBytes != 0 {
		t.Fatalf("CommandOutputBytes = %d, want 0 (provider applies default)", cfg.CommandOutputBytes)
	}
	if got := (Config{Image: "img"}).effectiveOutputBytes(); got != DefaultCommandOutputBytes {
		t.Fatalf("effectiveOutputBytes = %d, want %d", got, DefaultCommandOutputBytes)
	}
	if got := (Config{Image: "img"}).effectiveRequestTimeout(); got != 60*time.Second {
		t.Fatalf("effectiveRequestTimeout = %v, want 60s (mirrors cube)", got)
	}
	dir, err := (Config{Image: "img"}).effectiveStateDir()
	if err != nil || !strings.HasSuffix(dir, "podman-sandboxes") {
		t.Fatalf("effectiveStateDir = %q, %v; want .../podman-sandboxes", dir, err)
	}
}

func TestConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr string // substring; "" means valid
		notCfg  bool   // expect ErrNotConfigured in the chain
	}{
		{name: "image required", cfg: Config{}, wantErr: "image", notCfg: true},
		{name: "minimal valid", cfg: Config{Image: "localhost/esf-template:debian13-node24"}},
		{name: "output bytes below floor", cfg: Config{Image: "img", CommandOutputBytes: 1024}, wantErr: "command_output_bytes"},
		{name: "output bytes at floor", cfg: Config{Image: "img", CommandOutputBytes: 2048}},
		{name: "negative timeout", cfg: Config{Image: "img", RequestTimeout: -1}, wantErr: "request_timeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tc.wantErr)
			}
			if tc.notCfg && !errors.Is(err, ErrNotConfigured) {
				t.Fatalf("Validate() = %v, want ErrNotConfigured in chain", err)
			}
		})
	}
}

func TestConfigFromEnvPrecedence(t *testing.T) {
	t.Setenv("FACTORY_PODMAN_IMAGE", "localhost/from-env:1")
	t.Setenv("FACTORY_PODMAN_NETWORK", "host")
	t.Setenv("FACTORY_PODMAN_CGROUP_MANAGER", "cgroupfs")
	cfg := ConfigFromEnv()
	if cfg.Image != "localhost/from-env:1" || cfg.Network != "host" || cfg.CgroupManager != "cgroupfs" {
		t.Fatalf("ConfigFromEnv() = %+v, want env values applied", cfg)
	}
}

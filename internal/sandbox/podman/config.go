// Package podman implements a sandbox.Provider backed by podman
// containers. It exists for hosts where the CubeSandbox/KVM provider
// cannot run (no /dev/kvm): each sandbox is an extracted image rootfs on
// the host filesystem, and each Execute is a one-shot
// `podman run --rm --rootfs` invocation against that rootfs. The provider
// never uses `podman exec`, so it works where entering a running
// container is not possible.
package podman

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mitkox/esf/internal/tomlx"
)

const (
	// DefaultCommandOutputBytes bounds combined captured command output
	// when the operator does not configure a limit (mirrors cube).
	DefaultCommandOutputBytes int64 = 4 << 20
	// MinCommandOutputBytes is the smallest accepted explicit limit; the
	// bounding wrapper needs room for its truncation notice.
	MinCommandOutputBytes int64 = 2048

	defaultRequestTimeout = 60 * time.Second
)

// Config controls the podman provider. It has no secret fields: podman is
// a local CLI. The provider never relies on ambient podman configuration
// files — every invocation passes the flags derived from this struct.
type Config struct {
	// Binary is the podman executable name or path.
	Binary string `toml:"binary"`
	// Image is the template image reference (e.g.
	// localhost/esf-template:debian13-node24). Required.
	Image string `toml:"image"`
	// StateDir holds per-sandbox state (spec.json + extracted rootfs).
	// Empty: ~/.local/share/esf/podman-sandboxes. Factory wiring points
	// this at <storage.data_dir>/podman-sandboxes when unset.
	StateDir string `toml:"state_dir"`
	// Network is passed as `podman run --network <value>` ("host",
	// "none", or a network name). Empty: podman's ambient default.
	Network string `toml:"network"`
	// CgroupManager is passed as --cgroup-manager when non-empty
	// ("cgroupfs" on hosts without a systemd user session).
	CgroupManager string `toml:"cgroup_manager"`
	// StorageRoot / RunRoot are passed as --root / --runroot when
	// non-empty. Required on hosts whose default graphroot is unusable.
	StorageRoot string `toml:"storage_root"`
	RunRoot     string `toml:"run_root"`
	// User is passed as `podman run --user` when non-empty. Empty: the
	// image's default user (root for the ESF template).
	User string `toml:"user"`
	// CommandOutputBytes bounds combined stdout+stderr captured from a
	// single Execute. 0 selects DefaultCommandOutputBytes.
	CommandOutputBytes int64 `toml:"command_output_bytes"`
	// RequestTimeout bounds individual podman invocations that are not
	// Execute (ping, create/export, destroy).
	RequestTimeout tomlx.Duration `toml:"request_timeout"`
}

// ConfigFromEnv builds a Config from FACTORY_PODMAN_* environment
// variables, mirroring cube.ConfigFromEnv.
func ConfigFromEnv() Config {
	return Config{
		Binary:        envOr("FACTORY_PODMAN_BINARY", "podman"),
		Image:         os.Getenv("FACTORY_PODMAN_IMAGE"),
		StateDir:      os.Getenv("FACTORY_PODMAN_STATE_DIR"),
		Network:       os.Getenv("FACTORY_PODMAN_NETWORK"),
		CgroupManager: os.Getenv("FACTORY_PODMAN_CGROUP_MANAGER"),
		StorageRoot:   os.Getenv("FACTORY_PODMAN_STORAGE_ROOT"),
		RunRoot:       os.Getenv("FACTORY_PODMAN_RUN_ROOT"),
		User:          os.Getenv("FACTORY_PODMAN_USER"),
	}
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// Validate reports configuration problems. A missing image is
// ErrNotConfigured; anything else is a plain descriptive error listing
// every problem found.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Image) == "" {
		return fmt.Errorf("%w: podman image is required (set [podman] image or FACTORY_PODMAN_IMAGE)", ErrNotConfigured)
	}
	var problems []string
	if c.CommandOutputBytes < 0 || (c.CommandOutputBytes > 0 && c.CommandOutputBytes < MinCommandOutputBytes) {
		problems = append(problems, fmt.Sprintf("podman command_output_bytes must be 0 or at least %d", MinCommandOutputBytes))
	}
	if c.RequestTimeout.Std() < 0 {
		problems = append(problems, "podman request_timeout must not be negative")
	}
	if len(problems) > 0 {
		return errors.New("invalid podman configuration: " + strings.Join(problems, "; "))
	}
	return nil
}

// String summarizes the configuration for logs and doctor output. The
// config carries no secrets, so nothing needs redacting.
func (c Config) String() string {
	return fmt.Sprintf("podman(binary=%s image=%s network=%s state_dir=%s)",
		c.effectiveBinary(), c.Image, c.Network, c.StateDir)
}

func (c Config) effectiveBinary() string {
	if strings.TrimSpace(c.Binary) != "" {
		return c.Binary
	}
	return "podman"
}

func (c Config) effectiveOutputBytes() int64 {
	if c.CommandOutputBytes > 0 {
		return c.CommandOutputBytes
	}
	return DefaultCommandOutputBytes
}

func (c Config) effectiveRequestTimeout() time.Duration {
	if c.RequestTimeout.Std() > 0 {
		return c.RequestTimeout.Std()
	}
	return defaultRequestTimeout
}

func (c Config) effectiveStateDir() (string, error) {
	if strings.TrimSpace(c.StateDir) != "" {
		return c.StateDir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("%w: resolve home directory for podman state dir: %v", ErrNotConfigured, err)
	}
	return filepath.Join(home, ".local", "share", "esf", "podman-sandboxes"), nil
}

// baseArgs returns the global podman flags prepended to every invocation
// so behavior never depends on ambient podman configuration files.
func (c Config) baseArgs() []string {
	args := []string{}
	if strings.TrimSpace(c.StorageRoot) != "" {
		args = append(args, "--root", c.StorageRoot)
	}
	if strings.TrimSpace(c.RunRoot) != "" {
		args = append(args, "--runroot", c.RunRoot)
	}
	if strings.TrimSpace(c.CgroupManager) != "" {
		args = append(args, "--cgroup-manager", c.CgroupManager)
	}
	return args
}

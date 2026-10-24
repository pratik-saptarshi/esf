package podman

import (
	"errors"
	"fmt"
	"strings"
)

// Sentinel errors for the podman provider, mirroring the cube provider's
// classification style (internal/sandbox/cube/errors.go) so factory code
// can errors.Is them the same way.
var (
	ErrNotConfigured    = errors.New("podman sandbox is not configured")
	ErrUnavailable      = errors.New("podman sandbox is unavailable")
	ErrSandboxNotFound  = errors.New("podman sandbox not found")
	ErrTemplateNotFound = errors.New("podman template image not found")
	ErrInvalidSpec      = errors.New("invalid podman sandbox specification")
)

// classify maps a failed podman invocation onto the package sentinels. The
// sentinel leads the wrap chain; a tail of podman's stderr is kept for
// diagnosis (podman writes its real reason there).
func classify(runErr error, stderr string) error {
	lower := strings.ToLower(stderr)
	switch {
	case strings.Contains(lower, "no such image"),
		strings.Contains(lower, "image not known"),
		strings.Contains(lower, "manifest unknown"):
		return fmt.Errorf("%w: %v: %s", ErrTemplateNotFound, runErr, tailText(stderr))
	case strings.Contains(lower, "no such container"),
		strings.Contains(lower, "no container with name"):
		return fmt.Errorf("%w: %v: %s", ErrSandboxNotFound, runErr, tailText(stderr))
	default:
		return fmt.Errorf("%w: %v: %s", ErrUnavailable, runErr, tailText(stderr))
	}
}

// tailText returns the last few lines of s, capped, for error messages.
func tailText(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 512 {
		s = s[len(s)-512:]
	}
	return s
}

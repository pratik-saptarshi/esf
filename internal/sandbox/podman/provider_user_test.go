package podman

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/mitkox/esf/internal/sandbox"
)

// TestProviderCreateUserOwnershipGate pins the fail-closed contract for
// [podman] user: image ownership (e.g. /home/esf, UID 1000) is preserved
// at extraction by chown, which only a root extractor can do. When ESF
// runs unprivileged the chown would be silently skipped and a non-root
// container user could exec but could not write its own home, so Create
// must refuse a non-empty user unless ESF itself runs as root. user=""
// is the escape hatch: the sandbox runs with the provider's host-user
// ownership (known-degraded for user-owned paths) and Create proceeds.
func TestProviderCreateUserOwnershipGate(t *testing.T) {
	ctx := context.Background()

	// reject: user set while ESF is unprivileged.
	t.Run("reject/user set and non-root", func(t *testing.T) {
		orig := geteuid
		geteuid = func() int { return 1000 }
		t.Cleanup(func() { geteuid = orig })

		fr := &fakeRunner{tarBytes: rootfsTar(t)}
		p := testProvider(t, fr)
		p.cfg.User = "esf"
		sb, err := p.Create(ctx, sandbox.Spec{Template: "localhost/test:1"})
		if err == nil {
			t.Fatalf("Create(user=esf, non-root) = nil error, want ErrInvalidSpec rejection")
		}
		if sb != nil {
			t.Fatalf("Create returned a sandbox alongside the rejection error")
		}
		if !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("Create error = %v, want errors.Is ErrInvalidSpec", err)
		}
		if !strings.Contains(err.Error(), "podman") {
			t.Fatalf("Create error = %q, want it to name the provider", err)
		}
		if !strings.Contains(err.Error(), "ownership") {
			t.Fatalf("Create error = %q, want it to name ownership preservation", err)
		}
		if !strings.Contains(err.Error(), "root") {
			t.Fatalf("Create error = %q, want it to mention running ESF as root", err)
		}
		if !strings.Contains(err.Error(), `user=""`) {
			t.Fatalf("Create error = %q, want it to name the user=\"\" escape hatch", err)
		}
		if len(fr.calls) != 0 {
			t.Fatalf("runner invoked %d times on a rejected Create, want 0: %v", len(fr.calls), fr.calls)
		}
		entries, rerr := os.ReadDir(p.cfg.StateDir)
		if rerr != nil {
			t.Fatalf("ReadDir state dir: %v", rerr)
		}
		if len(entries) != 0 {
			t.Fatalf("rejected Create left %d entries in the state dir, want 0", len(entries))
		}
	})

	// accept: user="" remains the documented escape hatch when ESF is
	// unprivileged — no error from this gate.
	t.Run("accept/user empty and non-root", func(t *testing.T) {
		orig := geteuid
		geteuid = func() int { return 1000 }
		t.Cleanup(func() { geteuid = orig })

		fr := &fakeRunner{tarBytes: rootfsTar(t)}
		p := testProvider(t, fr)
		p.cfg.User = ""
		sb, err := p.Create(ctx, sandbox.Spec{Template: "localhost/test:1"})
		if err != nil {
			t.Fatalf("Create(user=\"\", non-root) = %v, want success (escape hatch)", err)
		}
		if sb == nil {
			t.Fatalf("Create returned a nil sandbox with nil error")
		}
		if len(fr.calls) == 0 {
			t.Fatalf("runner never invoked on an accepted Create")
		}
	})

	// accept: user set while ESF runs as root — ownership can be preserved.
	t.Run("accept/user set and root", func(t *testing.T) {
		orig := geteuid
		geteuid = func() int { return 0 }
		t.Cleanup(func() { geteuid = orig })

		fr := &fakeRunner{tarBytes: rootfsTar(t)}
		p := testProvider(t, fr)
		p.cfg.User = "esf"
		sb, err := p.Create(ctx, sandbox.Spec{Template: "localhost/test:1"})
		if err != nil {
			t.Fatalf("Create(user=esf, root) = %v, want success", err)
		}
		if sb == nil {
			t.Fatalf("Create returned a nil sandbox with nil error")
		}
		if len(fr.calls) == 0 {
			t.Fatalf("runner never invoked on an accepted Create")
		}
	})
}

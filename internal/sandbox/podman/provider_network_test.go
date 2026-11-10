package podman

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/mitkox/esf/internal/sandbox"
)

func boolPtr(b bool) *bool { return &b }

// TestProviderCreateNetworkPolicy pins the fail-closed contract for
// spec.Network: the provider runs every sandbox on the deployment's
// static --network setting and cannot enforce a per-run egress
// policy, so any restrictive element must reject Create before any
// state is written or podman is invoked. A zero Network (deployment
// default) and an explicitly open policy are accepted: open egress is
// what the deployment network already provides.
func TestProviderCreateNetworkPolicy(t *testing.T) {
	ctx := context.Background()

	reject := []struct {
		name    string
		network sandbox.Network
		token   string
	}{
		{"allow internet explicitly false", sandbox.Network{AllowInternet: boolPtr(false)}, "allow_internet=false"},
		{"allow out list", sandbox.Network{AllowOut: []string{"api.example.com"}}, "allow_out"},
		{"deny out list", sandbox.Network{DenyOut: []string{"10.0.0.0/8"}}, "deny_out"},
		{"l7 rules", sandbox.Network{Rules: []sandbox.NetworkRule{{Name: "factory-x-model", Action: sandbox.NetworkAction{Allow: true}}}}, "rules"},
		{"open internet with deny list", sandbox.Network{AllowInternet: boolPtr(true), DenyOut: []string{"169.254.0.0/16"}}, "deny_out"},
	}
	for _, tc := range reject {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			fr := &fakeRunner{tarBytes: rootfsTar(t)}
			p := testProvider(t, fr)
			sb, err := p.Create(ctx, sandbox.Spec{Template: "localhost/test:1", Network: tc.network})
			if err == nil {
				t.Fatalf("Create(network=%+v) = nil error, want ErrInvalidSpec rejection", tc.network)
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
			if !strings.Contains(err.Error(), tc.token) {
				t.Fatalf("Create error = %q, want it to name the policy element %q", err, tc.token)
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
	}

	accept := []struct {
		name    string
		network sandbox.Network
	}{
		{"zero network", sandbox.Network{}},
		{"allow internet explicitly true", sandbox.Network{AllowInternet: boolPtr(true)}},
		{"open with empty lists", sandbox.Network{AllowInternet: boolPtr(true), AllowOut: []string{}, DenyOut: []string{}}},
	}
	for _, tc := range accept {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			fr := &fakeRunner{tarBytes: rootfsTar(t)}
			p := testProvider(t, fr)
			sb, err := p.Create(ctx, sandbox.Spec{Template: "localhost/test:1", Network: tc.network})
			if err != nil {
				t.Fatalf("Create(network=%+v) = %v, want success", tc.network, err)
			}
			if sb == nil {
				t.Fatalf("Create returned a nil sandbox with nil error")
			}
			if len(fr.calls) == 0 {
				t.Fatalf("runner never invoked on an accepted Create")
			}
		})
	}
}

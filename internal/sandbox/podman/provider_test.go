package podman

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mitkox/esf/internal/sandbox"
)

// fakeRunner emulates the podman CLI for provider unit tests.
type fakeRunner struct {
	mu       sync.Mutex
	calls    [][]string
	infoCode int
	imgCode  int
	tarBytes []byte
}

func (f *fakeRunner) Run(_ context.Context, _ io.Reader, stdout, stderr io.Writer, args ...string) (int, error) {
	f.mu.Lock()
	f.calls = append(f.calls, append([]string{}, args...))
	f.mu.Unlock()
	// Strip global flags (none are set in tests) and dispatch on the verb.
	verb := ""
	for _, a := range args {
		switch a {
		case "info", "image", "create", "export", "rm", "ps", "pull":
			verb = a
		}
		if verb != "" {
			break
		}
	}
	switch verb {
	case "info":
		if f.infoCode != 0 {
			io.WriteString(stderr, "cannot connect to podman socket")
		}
		return f.infoCode, nil
	case "image": // image exists <ref>
		if f.imgCode != 0 {
			io.WriteString(stderr, "no such image")
		}
		return f.imgCode, nil
	case "create":
		io.WriteString(stdout, "fake-container-id\n")
		return 0, nil
	case "export":
		_, err := stdout.Write(f.tarBytes)
		return 0, err
	default: // rm, ps, pull
		return 0, nil
	}
}

func rootfsTar(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte("rootfs-ok\n")
	if err := tw.WriteHeader(&tar.Header{Name: "esf-marker.txt", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func testProvider(t *testing.T, fr *fakeRunner) *Provider {
	t.Helper()
	cfg := Config{Binary: "podman", Image: "localhost/test:1", StateDir: t.TempDir()}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p.run = fr
	return p
}

func TestProviderPingStub(t *testing.T) {
	ctx := context.Background()
	if err := testProvider(t, &fakeRunner{}).Ping(ctx); err != nil {
		t.Fatalf("Ping (healthy stub) = %v, want nil", err)
	}
	err := testProvider(t, &fakeRunner{infoCode: 1}).Ping(ctx)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Ping (info fails) = %v, want ErrUnavailable", err)
	}
	err = testProvider(t, &fakeRunner{imgCode: 1}).Ping(ctx)
	if !errors.Is(err, ErrTemplateNotFound) {
		t.Fatalf("Ping (image missing) = %v, want ErrTemplateNotFound", err)
	}
}

func TestProviderCreateReattachListDestroyStub(t *testing.T) {
	ctx := context.Background()
	p := testProvider(t, &fakeRunner{tarBytes: rootfsTar(t)})
	sb, err := p.Create(ctx, sandbox.Spec{Template: "localhost/test:1", Metadata: map[string]string{"run": "r1"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	id := sb.ID()
	if !validSandboxID(id) {
		t.Fatalf("Create ID = %q, want podman-<32 hex>", id)
	}
	dir := filepath.Join(p.cfg.StateDir, id)
	marker, err := os.ReadFile(filepath.Join(dir, "rootfs", "esf-marker.txt"))
	if err != nil || string(marker) != "rootfs-ok\n" {
		t.Fatalf("rootfs marker = %q, %v", marker, err)
	}
	fi, err := os.Stat(filepath.Join(dir, "spec.json"))
	if err != nil {
		t.Fatalf("spec.json: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("spec.json mode = %v, want 0600 (spec env must not be world-readable)", fi.Mode().Perm())
	}
	infos, err := p.List(ctx)
	if err != nil || len(infos) != 1 || infos[0].ID != id || infos[0].ProviderID != "podman" || infos[0].Template != "localhost/test:1" {
		t.Fatalf("List = %+v, %v", infos, err)
	}
	back, err := p.Reattach(ctx, id)
	if err != nil || back.ID() != id || back.Template() != "localhost/test:1" {
		t.Fatalf("Reattach = %+v, %v", back, err)
	}
	if err := p.Destroy(ctx, id); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("state dir still present after Destroy: %v", err)
	}
	if err := p.Destroy(ctx, id); err != nil {
		t.Fatalf("Destroy (idempotent) = %v, want nil", err)
	}
	infos, err = p.List(ctx)
	if err != nil || len(infos) != 0 {
		t.Fatalf("List after Destroy = %+v, %v", infos, err)
	}
}

func TestProviderRejectsBadID(t *testing.T) {
	ctx := context.Background()
	p := testProvider(t, &fakeRunner{})
	for _, bad := range []string{"", "../etc", "podman-xyz", "podman-" + strings.Repeat("z", 32), "cube-123"} {
		if _, err := p.Reattach(ctx, bad); !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("Reattach(%q) = %v, want ErrInvalidSpec", bad, err)
		}
		if err := p.Destroy(ctx, bad); !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("Destroy(%q) = %v, want ErrInvalidSpec", bad, err)
		}
	}
	absent := "podman-" + strings.Repeat("a", 32)
	if _, err := p.Reattach(ctx, absent); !errors.Is(err, ErrSandboxNotFound) {
		t.Fatalf("Reattach(absent) = %v, want ErrSandboxNotFound", err)
	}
	if err := p.Destroy(ctx, absent); err != nil {
		t.Fatalf("Destroy(absent) = %v, want nil (idempotent)", err)
	}
}

func TestProviderCapabilitiesAllFalse(t *testing.T) {
	p := testProvider(t, &fakeRunner{})
	if caps := p.Capabilities(); caps != (sandbox.Capabilities{}) {
		t.Fatalf("Capabilities = %+v, want all false (honest container model)", caps)
	}
	if p.Name() != "podman" {
		t.Fatalf("Name = %q, want podman", p.Name())
	}
}

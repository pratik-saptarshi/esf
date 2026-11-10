package podman

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/mitkox/esf/internal/sandbox"
)

// openFDCount returns the number of open file descriptors for this
// process via /proc/self/fd (Linux) or /dev/fd (Darwin/BSD). It skips
// the test where neither is available rather than guessing.
func openFDCount(t *testing.T) int {
	t.Helper()
	for _, dir := range []string{"/proc/self/fd", "/dev/fd"} {
		entries, err := os.ReadDir(dir)
		if err == nil {
			return len(entries)
		}
	}
	t.Skip("no /proc/self/fd or /dev/fd to count open file descriptors")
	return -1
}

// exportFailRunner emulates podman with a failing export step.
type exportFailRunner struct{}

func (exportFailRunner) Run(_ context.Context, _ io.Reader, _, stderr io.Writer, args ...string) (int, error) {
	for _, a := range args {
		if a == "export" {
			_, _ = io.WriteString(stderr, "export boom\n")
			return 1, nil
		}
	}
	return 0, nil
}

// TestExportTempFileClosedOnSuccess pins that materializeRootfs closes
// the image-export temp file on the success path: after Create
// returns, the process must hold no extra open fds (an unlinked but
// still-open temp file would pin its disk blocks until GC).
func TestExportTempFileClosedOnSuccess(t *testing.T) {
	p := testProvider(t, &fakeRunner{tarBytes: rootfsTar(t)})
	ctx := context.Background()
	before := openFDCount(t)
	const creates = 5
	for i := 0; i < creates; i++ {
		sb, err := p.Create(ctx, sandbox.Spec{Template: "localhost/test:1"})
		if err != nil {
			t.Fatalf("Create #%d: %v", i, err)
		}
		if err := p.Destroy(ctx, sb.ID()); err != nil {
			t.Fatalf("Destroy #%d: %v", i, err)
		}
	}
	after := openFDCount(t)
	if after > before {
		t.Fatalf("Create leaked %d open file descriptors over %d creates (before=%d after=%d): the export temp file is not closed",
			after-before, creates, before, after)
	}
	// The temp file itself must also be gone from disk.
	matches, err := filepath.Glob(filepath.Join(p.cfg.StateDir, "podman-*", "esf-export-*.tar"))
	if err != nil {
		t.Fatalf("Glob export temps: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("export temp files left on disk: %v", matches)
	}
}

// TestExportTempFileClosedOnFailure pins the same invariant on the
// error return paths (export exit != 0): the temp file must be closed
// even when Create fails.
func TestExportTempFileClosedOnFailure(t *testing.T) {
	cfg := Config{Binary: "podman", Image: "localhost/test:1", StateDir: t.TempDir()}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p.run = exportFailRunner{}
	ctx := context.Background()
	before := openFDCount(t)
	const creates = 5
	for i := 0; i < creates; i++ {
		if _, err := p.Create(ctx, sandbox.Spec{Template: "localhost/test:1"}); err == nil {
			t.Fatalf("Create #%d: expected export failure, got nil error", i)
		}
	}
	after := openFDCount(t)
	if after > before {
		t.Fatalf("failed Create leaked %d open file descriptors over %d attempts (before=%d after=%d): the export temp file is not closed on the error path",
			after-before, creates, before, after)
	}
}

package sandbox

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// setupTraced wraps a fresh Fake with telemetry enabled and returns
// the wrapped provider, the fake and the telemetry file path.
func setupTraced(t *testing.T) (Provider, *Fake, string) {
	t.Helper()
	path := telemetryFile(t)
	fake := NewFake()
	return WrapProvider(fake), fake, path
}

// Every seam operation emits one span with the contract attributes:
// operation, provider and duration_ms on all of them, sandbox_id on
// the sandbox-scoped ones, exit_code on execute.
func TestTracedProviderEmitsSpansForAllOperations(t *testing.T) {
	wrapped, _, path := setupTraced(t)
	ctx := context.Background()

	sb, err := wrapped.Create(ctx, Spec{Template: "tmpl"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := sb.Execute(ctx, Command{Argv: []string{"true"}}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if err := sb.WriteFile(ctx, "/a.txt", []byte("hi")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := sb.ReadFile(ctx, "/a.txt"); err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if _, err := wrapped.Reattach(ctx, sb.ID()); err != nil {
		t.Fatalf("Reattach: %v", err)
	}
	if _, err := wrapped.List(ctx); err != nil {
		t.Fatalf("List: %v", err)
	}
	if err := wrapped.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if err := sb.Destroy(ctx); err != nil {
		t.Fatalf("Sandbox Destroy: %v", err)
	}
	if err := wrapped.Destroy(ctx, sb.ID()); err != nil {
		t.Fatalf("Provider Destroy: %v", err)
	}

	records := readRecords(t, path)
	byOp := recordsByOperation(records)
	wantOps := []string{"create", "execute", "write_file", "read_file",
		"reattach", "list", "ping", "sandbox_destroy", "destroy"}
	if len(records) != len(wantOps) {
		t.Fatalf("got %d records, want %d: %v", len(records), len(wantOps), byOp)
	}
	for _, op := range wantOps {
		rec, ok := byOp[op]
		if !ok {
			t.Errorf("no record for operation %q", op)
			continue
		}
		if rec.Name != "esf."+op {
			t.Errorf("%s: span name = %q, want esf.%s", op, rec.Name, op)
		}
		if rec.Status != "UNSET" {
			t.Errorf("%s: status = %q, want UNSET", op, rec.Status)
		}
		if rec.Attributes["provider"] != "fake" {
			t.Errorf("%s: provider = %v, want fake", op, rec.Attributes["provider"])
		}
		if _, ok := rec.Attributes["duration_ms"].(float64); !ok {
			t.Errorf("%s: duration_ms missing or not a number", op)
		}
	}
	for _, op := range []string{"create", "execute", "write_file", "read_file",
		"reattach", "sandbox_destroy", "destroy"} {
		if got := byOp[op].Attributes["sandbox_id"]; got != "fake-sandbox-1" {
			t.Errorf("%s: sandbox_id = %v, want fake-sandbox-1", op, got)
		}
	}
	if got := byOp["execute"].Attributes["exit_code"]; got != float64(0) {
		t.Errorf("execute: exit_code = %v, want 0", got)
	}
}

// A non-zero command exit is a result, not a transport failure: the
// exit code is recorded and the status stays UNSET.
func TestTracedExecuteNonZeroExitStaysUnset(t *testing.T) {
	wrapped, fake, path := setupTraced(t)
	fake.ExecuteFunc = func(cmd Command) (Execution, error) {
		return Execution{ExitCode: 3}, nil
	}
	sb, err := wrapped.Create(context.Background(), Spec{Template: "tmpl"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	exec, err := sb.Execute(context.Background(), Command{Argv: []string{"false"}})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if exec.ExitCode != 3 {
		t.Fatalf("exit code = %d, want 3", exec.ExitCode)
	}
	byOp := recordsByOperation(readRecords(t, path))
	rec := byOp["execute"]
	if rec.Attributes["exit_code"] != float64(3) {
		t.Errorf("exit_code = %v, want 3", rec.Attributes["exit_code"])
	}
	if rec.Status != "UNSET" {
		t.Errorf("status = %q, want UNSET for a non-zero exit", rec.Status)
	}
}

// A transport error from Create ends the span with status ERROR and
// no sandbox_id.
func TestTracedCreateErrorRecordsErrorStatus(t *testing.T) {
	wrapped, fake, path := setupTraced(t)
	fake.CreateErr = errors.New("boom")
	if _, err := wrapped.Create(context.Background(), Spec{Template: "tmpl"}); err == nil {
		t.Fatal("Create succeeded, want error")
	}
	records := readRecords(t, path)
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	rec := records[0]
	if rec.Status != "ERROR" {
		t.Errorf("status = %q, want ERROR", rec.Status)
	}
	if _, ok := rec.Attributes["sandbox_id"]; ok {
		t.Errorf("sandbox_id recorded for a failed create: %v", rec.Attributes)
	}
}

// A transport error from Execute ends the span with status ERROR and
// no exit_code (there is no command outcome to report).
func TestTracedExecuteErrorRecordsErrorStatus(t *testing.T) {
	wrapped, fake, path := setupTraced(t)
	fake.ExecuteFunc = func(cmd Command) (Execution, error) {
		return Execution{}, errors.New("transport down")
	}
	sb, err := wrapped.Create(context.Background(), Spec{Template: "tmpl"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := sb.Execute(context.Background(), Command{Argv: []string{"true"}}); err == nil {
		t.Fatal("Execute succeeded, want error")
	}
	byOp := recordsByOperation(readRecords(t, path))
	rec := byOp["execute"]
	if rec.Status != "ERROR" {
		t.Errorf("status = %q, want ERROR", rec.Status)
	}
	if _, ok := rec.Attributes["exit_code"]; ok {
		t.Errorf("exit_code recorded for a transport error: %v", rec.Attributes)
	}
}

// Canary: nothing about the work itself — spec env and metadata,
// command argv, env and stdin, file paths or file contents — may
// ever appear in the telemetry output.
func TestTracedOperationsNeverRecordWorkContent(t *testing.T) {
	wrapped, _, path := setupTraced(t)
	ctx := context.Background()
	canaries := map[string]string{
		"spec env":      "CANARY-SPEC-ENV-41a2",
		"spec metadata": "CANARY-SPEC-META-41a2",
		"template":      "CANARY-TEMPLATE-41a2",
		"argv":          "CANARY-ARGV-41a2",
		"command env":   "CANARY-CMD-ENV-41a2",
		"stdin":         "CANARY-STDIN-41a2",
		"file path":     "CANARY-PATH-41a2",
		"file contents": "CANARY-FILE-41a2",
	}
	sb, err := wrapped.Create(ctx, Spec{
		Template: canaries["template"],
		Env:      map[string]string{"API_KEY": canaries["spec env"]},
		Metadata: map[string]string{"note": canaries["spec metadata"]},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := sb.Execute(ctx, Command{
		Argv:  []string{"echo", canaries["argv"]},
		Env:   map[string]string{"X": canaries["command env"]},
		Stdin: []byte(canaries["stdin"]),
	}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	filePath := "/" + canaries["file path"] + ".txt"
	if err := sb.WriteFile(ctx, filePath, []byte(canaries["file contents"])); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := sb.ReadFile(ctx, filePath); err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read telemetry file: %v", err)
	}
	for kind, canary := range canaries {
		if strings.Contains(string(data), canary) {
			t.Errorf("%s canary leaked into telemetry output", kind)
		}
	}
}

// minimalProvider implements only the Provider interface — none of
// the optional lifecycle interfaces.
type minimalProvider struct{}

func (minimalProvider) Name() string { return "minimal" }
func (minimalProvider) Capabilities() Capabilities {
	return Capabilities{}
}
func (minimalProvider) Create(_ context.Context, spec Spec) (Sandbox, error) {
	return &minimalSandbox{id: "min-1", template: spec.Template}, nil
}
func (minimalProvider) Reattach(_ context.Context, sandboxID string) (Sandbox, error) {
	return &minimalSandbox{id: sandboxID}, nil
}
func (minimalProvider) Destroy(context.Context, string) error { return nil }
func (minimalProvider) List(context.Context) ([]Info, error)  { return nil, nil }
func (minimalProvider) Ping(context.Context) error            { return nil }

// minimalSandbox implements only the Sandbox interface — in
// particular, not NetworkUpdater.
type minimalSandbox struct {
	id       string
	template string
}

func (s *minimalSandbox) ID() string       { return s.id }
func (s *minimalSandbox) Template() string { return s.template }
func (s *minimalSandbox) Execute(context.Context, Command) (Execution, error) {
	return Execution{ExitCode: 0}, nil
}
func (s *minimalSandbox) WriteFile(context.Context, string, []byte) error { return nil }
func (s *minimalSandbox) ReadFile(context.Context, string) ([]byte, error) {
	return []byte{}, nil
}
func (s *minimalSandbox) Destroy(context.Context) error { return nil }

// The decorated provider must expose exactly the optional interfaces
// the inner provider implements: the factory detects support by type
// assertion, and exposing more would defeat its SKIPPED path.
func TestTracedProviderPreservesOptionalInterfaces(t *testing.T) {
	telemetryFile(t)

	full := WrapProvider(NewFake())
	if _, ok := full.(Suspender); !ok {
		t.Error("wrapped Fake lost Suspender")
	}
	if _, ok := full.(Previewer); !ok {
		t.Error("wrapped Fake lost Previewer")
	}
	if _, ok := full.(Stater); !ok {
		t.Error("wrapped Fake lost Stater")
	}
	if _, ok := full.(Closer); ok {
		t.Error("wrapped Fake gained Closer")
	}

	minimal := WrapProvider(minimalProvider{})
	if _, ok := minimal.(Suspender); ok {
		t.Error("wrapped minimal provider gained Suspender")
	}
	if _, ok := minimal.(Previewer); ok {
		t.Error("wrapped minimal provider gained Previewer")
	}
	if _, ok := minimal.(Stater); ok {
		t.Error("wrapped minimal provider gained Stater")
	}
	if _, ok := minimal.(Closer); ok {
		t.Error("wrapped minimal provider gained Closer")
	}
}

// closerProvider implements Provider plus the optional Closer, so the
// wrapper must keep Close and delegate to it whenever telemetry wraps.
type closerProvider struct {
	minimalProvider
	closeErr error
}

func (p *closerProvider) Close() error { return p.closeErr }

// The decorated provider must expose Closer exactly when the inner
// provider implements it: the factory closes the provider it wrapped, so
// losing Close would skip provider cleanup entirely.
func TestTracedProviderPreservesCloser(t *testing.T) {
	telemetryFile(t)
	wrapped := WrapProvider(&closerProvider{closeErr: errors.New("close-boom")})
	if _, ok := wrapped.(Closer); !ok {
		t.Fatal("wrapped provider lost Closer")
	}
	closer := wrapped.(Closer)
	if err := closer.Close(); err == nil || err.Error() != "close-boom" {
		t.Fatalf("Close = %v, want the delegated error", err)
	}
}

// Optional lifecycle calls through the decorated provider are
// delegated and traced.
func TestTracedOptionalCallsAreTraced(t *testing.T) {
	wrapped, _, path := setupTraced(t)
	ctx := context.Background()
	sb, err := wrapped.Create(ctx, Spec{Template: "tmpl"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	suspender, ok := wrapped.(Suspender)
	if !ok {
		t.Fatal("wrapped Fake does not implement Suspender")
	}
	if err := suspender.Suspend(ctx, sb.ID()); err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	if err := suspender.Resume(ctx, sb.ID()); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	byOp := recordsByOperation(readRecords(t, path))
	for _, op := range []string{"suspend", "resume"} {
		rec, ok := byOp[op]
		if !ok {
			t.Errorf("no record for operation %q", op)
			continue
		}
		if rec.Attributes["sandbox_id"] != sb.ID() {
			t.Errorf("%s: sandbox_id = %v, want %v", op, rec.Attributes["sandbox_id"], sb.ID())
		}
	}
}

// The decorated sandbox must expose NetworkUpdater exactly when the
// inner sandbox does.
func TestTracedSandboxPreservesNetworkUpdater(t *testing.T) {
	wrapped, _, path := setupTraced(t)
	ctx := context.Background()
	sb, err := wrapped.Create(ctx, Spec{Template: "tmpl"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	updater, ok := sb.(NetworkUpdater)
	if !ok {
		t.Fatal("wrapped FakeSandbox lost NetworkUpdater")
	}
	if err := updater.UpdateNetwork(ctx, Network{}); err != nil {
		t.Fatalf("UpdateNetwork: %v", err)
	}
	byOp := recordsByOperation(readRecords(t, path))
	if _, ok := byOp["update_network"]; !ok {
		t.Error("no record for operation update_network")
	}

	minimal := WrapProvider(minimalProvider{})
	msb, err := minimal.Create(ctx, Spec{})
	if err != nil {
		t.Fatalf("minimal Create: %v", err)
	}
	if _, ok := msb.(NetworkUpdater); ok {
		t.Error("wrapped minimal sandbox gained NetworkUpdater")
	}
}

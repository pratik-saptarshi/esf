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
	if _, ok := full.(DefaultTemplater); ok {
		t.Error("wrapped Fake gained DefaultTemplater")
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
	if _, ok := minimal.(DefaultTemplater); ok {
		t.Error("wrapped minimal provider gained DefaultTemplater")
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

// templaterProvider implements Provider plus the optional
// DefaultTemplater, so the wrapper must keep DefaultTemplate and
// delegate to it whenever telemetry wraps.
type templaterProvider struct {
	minimalProvider
	template string
}

func (p *templaterProvider) DefaultTemplate() string { return p.template }

// templaterFake is the full Fake plus DefaultTemplater, so the
// wrapper's full-lifecycle shape must keep DefaultTemplate too.
type templaterFake struct {
	*Fake
	template string
}

func (p *templaterFake) DefaultTemplate() string { return p.template }

// The decorated provider must expose DefaultTemplater exactly when the
// inner provider implements it: the factory asks the provider it
// wrapped for the default template during create recovery, so losing
// DefaultTemplate would compare recovery against the wrong template.
func TestTracedProviderPreservesDefaultTemplater(t *testing.T) {
	telemetryFile(t)

	wrapped := WrapProvider(&templaterProvider{template: "tmpl-default"})
	templater, ok := wrapped.(DefaultTemplater)
	if !ok {
		t.Fatal("wrapped provider lost DefaultTemplater")
	}
	if got := templater.DefaultTemplate(); got != "tmpl-default" {
		t.Fatalf("DefaultTemplate = %q, want the delegated %q", got, "tmpl-default")
	}

	full := WrapProvider(&templaterFake{Fake: NewFake(), template: "fake-default"})
	templater, ok = full.(DefaultTemplater)
	if !ok {
		t.Fatal("wrapped full provider lost DefaultTemplater")
	}
	if got := templater.DefaultTemplate(); got != "fake-default" {
		t.Fatalf("DefaultTemplate = %q, want the delegated %q", got, "fake-default")
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

// The wrapper's shape switch is hand-enumerated — one anonymous struct
// per interface combination — so the mixin providers below let one
// table pin every combination: the decorated provider must expose
// exactly the optional interfaces its inner provider implements, for
// all five of them (Suspender, Previewer, Stater, Closer,
// DefaultTemplater).

type suspMixin struct{}

func (suspMixin) Suspend(context.Context, string) error { return nil }
func (suspMixin) Resume(context.Context, string) error  { return nil }

type prevMixin struct{}

func (prevMixin) PreviewURL(context.Context, string, int) (string, error) { return "", nil }

type statMixin struct{}

func (statMixin) SandboxState(context.Context, string) (string, error) { return "", nil }

type closMixin struct{}

func (closMixin) Close() error { return nil }

type tempMixin struct{}

func (tempMixin) DefaultTemplate() string { return "probe-default" }

type combo00 struct{ minimalProvider }
type combo01 struct {
	minimalProvider
	suspMixin
}
type combo02 struct {
	minimalProvider
	prevMixin
}
type combo03 struct {
	minimalProvider
	suspMixin
	prevMixin
}
type combo04 struct {
	minimalProvider
	statMixin
}
type combo05 struct {
	minimalProvider
	suspMixin
	statMixin
}
type combo06 struct {
	minimalProvider
	prevMixin
	statMixin
}
type combo07 struct {
	minimalProvider
	suspMixin
	prevMixin
	statMixin
}
type combo08 struct {
	minimalProvider
	closMixin
}
type combo09 struct {
	minimalProvider
	suspMixin
	closMixin
}
type combo10 struct {
	minimalProvider
	prevMixin
	closMixin
}
type combo11 struct {
	minimalProvider
	suspMixin
	prevMixin
	closMixin
}
type combo12 struct {
	minimalProvider
	statMixin
	closMixin
}
type combo13 struct {
	minimalProvider
	suspMixin
	statMixin
	closMixin
}
type combo14 struct {
	minimalProvider
	prevMixin
	statMixin
	closMixin
}
type combo15 struct {
	minimalProvider
	suspMixin
	prevMixin
	statMixin
	closMixin
}
type combo16 struct {
	minimalProvider
	tempMixin
}
type combo17 struct {
	minimalProvider
	suspMixin
	tempMixin
}
type combo18 struct {
	minimalProvider
	prevMixin
	tempMixin
}
type combo19 struct {
	minimalProvider
	suspMixin
	prevMixin
	tempMixin
}
type combo20 struct {
	minimalProvider
	statMixin
	tempMixin
}
type combo21 struct {
	minimalProvider
	suspMixin
	statMixin
	tempMixin
}
type combo22 struct {
	minimalProvider
	prevMixin
	statMixin
	tempMixin
}
type combo23 struct {
	minimalProvider
	suspMixin
	prevMixin
	statMixin
	tempMixin
}
type combo24 struct {
	minimalProvider
	closMixin
	tempMixin
}
type combo25 struct {
	minimalProvider
	suspMixin
	closMixin
	tempMixin
}
type combo26 struct {
	minimalProvider
	prevMixin
	closMixin
	tempMixin
}
type combo27 struct {
	minimalProvider
	suspMixin
	prevMixin
	closMixin
	tempMixin
}
type combo28 struct {
	minimalProvider
	statMixin
	closMixin
	tempMixin
}
type combo29 struct {
	minimalProvider
	suspMixin
	statMixin
	closMixin
	tempMixin
}
type combo30 struct {
	minimalProvider
	prevMixin
	statMixin
	closMixin
	tempMixin
}
type combo31 struct {
	minimalProvider
	suspMixin
	prevMixin
	statMixin
	closMixin
	tempMixin
}

func TestTracedProviderShapeMatrix(t *testing.T) {
	telemetryFile(t)
	cases := []struct {
		inner Provider
		want  [5]bool // Suspender, Previewer, Stater, Closer, DefaultTemplater
	}{
		{inner: combo00{minimalProvider{}}, want: [5]bool{false, false, false, false, false}},
		{inner: combo01{minimalProvider{}, suspMixin{}}, want: [5]bool{true, false, false, false, false}},
		{inner: combo02{minimalProvider{}, prevMixin{}}, want: [5]bool{false, true, false, false, false}},
		{inner: combo03{minimalProvider{}, suspMixin{}, prevMixin{}}, want: [5]bool{true, true, false, false, false}},
		{inner: combo04{minimalProvider{}, statMixin{}}, want: [5]bool{false, false, true, false, false}},
		{inner: combo05{minimalProvider{}, suspMixin{}, statMixin{}}, want: [5]bool{true, false, true, false, false}},
		{inner: combo06{minimalProvider{}, prevMixin{}, statMixin{}}, want: [5]bool{false, true, true, false, false}},
		{inner: combo07{minimalProvider{}, suspMixin{}, prevMixin{}, statMixin{}}, want: [5]bool{true, true, true, false, false}},
		{inner: combo08{minimalProvider{}, closMixin{}}, want: [5]bool{false, false, false, true, false}},
		{inner: combo09{minimalProvider{}, suspMixin{}, closMixin{}}, want: [5]bool{true, false, false, true, false}},
		{inner: combo10{minimalProvider{}, prevMixin{}, closMixin{}}, want: [5]bool{false, true, false, true, false}},
		{inner: combo11{minimalProvider{}, suspMixin{}, prevMixin{}, closMixin{}}, want: [5]bool{true, true, false, true, false}},
		{inner: combo12{minimalProvider{}, statMixin{}, closMixin{}}, want: [5]bool{false, false, true, true, false}},
		{inner: combo13{minimalProvider{}, suspMixin{}, statMixin{}, closMixin{}}, want: [5]bool{true, false, true, true, false}},
		{inner: combo14{minimalProvider{}, prevMixin{}, statMixin{}, closMixin{}}, want: [5]bool{false, true, true, true, false}},
		{inner: combo15{minimalProvider{}, suspMixin{}, prevMixin{}, statMixin{}, closMixin{}}, want: [5]bool{true, true, true, true, false}},
		{inner: combo16{minimalProvider{}, tempMixin{}}, want: [5]bool{false, false, false, false, true}},
		{inner: combo17{minimalProvider{}, suspMixin{}, tempMixin{}}, want: [5]bool{true, false, false, false, true}},
		{inner: combo18{minimalProvider{}, prevMixin{}, tempMixin{}}, want: [5]bool{false, true, false, false, true}},
		{inner: combo19{minimalProvider{}, suspMixin{}, prevMixin{}, tempMixin{}}, want: [5]bool{true, true, false, false, true}},
		{inner: combo20{minimalProvider{}, statMixin{}, tempMixin{}}, want: [5]bool{false, false, true, false, true}},
		{inner: combo21{minimalProvider{}, suspMixin{}, statMixin{}, tempMixin{}}, want: [5]bool{true, false, true, false, true}},
		{inner: combo22{minimalProvider{}, prevMixin{}, statMixin{}, tempMixin{}}, want: [5]bool{false, true, true, false, true}},
		{inner: combo23{minimalProvider{}, suspMixin{}, prevMixin{}, statMixin{}, tempMixin{}}, want: [5]bool{true, true, true, false, true}},
		{inner: combo24{minimalProvider{}, closMixin{}, tempMixin{}}, want: [5]bool{false, false, false, true, true}},
		{inner: combo25{minimalProvider{}, suspMixin{}, closMixin{}, tempMixin{}}, want: [5]bool{true, false, false, true, true}},
		{inner: combo26{minimalProvider{}, prevMixin{}, closMixin{}, tempMixin{}}, want: [5]bool{false, true, false, true, true}},
		{inner: combo27{minimalProvider{}, suspMixin{}, prevMixin{}, closMixin{}, tempMixin{}}, want: [5]bool{true, true, false, true, true}},
		{inner: combo28{minimalProvider{}, statMixin{}, closMixin{}, tempMixin{}}, want: [5]bool{false, false, true, true, true}},
		{inner: combo29{minimalProvider{}, suspMixin{}, statMixin{}, closMixin{}, tempMixin{}}, want: [5]bool{true, false, true, true, true}},
		{inner: combo30{minimalProvider{}, prevMixin{}, statMixin{}, closMixin{}, tempMixin{}}, want: [5]bool{false, true, true, true, true}},
		{inner: combo31{minimalProvider{}, suspMixin{}, prevMixin{}, statMixin{}, closMixin{}, tempMixin{}}, want: [5]bool{true, true, true, true, true}},
	}
	for i, tc := range cases {
		wrapped := WrapProvider(tc.inner)
		got := [5]bool{}
		_, got[0] = wrapped.(Suspender)
		_, got[1] = wrapped.(Previewer)
		_, got[2] = wrapped.(Stater)
		_, got[3] = wrapped.(Closer)
		_, got[4] = wrapped.(DefaultTemplater)
		if got != tc.want {
			t.Errorf("case %d: wrapped exposes %v, want %v", i, got, tc.want)
		}
	}
}

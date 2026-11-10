package sandbox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// contractRecord mirrors the shared telemetry contract's record
// shape (tools/ghg/telemetry.py in the AEP repo) for assertions.
type contractRecord struct {
	Name         string         `json:"name"`
	TraceID      string         `json:"trace_id"`
	SpanID       string         `json:"span_id"`
	ParentSpanID *string        `json:"parent_span_id"`
	StartTime    int64          `json:"start_time"`
	EndTime      int64          `json:"end_time"`
	Status       string         `json:"status"`
	Attributes   map[string]any `json:"attributes"`
}

var (
	traceIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	spanIDPattern  = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

// telemetryFile points ESF_OTEL_FILE at a fresh temp file and
// returns its path. These tests mutate process env, so they must
// not run in parallel.
func telemetryFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "spans.jsonl")
	t.Setenv(otelEnvVar, path)
	return path
}

func readRecords(t *testing.T, path string) []contractRecord {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read telemetry file: %v", err)
	}
	var records []contractRecord
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var rec contractRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("unmarshal record %q: %v", line, err)
		}
		records = append(records, rec)
	}
	return records
}

func recordsByOperation(records []contractRecord) map[string]contractRecord {
	out := map[string]contractRecord{}
	for _, rec := range records {
		op, _ := rec.Attributes["operation"].(string)
		out[op] = rec
	}
	return out
}

// The exported record must match the shared contract field for
// field: exactly the eight fields, hex id shapes, integer
// nanosecond timestamps, and a null parent for a root span.
func TestJSONLRecordMatchesContractShape(t *testing.T) {
	path := telemetryFile(t)
	tel := telemetryFromEnv()
	if tel == nil {
		t.Fatal("telemetryFromEnv returned nil with ESF_OTEL_FILE set")
	}
	_, rec := tel.start(context.Background(), "shape")
	rec.set("provider", "fake")
	rec.finish(nil)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read telemetry file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d records, want 1", len(lines))
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &raw); err != nil {
		t.Fatalf("unmarshal raw record: %v", err)
	}
	wantKeys := []string{"name", "trace_id", "span_id", "parent_span_id",
		"start_time", "end_time", "status", "attributes"}
	if len(raw) != len(wantKeys) {
		t.Fatalf("record has %d fields, want %d: %v", len(raw), len(wantKeys), raw)
	}
	for _, key := range wantKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("record missing contract field %q", key)
		}
	}
	records := readRecords(t, path)
	got := records[0]
	if got.Name != "esf.shape" {
		t.Errorf("name = %q, want esf.shape", got.Name)
	}
	if !traceIDPattern.MatchString(got.TraceID) {
		t.Errorf("trace_id = %q, want 32 lowercase hex chars", got.TraceID)
	}
	if !spanIDPattern.MatchString(got.SpanID) {
		t.Errorf("span_id = %q, want 16 lowercase hex chars", got.SpanID)
	}
	if got.ParentSpanID != nil {
		t.Errorf("parent_span_id = %q, want null for a root span", *got.ParentSpanID)
	}
	if got.StartTime <= 0 || got.EndTime < got.StartTime {
		t.Errorf("start/end = %d/%d, want 0 < start <= end (ns)", got.StartTime, got.EndTime)
	}
	if got.Status != "UNSET" {
		t.Errorf("status = %q, want UNSET", got.Status)
	}
	if got.Attributes["operation"] != "shape" || got.Attributes["provider"] != "fake" {
		t.Errorf("attributes = %v, want operation=shape provider=fake", got.Attributes)
	}
	if _, ok := got.Attributes["duration_ms"].(float64); !ok {
		t.Errorf("duration_ms missing or not a number: %v", got.Attributes)
	}
}

// Canary: attributes set through the recorder's single set path with
// non-allowlisted keys must never reach the record. Removing the
// filter in filterAttributes turns this test red.
func TestAttributeFilterDropsNonAllowlistedKeys(t *testing.T) {
	path := telemetryFile(t)
	tel := telemetryFromEnv()
	if tel == nil {
		t.Fatal("telemetryFromEnv returned nil with ESF_OTEL_FILE set")
	}
	const canary = "CANARY-SECRET-9c1e"
	_, rec := tel.start(context.Background(), "canary")
	rec.set("command_argv", canary)
	rec.set("env_value", canary)
	rec.set("file_contents", canary)
	rec.set("provider", "fake")
	rec.finish(nil)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read telemetry file: %v", err)
	}
	if strings.Contains(string(data), canary) {
		t.Fatalf("canary leaked into telemetry output: %s", data)
	}
	records := readRecords(t, path)
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	for key := range records[0].Attributes {
		if !allowedAttributes[key] {
			t.Errorf("non-allowlisted attribute %q reached the record", key)
		}
	}
}

// With ESF_OTEL_FILE unset, WrapProvider returns the inner provider
// itself and no file is created anywhere.
func TestWrapProviderDisabledReturnsInner(t *testing.T) {
	t.Setenv(otelEnvVar, "")
	fake := NewFake()
	wrapped := WrapProvider(fake)
	if wrapped != Provider(fake) {
		t.Fatal("WrapProvider with telemetry disabled did not return the inner provider")
	}
	sb, err := wrapped.Create(context.Background(), Spec{Template: "tmpl"})
	if err != nil {
		t.Fatalf("Create through unwrapped provider: %v", err)
	}
	if sb.ID() != "fake-sandbox-1" {
		t.Errorf("sandbox ID = %q, want fake-sandbox-1", sb.ID())
	}
}

// With ESF_OTEL_FILE pointing into a missing directory, telemetry
// degrades to the no-op path: the inner provider is returned and
// calls succeed.
func TestWrapProviderUnusablePathReturnsInner(t *testing.T) {
	t.Setenv(otelEnvVar, filepath.Join(t.TempDir(), "missing", "spans.jsonl"))
	fake := NewFake()
	wrapped := WrapProvider(fake)
	if wrapped != Provider(fake) {
		t.Fatal("WrapProvider with unusable telemetry path did not return the inner provider")
	}
	if err := wrapped.Ping(context.Background()); err != nil {
		t.Fatalf("Ping through unwrapped provider: %v", err)
	}
}

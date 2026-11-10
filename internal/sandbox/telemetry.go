package sandbox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// Optional OpenTelemetry instrumentation for the sandbox seam.
//
// Telemetry is off by default. It is enabled only when the env var
// ESF_OTEL_FILE names a JSONL output file. When the var is unset or
// the output path is unusable, wrapping a provider returns the
// provider itself: no file is created and behaviour is unchanged.
//
// The exported records implement the shared telemetry contract (the
// record shape defined by tools/ghg/telemetry.py in the AEP repo):
// one JSON object per finished span with the fields name, trace_id,
// span_id, parent_span_id, start_time, end_time, status and
// attributes. Downstream consumers read that shape regardless of
// which runtime produced it.
//
// Spans carry ONLY allowlisted attributes (see allowedAttributes):
// never command argv, never env values, never file contents, never
// spec metadata. Every attribute passes through filterAttributes via
// the recorder's set method, which is the one and only
// attribute-setting path; the exporter deliberately does not
// re-filter, so that path is the sole guard against leaks.
//
// Any telemetry-side failure degrades silently to the no-op path, so
// telemetry can never break the caller.

const otelEnvVar = "ESF_OTEL_FILE"

// allowedAttributes is the esf adapter's attribute allowlist:
// operation, provider and exit_code/duration_ms per the shared
// contract, plus sandbox_id, the one per-runtime identifier this
// adapter records.
var allowedAttributes = map[string]bool{
	"operation":   true,
	"provider":    true,
	"exit_code":   true,
	"duration_ms": true,
	"sandbox_id":  true,
}

// filterAttributes returns only allowlisted keys whose values are
// scalars. It is the single attribute filter for the whole adapter.
func filterAttributes(attrs map[string]any) map[string]any {
	out := make(map[string]any, len(attrs))
	for key, value := range attrs {
		if !allowedAttributes[key] {
			continue
		}
		switch value.(type) {
		case string, int, int64, float64, bool:
			out[key] = value
		}
	}
	return out
}

// spanRecord is the contract record: one JSON object per span. Field
// order matches the contract's _record shape.
type spanRecord struct {
	Name         string         `json:"name"`
	TraceID      string         `json:"trace_id"`
	SpanID       string         `json:"span_id"`
	ParentSpanID *string        `json:"parent_span_id"`
	StartTime    int64          `json:"start_time"`
	EndTime      int64          `json:"end_time"`
	Status       string         `json:"status"`
	Attributes   map[string]any `json:"attributes"`
}

// statusName maps an OTel status code to the contract's status
// string (the Python enum names used by the contract exporter).
func statusName(code codes.Code) string {
	switch code {
	case codes.Ok:
		return "OK"
	case codes.Error:
		return "ERROR"
	default:
		return "UNSET"
	}
}

// jsonlExporter appends one contract record per finished span to a
// file. It never reports an error: telemetry must not break callers.
type jsonlExporter struct {
	mu   sync.Mutex
	path string
}

func (e *jsonlExporter) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	f, err := os.OpenFile(e.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil
	}
	defer f.Close()
	for _, span := range spans {
		line, err := json.Marshal(recordOf(span))
		if err != nil {
			continue
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			return nil
		}
	}
	return nil
}

func (e *jsonlExporter) Shutdown(context.Context) error { return nil }

// recordOf converts a finished span to its contract record.
func recordOf(span sdktrace.ReadOnlySpan) spanRecord {
	rec := spanRecord{
		Name:       span.Name(),
		TraceID:    span.SpanContext().TraceID().String(),
		SpanID:     span.SpanContext().SpanID().String(),
		StartTime:  span.StartTime().UnixNano(),
		EndTime:    span.EndTime().UnixNano(),
		Status:     statusName(span.Status().Code),
		Attributes: make(map[string]any),
	}
	if parent := span.Parent(); parent.IsValid() {
		id := parent.SpanID().String()
		rec.ParentSpanID = &id
	}
	for _, kv := range span.Attributes() {
		switch kv.Value.Type() {
		case attribute.STRING:
			rec.Attributes[string(kv.Key)] = kv.Value.AsString()
		case attribute.INT64:
			rec.Attributes[string(kv.Key)] = kv.Value.AsInt64()
		case attribute.FLOAT64:
			rec.Attributes[string(kv.Key)] = kv.Value.AsFloat64()
		case attribute.BOOL:
			rec.Attributes[string(kv.Key)] = kv.Value.AsBool()
		}
		// Non-scalar attribute values are dropped: the attribute
		// filter only ever admits scalars, so none can occur here.
	}
	return rec
}

// telemetry is a configured tracer for one output file.
type telemetry struct {
	tracer trace.Tracer
}

var (
	telemetryMu    sync.Mutex
	telemetryCache = map[string]*telemetry{}
)

// telemetryFromEnv returns the telemetry configured by ESF_OTEL_FILE,
// or nil when telemetry is disabled or cannot be set up. Setup is
// lazy and cached per output file, so distinct files in one process
// do not collide. It never fails: any problem yields nil (no-op).
func telemetryFromEnv() *telemetry {
	path := os.Getenv(otelEnvVar)
	if path == "" {
		return nil
	}
	if dir := filepath.Dir(path); dir != "" {
		if _, err := os.Stat(dir); err != nil {
			// Unusable path (parent dir missing): no-op, as in ghg.
			return nil
		}
	}
	telemetryMu.Lock()
	defer telemetryMu.Unlock()
	if cached, ok := telemetryCache[path]; ok {
		return cached
	}
	res, err := resource.New(context.Background(), resource.WithAttributes(
		attribute.String("service.name", "esf"),
	))
	if err != nil {
		res = resource.Empty()
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(
			&jsonlExporter{path: path})),
	)
	tel := &telemetry{tracer: provider.Tracer("esf")}
	telemetryCache[path] = tel
	return tel
}

// spanRecorder is one in-flight operation span. Attributes are
// buffered through set (the single, filtered set path) and applied
// to the span at finish. A nil or inactive recorder is a pure no-op.
type spanRecorder struct {
	span   trace.Span
	start  time.Time
	attrs  map[string]any
	active bool
}

// start begins an operation span named "esf.<operation>" and records
// the operation attribute. When telemetry is unavailable the
// returned recorder is inactive and every method is a no-op.
func (t *telemetry) start(ctx context.Context, operation string) (context.Context, *spanRecorder) {
	if t == nil || t.tracer == nil {
		return ctx, &spanRecorder{}
	}
	ctx, span := t.tracer.Start(ctx, "esf."+operation)
	rec := &spanRecorder{span: span, start: time.Now(), attrs: map[string]any{}, active: true}
	rec.set("operation", operation)
	return ctx, rec
}

// set records an attribute, filtered through filterAttributes. It
// is the one and only attribute-setting path.
func (r *spanRecorder) set(key string, value any) {
	if !r.active {
		return
	}
	if filtered := filterAttributes(map[string]any{key: value}); filtered[key] != nil {
		r.attrs[key] = filtered[key]
	}
}

// finish records duration_ms, applies the buffered attributes, sets
// the span status (ERROR when err is non-nil) and ends the span. The
// outcome is taken only from err; a result such as a non-zero
// command exit code is recorded as an attribute by the caller and
// never turns into an ERROR status here.
func (r *spanRecorder) finish(err error) {
	if !r.active {
		return
	}
	r.set("duration_ms", float64(time.Since(r.start))/float64(time.Millisecond))
	for key, value := range r.attrs {
		switch v := value.(type) {
		case string:
			r.span.SetAttributes(attribute.String(key, v))
		case int:
			r.span.SetAttributes(attribute.Int64(key, int64(v)))
		case int64:
			r.span.SetAttributes(attribute.Int64(key, v))
		case float64:
			r.span.SetAttributes(attribute.Float64(key, v))
		case bool:
			r.span.SetAttributes(attribute.Bool(key, v))
		}
	}
	if err != nil {
		r.span.SetStatus(codes.Error, "")
	}
	r.span.End()
	r.active = false
}

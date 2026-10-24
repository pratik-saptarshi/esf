package podman

import (
	"bytes"
	"fmt"
)

// boundedCommandScript wraps a rendered command line so each output
// stream is capped at limit bytes inside the sandbox before anything
// reaches the host, mirroring the cube wrapper's contract
// (internal/sandbox/cube/output.go): an overflowing stream is truncated
// to the limit, ESF_OUTPUT_LIMIT_EXCEEDED is appended to stderr, and
// the recorded exit code becomes 122. The final exit code is written to
// exitFilePath (decision D5).
func boundedCommandScript(line string, limit int64) string {
	return fmt.Sprintf(`mkdir -p /run
esf_out_file=$(mktemp /tmp/esf-out.XXXXXX)
esf_err_file=$(mktemp /tmp/esf-err.XXXXXX)
( %s ) >"$esf_out_file" 2>"$esf_err_file"
esf_exit=$?
esf_over=0
if [ "$(wc -c <"$esf_out_file")" -gt %d ]; then esf_over=1; fi
if [ "$(wc -c <"$esf_err_file")" -gt %d ]; then esf_over=1; fi
head -c %d "$esf_out_file"
head -c %d "$esf_err_file" >&2
if [ "$esf_over" = "1" ]; then
  printf '\nESF_OUTPUT_LIMIT_EXCEEDED: output exceeded the %d byte per-stream limit\n' >&2
  esf_exit=122
fi
printf '%%s' "$esf_exit" > /run/esf-exit
rm -f "$esf_out_file" "$esf_err_file"
exit "$esf_exit"
`, line, limit, limit, limit, limit, limit)
}

// cappedBuffer is an io.Writer retaining at most limit bytes. Defense in
// depth behind boundedCommandScript: a wrapper bug must never turn into
// unbounded host memory.
type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int64
	discarded int64
}

func (w *cappedBuffer) Write(p []byte) (int, error) {
	room := w.limit - int64(w.buf.Len())
	switch {
	case room >= int64(len(p)):
		w.buf.Write(p)
	case room > 0:
		w.buf.Write(p[:room])
		w.discarded += int64(len(p)) - room
	default:
		w.discarded += int64(len(p))
	}
	return len(p), nil
}

func (w *cappedBuffer) String() string { return w.buf.String() }

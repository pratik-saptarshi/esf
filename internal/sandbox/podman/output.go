package podman

import (
	"bytes"
	"fmt"
)

// boundedCommandScript wraps a rendered command line so each output
// stream is capped at limit bytes inside the sandbox before anything
// reaches the host, mirroring the cube wrapper's mechanism and
// contract (internal/sandbox/cube/output.go): the command writes to
// FIFOs drained by readers that keep at most limit+1 bytes per stream,
// so stored output is bounded WHILE the command runs — an overflowing
// producer loses its reader and is stopped by the closed pipe instead
// of filling the rootfs until it exits. The extra byte distinguishes
// an exact-limit result from overflow. An overflowing stream is
// truncated to the limit, ESF_OUTPUT_LIMIT_EXCEEDED is appended to
// stderr, and the recorded exit code becomes 122. The final exit code
// is written to exitFilePath (decision D5).
func boundedCommandScript(line string, limit int64) string {
	return fmt.Sprintf(`mkdir -p /run
esf_output_dir=$(mktemp -d) || exit 125
trap 'rm -rf "$esf_output_dir"' EXIT
mkfifo "$esf_output_dir/out.pipe" "$esf_output_dir/err.pipe" || exit 125
head -c %d <"$esf_output_dir/out.pipe" >"$esf_output_dir/out" &
esf_out_pid=$!
head -c %d <"$esf_output_dir/err.pipe" >"$esf_output_dir/err" &
esf_err_pid=$!
( %s ) >"$esf_output_dir/out.pipe" 2>"$esf_output_dir/err.pipe"
esf_exit=$?
wait "$esf_out_pid" || true
wait "$esf_err_pid" || true
head -c %d "$esf_output_dir/out"
head -c %d "$esf_output_dir/err" >&2
if [ "$(wc -c <"$esf_output_dir/out")" -gt %d ] || [ "$(wc -c <"$esf_output_dir/err")" -gt %d ]; then
  printf '\nESF_OUTPUT_LIMIT_EXCEEDED: output exceeded the %d byte per-stream limit\n' >&2
  esf_exit=122
fi
printf '%%s' "$esf_exit" > /run/esf-exit
exit "$esf_exit"
`, limit+1, limit+1, line, limit, limit, limit, limit, limit)
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

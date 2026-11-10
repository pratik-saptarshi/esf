package podman

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
)

// runner executes the podman CLI. Production uses execRunner; unit tests
// substitute a fake. Implementations must return the process exit code
// separately from spawn/transport errors so callers can classify.
type runner interface {
	Run(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) (exitCode int, err error)
}

type execRunner struct{ binary string }

func (r execRunner) Run(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) (int, error) {
	cmd := exec.CommandContext(ctx, r.binary, args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	return -1, err // binary missing, context teardown, etc.
}

// invoke runs a short, small-output podman command with buffered output.
// A non-zero exit is reported in the result, not as an error; err is
// reserved for spawn/transport failures.
type invokeResult struct {
	Stdout []byte
	Stderr []byte
	Code   int
}

func (p *Provider) invoke(ctx context.Context, args ...string) (invokeResult, error) {
	var outBuf, errBuf bytes.Buffer
	full := append(append([]string{}, p.cfg.baseArgs()...), args...)
	code, err := p.run.Run(ctx, nil, &outBuf, &errBuf, full...)
	return invokeResult{Stdout: outBuf.Bytes(), Stderr: errBuf.Bytes(), Code: code}, err
}

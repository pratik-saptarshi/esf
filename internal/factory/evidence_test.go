package factory

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mitkox/esf/internal/agentharness"
	"github.com/mitkox/esf/internal/factoryartifacts"
	"github.com/mitkox/esf/internal/repository"
	"github.com/mitkox/esf/internal/sandbox"
	"github.com/mitkox/esf/internal/verification"
)

type failingEvidenceFactory struct {
	artifacts.Factory
	fail string
}
type failingEvidenceStore struct {
	artifacts.Store
	fail string
}

func (f failingEvidenceFactory) ForRun(id string) (artifacts.Store, error) {
	s, err := f.Factory.ForRun(id)
	return failingEvidenceStore{s, f.fail}, err
}
func (s failingEvidenceStore) Write(path string, data []byte) error {
	if path == s.fail {
		return fmt.Errorf("disk full writing %s", path)
	}
	return s.Store.Write(path, data)
}

// secretLeakingFactory fails ForRun or Write with an error embedding a
// secret-shaped value, so tests can prove the redactor scrubs it before the
// value reaches durable evidence.
type secretLeakingFactory struct {
	artifacts.Factory
	secret     string
	failForRun bool
}

type secretLeakingStore struct {
	artifacts.Store
	secret string
}

func (f secretLeakingFactory) ForRun(id string) (artifacts.Store, error) {
	if f.failForRun {
		return nil, fmt.Errorf("store unavailable: provider key %s rejected", f.secret)
	}
	s, err := f.Factory.ForRun(id)
	if err != nil {
		return nil, err
	}
	return secretLeakingStore{Store: s, secret: f.secret}, nil
}

func (s secretLeakingStore) Write(path string, data []byte) error {
	return fmt.Errorf("write %s failed: backend token %s expired", path, s.secret)
}

// TestWriteInventoryRedactsEvidenceErrors proves both evidence-error paths in
// WriteInventory (artifact-store open failure and artifact write failure) pass
// through the redactor. activities_lifecycle.go assigned err.Error() raw — the
// only unredacted EvidenceError assignments in the codebase.
func TestWriteInventoryRedactsEvidenceErrors(t *testing.T) {
	const secret = "opaque-inventory-secret-1234"
	for _, mode := range []struct {
		name       string
		failForRun bool
	}{
		{name: "forRun", failForRun: true},
		{name: "write", failForRun: false},
	} {
		t.Run(mode.name, func(t *testing.T) {
			provider := sandbox.NewFake()
			sb, err := provider.Create(context.Background(), sandbox.Spec{})
			if err != nil {
				t.Fatal(err)
			}
			realFactory, err := artifacts.NewLocal(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			acts, err := NewActivities(ActivitiesOptions{
				Provider:        provider,
				Repositories:    repository.New(nil),
				Harnesses:       agentharness.NewRegistry(),
				ArtifactFactory: secretLeakingFactory{Factory: realFactory, secret: secret, failForRun: mode.failForRun},
				Redactor:        NewRedactor(secret),
			})
			if err != nil {
				t.Fatal(err)
			}
			out, err := acts.WriteInventory(context.Background(), WriteInventoryInput{
				RunID: "run-redact-test", SandboxID: sb.ID(),
			})
			if err != nil {
				t.Fatalf("WriteInventory returned error: %v (evidence failures must not retry)", err)
			}
			if out.EvidenceError == "" {
				t.Fatalf("expected EvidenceError to be set on %s failure, got empty", mode.name)
			}
			if strings.Contains(out.EvidenceError, secret) {
				t.Fatalf("raw secret leaked into EvidenceError (%s): %q", mode.name, out.EvidenceError)
			}
			if !strings.Contains(out.EvidenceError, RedactionMask) {
				t.Fatalf("expected redaction mask in EvidenceError (%s): %q", mode.name, out.EvidenceError)
			}
		})
	}
}

func TestActivitiesSurfaceEvidenceWriteFailures(t *testing.T) {
	for _, path := range []string{ArtifactAgentStdout, ArtifactAgentStderr, ArtifactAgentPrompt, ArtifactAgentResult, "verification/check.stdout", "verification/check.stderr", ArtifactVerificationResult} {
		t.Run(path, func(t *testing.T) {
			provider := sandbox.NewFake()
			sb, err := provider.Create(context.Background(), sandbox.Spec{})
			if err != nil {
				t.Fatal(err)
			}
			store, err := artifacts.NewLocal(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			harness, err := agentharness.NewGeneric(agentharness.Spec{Name: "test", Executable: "agent", Timeout: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			registry := agentharness.NewRegistry()
			if err := registry.Register(harness); err != nil {
				t.Fatal(err)
			}
			acts, err := NewActivities(ActivitiesOptions{
				Provider: provider, Repositories: repository.New(nil), Harnesses: registry,
				ArtifactFactory: failingEvidenceFactory{store, path}, Redactor: NewRedactor(),
				Profiles: verification.Profiles{Profiles: map[string]verification.Profile{"test": {Name: "test", Steps: []verification.Step{{ID: "check", Argv: []string{"true"}}}}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			var evidence string
			if strings.HasPrefix(path, "verification") {
				out, err := acts.RunVerification(context.Background(), RunVerificationInput{RunID: "run-test", SandboxID: sb.ID(), Profile: "test", RepositoryDir: "/repo"})
				if err != nil {
					t.Fatalf("must not trigger execution retry: %v", err)
				}
				evidence = out.EvidenceError
			} else {
				out, err := acts.RunAgent(context.Background(), RunAgentInput{RunID: "run-test", SandboxID: sb.ID(), Harness: "test", RepositoryDir: "/repo", Prompt: "task", Timeout: time.Minute})
				if err != nil {
					t.Fatalf("must not trigger execution retry: %v", err)
				}
				evidence = out.EvidenceError
			}
			if !strings.Contains(evidence, "disk full") {
				t.Fatalf("storage error lost: %q", evidence)
			}
		})
	}
}

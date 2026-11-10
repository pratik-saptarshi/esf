package factory

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/mitkox/esf/internal/agentharness"
	"github.com/stretchr/testify/mock"
	"go.temporal.io/sdk/testsuite"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mitkox/esf/internal/sandbox"
	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
	"google.golang.org/protobuf/proto"
)

func TestTemporalConnectionSecurity(t *testing.T) {
	t.Setenv("TEST_TEMPORAL_KEY", "test-secret")
	for _, tc := range []struct {
		name   string
		config TemporalConfig
		valid  bool
	}{
		{"local", TemporalConfig{HostPort: "127.0.0.1:7233"}, true},
		{"remote plaintext", TemporalConfig{HostPort: "temporal.example:7233"}, false},
		{"remote TLS", TemporalConfig{HostPort: "temporal.example:7233", TLS: true}, true},
		{"plaintext credential", TemporalConfig{HostPort: "localhost:7233", APIKeyEnv: "TEST_TEMPORAL_KEY"}, false},
		{"TLS credential", TemporalConfig{HostPort: "localhost:7233", TLS: true, APIKeyEnv: "TEST_TEMPORAL_KEY"}, true},
		{"missing credential", TemporalConfig{HostPort: "localhost:7233", TLS: true, APIKeyEnv: "MISSING_TEST_TEMPORAL_KEY"}, false},
		{"missing key", TemporalConfig{HostPort: "localhost:7233", TLS: true, CertFile: "cert.pem"}, false},
		{"missing CA", TemporalConfig{HostPort: "localhost:7233", TLS: true, CAFile: "/nonexistent/ca.pem"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options, err := tc.config.connectionOptions()
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
			if options.TLS != nil && options.TLS.InsecureSkipVerify {
				t.Fatal("certificate validation disabled")
			}
		})
	}
}

func testCodec(t *testing.T, active string) *payloadCodec {
	t.Helper()
	data, err := json.Marshal(map[string]any{"active": active, "keys": map[string]string{
		"old": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		"new": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)),
	}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := loadPayloadCodec(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPayloadEncryptionRotationAndTampering(t *testing.T) {
	old := testCodec(t, "old")
	current := testCodec(t, "new")
	input := []*commonpb.Payload{{Metadata: map[string][]byte{"encoding": []byte("json/plain")}, Data: []byte(`"private prompt"`)}}
	encoded, err := old.Encode(input)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded[0].Data, []byte("private prompt")) {
		t.Fatal("plaintext persisted")
	}
	second, _ := old.Encode(input)
	if bytes.Equal(encoded[0].Data, second[0].Data) {
		t.Fatal("nonce reused")
	}
	decoded, err := current.Decode(encoded)
	if err != nil || !proto.Equal(decoded[0], input[0]) {
		t.Fatalf("rotation replay failed: %v", err)
	}
	encoded[0].Data[0] ^= 1
	if _, err := current.Decode(encoded); err == nil {
		t.Fatal("tampering accepted")
	}
	legacy, err := current.Decode(input)
	if err != nil || !proto.Equal(legacy[0], input[0]) {
		t.Fatal("legacy payload cannot be read")
	}
	delete(current.keys, "old")
	if _, err := current.Decode(second); err == nil {
		t.Fatal("missing key accepted")
	}
}

func TestFailureMessagesAreEncrypted(t *testing.T) {
	dc := converter.NewCodecDataConverter(converter.GetDefaultDataConverter(), testCodec(t, "new"))
	fc := temporal.NewDefaultFailureConverter(temporal.DefaultFailureConverterOptions{DataConverter: dc, EncodeCommonAttributes: true})
	failure := fc.ErrorToFailure(fmt.Errorf("sensitive failure text"))
	data, err := proto.Marshal(failure)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("sensitive failure text")) {
		t.Fatal("error leaked into history")
	}
	if fc.FailureToError(failure).Error() != "sensitive failure text" {
		t.Fatal("failure round trip failed")
	}
}

type lostCreateProvider struct{ *sandbox.Fake }

func (p *lostCreateProvider) Create(ctx context.Context, spec sandbox.Spec) (sandbox.Sandbox, error) {
	if _, err := p.Fake.Create(ctx, spec); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("create response lost")
}

func TestWorkflowRecoversLostCreateResponse(t *testing.T) {
	p := &lostCreateProvider{sandbox.NewFake()}
	p.ExecuteFunc = wrapWithBuildSuccess(gitAwareExecute("patch"))
	manifest, err := runWorkflow(t, p, baseRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.FactoryResult != StateSucceeded {
		t.Fatalf("recovery failed: %+v", manifest)
	}
	if len(p.Created()) != 1 || len(p.Live()) != 0 {
		t.Fatalf("created=%v, live=%v", p.Created(), p.Live())
	}
}

// defaultTemplateProvider models a provider (like podman) whose Create
// resolves a provider-specific default template when the spec names none.
type defaultTemplateProvider struct {
	*sandbox.Fake
	defaultTemplate string
}

func (p *defaultTemplateProvider) DefaultTemplate() string { return p.defaultTemplate }

func (p *defaultTemplateProvider) Create(ctx context.Context, spec sandbox.Spec) (sandbox.Sandbox, error) {
	if spec.Template == "" {
		spec.Template = p.defaultTemplate
	}
	return p.Fake.Create(ctx, spec)
}

// lostCreateDefaultTemplateProvider combines the provider default with a
// lost create response: the sandbox is created but the acknowledgement is
// dropped, so the workflow must recover it on retry.
type lostCreateDefaultTemplateProvider struct {
	*defaultTemplateProvider
}

func (p *lostCreateDefaultTemplateProvider) Create(ctx context.Context, spec sandbox.Spec) (sandbox.Sandbox, error) {
	if _, err := p.defaultTemplateProvider.Create(ctx, spec); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("create response lost")
}

// TestWorkflowRecoversLostCreateResponseWithProviderDefaultTemplate pins the
// recovery comparison against a provider default: with neither a cube
// template nor an explicit run template, a retried create must recover the
// acknowledged sandbox instead of failing the template comparison on the
// provider's own default image.
func TestWorkflowRecoversLostCreateResponseWithProviderDefaultTemplate(t *testing.T) {
	const defaultImage = "localhost/esf:test"
	p := &lostCreateDefaultTemplateProvider{&defaultTemplateProvider{Fake: sandbox.NewFake(), defaultTemplate: defaultImage}}
	p.ExecuteFunc = wrapWithBuildSuccess(gitAwareExecute("patch"))
	manifest, err := runWorkflowOpts(t, p, baseRequest(t), workflowRunOptions{
		mutateConfig: func(cfg *Config) {
			cfg.Cube.TemplateID = ""
			cfg.Podman.Image = defaultImage
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.FactoryResult != StateSucceeded {
		t.Fatalf("recovery failed: %+v", manifest)
	}
	if len(p.Created()) != 1 || len(p.Live()) != 0 {
		t.Fatalf("created=%v, live=%v", p.Created(), p.Live())
	}
}

func TestCleanupOwnershipExcludesOtherExecutions(t *testing.T) {
	for _, tc := range []struct {
		origin, run, execution string
		want                   bool
	}{
		{"factory", "run", "execution", true},
		{"factory", "run", "previous", false},
		{"factory", "other", "execution", false},
		{"other", "run", "execution", false},
		{"factory", "run", "", false},
	} {
		info := sandbox.Info{Metadata: map[string]string{"origin": tc.origin, "run_id": tc.run, "workflow_run_id": tc.execution}}
		if ownsSandbox(info, "run", "execution") != tc.want {
			t.Fatalf("incorrect ownership for %+v", tc)
		}
	}
}

func TestTotalTimeoutStillCleansUp(t *testing.T) {
	fake := sandbox.NewFake()
	fake.ExecuteFunc = wrapWithBuildSuccess(gitAwareExecute("patch"))
	req := baseRequest(t)
	req.TotalTimeout = time.Second
	manifest, err := runWorkflow(t, fake, req, func(env *testsuite.TestWorkflowEnvironment) {
		env.OnActivity("RunAgent", mock.Anything, mock.Anything).After(time.Minute).Return(RunAgentOutput{Result: agentharness.Result{ExitCode: 0}}, nil)
	})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.FactoryResult != StateInfrastructureFailed || !strings.Contains(manifest.Error, "total execution timeout") {
		t.Fatalf("timeout not enforced: %+v", manifest)
	}
	if len(fake.Live()) != 0 || !manifest.CleanupResult.Verified {
		t.Fatal("sandbox leaked after total timeout")
	}
}

func TestTimeoutCannotExceedOperatorLimit(t *testing.T) {
	if _, err := boundedTimeout(2*time.Hour, time.Hour, time.Hour); err == nil {
		t.Fatal("limit bypassed")
	}
	if _, err := boundedTimeout(-time.Second, time.Hour, time.Hour); err == nil {
		t.Fatal("negative timeout accepted")
	}
	got, err := boundedTimeout(0, time.Hour, time.Minute)
	if err != nil || got != time.Hour {
		t.Fatalf("default = %s, %v", got, err)
	}
}

func TestTemporalTLSValidatesServerIdentity(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "wrong.example"} {
		options, err := (TemporalConfig{HostPort: strings.TrimPrefix(server.URL, "https://"), TLS: true, CAFile: ca, ServerName: name}).connectionOptions()
		if err != nil {
			t.Fatal(err)
		}
		transport := &http.Transport{TLSClientConfig: options.TLS}
		client := &http.Client{Transport: transport, Timeout: time.Second}
		response, err := client.Get(server.URL)
		transport.CloseIdleConnections()
		if response != nil {
			response.Body.Close()
		}
		if name == "" && err != nil {
			t.Fatalf("trusted server rejected: %v", err)
		}
		if name != "" && err == nil {
			t.Fatal("wrong server identity accepted")
		}
	}
}

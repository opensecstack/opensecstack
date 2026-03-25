package modules

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/opensecstack/apiguard/internal/domain"
)

// Module is the interface every OWASP test module must implement.
type Module interface {
	// ID returns the OWASP module identifier (e.g. "a1_bola").
	ID() string
	// Name returns the human-readable name.
	Name() string
	// Run executes the module against the target using the provided test suite.
	// It returns zero or more findings.
	Run(ctx context.Context, exec HTTPExecutor, suite TestSuite, target string, auth *AuthConfig) ([]domain.Finding, error)
}

// HTTPExecutor performs a single HTTP request and returns the response.
type HTTPExecutor interface {
	Do(ctx context.Context, req *http.Request) (*HTTPResponse, error)
}

// HTTPResponse captures the parts of an HTTP response relevant to security analysis.
type HTTPResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Duration   time.Duration
}

// TestSuite is a simplified view of testgen.TestSuite consumed by modules.
type TestSuite struct {
	Cases []TestCase
}

// TestCase is a single test to execute.
type TestCase struct {
	ID       string
	Category string // "bola_id_enum", "bola_cross_user", "auth_removal", etc.
	Method   string
	Path     string
	Headers  map[string]string
	Body     []byte
}

// AuthConfig holds authentication state for a scan.
type AuthConfig struct {
	Type        string // "bearer", "jwt", "oauth2", "apikey", "basic"
	Token       string
	APIKey      string
	APIKeyName  string
	APIKeyIn    string // "header" or "query"
	Username    string
	Password    string
	OtherTokens []string // additional tokens for cross-user tests
}

// Registry holds all registered modules.
type Registry struct {
	modules map[string]Module
}

// NewRegistry returns a Registry pre-populated with all built-in modules.
func NewRegistry() *Registry {
	r := &Registry{modules: make(map[string]Module)}
	r.Register(&BOLAModule{})
	r.Register(&AuthModule{})
	r.Register(&MassAssignmentModule{})
	r.Register(&RateLimitModule{})
	r.Register(&FunctionAuthModule{})
	r.Register(&SensitiveFlowModule{})
	r.Register(&SSRFModule{})
	r.Register(&MisconfigModule{})
	r.Register(&InventoryModule{})
	r.Register(&UnsafeConsumptionModule{})
	return r
}

// Register adds a module to the registry.
func (r *Registry) Register(m Module) {
	r.modules[m.ID()] = m
}

// Get returns a module by ID.
func (r *Registry) Get(id string) (Module, bool) {
	m, ok := r.modules[id]
	return m, ok
}

// All returns all registered modules.
func (r *Registry) All() []Module {
	out := make([]Module, 0, len(r.modules))
	for _, m := range r.modules {
		out = append(out, m)
	}
	return out
}

// DefaultExecutor is the production HTTP executor.
type DefaultExecutor struct {
	client *http.Client
}

// NewDefaultExecutor creates an executor using the provided transport.
// Pass nil to use http.DefaultTransport.
func NewDefaultExecutor(transport http.RoundTripper, timeout time.Duration) *DefaultExecutor {
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &DefaultExecutor{
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			// Never follow redirects during security tests — they may mask findings.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// NewInsecureExecutor creates an executor that skips TLS verification.
// Used only when --tls-skip-verify is explicitly set by the user.
func NewInsecureExecutor(timeout time.Duration) *DefaultExecutor {
	return &DefaultExecutor{
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // explicit user opt-in
			},
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Do implements HTTPExecutor.
func (e *DefaultExecutor) Do(ctx context.Context, req *http.Request) (*HTTPResponse, error) {
	start := time.Now()
	resp, err := e.client.Do(req.WithContext(ctx))
	duration := time.Since(start)
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	const maxBody = 1 << 20 // 1 MiB
	body := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
		}
		if readErr != nil {
			break
		}
		if len(body) >= maxBody {
			body = body[:maxBody]
			break
		}
	}

	return &HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
		Duration:   duration,
	}, nil
}

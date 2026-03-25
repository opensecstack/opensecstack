package scanner

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/apiguard/internal/auth"
	"github.com/opensecstack/apiguard/internal/config"
	"github.com/opensecstack/apiguard/internal/domain"
	"github.com/opensecstack/apiguard/internal/modules"
	"github.com/opensecstack/apiguard/internal/testgen"
)

// Scanner performs API security scans.
type Scanner struct {
	config    *config.ScannerConfig
	logger    zerolog.Logger
	transport *http.Transport
}

// AuthConfig holds authentication settings for a scan request.
type AuthConfig struct {
	Token  string
	Type   string // bearer, api-key, basic
	Header string
}

// ScanRequest contains the parameters for a scan.
type ScanRequest struct {
	SpecPath      string
	Target        string
	AllowInternal bool
	TLSSkipVerify bool
	Modules       []string
	Auth          AuthConfig
}

// ParsedSpec represents the intermediate representation from the Rust parser.
type ParsedSpec struct {
	Endpoints   []ParsedEndpoint   `json:"endpoints"`
	AuthSchemes []ParsedAuthScheme `json:"auth_schemes"`
	Metadata    ParsedMetadata     `json:"metadata"`
}

// ParsedEndpoint represents a single API endpoint from the Rust IR.
type ParsedEndpoint struct {
	Path        string                    `json:"path"`
	Method      string                    `json:"method"`
	Parameters  []ParsedParameter         `json:"parameters"`
	RequestBody *ParsedRequestBody        `json:"request_body,omitempty"`
	Responses   map[string]ParsedResponse `json:"responses"`
	Security    []string                  `json:"security"`
	Tags        []string                  `json:"tags"`
	XApiguard   map[string]interface{}    `json:"x_apiguard"`
}

// ParsedParameter represents a parameter from the Rust IR.
type ParsedParameter struct {
	Name     string  `json:"name"`
	Location string  `json:"location"`
	Required bool    `json:"required"`
	Schema   *string `json:"schema,omitempty"`
}

// ParsedRequestBody represents a request body from the Rust IR.
type ParsedRequestBody struct {
	ContentTypes []string `json:"content_types"`
	Schema       *string  `json:"schema,omitempty"`
	Required     bool     `json:"required"`
}

// ParsedResponse represents a response from the Rust IR.
type ParsedResponse struct {
	Description string  `json:"description"`
	Schema      *string `json:"schema,omitempty"`
}

// ParsedAuthScheme represents an authentication scheme from the Rust IR.
type ParsedAuthScheme struct {
	Name       string  `json:"name"`
	SchemeType string  `json:"scheme_type"`
	Location   *string `json:"location,omitempty"`
	HeaderName *string `json:"header_name,omitempty"`
}

// ParsedMetadata holds API metadata from the Rust IR.
type ParsedMetadata struct {
	BaseURL    string `json:"base_url"`
	APIVersion string `json:"api_version"`
	SchemaHash string `json:"schema_hash"`
}

// shellMetachars matches characters that could be used for shell injection.
var shellMetachars = regexp.MustCompile(`[;&|$` + "`" + `\\!#~*?<>{}()\[\]'"\s]`)

// privateNetworks defines CIDR ranges that are considered private/internal.
var privateNetworks []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, cidr := range cidrs {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil {
			privateNetworks = append(privateNetworks, network)
		}
	}
}

// New creates a new Scanner.
func New(cfg *config.ScannerConfig, logger zerolog.Logger) *Scanner {
	return &Scanner{
		config: cfg,
		logger: logger.With().Str("component", "scanner").Logger(),
	}
}

// isNumericHost rejects hostnames that are purely numeric, hex, or octal
// (e.g., 0x7f000001, 017700000001, 2130706433) to prevent IP notation bypass.
func isNumericHost(host string) bool {
	if len(host) == 0 {
		return false
	}
	for _, c := range host {
		if !((c >= '0' && c <= '9') || c == 'x' || c == 'X' || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '.') {
			return false
		}
	}
	return true
}

// CreatePinnedTransport creates an HTTP transport that pins DNS resolution
// to the IPs validated during target URL validation, preventing DNS rebinding.
func CreatePinnedTransport(validatedHost string, validatedIPs []net.IP, tlsSkipVerify bool) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			// Only pin the validated host
			if host == validatedHost && len(validatedIPs) > 0 {
				// Use the first validated IP
				addr = net.JoinHostPort(validatedIPs[0].String(), port)
			}
			return (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: tlsSkipVerify},
	}
}

// validateTargetURL validates the target URL to prevent SSRF attacks.
// It rejects private/internal network addresses unless allowInternal is true.
// Returns the resolved IPs for use in DNS pinning to prevent rebinding attacks.
func validateTargetURL(rawURL string, allowInternal bool) ([]net.IP, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	if parsed.User != nil {
		return nil, fmt.Errorf("URLs with userinfo are not allowed as scan targets")
	}

	// Only allow http and https schemes.
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme %q: only http and https are allowed", parsed.Scheme)
	}

	hostname := parsed.Hostname()

	if strings.Contains(hostname, "%") {
		return nil, fmt.Errorf("IPv6 zone IDs are not allowed in target URLs")
	}

	if allowInternal {
		return nil, nil
	}

	// Reject well-known internal hostnames.
	lowerHost := strings.ToLower(hostname)
	if lowerHost == "localhost" {
		return nil, fmt.Errorf("target URL points to localhost; use --allow-internal to permit internal targets")
	}

	// Resolve the hostname to IP addresses and check each one.
	ip := net.ParseIP(hostname)
	var ips []net.IP
	if ip != nil {
		ips = []net.IP{ip}
	} else {
		// Reject numeric-only hostnames (hex 0x7f000001, octal 017700000001, decimal 2130706433)
		if isNumericHost(hostname) {
			return nil, fmt.Errorf("numeric IP notation %q is not allowed as target", hostname)
		}

		addrs, err := net.LookupIP(hostname)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve target hostname %q: %w", hostname, err)
		}
		ips = addrs
	}

	for _, addr := range ips {
		// Check for unspecified (0.0.0.0, ::).
		if addr.IsUnspecified() {
			return nil, fmt.Errorf("target URL resolves to unspecified address %s; use --allow-internal to permit internal targets", addr)
		}

		// Check cloud metadata endpoint.
		if addr.Equal(net.ParseIP("169.254.169.254")) {
			return nil, fmt.Errorf("target URL resolves to cloud metadata address %s; this is not allowed", addr)
		}

		// Check private/internal ranges.
		for _, network := range privateNetworks {
			if network.Contains(addr) {
				return nil, fmt.Errorf("target URL resolves to private address %s (%s); use --allow-internal to permit internal targets", addr, network)
			}
		}
	}

	return ips, nil
}

// validateSpecPath validates and sanitizes the spec file path to prevent path traversal.
// It opens the file first, then stats via the file descriptor to avoid TOCTOU races.
// Returns the cleaned absolute path and the file contents.
func (s *Scanner) validateSpecPath(specPath string) (string, []byte, error) {
	absPath, err := filepath.Abs(specPath)
	if err != nil {
		return "", nil, fmt.Errorf("invalid spec path: %w", err)
	}
	absPath = filepath.Clean(absPath)

	if runtime.GOOS == "windows" && strings.HasPrefix(absPath, "\\\\") {
		return "", nil, fmt.Errorf("UNC paths are not allowed for spec files")
	}

	// Open file first, then check via the file descriptor (no TOCTOU)
	f, err := os.Open(absPath)
	if err != nil {
		return "", nil, fmt.Errorf("cannot open spec file: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", nil, fmt.Errorf("cannot stat spec file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", nil, fmt.Errorf("spec path is not a regular file: %s", absPath)
	}

	// Enforce max size
	maxBytes := int64(s.config.MaxSpecSize) * 1024 * 1024
	if info.Size() > maxBytes {
		return "", nil, fmt.Errorf("spec file exceeds max size of %d MB", s.config.MaxSpecSize)
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return "", nil, fmt.Errorf("cannot read spec file: %w", err)
	}

	return absPath, data, nil
}

// validateParserBin validates the parser binary path to prevent command injection.
func validateParserBin(binPath string) error {
	// Check for shell metacharacters.
	if shellMetachars.MatchString(binPath) {
		return fmt.Errorf("parser binary path %q contains invalid characters", binPath)
	}

	// If it's an absolute path, verify the file exists and is executable.
	if filepath.IsAbs(binPath) {
		info, err := os.Stat(binPath)
		if err != nil {
			return fmt.Errorf("parser binary not found at %q: %w", binPath, err)
		}
		if info.IsDir() {
			return fmt.Errorf("parser binary path %q is a directory", binPath)
		}
		// On Unix, check executable bit. On Windows, existence is sufficient.
		if info.Mode()&0111 == 0 {
			return fmt.Errorf("parser binary %q is not executable", binPath)
		}
		return nil
	}

	// For relative names (no path separator), rely on PATH lookup.
	if strings.ContainsRune(binPath, filepath.Separator) || strings.ContainsRune(binPath, '/') {
		return fmt.Errorf("parser binary path %q must be either an absolute path or a bare binary name (no relative paths)", binPath)
	}

	return nil
}

// Run executes a scan against the target API.
func (s *Scanner) Run(ctx context.Context, req ScanRequest) (*domain.ScanResult, error) {
	scanID := uuid.New().String()
	startedAt := time.Now()

	// Validate target URL for SSRF protection and get resolved IPs for DNS pinning.
	validatedIPs, err := validateTargetURL(req.Target, req.AllowInternal)
	if err != nil {
		return nil, fmt.Errorf("target URL validation failed: %w", err)
	}

	// Store pinned transport for use by scan modules (prevents DNS rebinding).
	if parsedURL, err := url.Parse(req.Target); err == nil && len(validatedIPs) > 0 {
		s.transport = CreatePinnedTransport(parsedURL.Hostname(), validatedIPs, req.TLSSkipVerify)
	}

	// Validate and sanitize the spec file path (open-then-stat to avoid TOCTOU).
	cleanSpecPath, specData, err := s.validateSpecPath(req.SpecPath)
	if err != nil {
		return nil, fmt.Errorf("spec path validation failed: %w", err)
	}
	req.SpecPath = cleanSpecPath

	s.logger.Info().
		Str("scan_id", scanID).
		Str("spec", req.SpecPath).
		Str("target", req.Target).
		Msg("starting scan")

	s.logger.Debug().
		Int("spec_bytes", len(specData)).
		Msg("spec file loaded")

	// Step 2: Call the Rust parser via JSON file exchange.
	parsedSpec, err := s.parseSpec(ctx, req.SpecPath)
	if err != nil {
		return nil, fmt.Errorf("spec parsing failed: %w; install apiguard-parser or set APIGUARD_PARSER_BIN", err)
	}

	s.logger.Info().
		Str("base_url", parsedSpec.Metadata.BaseURL).
		Str("api_version", parsedSpec.Metadata.APIVersion).
		Int("endpoint_count", len(parsedSpec.Endpoints)).
		Msg("spec parsed successfully")

	// Step 2b: Initialise the auth handler from the scan request credentials.
	authCfg := auth.Config{
		Type:  auth.TokenType(req.Auth.Type),
		Token: req.Auth.Token,
	}
	authHandler, err := auth.NewHandler(authCfg, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth handler: %w", err)
	}
	_ = authHandler // will be consumed by scan modules in a future step

	// Step 3: Generate test cases from the parsed IR.
	// The IR file path is the same temp file pattern used by parseSpec; we need to
	// re-serialize the parsed spec to a temp file for the testgen to consume.
	irTmpPath, err := s.writeIRToTempFile(parsedSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to write IR for test generation: %w", err)
	}
	defer os.Remove(irTmpPath)

	testGen := testgen.New(s.logger, req.Target, req.Modules)
	suite, err := testGen.Generate(ctx, irTmpPath)
	if err != nil {
		return nil, fmt.Errorf("test generation failed: %w", err)
	}
	s.logger.Info().Int("test_cases", len(suite.TestCases)).Msg("test cases generated")

	// Step 4: Execute scan modules against the test suite.

	// Build the HTTP executor using the pinned transport (prevents DNS rebinding).
	httpExec := modules.NewDefaultExecutor(s.transport, 30*time.Second)

	// Build the auth config for modules from the scan request credentials.
	authConfig := &modules.AuthConfig{
		Type:  req.Auth.Type,
		Token: req.Auth.Token,
	}

	// Convert testgen.TestSuite cases to modules.TestSuite cases.
	modSuite := modules.TestSuite{Cases: make([]modules.TestCase, 0, len(suite.TestCases))}
	for _, tc := range suite.TestCases {
		// Flatten the first request's headers and body for use by modules.
		var headers map[string]string
		var body []byte
		if len(tc.Requests) > 0 {
			first := tc.Requests[0]
			headers = make(map[string]string, len(first.Headers))
			for _, h := range first.Headers {
				if len(h) == 2 {
					headers[h[0]] = h[1]
				}
			}
			if len(first.Body) > 0 && string(first.Body) != "null" {
				body = first.Body
			}
		}
		modSuite.Cases = append(modSuite.Cases, modules.TestCase{
			ID:       tc.ID,
			Category: tc.Category,
			Method:   tc.EndpointMethod,
			Path:     tc.EndpointPath,
			Headers:  headers,
			Body:     body,
		})
	}

	// Build an enabled-module set for fast lookup (empty = run all).
	enabledModules := make(map[string]bool, len(req.Modules))
	for _, id := range req.Modules {
		enabledModules[id] = true
	}

	registry := modules.NewRegistry()
	var allFindings []domain.Finding

	for _, mod := range registry.All() {
		if len(enabledModules) > 0 && !enabledModules[mod.ID()] {
			continue
		}

		s.logger.Info().Str("module", mod.ID()).Msg("running module")

		modFindings, modErr := mod.Run(ctx, httpExec, modSuite, req.Target, authConfig)
		if modErr != nil {
			s.logger.Error().Err(modErr).Str("module", mod.ID()).Msg("module execution failed")
			continue
		}

		s.logger.Info().
			Str("module", mod.ID()).
			Int("findings", len(modFindings)).
			Msg("module completed")

		allFindings = append(allFindings, modFindings...)
	}

	// Compute summary counts.
	summary := domain.ScanSummary{TotalFindings: len(allFindings)}
	for _, f := range allFindings {
		switch f.Severity {
		case domain.SeverityCritical:
			summary.Critical++
		case domain.SeverityHigh:
			summary.High++
		case domain.SeverityMedium:
			summary.Medium++
		case domain.SeverityLow:
			summary.Low++
		case domain.SeverityInfo:
			summary.Info++
		}
	}

	if allFindings == nil {
		allFindings = []domain.Finding{}
	}

	result := &domain.ScanResult{
		ID:          scanID,
		Status:      domain.ScanStatusCompleted,
		Target:      req.Target,
		Findings:    allFindings,
		Summary:     summary,
		StartedAt:   startedAt,
		CompletedAt: time.Now(),
	}

	s.logger.Info().
		Str("scan_id", scanID).
		Str("status", string(result.Status)).
		Int("findings", len(allFindings)).
		Dur("duration", result.CompletedAt.Sub(result.StartedAt)).
		Msg("scan completed")

	return result, nil
}

// parseSpec calls the Rust parser binary to parse the OpenAPI spec into IR.
func (s *Scanner) parseSpec(ctx context.Context, specPath string) (*ParsedSpec, error) {
	// Create a temp file for the parser output.
	tmpDir := os.TempDir()
	outputPath := filepath.Join(tmpDir, fmt.Sprintf("apiguard-ir-%s.json", uuid.New().String()))
	defer os.Remove(outputPath)

	// Look for the Rust parser binary, with validation.
	parserBin := "apiguard-parser"
	if binPath := os.Getenv("APIGUARD_PARSER_BIN"); binPath != "" {
		parserBin = binPath
	}

	if err := validateParserBin(parserBin); err != nil {
		return nil, fmt.Errorf("parser binary validation failed: %w", err)
	}

	cmd := exec.CommandContext(ctx, parserBin, "parse", "--input", specPath, "--output", outputPath)
	cmd.Stderr = os.Stderr

	s.logger.Debug().
		Str("parser", parserBin).
		Str("input", specPath).
		Str("output", outputPath).
		Msg("invoking rust parser")

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("parser execution failed: %w", err)
	}

	// Read the parser output.
	irData, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read parser output: %w", err)
	}

	var parsed ParsedSpec
	if err := json.Unmarshal(irData, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse IR JSON: %w", err)
	}

	return &parsed, nil
}

// writeIRToTempFile serializes the parsed spec to a temporary JSON file
// so the testgen package can consume it.
func (s *Scanner) writeIRToTempFile(spec *ParsedSpec) (string, error) {
	data, err := json.Marshal(spec)
	if err != nil {
		return "", fmt.Errorf("failed to marshal IR: %w", err)
	}

	tmpDir := os.TempDir()
	outputPath := filepath.Join(tmpDir, fmt.Sprintf("apiguard-ir-%s.json", uuid.New().String()))

	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return "", fmt.Errorf("failed to write IR temp file: %w", err)
	}

	return outputPath, nil
}

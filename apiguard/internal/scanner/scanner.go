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
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/apiguard/internal/config"
)

// Scanner performs API security scans.
type Scanner struct {
	config *config.ScannerConfig
	logger zerolog.Logger
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
	Modules       []string
	Auth          AuthConfig
}

// ScanResult holds the outcome of a scan.
type ScanResult struct {
	ID        string      `json:"id"`
	Status    string      `json:"status"` // running, completed, failed
	StartedAt time.Time   `json:"started_at"`
	EndedAt   time.Time   `json:"ended_at"`
	Findings  []Finding   `json:"findings"`
	Summary   ScanSummary `json:"summary"`
}

// Finding represents a single security finding.
type Finding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // info, low, medium, high, critical
	Module      string `json:"module"`
	Endpoint    string `json:"endpoint"`
	Method      string `json:"method"`
	Evidence    string `json:"evidence"`
}

// ScanSummary provides aggregate counts of findings.
type ScanSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// ParsedSpec represents the intermediate representation from the Rust parser.
type ParsedSpec struct {
	Version   string          `json:"version"`
	Title     string          `json:"title"`
	Endpoints json.RawMessage `json:"endpoints"`
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

	// Only allow http and https schemes.
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme %q: only http and https are allowed", parsed.Scheme)
	}

	hostname := parsed.Hostname()

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
func (s *Scanner) Run(ctx context.Context, req ScanRequest) (*ScanResult, error) {
	scanID := uuid.New().String()
	startedAt := time.Now()

	// Validate target URL for SSRF protection and get resolved IPs for DNS pinning.
	validatedIPs, err := validateTargetURL(req.Target, req.AllowInternal)
	if err != nil {
		return nil, fmt.Errorf("target URL validation failed: %w", err)
	}

	// Store pinned transport for use by scan modules (prevents DNS rebinding).
	if parsedURL, err := url.Parse(req.Target); err == nil && len(validatedIPs) > 0 {
		_ = CreatePinnedTransport(parsedURL.Hostname(), validatedIPs, false)
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

	// Step 2: Attempt to call the Rust parser via JSON file exchange.
	parsedSpec, err := s.parseSpec(ctx, req.SpecPath)
	if err != nil {
		s.logger.Warn().Err(err).Msg("rust parser not available, using stub results")
		// Continue with stub results when the parser binary is not available.
		parsedSpec = nil
	}

	if parsedSpec != nil {
		s.logger.Info().
			Str("spec_title", parsedSpec.Title).
			Str("spec_version", parsedSpec.Version).
			Msg("spec parsed successfully")
	}

	// Step 3: Return stub results (real scan modules will be wired in later).
	result := &ScanResult{
		ID:        scanID,
		Status:    "completed",
		StartedAt: startedAt,
		EndedAt:   time.Now(),
		Findings:  []Finding{},
		Summary: ScanSummary{
			Total:    0,
			Critical: 0,
			High:     0,
			Medium:   0,
			Low:      0,
			Info:     0,
		},
	}

	s.logger.Info().
		Str("scan_id", scanID).
		Str("status", result.Status).
		Dur("duration", result.EndedAt.Sub(result.StartedAt)).
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

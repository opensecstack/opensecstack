package modules

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/apiguard/internal/domain"
	"github.com/opensecstack/apiguard/internal/testgen"
)

// Module is the interface all OWASP modules implement.
type Module interface {
	ID() string
	Name() string
	Execute(ctx context.Context, cases []testgen.TestCase) ([]domain.Finding, error)
}

// HTTPResponse captures the result of executing a test request.
type HTTPResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Duration   time.Duration
}

// HTTPExecutor handles sending requests and collecting responses.
type HTTPExecutor struct {
	client     *http.Client
	target     string
	logger     zerolog.Logger
	authToken  string
	authType   string
	authHeader string
}

// NewHTTPExecutor creates a new HTTPExecutor with the given transport and auth config.
func NewHTTPExecutor(transport *http.Transport, target string, logger zerolog.Logger, authToken, authType, authHeader string) *HTTPExecutor {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	if transport != nil {
		client.Transport = transport
	}

	if authHeader == "" {
		authHeader = "Authorization"
	}
	if authType == "" {
		authType = "bearer"
	}

	return &HTTPExecutor{
		client:     client,
		target:     strings.TrimRight(target, "/"),
		logger:     logger.With().Str("component", "http_executor").Logger(),
		authToken:  authToken,
		authType:   authType,
		authHeader: authHeader,
	}
}

// ExecuteRequest sends a single test request and returns the response.
func (e *HTTPExecutor) ExecuteRequest(ctx context.Context, req testgen.TestRequest) (*HTTPResponse, error) {
	fullURL := e.target + req.Path

	var bodyReader io.Reader
	if len(req.Body) > 0 && string(req.Body) != "null" {
		bodyReader = bytes.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers from the test request.
	for _, hdr := range req.Headers {
		if len(hdr) == 2 {
			httpReq.Header.Set(hdr[0], hdr[1])
		}
	}

	// Apply auth based on the auth strategy.
	e.applyAuth(httpReq, req.Auth)

	start := time.Now()
	resp, err := e.client.Do(httpReq)
	duration := time.Since(start)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	e.logger.Debug().
		Str("method", req.Method).
		Str("path", req.Path).
		Str("auth", req.Auth).
		Int("status", resp.StatusCode).
		Dur("duration", duration).
		Msg("request executed")

	return &HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
		Duration:   duration,
	}, nil
}

// applyAuth sets the appropriate authentication header based on the auth strategy.
func (e *HTTPExecutor) applyAuth(req *http.Request, strategy string) {
	switch strategy {
	case "none":
		// No auth header.
	case "valid":
		e.setAuthHeader(req, e.authToken)
	case "expired":
		expiredToken := generateExpiredJWT()
		e.setAuthHeader(req, expiredToken)
	case "other_user":
		otherToken := generateOtherUserJWT()
		e.setAuthHeader(req, otherToken)
	case "invalid":
		e.setAuthHeader(req, "invalid-token-xxx")
	default:
		// Treat unknown strategies as "none".
		e.logger.Warn().Str("strategy", strategy).Msg("unknown auth strategy, skipping auth")
	}
}

// setAuthHeader sets the auth header value, formatting it according to the auth type.
func (e *HTTPExecutor) setAuthHeader(req *http.Request, token string) {
	switch strings.ToLower(e.authType) {
	case "bearer":
		req.Header.Set(e.authHeader, "Bearer "+token)
	case "api-key":
		req.Header.Set(e.authHeader, token)
	case "basic":
		req.Header.Set(e.authHeader, "Basic "+token)
	default:
		req.Header.Set(e.authHeader, token)
	}
}

// generateExpiredJWT creates a JWT token with an expiration time in the past.
func generateExpiredJWT() string {
	header := base64URLEncode([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64URLEncode([]byte(fmt.Sprintf(
		`{"sub":"test-user","iat":%d,"exp":%d}`,
		time.Now().Add(-2*time.Hour).Unix(),
		time.Now().Add(-1*time.Hour).Unix(),
	)))
	signingInput := header + "." + payload
	sig := hmacSHA256([]byte("apiguard-test-key"), []byte(signingInput))
	return signingInput + "." + base64URLEncode(sig)
}

// generateOtherUserJWT creates a JWT token representing a different user.
func generateOtherUserJWT() string {
	header := base64URLEncode([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64URLEncode([]byte(fmt.Sprintf(
		`{"sub":"other-user-9999","iat":%d,"exp":%d,"role":"user"}`,
		time.Now().Unix(),
		time.Now().Add(1*time.Hour).Unix(),
	)))
	signingInput := header + "." + payload
	sig := hmacSHA256([]byte("apiguard-test-key"), []byte(signingInput))
	return signingInput + "." + base64URLEncode(sig)
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// formatRequest formats a test request as a human-readable HTTP request string.
func formatRequest(req testgen.TestRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", req.Method, req.Path)
	for _, hdr := range req.Headers {
		if len(hdr) == 2 {
			fmt.Fprintf(&b, "%s: %s\r\n", hdr[0], hdr[1])
		}
	}
	b.WriteString("\r\n")
	if len(req.Body) > 0 && string(req.Body) != "null" {
		var pretty bytes.Buffer
		if json.Indent(&pretty, req.Body, "", "  ") == nil {
			b.Write(pretty.Bytes())
		} else {
			b.Write(req.Body)
		}
	}
	return b.String()
}

// formatResponse formats an HTTP response as a human-readable string.
func formatResponse(resp *HTTPResponse) string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d\r\n", resp.StatusCode)
	for key, values := range resp.Headers {
		for _, v := range values {
			fmt.Fprintf(&b, "%s: %s\r\n", key, v)
		}
	}
	b.WriteString("\r\n")
	if len(resp.Body) > 0 {
		// Truncate large response bodies in evidence.
		body := resp.Body
		if len(body) > 4096 {
			body = append(body[:4096], []byte("\n... [truncated]")...)
		}
		var pretty bytes.Buffer
		if json.Indent(&pretty, body, "", "  ") == nil {
			b.Write(pretty.Bytes())
		} else {
			b.Write(body)
		}
	}
	return b.String()
}

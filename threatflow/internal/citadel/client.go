package citadel

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// FailMode decides what happens when CITADEL cannot be reached during a
// MARSHAL check. FailOpen allows the mutation (best for dev / low-risk);
// FailClosed rejects it (required for production).
type FailMode int

const (
	FailOpen FailMode = iota
	FailClosed
)

// Client is the CITADEL connector used by ThreatFlow. When baseURL is empty
// every method is a no-op — the process runs without governance.
type Client struct {
	baseURL   string
	keyID     string
	secret    string
	projectID string
	failMode  FailMode

	http   *http.Client
	logger zerolog.Logger

	// async WORM queue
	wg  sync.WaitGroup
	sem chan struct{}

	// chain verification
	mu            sync.Mutex
	lastChainHash string
}

// Config bundles the options used by New.
type Config struct {
	BaseURL   string
	KeyID     string
	Secret    string
	ProjectID string
	FailMode  FailMode
}

// New builds a Client. When cfg.BaseURL is empty the Client operates in no-op
// mode and never attempts to reach CITADEL.
func New(cfg Config, logger zerolog.Logger) *Client {
	return &Client{
		baseURL:   strings.TrimRight(cfg.BaseURL, "/"),
		keyID:     cfg.KeyID,
		secret:    cfg.Secret,
		projectID: orDefault(cfg.ProjectID, "threatflow"),
		failMode:  cfg.FailMode,
		http:      &http.Client{Timeout: 10 * time.Second},
		logger:    logger.With().Str("component", "citadel").Logger(),
		sem:       make(chan struct{}, 64),
	}
}

// Enabled reports whether the client will issue real requests.
func (c *Client) Enabled() bool {
	return c != nil && c.baseURL != ""
}

// verifierPlaceholder is the fixed Verifier identity ThreatFlow submits for
// every Kerkese. None of ThreatFlow's governed actions (IOC ingest/revoke,
// STIX bundle import, feed create/delete/toggle) have a real second-approver
// concept today — there is no separate "approve" step, just a single
// mutating request from the operator who initiated it. Following the same
// documented pattern apiguard used (citadel adrs/005-sinauth-identity-bridge.md,
// "Producer wiring — apiguard only in this pass"): a fixed, clearly-named
// placeholder distinct from any real user so it never collides with the
// Actor and never trips Gate 3's NDS_SAME_IDENTITY HARD_STOP. VerifierToken
// is always left empty (no real second person to forward a token for).
// Building genuine two-person approval for these actions is a separate
// product change, tracked as follow-up, not fabricated here. This is safe
// to defer because citadel.enforce_signatures stays at its ADR-004 default
// (false) — the gap surfaces as a Gate 1/Gate 3 WARN reason, not silently.
const verifierPlaceholder = "threatflow-system-verifier"

// Evaluate asks MARSHAL whether an action is allowed. When the client is
// disabled the decision is always EXECUTE. When CITADEL is unreachable the
// configured FailMode decides whether to allow or reject.
//
// actorUserID is the real authenticated caller's identity — a sinauth UUID
// when the caller presented a genuine sinauth RS256 token, or ThreatFlow's
// own "apikey:<uuid>" / "bootstrap:<name>" subject when the caller used the
// API-key/HS256 fallback (see internal/auth.Identity.Subject). actorToken is
// the raw bearer token forwarded from the incoming request's Authorization
// header — callers MUST leave it empty when the caller authenticated via the
// API-key/HS256 fallback, since there is no real sinauth token to forward in
// that case (see citadel adrs/005-sinauth-identity-bridge.md); a missing
// token is a non-blocking WARN under CITADEL's current soft-mode
// enforce_signatures=false config, not a failure.
func (c *Client) Evaluate(ctx context.Context, action, description, actorUserID, actorEmail, actorRole, actorToken string) (*Decision, error) {
	if !c.Enabled() {
		return &Decision{Outcome: OutcomeExecute, ExecutionID: uuid.New(), TsUTC: time.Now().UTC()}, nil
	}

	kerkese := &Kerkese{
		KerkeseVersion: "1.0",
		TsUTC:          time.Now().UTC(),
		ProjectID:      c.projectID,
		ExecutionID:    uuid.New(),
		Action: KerkeseAction{
			Type:        action,
			Description: description,
		},
		Actor: KerkeseActor{
			UserID: actorUserID,
			Role:   actorRole,
			Email:  actorEmail,
		},
		Verifier: KerkeseVerifier{
			UserID: verifierPlaceholder,
			Role:   "group_sig_verifier",
		},
		SoD: KerkeseSoD{
			OperatorUserID: actorUserID,
			VerifierUserID: verifierPlaceholder,
		},
		ActorToken: actorToken,
	}
	body, err := json.Marshal(kerkese)
	if err != nil {
		return nil, fmt.Errorf("marshal kerkese: %w", err)
	}
	resp, err := c.do(ctx, http.MethodPost, "/api/v1/marshal/evaluate", body)
	if err != nil {
		return c.failFallback(err)
	}
	defer resp.Body.Close()
	defer func() { _, _ = io.Copy(io.Discard, resp.Body) }()

	if resp.StatusCode != http.StatusOK {
		return c.failFallback(fmt.Errorf("marshal status %d", resp.StatusCode))
	}
	var d Decision
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return c.failFallback(fmt.Errorf("decode decision: %w", err))
	}
	return &d, nil
}

// Emit posts a WORM event synchronously. Use EmitAsync for the non-blocking
// variant (handler hot path).
func (c *Client) Emit(ctx context.Context, source, eventType string, payload any) error {
	if !c.Enabled() {
		return nil
	}
	reqBody := map[string]any{
		"source":     source,
		"event_type": eventType,
		"project_id": c.projectID,
		"payload":    payload,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal worm payload: %w", err)
	}
	resp, err := c.do(ctx, http.MethodPost, "/api/v1/worm/emit", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	defer func() { _, _ = io.Copy(io.Discard, resp.Body) }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("worm status %d", resp.StatusCode)
	}

	var result struct {
		WORMEntryID string `json:"worm_entry_id"`
		ChainHash   string `json:"chain_hash"`
		PrevHash    string `json:"prev_hash"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode worm response: %w", err)
	}

	c.mu.Lock()
	if c.lastChainHash != "" && result.PrevHash != "" && result.PrevHash != c.lastChainHash {
		c.logger.Warn().
			Str("expected_prev", c.lastChainHash).
			Str("got_prev", result.PrevHash).
			Str("entry", result.WORMEntryID).
			Msg("WORM chain break detected")
	}
	c.lastChainHash = result.ChainHash
	c.mu.Unlock()
	return nil
}

// EmitAsync schedules a WORM event on a bounded goroutine pool. Drops the
// event (with a warn log) if the pool is saturated — governance emission is
// best-effort and must never stall the mutation hot path.
func (c *Client) EmitAsync(source, eventType string, payload any) {
	if !c.Enabled() {
		return
	}
	select {
	case c.sem <- struct{}{}:
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			defer func() { <-c.sem }()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := c.Emit(ctx, source, eventType, payload); err != nil {
				c.logger.Warn().Err(err).Str("event_type", eventType).Msg("worm emit failed")
			}
		}()
	default:
		c.logger.Warn().Str("event_type", eventType).Msg("worm queue saturated — event dropped")
	}
}

// Drain blocks until all queued EmitAsync goroutines finish or ctx expires.
// Call during graceful shutdown so audit events are not lost.
func (c *Client) Drain(ctx context.Context) {
	if c == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (c *Client) failFallback(err error) (*Decision, error) {
	c.logger.Warn().Err(err).Int("fail_mode", int(c.failMode)).Msg("marshal unreachable")
	if c.failMode == FailClosed {
		return &Decision{
			Outcome: OutcomeRefuse,
			Reasons: []string{"CITADEL unreachable; fail-closed policy applied"},
			TsUTC:   time.Now().UTC(),
		}, nil
	}
	return &Decision{
		Outcome: OutcomeExecute,
		Reasons: []string{"CITADEL unreachable; fail-open policy applied"},
		TsUTC:   time.Now().UTC(),
	}, nil
}

// do performs a signed HTTP request to CITADEL. Headers mirror apiguard's
// connector-auth scheme so the same CITADEL key can serve both services.
//
//	X-CITADEL-KEY  — connector key ID
//	X-CITADEL-TS   — Unix seconds timestamp
//	X-CITADEL-SIG  — hmac-sha256=hex(HMAC_SHA256(secret, key + ":" + ts + ":" + hex(sha256(body))))
func (c *Client) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	ts := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	bodyHash := sha256.Sum256(body)
	message := c.keyID + ":" + ts + ":" + hex.EncodeToString(bodyHash[:])
	mac := hmac.New(sha256.New, []byte(c.secret))
	mac.Write([]byte(message))
	sig := "hmac-sha256=" + hex.EncodeToString(mac.Sum(nil))

	req.Header.Set("X-CITADEL-KEY", c.keyID)
	req.Header.Set("X-CITADEL-TS", ts)
	req.Header.Set("X-CITADEL-SIG", sig)

	return c.http.Do(req)
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

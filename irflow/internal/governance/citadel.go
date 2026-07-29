package governance

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/opensecstack/opensecstack/irflow/internal/incident"
)

// CitadelClient talks to CITADEL's /api/v1/marshal/evaluate and /api/v1/worm/emit
// endpoints. A zero-valued client is not usable; construct one via NewCitadelClient.
//
// Request signing: every POST is HMAC-SHA256 signed in the X-Citadel-Signature
// header using the configured shared secret. CITADEL does not yet validate
// these signatures server-side, but signing now keeps IRFlow forward-compatible.
type CitadelClient struct {
	baseURL   string
	secret    string
	keyID     string
	projectID string
	dryRun    bool
	http      *http.Client
}

// CitadelClientConfig bundles the constructor inputs.
type CitadelClientConfig struct {
	BaseURL   string
	KeyID     string
	KeySecret string
	ProjectID string
	DryRun    bool
	Timeout   time.Duration
}

// NewCitadelClient constructs a CitadelClient. If timeout is zero, 10s is used.
func NewCitadelClient(cfg CitadelClientConfig) *CitadelClient {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &CitadelClient{
		baseURL:   strings.TrimRight(cfg.BaseURL, "/"),
		secret:    cfg.KeySecret,
		keyID:     cfg.KeyID,
		projectID: cfg.ProjectID,
		dryRun:    cfg.DryRun,
		http:      &http.Client{Timeout: cfg.Timeout},
	}
}

// ---------------------------------------------------------------------------
// MARSHAL evaluation
// ---------------------------------------------------------------------------

// kerkese mirrors the CITADEL wire format exactly (see sdk/go/citadel/types.go,
// the canonical cross-platform contract, and citadel adrs/004 and 005). We
// keep it private so callers only see the incident-package interface types.
//
// This struct is IRFlow's own copy rather than an import of
// sdk/go/citadel.Kerkese: IRFlow's CitadelClient carries extra functionality
// (HMAC-SHA256 request signing, a WORM /emit method) that the shared SDK
// Client does not provide, so — following the same treatment applied to
// apiguard's internal/citadel package — the type definitions are fixed up in
// place to match the SDK shape rather than switching to the SDK client.
type kerkese struct {
	KerkeseVersion string          `json:"kerkese_version"`
	TsUTC          time.Time       `json:"ts_utc"`
	ProjectID      string          `json:"project_id"`
	ExecutionID    string          `json:"execution_id"`
	Action         kerkeseAction   `json:"action"`
	Actor          kerkesePerson   `json:"actor"`
	Verifier       kerkesePerson   `json:"verifier"`
	Evidence       kerkeseEvidence `json:"evidence"`
	SoD            kerkeseSoD      `json:"sod"`
	DryRun         bool            `json:"dry_run,omitempty"`

	// SigOperator/SigVerifier: hex-encoded Ed25519 signatures (citadel
	// ADR-004). IRFlow does not currently sign requests — no per-user
	// private-key custody UX exists yet — so these are always left empty,
	// which CITADEL treats as a soft-mode warning (citadel.enforce_signatures
	// = false), not a block.
	SigOperator string `json:"sig_operator,omitempty"`
	SigVerifier string `json:"sig_verifier,omitempty"`

	// ActorToken/VerifierToken: sinauth bearer tokens proving the Operator's
	// and Verifier's authenticated identity (citadel ADR-005). Forwarded
	// verbatim from incident.MarshalRequest; CITADEL verifies them directly
	// against sinauth's JWKS and discards them (never persisted).
	ActorToken    string `json:"actor_token,omitempty"`
	VerifierToken string `json:"verifier_token,omitempty"`
}

type kerkeseAction struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	IncidentID  string `json:"incident_id,omitempty"`
}

// kerkesePerson represents both Actor (Operator) and Verifier — identical
// shape, reused for both to avoid duplicating two structurally-equal types.
// UserID is a sinauth UUID string (citadel ADR-005 changed this from int64;
// IRFlow previously folded it through a lossy hashUserID() hash, which is
// deleted along with the int64 field it existed to work around).
type kerkesePerson struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

type kerkeseEvidence struct {
	Extra map[string]any `json:"extra,omitempty"`
}

// kerkeseSoD carries the Separation of Duties identifiers as sinauth UUID
// strings (citadel ADR-005).
type kerkeseSoD struct {
	OperatorUserID string `json:"operator_user_id"`
	VerifierUserID string `json:"verifier_user_id"`
}

type citadelDecision struct {
	Outcome     string   `json:"outcome"`
	ExecutionID string   `json:"execution_id"`
	WORMEntryID string   `json:"worm_entry_id,omitempty"`
	Reasons     []string `json:"reasons"`
}

// Evaluate submits a Kerkese to /api/v1/marshal/evaluate and translates the
// response back into the incident-package interface type. req.OperatorID and
// req.VerifierID must already be real sinauth UUIDs derived from two
// separate authenticated sessions (see incident.Service.ApproveAction) — this
// method performs no identity derivation or transformation of its own.
func (c *CitadelClient) Evaluate(ctx context.Context, req incident.MarshalRequest) (*incident.MarshalResult, error) {
	operatorRole := req.OperatorRole
	if operatorRole == "" {
		operatorRole = "operator"
	}
	verifierRole := req.VerifierRole
	if verifierRole == "" {
		verifierRole = "verifier"
	}

	payload := kerkese{
		KerkeseVersion: "1.0",
		TsUTC:          time.Now().UTC(),
		ProjectID:      c.projectID,
		ExecutionID:    newUUIDv4(),
		DryRun:         c.dryRun,
		Action: kerkeseAction{
			Type:        req.ActionType,
			Description: req.Description,
			IncidentID:  req.IncidentID,
		},
		Actor:    kerkesePerson{UserID: req.OperatorID, Role: operatorRole},
		Verifier: kerkesePerson{UserID: req.VerifierID, Role: verifierRole},
		Evidence: kerkeseEvidence{},
		SoD: kerkeseSoD{
			OperatorUserID: req.OperatorID,
			VerifierUserID: req.VerifierID,
		},
		ActorToken:    req.ActorToken,
		VerifierToken: req.VerifierToken,
	}
	if req.ProjectID != "" {
		payload.ProjectID = req.ProjectID
	}
	if len(req.Evidence) > 0 {
		var extra map[string]any
		if err := json.Unmarshal(req.Evidence, &extra); err == nil {
			payload.Evidence.Extra = extra
		}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshalling kerkese: %w", err)
	}

	status, respBody, err := c.post(ctx, "/api/v1/marshal/evaluate", body)
	if err != nil {
		return nil, err
	}
	// CITADEL returns 200 for EXECUTE/REFUSE and 403 for HARD_STOP; both carry
	// a decision body, so we parse first and let the caller interpret outcome.
	if status != http.StatusOK && status != http.StatusForbidden {
		return nil, fmt.Errorf("citadel evaluate: unexpected status %d: %s", status, string(respBody))
	}

	var dec citadelDecision
	if err := json.Unmarshal(respBody, &dec); err != nil {
		return nil, fmt.Errorf("parsing decision: %w", err)
	}

	return &incident.MarshalResult{
		Outcome:     dec.Outcome,
		WORMEntryID: dec.WORMEntryID,
		Reasons:     dec.Reasons,
	}, nil
}

// ---------------------------------------------------------------------------
// WORM emit
// ---------------------------------------------------------------------------

type wormEmitRequest struct {
	Source    string          `json:"source"`
	EventType string          `json:"event_type"`
	ProjectID string          `json:"project_id"`
	Payload   json.RawMessage `json:"payload"`
}

type wormEmitResponse struct {
	WORMEntryID string `json:"worm_entry_id"`
	ChainHash   string `json:"chain_hash"`
	PrevHash    string `json:"prev_hash"`
	SequenceNum int64  `json:"sequence_num"`
}

// Emit appends an event to CITADEL's WORM audit chain.
func (c *CitadelClient) Emit(ctx context.Context, event incident.WORMEvent) (*incident.WORMReceipt, error) {
	projectID := event.ProjectID
	if projectID == "" {
		projectID = c.projectID
	}

	body, err := json.Marshal(wormEmitRequest{
		Source:    event.Source,
		EventType: event.EventType,
		ProjectID: projectID,
		Payload:   event.Payload,
	})
	if err != nil {
		return nil, fmt.Errorf("marshalling worm emit: %w", err)
	}

	status, respBody, err := c.post(ctx, "/api/v1/worm/emit", body)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("citadel worm emit: status %d: %s", status, string(respBody))
	}

	var out wormEmitResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("parsing worm response: %w", err)
	}
	return &incident.WORMReceipt{
		WORMEntryID: out.WORMEntryID,
		ChainHash:   out.ChainHash,
		SequenceNum: out.SequenceNum,
	}, nil
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

// post issues a signed POST and returns (status, bodyBytes, err). The
// response body is fully read and closed inside this helper so callers only
// see immutable bytes — avoids the bodyclose lint trap when you'd otherwise
// return *http.Response.
func (c *CitadelClient) post(ctx context.Context, path string, body []byte) (int, []byte, error) {
	if c.baseURL == "" {
		return 0, nil, fmt.Errorf("citadel client: base URL not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.keyID != "" {
		req.Header.Set("X-Citadel-Key-Id", c.keyID)
	}
	if c.secret != "" {
		req.Header.Set("X-Citadel-Signature", sign(c.secret, body))
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("reading response: %w", err)
	}
	return resp.StatusCode, respBody, nil
}

func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// newUUIDv4 generates an RFC 4122 version-4 UUID without pulling in an
// external dependency. Used to populate Kerkese.ExecutionID.
func newUUIDv4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Deterministic fallback — still produces a syntactically valid UUID
		// that CITADEL will accept; the entropy loss is acceptable because
		// ExecutionID is not security-critical on the IRFlow side.
		for i := range b {
			b[i] = byte(time.Now().UnixNano() >> (i % 8 * 8))
		}
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

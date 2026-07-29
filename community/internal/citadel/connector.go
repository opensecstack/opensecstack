package citadel

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

type Client struct {
	apiURL  string
	secrets []string
	keyID   string
	dryRun  bool
	http    *http.Client
}

type Event struct {
	Kind      string         `json:"kind"`
	NodeID    string         `json:"node_id"`
	Timestamp time.Time      `json:"timestamp"`
	Payload   map[string]any `json:"payload"`
}

func New(apiURL string, secrets []string, keyID string, dryRun bool) *Client {
	return &Client{
		apiURL:  apiURL,
		secrets: secrets,
		keyID:   keyID,
		dryRun:  dryRun,
		http:    &http.Client{Timeout: 10 * time.Second},
	}
}

// wormEmitRequest mirrors the request body CITADEL's WORM handler expects at
// POST /api/v1/worm/emit (see citadel/internal/api/handlers/worm.go's
// emitRequest) — source and event_type are required, project_id and payload
// are optional/best-effort.
type wormEmitRequest struct {
	Source    string          `json:"source"`
	EventType string          `json:"event_type"`
	ProjectID string          `json:"project_id"`
	Payload   json.RawMessage `json:"payload"`
}

// wormEmitResponse mirrors CITADEL's emitResponse — unused by callers today,
// decoded only to validate the shape during tests/debugging.
type wormEmitResponse struct {
	WORMEntryID string `json:"worm_entry_id"`
	ChainHash   string `json:"chain_hash"`
	PrevHash    string `json:"prev_hash"`
	SequenceNum int64  `json:"sequence_num"`
}

// Emit appends an audit-only event to CITADEL's WORM chain via
// POST /api/v1/worm/emit. This is a plain immutable-log append — no
// authorization decision is made — distinct from a MARSHAL governance
// evaluation (see GovernanceClient.EvaluateDeletion in governance.go).
//
// Historical note: this used to POST to /api/v1/events, a route that has
// never existed on CITADEL (see citadel/internal/api/server.go's route
// table) — every call silently failed. Source is fixed to "community";
// Event.Kind maps to worm's event_type; Event.NodeID doubles as project_id
// since community has no separate multi-tenant project concept.
func (c *Client) Emit(ctx context.Context, ev Event) error {
	if c.dryRun || c.apiURL == "" {
		slog.Info("citadel dry-run", "event", ev.Kind)
		return nil
	}

	payload, err := json.Marshal(ev.Payload)
	if err != nil {
		return err
	}
	body, err := json.Marshal(wormEmitRequest{
		Source:    "community",
		EventType: ev.Kind,
		ProjectID: ev.NodeID,
		Payload:   payload,
	})
	if err != nil {
		return err
	}

	sig := c.sign(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL+"/api/v1/worm/emit", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Citadel-Signature", sig)
	req.Header.Set("X-Citadel-Key-ID", c.keyID)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("citadel returned %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) sign(body []byte) string {
	if len(c.secrets) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(c.secrets[0]))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

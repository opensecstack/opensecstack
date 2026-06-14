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

func (c *Client) Emit(ctx context.Context, ev Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}

	if c.dryRun || c.apiURL == "" {
		slog.Info("citadel dry-run", "event", ev.Kind)
		return nil
	}

	sig := c.sign(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL+"/api/v1/events", bytes.NewReader(body))
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

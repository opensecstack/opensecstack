package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/opencsirt/internal/db"
)

// taranisItem is a single OSINT item as delivered by TARANIS-NG.
type taranisItem struct {
	ID          string        `json:"id"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Source      string        `json:"source"`
	Published   string        `json:"published"`
	Attributes  []taranisAttr `json:"attributes"`
	Tags        []string      `json:"tags"`
}

type taranisAttr struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// TaranisWebhookHandler verifies HMAC-SHA256 on inbound TARANIS-NG pushes and
// converts items into OpenCSIRT incidents. Items with a "cve" attribute are
// promoted to medium-severity incidents; others are recorded as informational.
type TaranisWebhookHandler struct {
	secret    []byte
	incidents *db.IncidentStore
	logger    zerolog.Logger
}

// NewTaranisWebhookHandler constructs the inbound webhook handler.
func NewTaranisWebhookHandler(secret []byte, incidents *db.IncidentStore, logger zerolog.Logger) *TaranisWebhookHandler {
	return &TaranisWebhookHandler{
		secret:    secret,
		incidents: incidents,
		logger:    logger,
	}
}

func (h *TaranisWebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	if len(h.secret) > 0 {
		ts := r.Header.Get("X-Timestamp")
		sig := r.Header.Get("X-Signature")
		if err := VerifyHMAC(h.secret, ts, sig, body); err != nil {
			h.logger.Warn().Err(err).Msg("taranis: webhook hmac failed")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	var items []taranisItem
	if err := json.Unmarshal(body, &items); err != nil {
		// Try single-item envelope.
		var single taranisItem
		if err2 := json.Unmarshal(body, &single); err2 != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		items = []taranisItem{single}
	}

	for _, item := range items {
		if err := h.processItem(r.Context(), item); err != nil {
			h.logger.Error().Err(err).Str("item_id", item.ID).Msg("taranis: process item failed")
		}
	}

	w.WriteHeader(http.StatusOK)
}

func (h *TaranisWebhookHandler) processItem(ctx context.Context, item taranisItem) error {
	severity, iocCount := classifyItem(item)
	inc := &db.Incident{
		Source:      "taranis",
		Severity:    severity,
		Title:       item.Title,
		Description: item.Description,
		Metadata: map[string]any{
			"taranis_id": item.ID,
			"source":     item.Source,
			"ioc_count":  iocCount,
			"tags":       item.Tags,
		},
	}
	if err := h.incidents.Insert(ctx, inc); err != nil {
		return fmt.Errorf("insert incident: %w", err)
	}
	h.logger.Info().Str("incident_id", inc.ID.String()).Str("severity", severity).
		Int("ioc_count", iocCount).Msg("taranis: incident created")
	return nil
}

// classifyItem returns severity and the count of recognised IOC attributes.
func classifyItem(item taranisItem) (severity string, iocCount int) {
	hasCVE := false
	for _, a := range item.Attributes {
		switch a.Key {
		case "cve":
			hasCVE = true
			iocCount++
		case "ip", "domain", "url":
			iocCount++
		}
	}
	if hasCVE {
		return "medium", iocCount
	}
	return "low", iocCount
}

// TaranisClient polls the TARANIS-NG REST API periodically and processes new
// OSINT items as incidents. The cursor is kept in memory — a process restart
// re-processes items from the last 24 h only.
type TaranisClient struct {
	apiURL    string
	apiKey    string
	interval  time.Duration
	http      *http.Client
	incidents *db.IncidentStore
	logger    zerolog.Logger

	mu     sync.Mutex
	cursor string
}

// NewTaranisClient constructs the polling client.
func NewTaranisClient(apiURL, apiKey string, interval time.Duration, incidents *db.IncidentStore, logger zerolog.Logger) *TaranisClient {
	return &TaranisClient{
		apiURL:    apiURL,
		apiKey:    apiKey,
		interval:  interval,
		http:      &http.Client{Timeout: 30 * time.Second},
		incidents: incidents,
		logger:    logger,
	}
}

// Run starts the poll loop. Returns when ctx is done.
func (c *TaranisClient) Run(ctx context.Context) {
	if c.apiURL == "" {
		c.logger.Info().Msg("taranis: API URL empty, poller disabled")
		return
	}
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.pollOnce(ctx); err != nil {
				c.logger.Warn().Err(err).Msg("taranis: poll failed")
			}
		}
	}
}

func (c *TaranisClient) loadCursor() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cursor
}

func (c *TaranisClient) storeCursor(cur string) {
	c.mu.Lock()
	c.cursor = cur
	c.mu.Unlock()
}

func (c *TaranisClient) pollOnce(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	u := c.apiURL + "/api/v1/osint-sources/items?limit=100"
	if cur := c.loadCursor(); cur != "" {
		u += "&after=" + cur
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("taranis: poll %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}

	var result struct {
		Items      []taranisItem `json:"items"`
		NextCursor string        `json:"next_cursor"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	for _, item := range result.Items {
		if err := c.processItem(ctx, item); err != nil {
			c.logger.Error().Err(err).Str("item_id", item.ID).Msg("taranis: process polled item failed")
		}
	}

	if result.NextCursor != "" {
		c.storeCursor(result.NextCursor)
	}

	c.logger.Info().Int("count", len(result.Items)).Msg("taranis: polled")
	return nil
}

func (c *TaranisClient) processItem(ctx context.Context, item taranisItem) error {
	severity, iocCount := classifyItem(item)
	inc := &db.Incident{
		Source:      "taranis",
		Severity:    severity,
		Title:       item.Title,
		Description: item.Description,
		Metadata: map[string]any{
			"taranis_id": item.ID,
			"source":     item.Source,
			"ioc_count":  iocCount,
			"tags":       item.Tags,
		},
	}
	if err := c.incidents.Insert(ctx, inc); err != nil {
		return fmt.Errorf("insert incident: %w", err)
	}
	c.logger.Info().Str("incident_id", inc.ID.String()).Str("severity", severity).Msg("taranis: incident created from poll")
	return nil
}

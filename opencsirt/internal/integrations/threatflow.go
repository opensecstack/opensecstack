package integrations

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/opencsirt/internal/db"
)

// ThreatFlowClient pulls IOC bundles from ThreatFlow and pushes
// published advisories back to ThreatFlow's ingest endpoint.
type ThreatFlowClient struct {
	apiURL    string
	apiKey    string
	interval  time.Duration
	http      *http.Client
	store     *db.IOCIngestStore
	logger    zerolog.Logger
}

func NewThreatFlowClient(apiURL, apiKey string, interval time.Duration, store *db.IOCIngestStore, logger zerolog.Logger) *ThreatFlowClient {
	return &ThreatFlowClient{
		apiURL:   apiURL,
		apiKey:   apiKey,
		interval: interval,
		http:     &http.Client{Timeout: 30 * time.Second},
		store:    store,
		logger:   logger,
	}
}

// Run starts the IOC poller. Returns when ctx is done.
func (c *ThreatFlowClient) Run(ctx context.Context) {
	if c.apiURL == "" {
		c.logger.Info().Msg("threatflow: API URL empty, poller disabled")
		return
	}
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.pullOnce(ctx); err != nil {
				c.logger.Warn().Err(err).Msg("threatflow: pull failed")
			}
		}
	}
}

func (c *ThreatFlowClient) pullOnce(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiURL+"/api/v1/iocs?type=all", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("threatflow: upstream_auth_failed (%d)", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("threatflow: pull %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
	if err != nil {
		return err
	}
	hash := sha256.Sum256(body)
	hashHex := hex.EncodeToString(hash[:])

	last, err := c.store.LastForSource(ctx, "threatflow")
	if err == nil && last.BundleSHA256 == hashHex {
		return nil // unchanged
	}

	var parsed struct {
		IOCs []map[string]any `json:"iocs"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return err
	}
	_ = c.store.Insert(ctx, &db.IOCIngestEntry{
		Source:       "threatflow",
		BundleSHA256: hashHex,
		Count:        len(parsed.IOCs),
	})
	c.logger.Info().Int("count", len(parsed.IOCs)).Msg("threatflow: ingested")
	return nil
}

// PushAdvisory sends a published CSAF doc to ThreatFlow's ingest.
func (c *ThreatFlowClient) PushAdvisory(ctx context.Context, csafDoc map[string]any) error {
	if c.apiURL == "" {
		return errors.New("threatflow: API URL not configured")
	}
	body, err := json.Marshal(csafDoc)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.apiURL+"/api/v1/advisories", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("threatflow: upstream_auth_failed (%d)", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("threatflow: push %d", resp.StatusCode)
	}
	return nil
}

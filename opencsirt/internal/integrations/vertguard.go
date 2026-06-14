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
)

// VertGuardSubscriber polls VertGuard's AI-threat advisory feed for
// cross-CSIRT AI threat sharing. Each new advisory creates an OpenCSIRT
// incident with source=peer_csirt + metadata.vertguard_advisory_id.
type VertGuardSubscriber struct {
	apiURL     string
	apiKey     string
	http       *http.Client
	logger     zerolog.Logger
	onAdvisory func(ctx context.Context, advisoryID string, payload map[string]any) error
	mu         sync.Mutex
	seen       map[string]struct{}
}

func NewVertGuardSubscriber(apiURL, apiKey string, onAdvisory func(context.Context, string, map[string]any) error, logger zerolog.Logger) *VertGuardSubscriber {
	return &VertGuardSubscriber{
		apiURL:     apiURL,
		apiKey:     apiKey,
		http:       &http.Client{Timeout: 30 * time.Second},
		logger:     logger,
		onAdvisory: onAdvisory,
		seen:       make(map[string]struct{}),
	}
}

func (s *VertGuardSubscriber) Run(ctx context.Context) {
	if s.apiURL == "" {
		s.logger.Info().Msg("vertguard: API URL empty, subscriber disabled")
		return
	}
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.pullOnce(ctx); err != nil {
				s.logger.Warn().Err(err).Msg("vertguard: pull failed")
			}
		}
	}
}

func (s *VertGuardSubscriber) pullOnce(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		s.apiURL+"/api/v1/ai-advisories?since=1h", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("vertguard: upstream_auth_failed (%d)", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("vertguard: pull %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return err
	}
	var feed struct {
		Advisories []struct {
			ID      string         `json:"id"`
			Payload map[string]any `json:"payload"`
		} `json:"advisories"`
	}
	if err := json.Unmarshal(body, &feed); err != nil {
		return err
	}
	for _, a := range feed.Advisories {
		s.mu.Lock()
		if _, ok := s.seen[a.ID]; ok {
			s.mu.Unlock()
			continue
		}
		s.mu.Unlock()
		// do callback work without holding the lock to avoid blocking during I/O
		if s.onAdvisory != nil {
			if err := s.onAdvisory(ctx, a.ID, a.Payload); err != nil {
				s.logger.Error().Err(err).Str("advisory_id", a.ID).Msg("vertguard: advisory callback failed")
				continue
			}
		}
		s.mu.Lock()
		s.seen[a.ID] = struct{}{}
		s.mu.Unlock()
	}
	return nil
}

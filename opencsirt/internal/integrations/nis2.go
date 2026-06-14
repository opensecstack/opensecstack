package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// NIS2Client posts Article 23 incident notifications to NIS2 Compass
// when an OpenCSIRT incident reaches severity ≥ HIGH.
type NIS2Client struct {
	apiURL string
	http   *http.Client
	logger zerolog.Logger
}

func NewNIS2Client(apiURL string, logger zerolog.Logger) *NIS2Client {
	return &NIS2Client{
		apiURL: apiURL,
		http:   &http.Client{Timeout: 15 * time.Second},
		logger: logger,
	}
}

type NIS2Notification struct {
	IncidentID     uuid.UUID  `json:"incident_id"`
	ConstituencyID *uuid.UUID `json:"constituency_id,omitempty"`
	Severity       string     `json:"severity"`
	Title          string     `json:"title"`
	OpenedAt       time.Time  `json:"opened_at"`
	Source         string     `json:"source"`
}

func (c *NIS2Client) Notify(ctx context.Context, n NIS2Notification) error {
	if c.apiURL == "" {
		c.logger.Debug().Msg("nis2: API URL empty, notification suppressed")
		return nil
	}
	if n.Severity != "high" && n.Severity != "critical" {
		return errors.New("nis2: severity below notification threshold")
	}
	body, err := json.Marshal(n)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.apiURL+"/api/v1/notifications/article23", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("nis2: notify %d", resp.StatusCode)
	}
	return nil
}

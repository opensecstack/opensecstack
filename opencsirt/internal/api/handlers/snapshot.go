package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/opensecstack/opencsirt/internal/db"
)

// Snapshot is the JSON metrics endpoint that the dashboard polls.
type Snapshot struct {
	Incidents   *db.IncidentStore
	Advisories  *db.AdvisoryStore
	Outbox      *db.OutboxStore
	IOCIngest   *db.IOCIngestStore
	QueueDepth  func() int
	HealthCheck func(context.Context) bool
	NodeName    string
	Version     string
}

type snapshotResponse struct {
	IncidentsByStatus  map[string]int `json:"incidents_by_status"`
	AdvisoriesByState  map[string]int `json:"advisories_by_state"`
	OutboxPending      int            `json:"outbox_pending"`
	OutboxFailed       int            `json:"outbox_failed"`
	CitadelQueueDepth  int            `json:"citadel_queue_depth"`
	IOCsLastIngestedAt *time.Time     `json:"iocs_last_ingested_at,omitempty"`
	IOCsLastBundleSize int            `json:"iocs_last_bundle_size"`
	AdvisoryServiceUp  bool           `json:"advisory_service_up"`
	Node               string         `json:"node"`
	Version            string         `json:"version"`
	SnapshotAt         time.Time      `json:"snapshot_at"`
}

func (h *Snapshot) Get(w http.ResponseWriter, r *http.Request) {
	resp := snapshotResponse{
		Node:       h.NodeName,
		Version:    h.Version,
		SnapshotAt: time.Now().UTC(),
	}
	if m, err := h.Incidents.CountByStatus(r.Context()); err == nil {
		resp.IncidentsByStatus = m
	}
	if m, err := h.Advisories.CountByState(r.Context()); err == nil {
		resp.AdvisoriesByState = m
	}
	if n, err := h.Outbox.PendingCount(r.Context()); err == nil {
		resp.OutboxPending = n
	}
	if n, err := h.Outbox.FailedCount(r.Context()); err == nil {
		resp.OutboxFailed = n
	}
	if h.QueueDepth != nil {
		resp.CitadelQueueDepth = h.QueueDepth()
	}
	if last, err := h.IOCIngest.LastForSource(r.Context(), "threatflow"); err == nil {
		resp.IOCsLastIngestedAt = &last.IngestedAt
		resp.IOCsLastBundleSize = last.Count
	}
	if h.HealthCheck != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
		defer cancel()
		resp.AdvisoryServiceUp = h.HealthCheck(ctx)
	}
	writeJSON(w, http.StatusOK, resp)
}

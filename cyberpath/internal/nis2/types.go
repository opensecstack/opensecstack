// Package nis2 holds the outbound HTTP client that talks to NIS2
// Compass. CyberPath calls Compass to surface gap-driven track
// recommendations and to push coverage data back for cross-platform
// aggregation.
//
// Wire in cmd/server/main.go via Options.NIS2Client. The existing
// handler stub at internal/api/handlers/coverage.go will be updated
// by the wire-up step to consult this client.
package nis2

import "time"

// GapID is the NIS2 Compass gap identifier, e.g. "art21.g" or
// "art21_g". Both dotted and underscored forms are accepted upstream;
// callers should pass through whatever Compass sent them.
type GapID string

// TrackRecommendation is one entry in a /recommend response.
type TrackRecommendation struct {
	TrackID          string `json:"track_id"`
	Reason           string `json:"reason,omitempty"`
	Priority         string `json:"priority"` // primary | secondary | optional
	EstimatedMinutes int    `json:"estimated_minutes"`
}

// TrackCompletion is a single completed-track row reported back to
// Compass for cross-platform coverage aggregation.
type TrackCompletion struct {
	TrackID        string    `json:"track_id"`
	TrackVersion   string    `json:"track_version"`
	CompletionID   string    `json:"completion_id"`
	CompletedAt    time.Time `json:"completed_at"`
	Certification  bool      `json:"certification"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
	EvidenceHash   string    `json:"evidence_hash,omitempty"`
}

// CoverageReport is the body shape pushed to Compass when CyberPath
// proactively reports a user's accumulated coverage.
type CoverageReport struct {
	UserID           string            `json:"user_id"`
	Tenant           string            `json:"tenant,omitempty"`
	CompletedTracks  []TrackCompletion `json:"completed_tracks"`
	AsOf             time.Time         `json:"as_of"`
}

// recommendRequest is the body shape POSTed to /api/v1/recommend.
type recommendRequest struct {
	Tenant string `json:"tenant,omitempty"`
	Gap    GapID  `json:"gap"`
}

// recommendResponse mirrors the Compass response envelope.
type recommendResponse struct {
	Gap             GapID                 `json:"gap"`
	Measure         string                `json:"measure,omitempty"`
	Recommendations []TrackRecommendation `json:"recommendations"`
}

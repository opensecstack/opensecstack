// Package content — service.go is the high-level facade consumed by
// HTTP handlers (e.g. /api/v1/admin/content/reload) and the
// `cyberpath-cli content lint` command.
//
// The Service composes loader + validator + publisher and tracks the
// last-published content_hash per track so Reload can be idempotent
// for unchanged tracks.
package content

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
)

// Service ties loader → validator → publisher together.
type Service struct {
	ContentDir string
	Publisher  *Publisher

	mu       sync.Mutex
	lastHash map[string]string // track-id → last-known content_hash
}

// NewService constructs a Service rooted at contentDir.
func NewService(contentDir string, p *Publisher) *Service {
	return &Service{
		ContentDir: contentDir,
		Publisher:  p,
		lastHash:   make(map[string]string),
	}
}

// Reload re-scans the content directory and re-publishes every track
// whose content_hash changed since the previous Reload. UPSERT
// semantics make re-publishing an unchanged track a no-op at the DB
// level, but skipping the work avoids burning a transaction.
//
// Pass uuid.Nil for byUser if the call originates from a system
// process (CLI, scheduled reconcile).
func (s *Service) Reload(ctx context.Context, byUser uuid.UUID) (ReloadReport, error) {
	const op = "service.Reload"
	report := ReloadReport{}

	tracks, err := LoadAllTracks(s.ContentDir)
	if err != nil {
		return report, fmt.Errorf("content/%s: %w", op, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, t := range tracks {
		hash := HashTrack(t)
		if prev, ok := s.lastHash[t.ID]; ok && prev == hash {
			report.Unchanged = append(report.Unchanged, t.ID)
			continue
		}
		if s.Publisher == nil {
			return report, fmt.Errorf("content/%s: publisher is nil", op)
		}
		if err := s.Publisher.Publish(ctx, t, byUser); err != nil {
			report.Failed = append(report.Failed, FailedTrack{ID: t.ID, Err: err.Error()})
			continue
		}
		s.lastHash[t.ID] = hash
		report.Published = append(report.Published, t.ID)
	}
	return report, nil
}

// Lint runs the loader + validator across dir and returns a per-track
// diagnostic report. It does NOT touch the database — safe to invoke
// from `cyberpath-cli content lint` against an unconfigured deployment.
func (s *Service) Lint(ctx context.Context, dir string) ([]LintResult, error) {
	const op = "service.Lint"
	if dir == "" {
		dir = s.ContentDir
	}
	tracks, err := LoadAllTracks(dir)
	if err != nil {
		return nil, fmt.Errorf("content/%s: %w", op, err)
	}
	out := make([]LintResult, 0, len(tracks))
	for _, t := range tracks {
		out = append(out, LintResult{
			TrackID:     t.ID,
			Version:     t.Version,
			Diagnostics: ValidateTrackWithRoot(t, dir),
		})
	}
	return out, nil
}

// ReloadReport is the structured outcome of Service.Reload.
type ReloadReport struct {
	Published []string      `json:"published"`
	Unchanged []string      `json:"unchanged"`
	Failed    []FailedTrack `json:"failed,omitempty"`
}

// FailedTrack describes a single failed publish attempt during Reload.
type FailedTrack struct {
	ID  string `json:"id"`
	Err string `json:"error"`
}

// LintResult bundles the diagnostics for one track.
type LintResult struct {
	TrackID     string            `json:"track_id"`
	Version     string            `json:"version"`
	Diagnostics []ValidationError `json:"diagnostics"`
}

// HasErrors reports whether the result has any "error"-severity entries.
func (r LintResult) HasErrors() bool {
	for _, d := range r.Diagnostics {
		if d.Severity == "error" {
			return true
		}
	}
	return false
}

package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/openscrub/internal/dataplane"
)

// SnapshotResponse is the JSON body of GET /api/v1/metrics/snapshot.
//
// Field semantics match docs/metrics.md so the dashboard can compute
// rates client-side. All counters are monotonic since process start;
// rates are derived in the browser from two snapshots.
type SnapshotResponse struct {
	PPSPassed         uint64    `json:"pps_passed"`
	PPSDropped        uint64    `json:"pps_dropped"`
	PPSRatelimited    uint64    `json:"pps_ratelimited"`
	SynCookiesSent    uint64    `json:"syn_cookies_sent"`
	RulesActive       int       `json:"rules_active"`
	RulesV4           int       `json:"rules_v4"`
	RulesV6           int       `json:"rules_v6"`
	RulesRatelimit    int       `json:"rules_ratelimit"`
	RulesSynCookie    int       `json:"rules_syncookie"`
	IOCPullLastAt     time.Time `json:"ioc_pull_last_at"`
	IOCPullCount      int       `json:"ioc_pull_count"`
	CitadelQueueDepth int       `json:"citadel_queue_depth"`
	DataplaneAttached bool      `json:"dataplane_attached"`
	SnapshotAt        time.Time `json:"snapshot_at"`
}

// SnapshotRulesSource exposes the rule-counter aggregates the snapshot
// handler needs. Implemented in cmd/openscrub/main.go against the
// rules.Repo + dataplane.Snapshot pair so the dashboard sees the same
// per-family numbers as Prometheus.
type SnapshotRulesSource interface {
	// CountByType returns active counts for blocklist/ratelimit/syncookie.
	CountByType(ctx context.Context) (blocklist, ratelimit, syncookie int, err error)
	// V4V6Split returns the IPv4/IPv6 split for blocklist rules. The
	// dashboard groups them separately on the rule-table page.
	V4V6Split(ctx context.Context) (v4, v6 int, err error)
}

// SnapshotIOCSource exposes the most recent IOC ingest log row.
// Implemented in main.go against db.IOCIngestLogStore.
type SnapshotIOCSource interface {
	LastIngest(ctx context.Context) (lastAt time.Time, count int, err error)
}

// SnapshotCitadelSource exposes the in-flight retry-queue depth.
type SnapshotCitadelSource interface {
	QueueDepth() int
}

// Snapshot is the handler for GET /api/v1/metrics/snapshot. Read-only;
// safe under analyst+ role.
type Snapshot struct {
	Plane             dataplane.Client
	Rules             SnapshotRulesSource
	IOC               SnapshotIOCSource
	Citadel           SnapshotCitadelSource
	DataplaneAttached func() bool
	Logger            zerolog.Logger
	Now               func() time.Time
}

// Get serves the snapshot. Each downstream source is best-effort: a
// failing dataplane probe yields zeroes for the pps_* fields rather
// than a 500, so the dashboard still renders the rule + ioc panes.
func (h *Snapshot) Get(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC
	if h.Now != nil {
		now = h.Now
	}
	resp := SnapshotResponse{SnapshotAt: now()}

	if h.Plane != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 1500*time.Millisecond)
		defer cancel()
		if s, err := h.Plane.Stats(ctx); err == nil {
			resp.PPSPassed = s.PacketsPassed
			resp.PPSDropped = s.PacketsDropped
			resp.PPSRatelimited = s.PacketsRatelimited
			// SYN-cookie sent count is exposed by the Rust loader on
			// the same Stats RPC; older loaders return 0 here, which
			// is fine — the panel just shows "0".
			resp.SynCookiesSent = s.SynCookiesSent
		} else {
			h.Logger.Debug().Err(err).Msg("snapshot: dataplane stats unavailable")
		}
	}

	if h.Rules != nil {
		bl, rl, sc, err := h.Rules.CountByType(r.Context())
		if err == nil {
			resp.RulesRatelimit = rl
			resp.RulesSynCookie = sc
			resp.RulesActive = bl + rl + sc
		} else {
			h.Logger.Debug().Err(err).Msg("snapshot: rules CountByType failed")
		}
		v4, v6, err := h.Rules.V4V6Split(r.Context())
		if err == nil {
			resp.RulesV4 = v4
			resp.RulesV6 = v6
		} else {
			h.Logger.Debug().Err(err).Msg("snapshot: rules V4V6Split failed")
		}
	}

	if h.IOC != nil {
		if last, count, err := h.IOC.LastIngest(r.Context()); err == nil {
			resp.IOCPullLastAt = last
			resp.IOCPullCount = count
		} else {
			h.Logger.Debug().Err(err).Msg("snapshot: ioc LastIngest failed")
		}
	}

	if h.Citadel != nil {
		resp.CitadelQueueDepth = h.Citadel.QueueDepth()
	}

	if h.DataplaneAttached != nil {
		resp.DataplaneAttached = h.DataplaneAttached()
	}

	writeJSON(w, http.StatusOK, resp)
}

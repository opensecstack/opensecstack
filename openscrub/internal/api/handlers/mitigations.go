package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// MitigationView is the JSON shape of one row in GET /api/v1/mitigations.
// Decoupled from db.Mitigation so the handler doesn't import internal/db
// (and so the wire format is stable independent of column changes).
type MitigationView struct {
	ID             uuid.UUID  `json:"id"`
	RuleID         uuid.UUID  `json:"rule_id"`
	StartedAt      time.Time  `json:"started_at"`
	EndedAt        *time.Time `json:"ended_at,omitempty"`
	PacketsDropped int64      `json:"packets_dropped"`
	BytesDropped   int64      `json:"bytes_dropped"`
	SrcIP          string     `json:"src_ip,omitempty"`
	Emitted        bool       `json:"emitted"`
}

// MitigationLister is the storage interface the handler needs. The
// concrete *db.MitigationStore is adapted in cmd/openscrub/main.go.
type MitigationLister interface {
	List(ctx context.Context, since time.Time, ruleID uuid.UUID, limit int) ([]MitigationView, error)
}

// Mitigations is the handler set for /api/v1/mitigations.
type Mitigations struct {
	Lister MitigationLister
	Logger zerolog.Logger
}

// List handles GET /api/v1/mitigations?since=…&rule_id=…&limit=…
//
// Query params (all optional):
//   - since:   RFC-3339 timestamp; only rows with started_at >= since
//   - rule_id: UUID; only rows for that rule
//   - limit:   1..1000, default 200
func (h *Mitigations) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	var since time.Time
	if s := q.Get("since"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_since", "since must be RFC3339")
			return
		}
		since = t
	}

	var ruleID uuid.UUID
	if s := q.Get("rule_id"); s != "" {
		id, err := uuid.Parse(s)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_rule_id", "rule_id must be uuid")
			return
		}
		ruleID = id
	}

	limit, _ := strconv.Atoi(q.Get("limit"))

	if h.Lister == nil {
		// No DB configured (in-memory dev mode). Return empty list so
		// dashboards don't 500 — mitigations only exist with a real
		// data plane + Postgres anyway.
		writeJSON(w, http.StatusOK, map[string]any{"mitigations": []MitigationView{}, "count": 0})
		return
	}

	rows, err := h.Lister.List(r.Context(), since, ruleID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	if rows == nil {
		rows = []MitigationView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"mitigations": rows, "count": len(rows)})
}

// MitigationViewFrom converts a (id, ruleID, …, srcIP) tuple into the
// wire view. Helper kept here so the wireup adapter in main.go doesn't
// duplicate the IP-to-string conversion.
func MitigationViewFrom(
	id, ruleID uuid.UUID, started time.Time, ended *time.Time,
	packets, bytes int64, src *netip.Addr, emitted bool,
) MitigationView {
	v := MitigationView{
		ID: id, RuleID: ruleID, StartedAt: started, EndedAt: ended,
		PacketsDropped: packets, BytesDropped: bytes, Emitted: emitted,
	}
	if src != nil {
		v.SrcIP = src.String()
	}
	return v
}

// Compile-time check that the JSON encoding doesn't drift.
var _ = json.Marshal

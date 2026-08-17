package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/opensecstack/vertguard/internal/citadel"
	"github.com/opensecstack/vertguard/internal/ioc"
	"github.com/opensecstack/vertguard/internal/threatfeed/atlas"
)

// maxObservedBehaviourBytes caps the MapATLAS request body size and the
// inbound observed_behaviour string length. 8 KiB is plenty for natural
// behaviour descriptions and prevents resource amplification.
const maxObservedBehaviourBytes = 8 << 10

// defaultIOCsPageLimit / maxIOCsPageLimit bound pagination on
// GET /api/v1/threatfeed/iocs.
const (
	defaultIOCsPageLimit = 100
	maxIOCsPageLimit     = 1000
)

// IOCStore is the subset of ioc.Store the handler touches. Defined as
// an interface so tests can pass a fake without a Postgres pool.
type IOCStore interface {
	List(ctx context.Context, f ioc.ListFilter) ([]ioc.IOC, int, error)
	Upsert(ctx context.Context, in ioc.IOC) (ioc.UpsertResult, error)
}

// ThreatFeedHandler wires Module 4 endpoints.
//
// VG-006: Store is the persistent IOC backing for ListIOCs + the
// admin POST. When nil the handler falls back to the embedded ATLAS
// subset so trimmed test setups still produce a useful payload.
type ThreatFeedHandler struct {
	atlasSet []atlas.Technique
	Store    IOCStore
	Citadel  WORMEmitter
	Tenant   string
}

// NewThreatFeedHandler constructs the handler with the embedded
// ATLAS initial dataset.
func NewThreatFeedHandler() *ThreatFeedHandler {
	return &ThreatFeedHandler{atlasSet: atlas.Initial()}
}

// ListIOCs handles GET /api/v1/threatfeed/iocs.
// Query params: kind, source, limit, cursor. Response shape stays
// stable: {iocs:[…], total, next_cursor?}.
func (h *ThreatFeedHandler) ListIOCs(w http.ResponseWriter, r *http.Request) {
	limit, offset, err := parsePageParams(r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_pagination", err.Error())
		return
	}

	if h.Store != nil {
		h.listFromStore(w, r, limit, offset)
		return
	}
	h.listFromATLAS(w, limit, offset)
}

func (h *ThreatFeedHandler) listFromStore(w http.ResponseWriter, r *http.Request, limit, offset int) {
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))
	source := strings.TrimSpace(r.URL.Query().Get("source"))
	if kind != "" && !ioc.ValidKind(ioc.Kind(kind)) {
		writeJSONError(w, http.StatusBadRequest, "invalid_kind",
			"kind must be one of ip|cidr|domain|url|hash_sha256|hash_md5")
		return
	}
	rows, next, err := h.Store.List(r.Context(), ioc.ListFilter{
		Kind: kind, Source: source, Tenant: h.Tenant,
		Cursor: offset, Limit: limit,
	})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "store_unavailable",
			"ioc store query failed")
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, x := range rows {
		out = append(out, map[string]any{
			"kind":       string(x.Kind),
			"value":      x.Value,
			"source":     x.Source,
			"confidence": x.Confidence,
			"tags":       x.Tags,
			"first_seen": x.FirstSeen,
			"last_seen":  x.LastSeen,
			"expires_at": x.ExpiresAt,
		})
	}
	resp := map[string]any{
		"iocs":  out,
		"total": len(out),
	}
	if next > 0 {
		resp["next_cursor"] = strconv.Itoa(next)
	}
	writeJSON(w, http.StatusOK, resp)
	if len(out) > 0 {
		h.emitDetection("vertguard.detection.threatfeed_query", map[string]any{
			"endpoint": "list_iocs",
			"returned": len(out),
		})
	}
}

func (h *ThreatFeedHandler) listFromATLAS(w http.ResponseWriter, limit, offset int) {
	total := len(h.atlasSet)
	end := offset + limit
	if end > total {
		end = total
	}
	if offset > total {
		offset = total
	}
	page := h.atlasSet[offset:end]

	out := make([]map[string]any, 0, len(page))
	for _, t := range page {
		out = append(out, map[string]any{
			"type":      "ai_attack_technique",
			"value":     t.ID,
			"name":      t.Name,
			"technique": t.ID,
			"tactic":    t.TacticID,
			"source":    "mitre-atlas-embedded",
			"reference": t.URL,
		})
	}

	resp := map[string]any{
		"iocs":  out,
		"total": total,
		"note":  "Phase 4.1 initial — embedded ATLAS subset; full community-feed sync lands in VG-006.",
	}
	if end < total {
		resp["next_cursor"] = strconv.Itoa(end)
	}
	writeJSON(w, http.StatusOK, resp)

	if len(out) > 0 {
		h.emitDetection("vertguard.detection.threatfeed_query", map[string]any{
			"endpoint": "list_iocs",
			"returned": len(out),
		})
	}
}

// CreateIOC handles POST /api/v1/threatfeed/ioc — admin-only manual
// insert. Body matches the persisted IOC shape; the audit row is
// emitted via CITADEL when configured.
func (h *ThreatFeedHandler) CreateIOC(w http.ResponseWriter, r *http.Request) {
	if h.Store == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "store_unavailable",
			"ioc store not configured")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	var in struct {
		Kind       string   `json:"kind"`
		Value      string   `json:"value"`
		Source     string   `json:"source"`
		Confidence float64  `json:"confidence"`
		Tags       []string `json:"tags"`
		ExpiresAt  *string  `json:"expires_at"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		if strings.Contains(err.Error(), "request body too large") {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "input_too_large",
				"request body exceeds maximum size")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "input_malformed", "invalid JSON body")
		return
	}
	if !ioc.ValidKind(ioc.Kind(in.Kind)) {
		writeJSONError(w, http.StatusBadRequest, "invalid_kind", "kind missing or unsupported")
		return
	}
	if strings.TrimSpace(in.Value) == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_value", "value is required")
		return
	}
	if in.Confidence < 0 || in.Confidence > 1 {
		writeJSONError(w, http.StatusBadRequest, "invalid_confidence",
			"confidence must be in [0,1]")
		return
	}
	row := ioc.IOC{
		Kind:       ioc.Kind(in.Kind),
		Value:      strings.TrimSpace(in.Value),
		Source:     strDefault(in.Source, "manual"),
		Confidence: in.Confidence,
		Tags:       in.Tags,
		Tenant:     h.Tenant,
	}
	if in.ExpiresAt != nil && *in.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *in.ExpiresAt)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_expires_at",
				"expires_at must be RFC3339")
			return
		}
		row.ExpiresAt = &t
	}
	res, err := h.Store.Upsert(r.Context(), row)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "store_unavailable",
			"ioc upsert failed")
		return
	}
	verdict := "updated"
	if res == ioc.UpsertInserted {
		verdict = "inserted"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"result": verdict,
		"kind":   string(row.Kind),
		"value":  row.Value,
	})
	h.emitDetection("vertguard.threatfeed.ioc_manual_insert", map[string]any{
		"kind":   row.Kind,
		"source": row.Source,
	})
}

func strDefault(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

// MapATLAS handles POST /api/v1/threatfeed/atlas.
func (h *ThreatFeedHandler) MapATLAS(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxObservedBehaviourBytes+1<<10)
	var req struct {
		ObservedBehaviour string `json:"observed_behaviour"`
	}
	if err := decodeJSON(r, &req); err != nil {
		if strings.Contains(err.Error(), "request body too large") {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "input_too_large",
				"request body exceeds maximum size")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "input_malformed", "invalid JSON body")
		return
	}
	if req.ObservedBehaviour == "" {
		writeJSONError(w, http.StatusBadRequest, "input_empty", "observed_behaviour is required")
		return
	}
	if len(req.ObservedBehaviour) > maxObservedBehaviourBytes {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "input_too_large",
			"observed_behaviour exceeds maximum size")
		return
	}

	lower := strings.ToLower(req.ObservedBehaviour)

	matches := make([]map[string]any, 0)
	for _, t := range h.atlasSet {
		score := keywordOverlap(lower, strings.ToLower(t.Name+" "+t.Description))
		if score > 0 {
			if score < 0 {
				score = 0
			}
			if score > 1 {
				score = 1
			}
			matches = append(matches, map[string]any{
				"technique_id": t.ID,
				"name":         t.Name,
				"tactic":       t.TacticID,
				"confidence":   score,
				"atlas_url":    t.URL,
			})
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"matches": matches,
	})

	if len(matches) > 0 {
		h.emitDetection("vertguard.detection.threatfeed_query", map[string]any{
			"endpoint": "map_atlas",
			"matches":  len(matches),
		})
	}
}

// CoverageReport handles GET /api/v1/threatfeed/atlas/coverage.
func (h *ThreatFeedHandler) CoverageReport(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"atlas_version":      "embedded-initial",
		"techniques_covered": len(h.atlasSet),
		"note":               "Detailed pattern-vs-technique gap report lands with VG-006.",
		"techniques":         h.atlasSet,
	}
	writeJSON(w, http.StatusOK, out)
}

// emitDetection sends a best-effort fire-and-forget WORM record for a
// threatfeed-related observation. Skips silently when Citadel is unset.
func (h *ThreatFeedHandler) emitDetection(eventType string, _ map[string]any) {
	if h == nil || h.Citadel == nil {
		return
	}
	h.Citadel.EmitAsync(context.Background(), citadel.Evidence{
		EventType: eventType,
		Subject:   "threatfeed",
		Verdict:   "informational",
		Tenant:    h.Tenant,
		Timestamp: time.Now().UTC(),
	})
}

// parsePageParams extracts limit (1..maxIOCsPageLimit, default
// defaultIOCsPageLimit) and an opaque cursor (currently a numeric
// offset) from the request query string.
func parsePageParams(r *http.Request) (limit, offset int, err error) {
	limit = defaultIOCsPageLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, perr := strconv.Atoi(v)
		if perr != nil || n <= 0 {
			return 0, 0, errInvalidLimit
		}
		if n > maxIOCsPageLimit {
			n = maxIOCsPageLimit
		}
		limit = n
	}
	if v := r.URL.Query().Get("cursor"); v != "" {
		n, perr := strconv.Atoi(v)
		if perr != nil || n < 0 {
			return 0, 0, errInvalidCursor
		}
		offset = n
	}
	return limit, offset, nil
}

// errInvalidLimit / errInvalidCursor surface as 400 input errors.
var (
	errInvalidLimit  = pageErr("limit must be a positive integer")
	errInvalidCursor = pageErr("cursor must be a non-negative integer")
)

type pageErr string

func (e pageErr) Error() string { return string(e) }

// keywordOverlap returns a rough 0..1 confidence based on shared tokens.
func keywordOverlap(a, b string) float64 {
	stopwords := map[string]bool{
		"the": true, "a": true, "an": true, "of": true, "to": true, "in": true,
		"on": true, "at": true, "for": true, "with": true, "and": true, "or": true,
		"is": true, "are": true, "was": true, "be": true, "by": true,
	}
	isTokenRune := func(r rune) bool {
		return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
	}
	tokens := func(s string) map[string]bool {
		out := map[string]bool{}
		for _, t := range strings.FieldsFunc(s, func(r rune) bool {
			return !isTokenRune(r)
		}) {
			if len(t) > 2 && !stopwords[t] {
				out[t] = true
			}
		}
		return out
	}
	at := tokens(a)
	bt := tokens(b)
	if len(at) == 0 || len(bt) == 0 {
		return 0
	}
	shared := 0
	for t := range at {
		if bt[t] {
			shared++
		}
	}
	minLen := len(at)
	if len(bt) < minLen {
		minLen = len(bt)
	}
	score := float64(shared) / float64(minLen)
	if score < 0 {
		return 0
	}
	if score > 1 {
		return 1
	}
	return score
}

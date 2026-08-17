package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/opensecstack/vertguard/internal/citadel"
	"github.com/opensecstack/vertguard/internal/db"
	"github.com/opensecstack/vertguard/internal/phishing"
)

// PhishingMetrics is the subset of metrics the handler touches.
type PhishingMetrics interface {
	ObservePhishingScan(classification string, durationSec float64)
	IncPhishingIndicatorMatch(indicatorID, category string)
}

// PhishingHandler wires the Module 5 endpoint.
type PhishingHandler struct {
	Scanner *phishing.Scanner
	Store   *db.DB
	Metrics PhishingMetrics
	Citadel WORMEmitter
	Tenant  string
	// ML is optional — nil keeps regex-only behaviour.
	// Assign *ml.Client (internal/ml/client.go) here; see Phase 4.2 wiring in main.go.
	ML phishing.MLEnricher
}

// NewPhishingHandler is a convenience constructor.
func NewPhishingHandler(scanner *phishing.Scanner, store *db.DB, metrics PhishingMetrics) *PhishingHandler {
	return &PhishingHandler{Scanner: scanner, Store: store, Metrics: metrics}
}

type phishingScanRequest struct {
	Input string `json:"input"`
	Kind  string `json:"kind"`
}

// Scan handles POST /api/v1/phishing/scan.
func (h *PhishingHandler) Scan(w http.ResponseWriter, r *http.Request) {
	var req phishingScanRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "input_malformed", "invalid JSON body")
		return
	}
	if req.Input == "" {
		writeJSONError(w, http.StatusBadRequest, "input_empty", "input is required")
		return
	}
	kind := phishing.Kind(req.Kind)
	switch kind {
	case "":
		kind = phishing.KindURL
	case phishing.KindURL, phishing.KindEmail, phishing.KindHTML:
		// ok
	default:
		writeJSONError(w, http.StatusBadRequest, "kind_invalid",
			"kind must be one of: url, email, html")
		return
	}

	result, err := h.Scanner.ScanWithML(r.Context(), req.Input, kind, h.ML)
	if err != nil {
		var tooLarge *phishing.InputTooLargeError
		if errors.As(err, &tooLarge) {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "input_too_large",
				"input exceeds maximum size")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "scan_failed", "internal error")
		return
	}

	// Persist (best-effort — never fail the response on DB issues).
	if h.Store != nil {
		indicatorsJSON, _ := json.Marshal(result.Matches)
		rec := &db.PhishingScan{
			ScanID:         result.ScanID,
			Classification: string(result.Classification),
			Confidence:     result.Confidence,
			InputHash:      result.InputHash,
			InputLength:    result.InputLength,
			Kind:           string(result.Kind),
			IndicatorCount: len(result.Matches),
			Indicators:     indicatorsJSON,
			DurationMS:     result.DurationMS,
		}
		_ = h.Store.SavePhishingScan(r.Context(), rec)
	}

	// Metrics.
	if h.Metrics != nil {
		h.Metrics.ObservePhishingScan(string(result.Classification), result.DurationMS/1000.0)
		for _, m := range result.Matches {
			h.Metrics.IncPhishingIndicatorMatch(m.PatternID, string(m.Category))
		}
	}

	// CITADEL WORM emit (fire-and-forget).
	if h.Citadel != nil {
		categories := make([]string, 0, len(result.Matches))
		patterns := make([]string, 0, len(result.Matches))
		seen := make(map[string]struct{}, len(result.Matches))
		for _, m := range result.Matches {
			cat := string(m.Category)
			if _, ok := seen[cat]; !ok {
				categories = append(categories, cat)
				seen[cat] = struct{}{}
			}
			patterns = append(patterns, m.PatternID)
		}
		h.Citadel.EmitAsync(r.Context(), citadel.Evidence{
			EventType:     "phishing_scan",
			Subject:       result.InputHash,
			Verdict:       string(result.Classification),
			Score:         result.Confidence,
			Categories:    categories,
			Patterns:      patterns,
			Tenant:        h.Tenant,
			Timestamp:     time.Now().UTC(),
			CorrelationID: result.ScanID,
		})
	}

	writeJSON(w, http.StatusOK, result)
}

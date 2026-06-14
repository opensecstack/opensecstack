package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/citadel"
	"github.com/opensecstack/vertguard/internal/db"
	"github.com/opensecstack/vertguard/internal/prompt"
)

// WORMEmitter is the subset of citadel.Client the handler uses. Kept
// as an interface so tests can stub it without HTTP plumbing.
type WORMEmitter interface {
	EmitAsync(ctx context.Context, ev citadel.Evidence) bool
}

// PromptService abstracts what the handler needs — lets tests plug
// mock scanners and mock stores.
type PromptService interface {
	Scan(ctx context.Context, input, ctxString string) (*prompt.ScanResult, error)
}

// PromptMetrics is the subset of metrics the handler touches.
type PromptMetrics interface {
	ObservePromptScan(classification string, durationSec float64)
	IncPatternMatch(patternID, category string)
}

// PromptScanner abstracts the scanner so tests can fake it without
// constructing the real regex engine. The production type
// (*prompt.Scanner) satisfies this implicitly.
type PromptScanner interface {
	ScanWithML(ctx context.Context, input, ctxTag string, ml prompt.MLEnricher) (*prompt.ScanResult, error)
}

// PromptHandler wires the Module 3 endpoint.
type PromptHandler struct {
	Scanner PromptScanner
	Store   *db.DB
	Metrics PromptMetrics
	Citadel WORMEmitter
	Tenant  string
	// ML is optional — nil keeps the legacy regex-only behaviour.
	ML prompt.MLEnricher
	// Logger is optional. nil → no warn-logging on the marshal-failure
	// branch (counters/metrics still fire). Wiring code should set it
	// to the server-wide zerolog instance.
	Logger *zerolog.Logger
}

// NewPromptHandler is a convenience constructor.
func NewPromptHandler(scanner PromptScanner, store *db.DB, metrics PromptMetrics) *PromptHandler {
	return &PromptHandler{Scanner: scanner, Store: store, Metrics: metrics}
}

type promptScanRequest struct {
	Input   string `json:"input"`
	Context string `json:"context"`
}

// Scan handles POST /api/v1/prompt/scan.
func (h *PromptHandler) Scan(w http.ResponseWriter, r *http.Request) {
	var req promptScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "input_malformed", "invalid JSON body")
		return
	}
	if req.Input == "" {
		writeJSONError(w, http.StatusBadRequest, "input_empty", "input is required")
		return
	}
	if req.Context == "" {
		req.Context = "user_chat_input"
	}
	// Reject unknown contexts rather than silently treating them as the
	// default — silently defaulting masks client bugs and produces
	// misleading audit trails ("user_chat_input" verdicts on inputs
	// that were actually marked untrusted_document_content).
	if !prompt.IsValidContext(req.Context) {
		writeJSONError(w, http.StatusBadRequest, "bad_context",
			"unknown context value; see API docs for the accepted set")
		return
	}

	result, err := h.Scanner.ScanWithML(r.Context(), req.Input, req.Context, h.ML)
	if err != nil {
		var tooLarge *prompt.InputTooLargeError
		if errors.As(err, &tooLarge) {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "input_too_large",
				"input exceeds maximum size")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "scan_failed", "internal error")
		return
	}

	// Persist (best-effort — don't fail the response if DB is slow).
	if h.Store != nil {
		matchesJSON, mErr := json.Marshal(result.Matches)
		if mErr != nil {
			// Should not happen with our value types, but log it
			// anyway and skip the matches column rather than
			// silently writing the zero value.
			if h.Logger != nil {
				h.Logger.Warn().Err(mErr).
					Str("scan_id", result.ScanID).
					Int("match_count", len(result.Matches)).
					Msg("prompt scan: failed to marshal matches; persisting empty array")
			}
			matchesJSON = []byte("[]")
		}
		rec := &db.PromptScan{
			ScanID:         result.ScanID,
			Classification: string(result.Classification),
			Confidence:     result.Confidence,
			InputHash:      result.InputHash,
			InputLength:    result.InputLength,
			Context:        req.Context,
			MatchCount:     len(result.Matches),
			Matches:        matchesJSON,
			WORMEntryID:    result.WORMEntryID,
			DurationMS:     result.DurationMS,
		}
		// Persist the ML enrichment — these were previously dropped on
		// the floor (Phase 4.2 regression). Migration 009 added the
		// columns. nil pointers map to SQL NULL, so a regex-only scan
		// stays distinguishable from an ML CLEAN verdict downstream.
		if result.MLVerdict != "" {
			conf := result.MLConfidence
			verdict := result.MLVerdict
			ver := result.MLBackendVersion
			rec.MLConfidence = &conf
			rec.MLVerdict = &verdict
			if ver != "" {
				rec.MLBackendVersion = &ver
			}
		}
		if err := h.Store.SavePromptScan(r.Context(), rec); err != nil && h.Logger != nil {
			h.Logger.Warn().Err(err).
				Str("scan_id", result.ScanID).
				Msg("prompt scan: persistence failed (non-fatal)")
		}
	}

	// Metrics.
	if h.Metrics != nil {
		h.Metrics.ObservePromptScan(string(result.Classification), result.DurationMS/1000.0)
		for _, m := range result.Matches {
			h.Metrics.IncPatternMatch(m.PatternID, string(m.Category))
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
			EventType:     "prompt_scan",
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

// ─── Helpers ────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeJSONError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": msg,
		"code":  code,
	})
}

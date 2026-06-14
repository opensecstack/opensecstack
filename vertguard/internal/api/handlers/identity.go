package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/opensecstack/vertguard/internal/citadel"
	"github.com/opensecstack/vertguard/internal/db"
	"github.com/opensecstack/vertguard/internal/identity"
)

// IdentityMetrics is the subset of metrics the handler touches.
type IdentityMetrics interface {
	ObserveIdentityScan(classification string, durationSec float64)
	IncIdentityIndicatorMatch(indicatorID, category string)
}

// IdentityHandler wires the Module 6 endpoint.
type IdentityHandler struct {
	Scanner *identity.Scanner
	Store   *db.DB
	Metrics IdentityMetrics
	Citadel WORMEmitter
	Tenant  string
	// ML is optional — Phase 4.3 follow-up. nil keeps rule-only behaviour.
	ML identity.MLEnricher
}

// NewIdentityHandler is a convenience constructor.
func NewIdentityHandler(scanner *identity.Scanner, store *db.DB, metrics IdentityMetrics) *IdentityHandler {
	return &IdentityHandler{Scanner: scanner, Store: store, Metrics: metrics}
}

// WithML wires the Phase 4.3 ML enricher. Returns h for chaining.
// Pass *ml.IdentityAdapter (from internal/ml) to connect the gRPC client.
func (h *IdentityHandler) WithML(ml identity.MLEnricher) *IdentityHandler {
	h.ML = ml
	return h
}

// Verify handles POST /api/v1/identity/verify.
func (h *IdentityHandler) Verify(w http.ResponseWriter, r *http.Request) {
	var req identity.ClaimRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "input_malformed", "invalid JSON body")
		return
	}
	if req.ClaimType == "" {
		writeJSONError(w, http.StatusBadRequest, "claim_type_missing", "claim_type is required")
		return
	}
	switch req.ClaimType {
	case identity.ClaimPassport, identity.ClaimNationalID,
		identity.ClaimDriverLicense, identity.ClaimLoginCreds:
	default:
		writeJSONError(w, http.StatusBadRequest, "claim_type_invalid",
			"claim_type must be one of: passport, national_id, driver_license, login_credentials")
		return
	}
	if req.Context == "" {
		req.Context = identity.ContextKYC
	}
	switch req.Context {
	case identity.ContextKYC, identity.ContextLogin, identity.ContextAccountRecovery:
	default:
		writeJSONError(w, http.StatusBadRequest, "context_invalid",
			"context must be one of: kyc, login, account_recovery")
		return
	}
	if req.Fields == nil {
		req.Fields = map[string]string{}
	}

	result, err := h.Scanner.ScanWithML(r.Context(), req, h.ML)
	if err != nil {
		var tooLarge *identity.InputTooLargeError
		if errors.As(err, &tooLarge) {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "input_too_large",
				"input exceeds maximum size")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "scan_failed", "internal error")
		return
	}

	// Persist (best-effort).
	if h.Store != nil {
		indicatorsJSON, _ := json.Marshal(result.Matches)
		rec := &db.IdentityScan{
			ScanID:         result.ScanID,
			Classification: string(result.Classification),
			Confidence:     result.Confidence,
			ClaimHash:      result.ClaimHash,
			ClaimType:      string(result.ClaimType),
			Context:        string(result.Context),
			IndicatorCount: len(result.Matches),
			Indicators:     indicatorsJSON,
			DurationMS:     result.DurationMS,
		}
		_ = h.Store.SaveIdentityScan(r.Context(), rec)
	}

	if h.Metrics != nil {
		h.Metrics.ObserveIdentityScan(string(result.Classification), result.DurationMS/1000.0)
		for _, m := range result.Matches {
			h.Metrics.IncIdentityIndicatorMatch(m.PatternID, string(m.Category))
		}
	}

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
			EventType:     "identity_verify",
			Subject:       result.ClaimHash,
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

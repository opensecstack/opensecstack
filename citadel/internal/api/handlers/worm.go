package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/citadel/internal/db"
)

// WORM handles POST /api/v1/worm/emit and GET /api/v1/worm/verify.
type WORM struct {
	logger zerolog.Logger
	db     *db.DB
}

// NewWORM creates a WORM handler.
func NewWORM(logger zerolog.Logger, database *db.DB) *WORM {
	return &WORM{logger: logger, db: database}
}

// emitRequest is the body for POST /api/v1/worm/emit.
type emitRequest struct {
	Source    string          `json:"source"`
	EventType string          `json:"event_type"`
	ProjectID string          `json:"project_id"`
	Payload   json.RawMessage `json:"payload"`
}

// emitResponse is returned by POST /api/v1/worm/emit.
type emitResponse struct {
	WORMEntryID string `json:"worm_entry_id"`
	ChainHash   string `json:"chain_hash"`
	PrevHash    string `json:"prev_hash"`
	SequenceNum int64  `json:"sequence_num"`
}

// Emit handles POST /api/v1/worm/emit.
func (w *WORM) Emit(rw http.ResponseWriter, r *http.Request) {
	var req emitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.logger.Error().Err(err).Msg("worm emit: decode request")
		http.Error(rw, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Source == "" || req.EventType == "" {
		http.Error(rw, `{"error":"source and event_type are required"}`, http.StatusBadRequest)
		return
	}

	// Serialize payload — use raw JSON if provided, otherwise empty object
	payload := []byte("{}")
	if len(req.Payload) > 0 {
		payload = req.Payload
	}

	entry, err := w.db.AppendWORM(r.Context(), req.Source, req.EventType, req.ProjectID, payload)
	if err != nil {
		w.logger.Error().Err(err).Msg("worm emit: append failed")
		http.Error(rw, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.logger.Info().
		Int64("sequence_num", entry.SequenceNum).
		Str("event_type", entry.EventType).
		Str("source", entry.Source).
		Msg("WORM entry appended")

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(rw).Encode(emitResponse{
		WORMEntryID: entry.ID.String(),
		ChainHash:   entry.ChainHash,
		PrevHash:    entry.PrevHash,
		SequenceNum: entry.SequenceNum,
	})
}

// Verify handles GET /api/v1/worm/verify?from=RFC3339&to=RFC3339.
func (w *WORM) Verify(rw http.ResponseWriter, r *http.Request) {
	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")

	from := time.Now().UTC().Add(-24 * time.Hour)
	to := time.Now().UTC()

	if fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err != nil {
			http.Error(rw, `{"error":"invalid from timestamp — use RFC3339"}`, http.StatusBadRequest)
			return
		}
		from = t
	}
	if toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err != nil {
			http.Error(rw, `{"error":"invalid to timestamp — use RFC3339"}`, http.StatusBadRequest)
			return
		}
		to = t
	}

	result, err := w.db.VerifyChain(r.Context(), from, to)
	if err != nil {
		w.logger.Error().Err(err).Msg("worm verify: chain verification failed")
		http.Error(rw, `{"error":"chain verification error"}`, http.StatusInternalServerError)
		return
	}

	w.logger.Info().
		Bool("valid", result.Valid).
		Int("entries_verified", result.EntriesVerified).
		Msg("WORM chain verified")

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(rw).Encode(result)
}

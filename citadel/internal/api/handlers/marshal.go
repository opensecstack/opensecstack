package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/citadel/internal/marshal"
)

// Marshal handles POST /api/v1/marshal/evaluate.
type Marshal struct {
	logger zerolog.Logger
	engine *marshal.Engine
}

// NewMarshal creates a Marshal handler backed by the given Engine.
func NewMarshal(logger zerolog.Logger, engine *marshal.Engine) *Marshal {
	return &Marshal{logger: logger, engine: engine}
}

// ServeHTTP evaluates a Kerkese through the 5 MARSHAL gates.
func (m *Marshal) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var k marshal.Kerkese
	if err := json.NewDecoder(r.Body).Decode(&k); err != nil {
		m.logger.Error().Err(err).Msg("marshal: decode kerkese")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	// Ensure TsUTC is set
	if k.TsUTC.IsZero() {
		k.TsUTC = time.Now().UTC()
	}

	// Ensure ExecutionID is set
	if k.ExecutionID == (uuid.UUID{}) {
		k.ExecutionID = marshal.NewExecutionID()
	}

	decision, err := m.engine.Evaluate(r.Context(), &k)
	if err != nil {
		m.logger.Error().Err(err).Msg("marshal: evaluate failed")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
		return
	}

	m.logger.Info().
		Str("outcome", decision.Outcome).
		Str("execution_id", decision.ExecutionID.String()).
		Str("action_type", k.Action.Type).
		Str("actor_user_id", k.Actor.UserID).
		Msg("MARSHAL decision")

	status := http.StatusOK
	switch decision.Outcome {
	case marshal.OutcomeHardStop, marshal.OutcomeRefuse:
		status = http.StatusForbidden
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(decision)
}

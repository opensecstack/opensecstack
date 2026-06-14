// Package handlers implements the HTTP layer.
package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/opensecstack/opencsirt/internal/auth"
	"github.com/opensecstack/opencsirt/internal/db"
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func decodeJSON(r *http.Request, dst any, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = 64 * 1024
	}
	r.Body = http.MaxBytesReader(nil, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func parseUUIDParam(r *http.Request, key string) (uuid.UUID, error) {
	v := chi.URLParam(r, key)
	if v == "" {
		return uuid.Nil, errors.New("missing path parameter " + key)
	}
	return uuid.Parse(v)
}

// parseLimitOffset validates and clamps the limit and offset query parameters.
// limit is clamped to [1, 500]; offset must be >= 0.
// Invalid (non-integer) values are treated as 0 / defaultLimit rather than
// silently accepted, and out-of-range values produce an HTTP 400 error.
func parseLimitOffset(r *http.Request, defaultLimit int) (int, int, error) {
	limit := defaultLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, 0, fmt.Errorf("limit must be an integer")
		}
		limit = n
	}
	if limit < 1 || limit > 500 {
		return 0, 0, fmt.Errorf("limit must be between 1 and 500")
	}

	offset := 0
	if v := r.URL.Query().Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, 0, fmt.Errorf("offset must be an integer")
		}
		offset = n
	}
	if offset < 0 || offset > math.MaxInt32 {
		return 0, 0, fmt.Errorf("offset must be between 0 and %d", math.MaxInt32)
	}

	return limit, offset, nil
}

func actorAndRole(r *http.Request) (uuid.UUID, string, error) {
	c, ok := auth.ClaimsFrom(r.Context())
	if !ok {
		return uuid.Nil, "", errors.New("no claims")
	}
	id, err := uuid.Parse(c.Sub)
	if err != nil {
		return uuid.Nil, "", err
	}
	return id, string(c.Role), nil
}

func mapDBError(err error) (int, string) {
	if errors.Is(err, db.ErrNotFound) {
		return http.StatusNotFound, "not found"
	}
	if errors.Is(err, db.ErrConflict) {
		return http.StatusConflict, "conflict"
	}
	return http.StatusInternalServerError, err.Error()
}

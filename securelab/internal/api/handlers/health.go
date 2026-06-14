// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/securelab/internal/version"
)

// HealthHandler returns an http.HandlerFunc that reports service liveness.
// The DB is probed with a 2-second timeout on every request so that degraded
// connectivity is surfaced in infrastructure health checks.
func HealthHandler(pool *pgxpool.Pool, startTime time.Time) http.HandlerFunc {
	type response struct {
		Status        string `json:"status"`
		DB            bool   `json:"db"`
		UptimeSeconds int64  `json:"uptime_seconds"`
		Version       string `json:"version"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		dbOK := pool.Ping(ctx) == nil
		status := "ok"
		if !dbOK {
			status = "degraded"
		}

		resp := response{
			Status:        status,
			DB:            dbOK,
			UptimeSeconds: int64(time.Since(startTime).Seconds()),
			Version:       version.Version,
		}

		w.Header().Set("Content-Type", "application/json")
		if !dbOK {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	}
}

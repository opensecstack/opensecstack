// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package handlers_test

import (
	"net/http"
	"testing"

	"go.uber.org/zap/zaptest"

	"github.com/opensecstack/securelab/internal/api/handlers"
)

// newResultsHandler builds a ResultsHandler with an unreachable pool,
// sufficient for tests that exercise the DB-error branch.
func newResultsHandler(t *testing.T) *handlers.ResultsHandler {
	t.Helper()
	return handlers.NewResultsHandler(unreachablePool(t), zaptest.NewLogger(t))
}

func TestListRuns_DBError(t *testing.T) {
	h := newResultsHandler(t)
	rr := do(h.ListRuns, newGetRequest("/", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on DB error, got %d", rr.Code)
	}
}

func TestGetRun_DBError(t *testing.T) {
	h := newResultsHandler(t)
	rr := do(h.GetRun, newGetRequest("/", map[string]string{"id": "run-1"}))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on DB error, got %d", rr.Code)
	}
}

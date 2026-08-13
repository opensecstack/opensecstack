// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package handlers_test

import (
	"net/http"
	"testing"

	"go.uber.org/zap/zaptest"

	"github.com/opensecstack/securelab/internal/api/handlers"
)

func TestGetCoverage_DBError(t *testing.T) {
	h := handlers.NewCoverageHandler(unreachablePool(t), zaptest.NewLogger(t))
	rr := do(h.GetCoverage, newGetRequest("/", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on DB error, got %d", rr.Code)
	}
}

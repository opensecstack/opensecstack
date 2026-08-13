// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package handlers_test

import (
	"net/http"
	"testing"

	"go.uber.org/zap/zaptest"

	"github.com/opensecstack/securelab/internal/api/handlers"
)

// newEnvHandler builds an EnvironmentsHandler with a nil pool, sufficient for
// tests that exercise validation logic which returns before any DB access.
func newEnvHandler(t *testing.T) *handlers.EnvironmentsHandler {
	t.Helper()
	return handlers.NewEnvironmentsHandler(nil, zaptest.NewLogger(t))
}

func TestCreateEnvironment_InvalidJSON(t *testing.T) {
	h := newEnvHandler(t)
	rr := post(h.CreateEnvironment, "{not valid json")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", rr.Code)
	}
}

func TestCreateEnvironment_MissingName(t *testing.T) {
	h := newEnvHandler(t)
	rr := post(h.CreateEnvironment, `{"kind":"docker","target_url":"http://target"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing name, got %d", rr.Code)
	}
}

func TestCreateEnvironment_InvalidKind(t *testing.T) {
	h := newEnvHandler(t)
	// "vm" is not one of the two supported kinds (docker, wasm).
	rr := post(h.CreateEnvironment, `{"name":"e1","kind":"vm","target_url":"http://target"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid kind, got %d", rr.Code)
	}
}

func TestCreateEnvironment_MissingTargetURL(t *testing.T) {
	h := newEnvHandler(t)
	rr := post(h.CreateEnvironment, `{"name":"e1","kind":"docker"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing target_url, got %d", rr.Code)
	}
}

func TestCreateEnvironment_EmptyKindRejected(t *testing.T) {
	h := newEnvHandler(t)
	rr := post(h.CreateEnvironment, `{"name":"e1","kind":"","target_url":"http://target"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty kind, got %d", rr.Code)
	}
}

func TestCreateEnvironment_KindIsCaseSensitive(t *testing.T) {
	// "Docker" (capitalised) must be rejected: the handler compares against
	// the literal lowercase strings "docker"/"wasm" with no normalisation.
	h := newEnvHandler(t)
	rr := post(h.CreateEnvironment, `{"name":"e1","kind":"Docker","target_url":"http://target"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for case-mismatched kind, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// DB-error branch tests
//
// These use an unreachablePool (see testhelpers_test.go) so the handler runs
// past validation into the DB call, which fails fast with a connection
// error — exercising the 500 branches without requiring a live Postgres.
// ---------------------------------------------------------------------------

func TestListEnvironments_DBError(t *testing.T) {
	h := handlers.NewEnvironmentsHandler(unreachablePool(t), zaptest.NewLogger(t))
	rr := do(h.ListEnvironments, newGetRequest("/", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on DB error, got %d", rr.Code)
	}
}

func TestGetEnvironment_DBError(t *testing.T) {
	h := handlers.NewEnvironmentsHandler(unreachablePool(t), zaptest.NewLogger(t))
	rr := do(h.GetEnvironment, newGetRequest("/", map[string]string{"id": "env-1"}))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on DB error, got %d", rr.Code)
	}
}

func TestCreateEnvironment_DBError(t *testing.T) {
	h := handlers.NewEnvironmentsHandler(unreachablePool(t), zaptest.NewLogger(t))
	rr := post(h.CreateEnvironment, `{"name":"e1","kind":"docker","target_url":"http://target"}`)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on DB error, got %d", rr.Code)
	}
}

func TestDeleteEnvironment_DBError(t *testing.T) {
	// GetEnvironment (the first DB call in DeleteEnvironment) fails, so the
	// handler never reaches the status checks or the UPDATE statement.
	h := handlers.NewEnvironmentsHandler(unreachablePool(t), zaptest.NewLogger(t))
	rr := do(h.DeleteEnvironment, newDeleteRequest("/", map[string]string{"id": "env-1"}))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on DB error, got %d", rr.Code)
	}
}

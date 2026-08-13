// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

// This file is a white-box (package handlers) unit test, unlike the rest of
// the package's tests which live in package handlers_test. writeJSON is
// unexported and otherwise only reachable through DB-backed success paths
// (e.g. a successful list/create) that this package's tests cannot exercise
// without a live Postgres instance (see testhelpers_test.go), so it is
// tested directly here instead.
package handlers

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestWriteJSON(t *testing.T) {
	rr := httptest.NewRecorder()

	writeJSON(rr, 201, map[string]string{"id": "abc"})

	if rr.Code != 201 {
		t.Fatalf("expected status 201, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json content type, got %q", ct)
	}

	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if body["id"] != "abc" {
		t.Fatalf("expected id=abc, got %v", body)
	}
}

func TestWriteJSON_List(t *testing.T) {
	rr := httptest.NewRecorder()

	writeJSON(rr, 200, []string{"a", "b"})

	if rr.Code != 200 {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	var body []string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if len(body) != 2 || body[0] != "a" || body[1] != "b" {
		t.Fatalf("unexpected body: %v", body)
	}
}

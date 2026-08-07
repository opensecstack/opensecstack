// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap/zaptest"

	"github.com/opensecstack/securelab/internal/api/handlers"
)

// newHandler builds a ScenariosHandler with a nil pool (sufficient for tests
// that return before any DB access).
func newHandler(t *testing.T) *handlers.ScenariosHandler {
	t.Helper()
	return handlers.NewScenariosHandler(nil, nil, zaptest.NewLogger(t))
}

// post sends a POST request with the given body to h and returns the recorder.
func post(h http.HandlerFunc, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// ---------------------------------------------------------------------------
// CreateScenario tests
// ---------------------------------------------------------------------------

func TestCreateScenario_EmptyBody(t *testing.T) {
	h := newHandler(t)
	rr := post(h.CreateScenario, "")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty body, got %d", rr.Code)
	}
}

func TestCreateScenario_InvalidJSON(t *testing.T) {
	h := newHandler(t)
	rr := post(h.CreateScenario, "{not valid json")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", rr.Code)
	}
}

func TestCreateScenario_MissingYAMLContent(t *testing.T) {
	h := newHandler(t)
	// Valid JSON but yaml_content field is absent / empty.
	rr := post(h.CreateScenario, `{"name":"test","severity":"low"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing yaml_content, got %d", rr.Code)
	}
}

func TestCreateScenario_InvalidYAML(t *testing.T) {
	h := newHandler(t)
	// yaml_content is present but contains YAML that cannot be parsed as a
	// ScenarioSpec (tab character where indentation should be spaces causes
	// yaml.Unmarshal to error in strict environments; use a clearly broken
	// YAML structure instead — an unbalanced mapping).
	body := `{"yaml_content":"name: test\nsteps:\n  - kind: bola\n  bad::"}`
	rr := post(h.CreateScenario, body)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid YAML, got %d", rr.Code)
	}
}

func TestCreateScenario_UnknownStepKind(t *testing.T) {
	h := newHandler(t)
	yaml := "name: test-scenario\nseverity: high\nsteps:\n  - kind: not_a_real_kind\n"
	body := `{"yaml_content":"` + escapeForJSON(yaml) + `"}`
	rr := post(h.CreateScenario, body)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for unknown step kind, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// RunScenario tests
// ---------------------------------------------------------------------------

func TestRunScenario_InvalidJSON(t *testing.T) {
	h := newHandler(t)
	rr := post(h.RunScenario, "{bad json")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", rr.Code)
	}
}

func TestRunScenario_MissingEnvironmentID(t *testing.T) {
	h := newHandler(t)
	rr := post(h.RunScenario, `{"environment_id":""}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing environment_id, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// escapeForJSON replaces newline characters with their JSON escape sequence so
// a multi-line YAML string can be embedded in a JSON string literal.
func escapeForJSON(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\t", `\t`)
	return s
}

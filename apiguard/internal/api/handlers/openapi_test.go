package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenAPI_StatusOK(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	w := httptest.NewRecorder()
	OpenAPI(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Result().StatusCode)
	}
}

func TestOpenAPI_ContentTypeJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	w := httptest.NewRecorder()
	OpenAPI(w, req)

	ct := w.Result().Header.Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}
}

func TestOpenAPI_ValidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	w := httptest.NewRecorder()
	OpenAPI(w, req)

	var body map[string]interface{}
	if err := json.NewDecoder(w.Result().Body).Decode(&body); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
}

func TestOpenAPI_HasOpenapiKey(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	w := httptest.NewRecorder()
	OpenAPI(w, req)

	var body map[string]interface{}
	if err := json.NewDecoder(w.Result().Body).Decode(&body); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}

	if _, ok := body["openapi"]; !ok {
		t.Fatal("response JSON missing top-level 'openapi' key")
	}
}

package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/openscrub/internal/api"
	"github.com/opensecstack/openscrub/internal/api/handlers"
	"github.com/opensecstack/openscrub/internal/auth"
	"github.com/opensecstack/openscrub/internal/dataplane"
	"github.com/opensecstack/openscrub/internal/rules"
)

func newTestServer(t *testing.T) (http.Handler, *rules.Service) {
	t.Helper()
	plane := dataplane.NewNoopClient()
	svc := rules.New(rules.Deps{
		Repo: rules.NewMemoryRepo(), Plane: plane, NodeName: "test", Logger: zerolog.Nop(),
	})
	r := api.NewRouter(api.Deps{
		Health:   &handlers.Health{},
		Rules:    &handlers.Rules{Service: svc, Logger: zerolog.Nop()},
		Verifier: auth.NewHS256Verifier(nil, ""),
		DevMode:  true,
		Logger:   zerolog.Nop(),
	})
	return r, svc
}

func TestPostRulesCreatesAndGet(t *testing.T) {
	srv, _ := newTestServer(t)

	body, _ := json.Marshal(map[string]any{
		"type":        "blocklist",
		"cidr":        "203.0.113.0/24",
		"ttl_seconds": 3600,
	})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d body=%s", rec.Code, rec.Body.String())
	}
	var created rules.Rule
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Type != rules.TypeBlocklist || created.CIDR != "203.0.113.0/24" {
		t.Fatalf("unexpected created: %+v", created)
	}

	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/rules/"+created.ID.String(), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("get: %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d", rec.Code)
	}
	var list struct {
		Rules []rules.Rule `json:"rules"`
		Count int          `json:"count"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if list.Count != 1 {
		t.Fatalf("count = %d", list.Count)
	}

	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/v1/rules/"+created.ID.String(), nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/rules/"+created.ID.String(), nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", rec.Code)
	}
}

func TestPostRulesValidationFailure(t *testing.T) {
	srv, _ := newTestServer(t)
	body, _ := json.Marshal(map[string]any{"type": "blocklist", "cidr": "not-cidr", "ttl_seconds": 60})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d want 400", rec.Code)
	}
}

func TestDeleteUnknownReturns404(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/v1/rules/"+uuid.New().String(), nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d want 404", rec.Code)
	}
}

func TestHealthEndpoint(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	var h map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &h)
	if _, ok := h["status"]; !ok {
		t.Fatal("missing status")
	}
}

func TestMetricsEndpoint(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("openscrub_rules_total")) {
		t.Fatal("metrics body missing openscrub_rules_total")
	}
}

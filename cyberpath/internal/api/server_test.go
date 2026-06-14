package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/opensecstack/cyberpath/internal/config"
	"github.com/opensecstack/cyberpath/internal/metrics"
)

func newTestRouter(t *testing.T) *chi.Mux {
	t.Helper()
	cfg := &config.Config{}
	cfg.Auth.DevMode = true
	return NewRouter(Options{
		Config:  cfg,
		Logger:  nil,
		Pinger:  nil,
		Metrics: metrics.New(),
	})
}

func TestRouterRegistersExpectedRoutes(t *testing.T) {
	r := newTestRouter(t)

	expected := []struct {
		method string
		path   string
	}{
		{"GET", "/healthz"},
		{"GET", "/readyz"},
		{"GET", "/version"},
		{"GET", "/api/v1/tracks"},
		{"GET", "/api/v1/tracks/phishing-recognition"},
		{"GET", "/api/v1/tracks/phishing-recognition/modules"},
		{"GET", "/api/v1/lessons/abc"},
		{"POST", "/api/v1/lessons/abc/complete"},
		{"POST", "/api/v1/quizzes/q1/submit"},
		{"POST", "/api/v1/labs/l1/start"},
		{"GET", "/api/v1/labs/l1/status"},
		{"GET", "/api/v1/users/u1/progress"},
		{"GET", "/api/v1/users/u1/certifications"},
		{"GET", "/api/v1/coverage/u1"},
		{"GET", "/api/v1/cyberpath/recommend?gap=art21_g"},
	}
	for _, e := range expected {
		req := httptest.NewRequest(e.method, e.path, nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code == http.StatusNotFound || rr.Code == http.StatusMethodNotAllowed {
			t.Errorf("route %s %s not registered (status=%d)", e.method, e.path, rr.Code)
		}
	}
}

package api

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/citadel/internal/config"
)

// newFakeSinauth spins up a local OIDC discovery + JWKS server so NewServer
// can construct a real SinauthVerifier without a live sinauth deployment.
func newFakeSinauth(t *testing.T) *httptest.Server {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	var server *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   server.URL,
			"jwks_uri": server.URL + "/.well-known/jwks.json",
		})
	})
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.PublicKey.E)).Bytes())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{
				{"kid": "test-key-1", "kty": "RSA", "alg": "RS256", "n": n, "e": e},
			},
		})
	})
	server = httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func TestNewServer_FailsWithoutReachableSinauthIssuer(t *testing.T) {
	cfg := &config.Config{
		Port:    8099,
		Citadel: config.CitadelConfig{SinauthIssuerURL: ""},
	}
	s, err := NewServer(cfg, nil, nil)
	if err == nil {
		t.Fatal("expected NewServer to fail with an empty/unreachable sinauth issuer URL")
	}
	if s != nil {
		t.Error("expected nil Server on error")
	}
}

func TestNewServer_RegistersRoutes(t *testing.T) {
	fake := newFakeSinauth(t)
	cfg := &config.Config{
		Port:    8099,
		Citadel: config.CitadelConfig{SinauthIssuerURL: fake.URL},
	}
	s, err := NewServer(cfg, nil, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s.Router() == nil {
		t.Fatal("expected non-nil router")
	}

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{"health ok (no db)", http.MethodGet, "/api/v1/health", http.StatusOK},
		{"marshal evaluate invalid body", http.MethodPost, "/api/v1/marshal/evaluate", http.StatusBadRequest},
		{"worm emit invalid body", http.MethodPost, "/api/v1/worm/emit", http.StatusBadRequest},
		{"unknown route", http.MethodGet, "/api/v1/nope", http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rw := httptest.NewRecorder()
			s.Router().ServeHTTP(rw, req)
			if rw.Code != tt.wantStatus {
				t.Errorf("%s %s: expected status %d, got %d: %s", tt.method, tt.path, tt.wantStatus, rw.Code, rw.Body.String())
			}
		})
	}
}

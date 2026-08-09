package handlers

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/opensecstack/opencsirt/internal/auth"
	"github.com/opensecstack/opencsirt/internal/db"
)

func TestParseLimitOffset(t *testing.T) {
	cases := []struct {
		name       string
		query      string
		defLimit   int
		wantLimit  int
		wantOffset int
		wantErr    bool
	}{
		{"defaults", "", 25, 25, 0, false},
		{"custom values", "limit=10&offset=20", 25, 10, 20, false},
		{"limit too low", "limit=0", 25, 0, 0, true},
		{"limit too high", "limit=501", 25, 0, 0, true},
		{"limit not an integer", "limit=abc", 25, 0, 0, true},
		{"offset negative", "offset=-1", 25, 0, 0, true},
		{"offset not an integer", "offset=abc", 25, 0, 0, true},
		{"limit at upper bound", "limit=500", 25, 500, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/?"+tc.query, nil)
			limit, offset, err := parseLimitOffset(req, tc.defLimit)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got limit=%d offset=%d", limit, offset)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if limit != tc.wantLimit || offset != tc.wantOffset {
				t.Fatalf("got limit=%d offset=%d, want limit=%d offset=%d", limit, offset, tc.wantLimit, tc.wantOffset)
			}
		})
	}
}

func TestParseUUIDParam(t *testing.T) {
	t.Run("missing param", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rctx := chi.NewRouteContext()
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		if _, err := parseUUIDParam(req, "id"); err == nil {
			t.Fatal("expected error for missing path parameter")
		}
	})

	t.Run("invalid uuid", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", "not-a-uuid")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		if _, err := parseUUIDParam(req, "id"); err == nil {
			t.Fatal("expected error for invalid uuid")
		}
	})

	t.Run("valid uuid", func(t *testing.T) {
		id := uuid.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", id.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		got, err := parseUUIDParam(req, "id")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != id {
			t.Fatalf("got %v, want %v", got, id)
		}
	})
}

func TestActorAndRole(t *testing.T) {
	t.Run("no claims", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if _, _, err := actorAndRole(req); err == nil {
			t.Fatal("expected error when no claims in context")
		}
	})

	t.Run("claims with invalid sub", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		ctx := auth.ContextWithClaims(req.Context(), &auth.Claims{Sub: "not-a-uuid", Role: auth.RoleAdmin})
		if _, _, err := actorAndRole(req.WithContext(ctx)); err == nil {
			t.Fatal("expected error when sub is not a valid uuid")
		}
	})

	t.Run("valid claims", func(t *testing.T) {
		id := uuid.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		ctx := auth.ContextWithClaims(req.Context(), &auth.Claims{Sub: id.String(), Role: auth.RoleOperator})
		gotID, gotRole, err := actorAndRole(req.WithContext(ctx))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if gotID != id || gotRole != string(auth.RoleOperator) {
			t.Fatalf("got id=%v role=%v, want id=%v role=%v", gotID, gotRole, id, auth.RoleOperator)
		}
	})
}

func TestMapDBError(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode int
	}{
		{"not found", db.ErrNotFound, http.StatusNotFound},
		{"conflict", db.ErrConflict, http.StatusConflict},
		{"other", errors.New("boom"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, msg := mapDBError(tc.err)
			if code != tc.wantCode {
				t.Fatalf("code = %d, want %d", code, tc.wantCode)
			}
			if msg == "" {
				t.Fatal("expected non-empty message")
			}
		})
	}
}

func TestDecodeJSON(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		var dst struct {
			Name string `json:"name"`
		}
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"name":"x"}`))
		if err := decodeJSON(req, &dst, 0); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dst.Name != "x" {
			t.Fatalf("Name = %q, want x", dst.Name)
		}
	})

	t.Run("unknown field rejected", func(t *testing.T) {
		var dst struct {
			Name string `json:"name"`
		}
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"name":"x","extra":"y"}`))
		if err := decodeJSON(req, &dst, 0); err == nil {
			t.Fatal("expected error for unknown field")
		}
	})

	t.Run("body too large is rejected", func(t *testing.T) {
		var dst struct {
			Name string `json:"name"`
		}
		big := `{"name":"` + string(bytes.Repeat([]byte("a"), 100)) + `"}`
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(big))
		if err := decodeJSON(req, &dst, 10); err == nil {
			t.Fatal("expected error when body exceeds maxBytes")
		}
	})
}

func TestWriteJSONAndWriteError(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusCreated, map[string]string{"a": "b"})
	if w.Code != http.StatusCreated {
		t.Fatalf("code = %d, want 201", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`"a":"b"`)) {
		t.Fatalf("body = %s, missing expected field", w.Body.String())
	}

	w2 := httptest.NewRecorder()
	writeError(w2, http.StatusBadRequest, "bad input")
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", w2.Code)
	}
	if !bytes.Contains(w2.Body.Bytes(), []byte(`"error":"bad input"`)) {
		t.Fatalf("body = %s, missing error field", w2.Body.String())
	}
}

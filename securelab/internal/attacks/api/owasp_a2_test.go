// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuildAlgNoneJWT_HasEmptySignatureAndAlgNone(t *testing.T) {
	tok, err := buildAlgNoneJWT(map[string]any{"sub": "attacker"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d: %q", len(parts), tok)
	}
	if parts[2] != "" {
		t.Errorf("expected empty signature segment, got %q", parts[2])
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if header["alg"] != "none" {
		t.Errorf("header.alg = %v, want none", header["alg"])
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload["sub"] != "attacker" {
		t.Errorf("payload.sub = %v, want attacker", payload["sub"])
	}
}

func TestBuildEmptySecretHS256JWT_SignatureVerifiesUnderEmptyKey(t *testing.T) {
	claims := map[string]any{"sub": "attacker"}
	tok, err := buildEmptySecretHS256JWT(claims)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d", len(parts))
	}
	if parts[2] == "" {
		t.Error("expected non-empty signature for HS256 token")
	}

	// Recompute the expected signature independently and confirm it matches.
	signingInput := parts[0] + "." + parts[1]
	wantSig := base64.RawURLEncoding.EncodeToString(hmacSHA256([]byte(""), []byte(signingInput)))
	if parts[2] != wantSig {
		t.Errorf("signature = %q, want %q (HMAC-SHA256 under empty key)", parts[2], wantSig)
	}
}

func TestAuthBypassAttack_Run_DetectsAcceptedInvalidToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/admin" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	a := NewAuthBypassAttack()
	result, err := a.Run(context.Background(), server.URL, map[string]any{
		"endpoints": []string{"/api/profile", "/api/admin"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected Success=true when /api/admin accepts a forged token")
	}
	if len(result.Evidence) == 0 {
		t.Error("expected non-empty evidence")
	}
}

func TestAuthBypassAttack_Run_NoVulnerableEndpoints(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	a := NewAuthBypassAttack()
	result, err := a.Run(context.Background(), server.URL, map[string]any{
		"endpoints": []string{"/api/profile"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("expected Success=false when all endpoints reject forged tokens")
	}
}

func TestAuthBypassAttack_Run_BlocksProductionTarget(t *testing.T) {
	a := NewAuthBypassAttack()
	_, err := a.Run(context.Background(), "https://api-prod.example.com", nil)
	if err == nil {
		t.Fatal("expected error for production target")
	}
}

func TestStringSliceParam(t *testing.T) {
	def := []string{"default"}
	if got := stringSliceParam(map[string]any{}, "k", def); len(got) != 1 || got[0] != "default" {
		t.Errorf("expected default, got %v", got)
	}
	got := stringSliceParam(map[string]any{"k": []string{"a", "b"}}, "k", def)
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("expected [a b], got %v", got)
	}
	got2 := stringSliceParam(map[string]any{"k": []any{"x", 5, "y"}}, "k", def)
	if len(got2) != 2 || got2[0] != "x" || got2[1] != "y" {
		t.Errorf("expected non-string items dropped, got %v", got2)
	}
}

func TestMapParam(t *testing.T) {
	def := map[string]any{"a": 1}
	if got := mapParam(map[string]any{}, "k", def); got["a"] != 1 {
		t.Errorf("expected default map, got %v", got)
	}
	custom := map[string]any{"b": 2}
	if got := mapParam(map[string]any{"k": custom}, "k", def); got["b"] != 2 {
		t.Errorf("expected custom map, got %v", got)
	}
}

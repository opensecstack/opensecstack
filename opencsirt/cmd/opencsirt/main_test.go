package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/opencsirt/internal/incident"
)

// ── effectiveJWTSecrets ─────────────────────────────────────────────

func TestEffectiveJWTSecrets_ConfiguredSecretWins(t *testing.T) {
	got := effectiveJWTSecrets([]byte("real-secret"), false)
	if len(got) != 1 || !bytes.Equal(got[0], []byte("real-secret")) {
		t.Fatalf("got %v, want [[real-secret]]", got)
	}
}

func TestEffectiveJWTSecrets_ConfiguredSecretWinsEvenInDevMode(t *testing.T) {
	got := effectiveJWTSecrets([]byte("real-secret"), true)
	if len(got) != 1 || !bytes.Equal(got[0], []byte("real-secret")) {
		t.Fatalf("dev mode must not override an explicitly configured secret; got %v", got)
	}
}

func TestEffectiveJWTSecrets_EmptyAndDevModeFallsBackToDevSecret(t *testing.T) {
	got := effectiveJWTSecrets(nil, true)
	want := []byte("dev-secret-do-not-use-in-prod-aaaaaaaaaaaa")
	if len(got) != 1 || !bytes.Equal(got[0], want) {
		t.Fatalf("got %v, want [[%s]]", got, want)
	}
}

func TestEffectiveJWTSecrets_EmptyAndNotDevModePassesThroughEmpty(t *testing.T) {
	// Outside dev mode, an unset secret must NOT be silently upgraded to a
	// working secret — that would defeat the auth boundary in production.
	// The empty value is passed through so auth.NewWithSinauth can reject it.
	got := effectiveJWTSecrets(nil, false)
	if len(got) != 1 || len(got[0]) != 0 {
		t.Fatalf("got %v, want [[]] (empty secret passed through, not upgraded)", got)
	}
}

// ── citadelHMACSecretsMissing ───────────────────────────────────────

func TestCitadelHMACSecretsMissing_URLSetNoSecrets(t *testing.T) {
	if !citadelHMACSecretsMissing("https://citadel.example", nil) {
		t.Fatal("expected true: CITADEL URL configured but no HMAC secrets")
	}
}

func TestCitadelHMACSecretsMissing_URLSetWithSecrets(t *testing.T) {
	if citadelHMACSecretsMissing("https://citadel.example", [][]byte{[]byte("s3cr3t")}) {
		t.Fatal("expected false: HMAC secrets are configured")
	}
}

func TestCitadelHMACSecretsMissing_URLNotSet(t *testing.T) {
	// CITADEL disabled entirely — missing secrets are not an error in
	// that configuration.
	if citadelHMACSecretsMissing("", nil) {
		t.Fatal("expected false: CITADEL not configured, so missing secrets is not fatal")
	}
}

func TestCitadelHMACSecretsMissing_URLNotSetButSecretsPresent(t *testing.T) {
	if citadelHMACSecretsMissing("", [][]byte{[]byte("s3cr3t")}) {
		t.Fatal("expected false: CITADEL not configured regardless of stray secrets")
	}
}

// ── vertGuardIncidentInput ──────────────────────────────────────────

func TestVertGuardIncidentInput_ShapesFixedFields(t *testing.T) {
	got := vertGuardIncidentInput("adv-123", map[string]any{"cve": "CVE-2026-0001"})

	if got.Source != "peer_csirt" {
		t.Errorf("Source = %q, want peer_csirt", got.Source)
	}
	if got.Severity != "medium" {
		t.Errorf("Severity = %q, want medium", got.Severity)
	}
	if got.Title != "VertGuard advisory: adv-123" {
		t.Errorf("Title = %q, want %q", got.Title, "VertGuard advisory: adv-123")
	}
	if got.Description != "Cross-CSIRT AI-threat advisory" {
		t.Errorf("Description = %q", got.Description)
	}
	if got.Metadata["vertguard_advisory_id"] != "adv-123" {
		t.Errorf("Metadata[vertguard_advisory_id] = %v, want adv-123", got.Metadata["vertguard_advisory_id"])
	}
	payload, ok := got.Metadata["payload"].(map[string]any)
	if !ok || payload["cve"] != "CVE-2026-0001" {
		t.Errorf("Metadata[payload] = %v, want passthrough of the input payload", got.Metadata["payload"])
	}
}

func TestVertGuardIncidentInput_ValidatesAgainstIncidentPackageRules(t *testing.T) {
	// The synthesized input must actually pass incident.Service.Create's
	// own validation gate (valid source/severity/non-empty title) —
	// otherwise every VertGuard-sourced advisory would silently fail to
	// become an incident. Exercised here without a live DB: New(nil,...)
	// only panics past validation.
	s := incident.New(nil, nil, nil, zerolog.Nop())
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected a nil-store panic AFTER validation passed, got none — input failed validation")
		}
	}()
	_, _ = s.Create(context.Background(), vertGuardIncidentInput("adv-1", nil), uuid.Nil, "vertguard_subscriber")
}

func TestVertGuardIncidentInput_NilPayloadIsPreserved(t *testing.T) {
	got := vertGuardIncidentInput("adv-1", nil)
	rawPayload, ok := got.Metadata["payload"]
	if !ok {
		t.Fatal("expected Metadata to contain a payload key even when input payload is nil")
	}
	// A nil map[string]any stored in a map[string]any value is a *typed*
	// nil boxed in an interface, so it does not compare equal to the
	// untyped nil literal — assert via the concrete type instead.
	payload, ok := rawPayload.(map[string]any)
	if !ok {
		t.Fatalf("payload has unexpected type %T", rawPayload)
	}
	if len(payload) != 0 {
		t.Errorf("payload = %v, want empty/nil passthrough", payload)
	}
}

package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestSignAndVerify_RoundTrip(t *testing.T) {
	secret := "topsecret"
	ts := "1700000000"
	body := []byte(`{"hello":"world"}`)

	sig := signPayload(secret, ts, body)
	if !VerifySignature(secret, ts, sig, body) {
		t.Fatal("signature did not round-trip")
	}
}

func TestVerify_RejectsBadSecret(t *testing.T) {
	ts := "1700000000"
	body := []byte(`{"x":1}`)
	good := signPayload("right", ts, body)
	if VerifySignature("wrong", ts, good, body) {
		t.Error("verify accepted wrong secret")
	}
}

func TestVerify_RejectsTamperedBody(t *testing.T) {
	ts := "1700000000"
	sig := signPayload("s", ts, []byte(`{"x":1}`))
	if VerifySignature("s", ts, sig, []byte(`{"x":2}`)) {
		t.Error("verify accepted tampered body")
	}
}

func TestSign_DeterministicAcrossCalls(t *testing.T) {
	secret := "s"
	body := []byte(`{"a":1}`)
	ts := time.Now().UTC().Format(time.RFC3339)
	a := signPayload(secret, ts, body)
	b := signPayload(secret, ts, body)
	if a != b {
		t.Errorf("sign not deterministic: %s vs %s", a, b)
	}
}

// signatureWireFormat matches the ecosystem-wide webhook signature contract
// documented in docs/webhook-spec.md and docs/security.md: "sha256=" followed
// by 64 lowercase hex characters (SHA-256 digest). Every real consumer of
// X-ThreatFlow-Signature (IRFlow's internal/webhook.Verifier and VertGuard's
// verifyThreatFlowSig) expects exactly this format. The distinct
// "hmac-sha256=" prefix belongs only to the CITADEL connector protocol
// (X-CITADEL-SIG) and must never leak into the webhook signer.
var signatureWireFormat = regexp.MustCompile(`^sha256=[0-9a-f]{64}$`)

// TestSignPayload_MatchesEcosystemWireFormat pins the exact header format
// produced by signPayload. This is a regression guard for the 2026-07-26
// audit finding: signPayload previously emitted "hmac-sha256=<hex>" (copied
// from the unrelated CITADEL connector scheme in internal/citadel/client.go),
// which every real consumer rejected because they verify against
// "sha256=<hex>" per this platform's own documented spec. A bare round-trip
// test (sign then verify with the same function) cannot catch this class of
// bug because both sides agree with each other while disagreeing with every
// external consumer — this test instead pins the wire format itself.
func TestSignPayload_MatchesEcosystemWireFormat(t *testing.T) {
	sig := signPayload("topsecret", "1700000000", []byte(`{"hello":"world"}`))
	if !signatureWireFormat.MatchString(sig) {
		t.Fatalf("signPayload produced %q, want format sha256=<64 hex chars> "+
			"(the ecosystem webhook contract every real consumer expects)", sig)
	}
	if strings.HasPrefix(sig, "hmac-sha256=") {
		t.Fatalf("signPayload regressed to the CITADEL-connector prefix "+
			"'hmac-sha256=' instead of the webhook contract 'sha256=': %q", sig)
	}
}

// verifyLikeRealConsumer independently reimplements the verification side of
// the ecosystem webhook contract exactly as IRFlow (internal/webhook.Verifier)
// and VertGuard (webhook_threatflow.verifyThreatFlowSig) do it, deliberately
// NOT by calling this package's own VerifySignature/signPayload for the
// "expected" side. Cross-platform source imports are disallowed in this
// monorepo (platforms integrate only through the SDK — see root CLAUDE.md),
// so this stand-in plays the role of "a real downstream consumer" for an
// integration-shaped test without violating that boundary.
func verifyLikeRealConsumer(secret, ts string, body []byte, sig string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(sig))
}

// TestSignPayload_AcceptedByRealConsumerVerifier constructs a real signed
// payload with this package's actual signPayload function and asserts a
// consumer-shaped verifier (mirroring IRFlow's and VertGuard's real
// verification code) accepts it. Before the 2026-07-26 fix, signPayload
// emitted "hmac-sha256=" and this test would fail with exactly the same
// symptom real deliveries hit in production: a 401 invalid_signature.
func TestSignPayload_AcceptedByRealConsumerVerifier(t *testing.T) {
	secret := "shared-webhook-secret"
	ts := "1753500000"
	body := []byte(`{"id":"evt-1","type":"ioc.created","payload":{"value":"198.51.100.42"}}`)

	sig := signPayload(secret, ts, body)

	if !verifyLikeRealConsumer(secret, ts, body, sig) {
		t.Fatalf("signature %q produced by signPayload was rejected by a "+
			"real-consumer-shaped verifier — this is the exact failure mode "+
			"that made every ThreatFlow->VertGuard/IRFlow webhook delivery "+
			"return 401 invalid_signature in production", sig)
	}

	// Tampering must still be rejected — this proves the test isn't
	// vacuously true (e.g. a verifier that always returns true).
	if verifyLikeRealConsumer(secret, ts, []byte(`{"tampered":true}`), sig) {
		t.Fatal("consumer-shaped verifier accepted a tampered body")
	}
	if verifyLikeRealConsumer("wrong-secret", ts, body, sig) {
		t.Fatal("consumer-shaped verifier accepted a mismatched secret")
	}
}

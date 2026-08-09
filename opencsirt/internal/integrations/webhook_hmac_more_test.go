package integrations

import (
	"testing"
	"time"
)

func TestVerifyHMAC_NilSecret(t *testing.T) {
	ts := time.Now().UTC().Format(time.RFC3339)
	if err := VerifyHMAC(nil, ts, "aa", []byte("x")); err == nil {
		t.Fatal("expected error when secret is nil")
	}
}

func TestVerifyHMAC_InvalidTimestampFormat(t *testing.T) {
	secret := []byte("s")
	if err := VerifyHMAC(secret, "not-a-timestamp", "aa", []byte("x")); err == nil {
		t.Fatal("expected error for unparsable timestamp")
	}
}

func TestVerifyHMAC_FutureTimestampRejected(t *testing.T) {
	secret := []byte("test-secret")
	body := []byte(`{}`)
	ts := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)
	sig := sign(t, secret, ts, body)
	if err := VerifyHMAC(secret, ts, sig, body); err == nil {
		t.Fatal("expected reject for a timestamp in the future beyond the replay window")
	}
}

func TestVerifyHMAC_RejectsReplayedRequest(t *testing.T) {
	secret := []byte("replay-secret")
	body := []byte(`{"a":1}`)
	ts := time.Now().UTC().Format(time.RFC3339)
	sig := sign(t, secret, ts, body)

	if err := VerifyHMAC(secret, ts, sig, body); err != nil {
		t.Fatalf("first request should be accepted: %v", err)
	}
	if err := VerifyHMAC(secret, ts, sig, body); err == nil {
		t.Fatal("second identical request must be rejected as a replay")
	}
}

func TestDeriveNonce_DeterministicAndDistinct(t *testing.T) {
	n1 := deriveNonce("ts1", []byte("body"))
	n2 := deriveNonce("ts1", []byte("body"))
	if n1 != n2 {
		t.Fatal("deriveNonce must be deterministic for identical inputs")
	}
	n3 := deriveNonce("ts2", []byte("body"))
	if n1 == n3 {
		t.Fatal("deriveNonce must differ when the timestamp changes")
	}
	n4 := deriveNonce("ts1", []byte("other"))
	if n1 == n4 {
		t.Fatal("deriveNonce must differ when the body changes")
	}
}

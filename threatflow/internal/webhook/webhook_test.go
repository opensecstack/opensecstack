package webhook

import (
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

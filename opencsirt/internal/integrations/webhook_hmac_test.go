package integrations

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func sign(t *testing.T, secret []byte, ts string, body []byte) string {
	t.Helper()
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(ts))
	m.Write([]byte("."))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

func TestVerifyHMACAcceptsValid(t *testing.T) {
	secret := []byte("test-secret")
	body := []byte(`{"hello":"world"}`)
	ts := time.Now().UTC().Format(time.RFC3339)
	sig := sign(t, secret, ts, body)
	if err := VerifyHMAC(secret, ts, sig, body); err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
}

func TestVerifyHMACRejectsTampered(t *testing.T) {
	secret := []byte("test-secret")
	body := []byte(`{"hello":"world"}`)
	ts := time.Now().UTC().Format(time.RFC3339)
	sig := sign(t, secret, ts, []byte(`{"hello":"evil"}`))
	if err := VerifyHMAC(secret, ts, sig, body); err == nil {
		t.Fatal("expected reject for tampered body")
	}
}

func TestVerifyHMACRejectsOldTimestamp(t *testing.T) {
	secret := []byte("test-secret")
	body := []byte(`{}`)
	ts := time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
	sig := sign(t, secret, ts, body)
	if err := VerifyHMAC(secret, ts, sig, body); err == nil {
		t.Fatal("expected reject for replay-window violation")
	}
}

func TestVerifyHMACRejectsBadHex(t *testing.T) {
	if err := VerifyHMAC([]byte("k"), time.Now().UTC().Format(time.RFC3339), "zzzz", []byte("x")); err == nil {
		t.Fatal("expected reject for bad hex")
	}
}

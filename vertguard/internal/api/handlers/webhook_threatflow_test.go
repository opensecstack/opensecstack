package handlers

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// signBody independently reimplements ThreatFlow's real outbound signing
// algorithm — see threatflow/internal/webhook/webhook.go's signPayload,
// which computes HMAC-SHA256 over ts + "." + body and prefixes the hex
// digest with "sha256=" (the ecosystem-wide webhook contract documented in
// threatflow/docs/webhook-spec.md). It is deliberately NOT implemented by
// calling verifyThreatFlowSig's own expected-value computation, so that a
// prefix/algorithm mismatch between the two sides shows up as a test
// failure instead of both sides silently agreeing with each other.
//
// Cross-platform Go source imports are disallowed in this monorepo
// (platforms integrate only through the SDK, per root CLAUDE.md), which is
// why this is a hand-mirrored reimplementation rather than a direct call
// into threatflow's package.
func signBody(secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// signBodyWithPrefix is like signBody but lets a test use an arbitrary
// signature prefix, so we can assert the receiver correctly rejects a
// mismatched scheme (e.g. the pre-fix ThreatFlow bug that emitted
// "hmac-sha256=" while this receiver expected "sha256=").
func signBodyWithPrefix(prefix, secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	return prefix + hex.EncodeToString(mac.Sum(nil))
}

func newRecv(t *testing.T, secret string, now time.Time) *ThreatflowReceiver {
	t.Helper()
	r := NewThreatflowReceiver(secret, nil, zerolog.Nop())
	r.Now = func() time.Time { return now }
	return r
}

func TestThreatflowReplayWindowRejectsStale(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	secret := "shh"
	r := newRecv(t, secret, now)
	body := []byte(`{"id":"x","event_type":"ioc.new"}`)
	stale := strconv.FormatInt(now.Add(-10*time.Minute).Unix(), 10)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/threatflow", bytes.NewReader(body))
	req.Header.Set("X-ThreatFlow-Timestamp", stale)
	req.Header.Set("X-ThreatFlow-Signature", signBody(secret, stale, body))
	rr := httptest.NewRecorder()
	r.Receive(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "stale_timestamp") {
		t.Errorf("missing stale_timestamp code: %s", rr.Body.String())
	}
}

func TestThreatflowReplayWindowAccepts(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	secret := "shh"
	r := newRecv(t, secret, now)
	body := []byte(`{"id":"x","event_type":"ioc.new"}`)
	ts := strconv.FormatInt(now.Add(-30*time.Second).Unix(), 10)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/threatflow", bytes.NewReader(body))
	req.Header.Set("X-ThreatFlow-Timestamp", ts)
	req.Header.Set("X-ThreatFlow-Signature", signBody(secret, ts, body))
	rr := httptest.NewRecorder()
	r.Receive(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestThreatflowReplayWindowFutureTimestamp(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	secret := "shh"
	r := newRecv(t, secret, now)
	body := []byte(`{"id":"x"}`)
	ts := strconv.FormatInt(now.Add(10*time.Minute).Unix(), 10)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/threatflow", bytes.NewReader(body))
	req.Header.Set("X-ThreatFlow-Timestamp", ts)
	req.Header.Set("X-ThreatFlow-Signature", signBody(secret, ts, body))
	rr := httptest.NewRecorder()
	r.Receive(rr, req)
	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "stale_timestamp") {
		t.Fatalf("want 401 stale_timestamp got %d %s", rr.Code, rr.Body.String())
	}
}

// TestThreatflowAcceptsRealThreatFlowSignatureFormat asserts the receiver
// accepts a signature built exactly the way ThreatFlow's real sender builds
// it: "sha256=" + hex(HMAC-SHA256(secret, ts + "." + body)). This is the
// integration-shaped regression test for the 2026-07-26 audit finding —
// ThreatFlow's signPayload used to emit "hmac-sha256=" (copied from the
// unrelated CITADEL connector scheme), which made verifyThreatFlowSig reject
// every real, correctly-signed delivery with 401 invalid_signature. Every
// production webhook with a configured secret failed this exact path.
func TestThreatflowAcceptsRealThreatFlowSignatureFormat(t *testing.T) {
	now := time.Unix(1_753_500_000, 0)
	secret := "prod-shared-secret"
	r := newRecv(t, secret, now)
	body := []byte(`{"id":"evt-1","event_type":"ioc.created","source":"alienvault-otx"}`)
	ts := strconv.FormatInt(now.Add(-1*time.Minute).Unix(), 10)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/threatflow", bytes.NewReader(body))
	req.Header.Set("X-ThreatFlow-Timestamp", ts)
	req.Header.Set("X-ThreatFlow-Signature", signBody(secret, ts, body))
	rr := httptest.NewRecorder()
	r.Receive(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("real ThreatFlow-format signature was rejected: want 200 got %d body=%s",
			rr.Code, rr.Body.String())
	}
}

// TestThreatflowRejectsCitadelConnectorSignaturePrefix locks in that the
// pre-fix bug format ("hmac-sha256=", the CITADEL connector protocol's
// prefix — see threatflow/internal/citadel/client.go) is correctly rejected.
// If ThreatFlow's sender ever regresses back to that prefix, this test turns
// the resulting silent production 401 into a caught CI failure instead.
func TestThreatflowRejectsCitadelConnectorSignaturePrefix(t *testing.T) {
	now := time.Unix(1_753_500_000, 0)
	secret := "prod-shared-secret"
	r := newRecv(t, secret, now)
	body := []byte(`{"id":"evt-1","event_type":"ioc.created"}`)
	ts := strconv.FormatInt(now.Add(-1*time.Minute).Unix(), 10)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/threatflow", bytes.NewReader(body))
	req.Header.Set("X-ThreatFlow-Timestamp", ts)
	req.Header.Set("X-ThreatFlow-Signature", signBodyWithPrefix("hmac-sha256=", secret, ts, body))
	rr := httptest.NewRecorder()
	r.Receive(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for mismatched signature prefix, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "invalid_signature") {
		t.Errorf("missing invalid_signature code: %s", rr.Body.String())
	}
}

func TestThreatflowOversizeBody(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	r := newRecv(t, "", now) // empty secret skips sig path; body cap still applies
	big := bytes.Repeat([]byte("a"), maxThreatflowBodyBytes+512)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/threatflow", bytes.NewReader(big))
	rr := httptest.NewRecorder()
	r.Receive(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413 got %d body=%s", rr.Code, rr.Body.String())
	}
}

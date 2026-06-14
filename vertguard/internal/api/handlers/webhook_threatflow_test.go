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

func signBody(secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
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

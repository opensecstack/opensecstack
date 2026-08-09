package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakePinger implements Pinger for handler tests.
type fakePinger struct {
	err error
}

func (f *fakePinger) Ping(_ context.Context) error { return f.err }

func TestLive(t *testing.T) {
	h := Live()
	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rr.Code)
	}
	var resp liveResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "alive" {
		t.Fatalf("status field = %q, want alive", resp.Status)
	}
}

func TestReadyHandler_NilPinger(t *testing.T) {
	Ready.Store(true)
	h := ReadyHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rr.Code)
	}
	var resp readyResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "ready" || resp.DB != "no_pinger" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestReadyHandler_PingerOK(t *testing.T) {
	Ready.Store(true)
	h := ReadyHandler(&fakePinger{})
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rr.Code)
	}
	var resp readyResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Status != "ready" || resp.DB != "ok" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestReadyHandler_PingerFails(t *testing.T) {
	Ready.Store(true)
	h := ReadyHandler(&fakePinger{err: errors.New("db down")})
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", rr.Code)
	}
	var resp readyResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Status != "not_ready" || resp.DB != "fail" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestReadyHandler_DrainingSkipsDBCheck(t *testing.T) {
	Ready.Store(false)
	defer Ready.Store(true) // restore for other tests in this package
	// Pinger would succeed, but the drain flag must still win.
	h := ReadyHandler(&fakePinger{})
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503 while draining", rr.Code)
	}
	var resp readyResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Status != "draining" || resp.DB != "skipped" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestHealth_NilPingerDegraded(t *testing.T) {
	h := Health(nil)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200 (nil pinger does not 503)", rr.Code)
	}
	var resp healthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "degraded" || resp.DB != "no_pinger" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestHealth_PingerOK(t *testing.T) {
	h := Health(&fakePinger{})
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rr.Code)
	}
	var resp healthResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Status != "ok" || resp.DB != "ok" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestHealth_PingerFailsReturns503AndDegraded(t *testing.T) {
	h := Health(&fakePinger{err: errors.New("boom")})
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", rr.Code)
	}
	var resp healthResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Status != "degraded" || resp.DB != "fail" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestMediaModuleStatus_Unset(t *testing.T) {
	// Reset MediaBinaryPath to empty for this test.
	MediaBinaryPath.Store("")
	if got := mediaModuleStatus(); got != "inactive (binary_path unset)" {
		t.Fatalf("mediaModuleStatus() = %q", got)
	}
}

func TestMediaModuleStatus_MissingBinary(t *testing.T) {
	MediaBinaryPath.Store("/path/does/not/exist/binary")
	defer MediaBinaryPath.Store("")
	got := mediaModuleStatus()
	if got != "inactive (binary missing at /path/does/not/exist/binary)" {
		t.Fatalf("mediaModuleStatus() = %q", got)
	}
}

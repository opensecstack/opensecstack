package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/vertguard/internal/ml"
)

type fakeMLInfoProvider struct {
	info *ml.ModelInfo
	err  error
}

func (f *fakeMLInfoProvider) ModelInfo(_ context.Context) (*ml.ModelInfo, error) {
	return f.info, f.err
}

func TestNewAdminMLHandler(t *testing.T) {
	f := &fakeMLInfoProvider{}
	h := NewAdminMLHandler(f)
	if h.Client != f {
		t.Fatal("NewAdminMLHandler did not wire the client")
	}
}

func TestAdminMLHandler_Info_NilClient(t *testing.T) {
	h := &AdminMLHandler{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/ml/info", nil)
	rw := httptest.NewRecorder()
	h.Info(rw, req)
	if rw.Code != http.StatusNotImplemented {
		t.Fatalf("status=%d, want 501", rw.Code)
	}
	var resp map[string]string
	_ = json.Unmarshal(rw.Body.Bytes(), &resp)
	if resp["code"] != "ml_disabled" {
		t.Fatalf("code=%q, want ml_disabled", resp["code"])
	}
}

func TestAdminMLHandler_Info_ClientError(t *testing.T) {
	h := NewAdminMLHandler(&fakeMLInfoProvider{err: errors.New("breaker open")})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/ml/info", nil)
	rw := httptest.NewRecorder()
	h.Info(rw, req)
	if rw.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", rw.Code)
	}
	var resp map[string]string
	_ = json.Unmarshal(rw.Body.Bytes(), &resp)
	if resp["code"] != "ml_unavailable" {
		t.Fatalf("code=%q, want ml_unavailable", resp["code"])
	}
}

func TestAdminMLHandler_Info_Success(t *testing.T) {
	info := &ml.ModelInfo{Name: "distilbert-prompt-v1", Version: "1.0.0", Backend: "onnx-cpu"}
	h := NewAdminMLHandler(&fakeMLInfoProvider{info: info})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/ml/info", nil)
	rw := httptest.NewRecorder()
	h.Info(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rw.Code)
	}
	var got ml.ModelInfo
	if err := json.Unmarshal(rw.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Name != info.Name || got.Backend != info.Backend {
		t.Fatalf("unexpected response: %+v", got)
	}
}

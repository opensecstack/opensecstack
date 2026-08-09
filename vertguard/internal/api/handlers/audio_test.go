package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/ml"
)

type fakeAudioML struct {
	res *ml.Result
	err error
}

func (f *fakeAudioML) ScoreAudio(_ context.Context, _ string, _, _ []byte, _ float32, _ bool, _, _ string) (*ml.Result, error) {
	return f.res, f.err
}

func newAudioReq(t *testing.T, body any) *http.Request {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/audio/score", bytes.NewReader(buf))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestNewAudioHandler(t *testing.T) {
	f := &fakeAudioML{}
	h := NewAudioHandler(f, zerolog.Nop())
	if h.ML != f {
		t.Fatal("NewAudioHandler did not wire the ML enricher")
	}
}

func TestAudioHandler_WithTenant_Chains(t *testing.T) {
	h := NewAudioHandler(&fakeAudioML{}, zerolog.Nop())
	got := h.WithTenant("tenant-9")
	if got != h || h.Tenant != "tenant-9" {
		t.Fatalf("WithTenant did not chain/set tenant: %+v", h)
	}
}

func TestAudioHandler_Score_NilML(t *testing.T) {
	h := &AudioHandler{}
	w := httptest.NewRecorder()
	h.Score(w, newAudioReq(t, map[string]any{"session_id": "s1"}))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", w.Code)
	}
}

func TestAudioHandler_Score_Validation(t *testing.T) {
	h := NewAudioHandler(&fakeAudioML{res: &ml.Result{}}, zerolog.Nop())
	cases := []struct {
		name string
		body map[string]any
	}{
		{"missing session_id", map[string]any{"mfcc_hash": "aa", "spectral_hash": "bb"}},
		{"missing mfcc_hash", map[string]any{"session_id": "s1", "spectral_hash": "bb"}},
		{"missing spectral_hash", map[string]any{"session_id": "s1", "mfcc_hash": "aa"}},
		{"bad mfcc_hash hex", map[string]any{"session_id": "s1", "mfcc_hash": "zz", "spectral_hash": "aa"}},
		{"bad spectral_hash hex", map[string]any{"session_id": "s1", "mfcc_hash": "aa", "spectral_hash": "zz"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.Score(w, newAudioReq(t, c.body))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d, want 400; body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestAudioHandler_Score_MalformedJSON(t *testing.T) {
	h := NewAudioHandler(&fakeAudioML{res: &ml.Result{}}, zerolog.Nop())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/audio/score", bytes.NewReader([]byte("{bad")))
	h.Score(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", w.Code)
	}
}

func TestAudioHandler_Score_MLError(t *testing.T) {
	h := NewAudioHandler(&fakeAudioML{err: errors.New("breaker open")}, zerolog.Nop())
	w := httptest.NewRecorder()
	h.Score(w, newAudioReq(t, map[string]any{
		"session_id": "s1", "mfcc_hash": "aabb", "spectral_hash": "ccdd",
	}))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", w.Code)
	}
}

func TestAudioHandler_Score_Success_VoiceCloneRiskFlag(t *testing.T) {
	cases := []struct {
		name       string
		confidence float64
		wantRisk   bool
	}{
		{"below threshold", 0.40, false},
		{"at threshold", 0.55, true},
		{"above threshold", 0.90, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := NewAudioHandler(&fakeAudioML{res: &ml.Result{
				Verdict: "SUSPICIOUS", Confidence: c.confidence, ModelVersion: "audio-v2",
			}}, zerolog.Nop())
			w := httptest.NewRecorder()
			h.Score(w, newAudioReq(t, map[string]any{
				"session_id": "s1", "mfcc_hash": "aabb", "spectral_hash": "ccdd", "voice_detected": true,
			}))
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d, want 200; body=%s", w.Code, w.Body.String())
			}
			var resp audioScoreResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if resp.VoiceCloneRisk != c.wantRisk {
				t.Fatalf("VoiceCloneRisk = %v, want %v (confidence=%v)", resp.VoiceCloneRisk, c.wantRisk, c.confidence)
			}
			if resp.ModelVersion != "audio-v2" {
				t.Fatalf("ModelVersion = %q, want audio-v2", resp.ModelVersion)
			}
			if resp.ScanID == "" {
				t.Fatal("expected non-empty ScanID")
			}
		})
	}
}

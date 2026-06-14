package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/opensecstack/vertguard/internal/citadel"
)

// fakeWORM counts EmitAsync calls so tests can assert detection
// emission without spinning up the real CITADEL client.
type fakeWORM struct {
	count atomic.Int32
	last  citadel.Evidence
}

func (f *fakeWORM) EmitAsync(_ context.Context, ev citadel.Evidence) bool {
	f.count.Add(1)
	f.last = ev
	return true
}

func TestMapATLASClampsConfidence(t *testing.T) {
	h := NewThreatFeedHandler()
	// Pathological input: repeat tokens that should heavily overlap with a
	// technique name to push raw overlap toward and beyond 1.0.
	tokens := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		tokens = append(tokens, "prompt", "injection", "jailbreak", "system")
	}
	body, _ := json.Marshal(map[string]string{
		"observed_behaviour": strings.Join(tokens, " "),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/threatfeed/atlas", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.MapATLAS(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Matches []struct {
			Confidence float64 `json:"confidence"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	for i, m := range resp.Matches {
		if m.Confidence < 0 || m.Confidence > 1 {
			t.Errorf("match[%d] confidence=%v out of [0,1]", i, m.Confidence)
		}
	}
}

func TestMapATLASRejectsOversizeInput(t *testing.T) {
	h := NewThreatFeedHandler()
	big := strings.Repeat("a", maxObservedBehaviourBytes+1)
	body, _ := json.Marshal(map[string]string{"observed_behaviour": big})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/threatfeed/atlas", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.MapATLAS(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413 got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "input_too_large") {
		t.Errorf("missing input_too_large code: %s", rr.Body.String())
	}
}

func TestListIOCsPagination(t *testing.T) {
	h := NewThreatFeedHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/threatfeed/iocs?limit=2", nil)
	rr := httptest.NewRecorder()
	h.ListIOCs(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	var resp struct {
		IOCs       []map[string]any `json:"iocs"`
		Total      int              `json:"total"`
		NextCursor string           `json:"next_cursor"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.IOCs) > 2 {
		t.Errorf("limit not enforced: got %d items", len(resp.IOCs))
	}
	if resp.Total > 2 && resp.NextCursor == "" {
		t.Errorf("expected next_cursor when total(%d)>limit(2)", resp.Total)
	}
}

func TestListIOCsCursorAndCitadelEmit(t *testing.T) {
	w := &fakeWORM{}
	h := NewThreatFeedHandler()
	h.Citadel = w
	req := httptest.NewRequest(http.MethodGet, "/api/v1/threatfeed/iocs?limit=1&cursor=0", nil)
	rr := httptest.NewRecorder()
	h.ListIOCs(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	if w.count.Load() == 0 {
		t.Errorf("expected CITADEL emission on non-empty result")
	}
	if w.last.EventType != "vertguard.detection.threatfeed_query" {
		t.Errorf("unexpected event type: %s", w.last.EventType)
	}
}

func TestListIOCsInvalidLimit(t *testing.T) {
	h := NewThreatFeedHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/threatfeed/iocs?limit=-5", nil)
	rr := httptest.NewRecorder()
	h.ListIOCs(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 got %d", rr.Code)
	}
}

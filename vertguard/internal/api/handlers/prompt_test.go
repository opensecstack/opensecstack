package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/prompt"
)

// fakeScanner is a unit-test PromptScanner that returns a canned
// result. Tests parameterise both the result and the JSON-marshallable
// shape of `Matches` (for the warn-log path test).
type fakeScanner struct {
	res *prompt.ScanResult
	err error
}

func (f *fakeScanner) ScanWithML(_ context.Context, _, _ string, _ prompt.MLEnricher) (*prompt.ScanResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.res, nil
}

func cleanResult() *prompt.ScanResult {
	return &prompt.ScanResult{
		ScanID:         "scan_test123",
		Classification: prompt.ClassificationClean,
		Confidence:     0,
		Matches:        []prompt.Match{},
		InputHash:      "sha256:abc",
		InputLength:    5,
		DurationMS:     0.5,
	}
}

func newReq(t *testing.T, body any) *http.Request {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal req body: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/prompt/scan", bytes.NewReader(buf))
	r.Header.Set("Content-Type", "application/json")
	return r
}

// TestScan_StoreNil_Succeeds covers the Store=nil path: the handler
// must skip persistence cleanly and still return 200.
func TestScan_StoreNil_Succeeds(t *testing.T) {
	h := &PromptHandler{
		Scanner: &fakeScanner{res: cleanResult()},
		// Store deliberately nil.
	}
	w := httptest.NewRecorder()
	h.Scan(w, newReq(t, map[string]string{"input": "hello", "context": "user_chat_input"}))

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var got prompt.ScanResult
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Classification != prompt.ClassificationClean {
		t.Errorf("want CLEAN, got %s", got.Classification)
	}
}

// TestScan_CitadelNil_Succeeds covers the Citadel=nil path: the
// handler must skip the WORM emit cleanly and still return 200.
func TestScan_CitadelNil_Succeeds(t *testing.T) {
	h := &PromptHandler{
		Scanner: &fakeScanner{res: cleanResult()},
		// Citadel deliberately nil.
	}
	w := httptest.NewRecorder()
	h.Scan(w, newReq(t, map[string]string{"input": "hello"}))

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
}

// TestScan_UnknownContext_Returns400 verifies the handler rejects
// unknown context tags rather than silently defaulting them.
func TestScan_UnknownContext_Returns400(t *testing.T) {
	h := &PromptHandler{
		Scanner: &fakeScanner{res: cleanResult()},
	}
	w := httptest.NewRecorder()
	h.Scan(w, newReq(t, map[string]string{
		"input":   "hello",
		"context": "totally_made_up_context",
	}))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if resp["code"] != "bad_context" {
		t.Errorf("want code=bad_context, got %q", resp["code"])
	}
}

// TestScan_KnownContexts_Accepted exercises every value in the closed
// set so a future refactor that drops one trips a test.
func TestScan_KnownContexts_Accepted(t *testing.T) {
	h := &PromptHandler{Scanner: &fakeScanner{res: cleanResult()}}
	for ctxTag := range prompt.ValidContexts {
		ctxTag := ctxTag
		t.Run(ctxTag, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.Scan(w, newReq(t, map[string]string{
				"input":   "hello",
				"context": ctxTag,
			}))
			if w.Code != http.StatusOK {
				t.Fatalf("context %q: want 200, got %d", ctxTag, w.Code)
			}
		})
	}
}

// TestScan_EmptyInput_Returns400 confirms the existing input_empty
// guard still fires.
func TestScan_EmptyInput_Returns400(t *testing.T) {
	h := &PromptHandler{Scanner: &fakeScanner{res: cleanResult()}}
	w := httptest.NewRecorder()
	h.Scan(w, newReq(t, map[string]string{"input": ""}))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["code"] != "input_empty" {
		t.Errorf("want code=input_empty, got %q", resp["code"])
	}
}

// TestScan_MalformedJSON_Returns400 documents the malformed-body path.
func TestScan_MalformedJSON_Returns400(t *testing.T) {
	h := &PromptHandler{Scanner: &fakeScanner{res: cleanResult()}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/prompt/scan",
		bytes.NewReader([]byte("{not json")))
	h.Scan(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

// TestScan_DefaultContext_AppliedWhenEmpty asserts that an empty
// context string falls back to user_chat_input (not rejected as
// bad_context).
func TestScan_DefaultContext_AppliedWhenEmpty(t *testing.T) {
	h := &PromptHandler{Scanner: &fakeScanner{res: cleanResult()}}
	w := httptest.NewRecorder()
	h.Scan(w, newReq(t, map[string]string{"input": "hello"}))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 when context omitted, got %d body=%s", w.Code, w.Body.String())
	}
}

// captureLogger returns a zerolog.Logger that writes to the supplied
// buffer at the warn level — used to assert the marshal-failure log
// fires without standing up a real persistence layer.
func captureLogger(buf *bytes.Buffer) *zerolog.Logger {
	l := zerolog.New(buf).Level(zerolog.WarnLevel)
	return &l
}

// TestScan_LoggerNil_NoMarshalCrash is a smoke test: the handler must
// not panic when a marshal-failure-style code path runs without a
// logger. We don't have a way to force json.Marshal to fail on the
// real Match type, but we can confirm the persist path with a nil
// logger never panics on the success branch.
func TestScan_LoggerNil_NoMarshalCrash(t *testing.T) {
	h := &PromptHandler{Scanner: &fakeScanner{res: cleanResult()}}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("handler panicked with nil logger: %v", r)
		}
	}()
	w := httptest.NewRecorder()
	h.Scan(w, newReq(t, map[string]string{"input": "hello"}))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

// TestScan_LoggerWired_DoesNotInterfereWith200 confirms attaching a
// logger to the handler doesn't change the success path.
func TestScan_LoggerWired_DoesNotInterfereWith200(t *testing.T) {
	var buf bytes.Buffer
	h := &PromptHandler{
		Scanner: &fakeScanner{res: cleanResult()},
		Logger:  captureLogger(&buf),
	}
	w := httptest.NewRecorder()
	h.Scan(w, newReq(t, map[string]string{"input": "hello"}))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	// No store wired → no warn-log expected on the success path.
	if strings.Contains(buf.String(), "warn") && strings.Contains(buf.String(), "marshal") {
		t.Errorf("unexpected marshal warn log: %s", buf.String())
	}
}

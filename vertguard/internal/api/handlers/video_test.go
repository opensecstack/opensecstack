package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"google.golang.org/grpc/metadata"

	"github.com/rs/zerolog"

	mlpb "github.com/opensecstack/vertguard/internal/ml/pb"
)

// withURLParam wraps a request with a chi route context carrying an
// arbitrary named URL param.
func withURLParam(r *http.Request, key, val string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, val)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// fakeVideoStream is a test double for
// mlpb.InferenceService_ScoreVideoStreamClient that lets tests control
// Send/Recv outcomes without a real gRPC connection.
type fakeVideoStream struct {
	sendErr         error
	recvEvent       *mlpb.VideoScoreEvent
	recvErr         error
	closeSendCalled bool
}

func (f *fakeVideoStream) Send(*mlpb.VideoFrameRequest) error { return f.sendErr }
func (f *fakeVideoStream) Recv() (*mlpb.VideoScoreEvent, error) {
	return f.recvEvent, f.recvErr
}
func (f *fakeVideoStream) Header() (metadata.MD, error) { return nil, nil }
func (f *fakeVideoStream) Trailer() metadata.MD         { return nil }
func (f *fakeVideoStream) CloseSend() error             { f.closeSendCalled = true; return nil }
func (f *fakeVideoStream) Context() context.Context     { return context.Background() }
func (f *fakeVideoStream) SendMsg(any) error            { return nil }
func (f *fakeVideoStream) RecvMsg(any) error            { return nil }

func TestCreateSession_ReturnsUniqueSessionIDs(t *testing.T) {
	h := NewVideoStreamHandler(nil, zerolog.Nop())
	w1 := httptest.NewRecorder()
	h.CreateSession(w1, httptest.NewRequest(http.MethodPost, "/api/v1/video/session", nil))
	w2 := httptest.NewRecorder()
	h.CreateSession(w2, httptest.NewRequest(http.MethodPost, "/api/v1/video/session", nil))

	if w1.Code != http.StatusOK || w2.Code != http.StatusOK {
		t.Fatalf("want 200/200, got %d/%d", w1.Code, w2.Code)
	}
	var r1, r2 sessionResponse
	_ = json.Unmarshal(w1.Body.Bytes(), &r1)
	_ = json.Unmarshal(w2.Body.Bytes(), &r2)
	if r1.SessionID == "" || r2.SessionID == "" {
		t.Fatal("session_id must not be empty")
	}
	if r1.SessionID == r2.SessionID {
		t.Fatal("two calls to CreateSession returned the same session_id")
	}
}

func TestStream_MissingSessionID_Returns400(t *testing.T) {
	h := NewVideoStreamHandler(nil, zerolog.Nop())
	r := withURLParam(httptest.NewRequest(http.MethodGet, "/api/v1/video/stream/", nil), "session_id", "")
	w := httptest.NewRecorder()
	h.Stream(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", w.Code, w.Body.String())
	}
}

// ─── scoreFrame ─────────────────────────────────────────────────────

func TestScoreFrame_NilStream_ReturnsUnavailable(t *testing.T) {
	h := NewVideoStreamHandler(nil, zerolog.Nop())
	score := h.scoreFrame(context.Background(), zerolog.Nop(), nil, "sess1", frameRequest{FrameSeq: 5})
	if score.Verdict != "UNAVAILABLE" {
		t.Errorf("Verdict = %q, want UNAVAILABLE", score.Verdict)
	}
	if score.FrameSeq != 5 {
		t.Errorf("FrameSeq = %d, want 5", score.FrameSeq)
	}
}

func TestScoreFrame_InvalidBase64_ReturnsUnavailable(t *testing.T) {
	h := NewVideoStreamHandler(nil, zerolog.Nop())
	stream := &fakeVideoStream{}
	score := h.scoreFrame(context.Background(), zerolog.Nop(), stream, "sess1", frameRequest{
		FrameSeq:      1,
		FeatureVector: "not-valid-base64!!!",
	})
	if score.Verdict != "UNAVAILABLE" {
		t.Errorf("Verdict = %q, want UNAVAILABLE for undecodable feature_vector", score.Verdict)
	}
}

// TestScoreFrame_URLEncodingFallback verifies the URL-safe base64
// fallback path actually gets exercised: a payload that fails
// standard-encoding decode but succeeds under URL encoding must still
// reach the gRPC Send/Recv calls.
func TestScoreFrame_URLEncodingFallback(t *testing.T) {
	// "\xff\xef" is not valid under either alphabet by content, so
	// instead pick bytes whose base64 URL-encoded form contains '-'/'_'
	// (chars illegal in standard base64) to force the fallback branch.
	raw := []byte{0xfb, 0xff, 0xbf} // URL-safe encoding: "-_-_"-style; std would differ only in charset used for +/ which these bytes don't need — use a byte sequence guaranteed to differ.
	urlEncoded := base64.URLEncoding.EncodeToString(raw)

	stream := &fakeVideoStream{
		recvEvent: &mlpb.VideoScoreEvent{FrameSeq: 9, Confidence: 0.42, Verdict: "CLEAN", LatencyMs: 3.5},
	}
	h := NewVideoStreamHandler(nil, zerolog.Nop())
	score := h.scoreFrame(context.Background(), zerolog.Nop(), stream, "sess1", frameRequest{
		FrameSeq:      9,
		FeatureVector: urlEncoded,
	})
	if score.Verdict != "CLEAN" {
		t.Errorf("Verdict = %q, want CLEAN (URL-encoding fallback should have succeeded and reached gRPC)", score.Verdict)
	}
	if score.Confidence != 0.42 {
		t.Errorf("Confidence = %v, want 0.42", score.Confidence)
	}
}

func TestScoreFrame_SendError_ReturnsUnavailable(t *testing.T) {
	h := NewVideoStreamHandler(nil, zerolog.Nop())
	stream := &fakeVideoStream{sendErr: context.DeadlineExceeded}
	score := h.scoreFrame(context.Background(), zerolog.Nop(), stream, "sess1", frameRequest{
		FrameSeq:      1,
		FeatureVector: base64.StdEncoding.EncodeToString([]byte{1, 2, 3}),
	})
	if score.Verdict != "UNAVAILABLE" {
		t.Errorf("Verdict = %q, want UNAVAILABLE on gRPC Send error", score.Verdict)
	}
}

func TestScoreFrame_RecvError_ReturnsUnavailable(t *testing.T) {
	h := NewVideoStreamHandler(nil, zerolog.Nop())
	stream := &fakeVideoStream{recvErr: context.DeadlineExceeded}
	score := h.scoreFrame(context.Background(), zerolog.Nop(), stream, "sess1", frameRequest{
		FrameSeq:      1,
		FeatureVector: base64.StdEncoding.EncodeToString([]byte{1, 2, 3}),
	})
	if score.Verdict != "UNAVAILABLE" {
		t.Errorf("Verdict = %q, want UNAVAILABLE on gRPC Recv error", score.Verdict)
	}
}

func TestScoreFrame_HappyPath_ReturnsMLVerdict(t *testing.T) {
	h := NewVideoStreamHandler(nil, zerolog.Nop())
	stream := &fakeVideoStream{
		recvEvent: &mlpb.VideoScoreEvent{FrameSeq: 7, Confidence: 0.91, Verdict: "BLOCKED", LatencyMs: 1.2},
	}
	score := h.scoreFrame(context.Background(), zerolog.Nop(), stream, "sess1", frameRequest{
		FrameSeq:      7,
		FeatureVector: base64.StdEncoding.EncodeToString([]byte{9, 9, 9}),
		FaceDetected:  true,
	})
	if score.Verdict != "BLOCKED" {
		t.Errorf("Verdict = %q, want BLOCKED", score.Verdict)
	}
	if score.Confidence != 0.91 {
		t.Errorf("Confidence = %v, want 0.91", score.Confidence)
	}
	if score.FrameSeq != 7 {
		t.Errorf("FrameSeq = %d, want 7 (from the ML event, not the request)", score.FrameSeq)
	}
}

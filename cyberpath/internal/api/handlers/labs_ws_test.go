// Tests for TerminalHandler (labs_ws.go) — covers the pre-upgrade
// validation/error paths, which is where the security- and
// availability-relevant logic lives (the byte-relay goroutines after
// a successful WS upgrade are integration-only and out of scope for
// unit tests).
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	dockertypes "github.com/docker/docker/api/types"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/opensecstack/cyberpath/internal/db"
)

// fakeExecStreamer implements ExecStreamer.
type fakeExecStreamer struct {
	err error
}

func (f *fakeExecStreamer) ExecStream(_ context.Context, _ string) (dockertypes.HijackedResponse, error) {
	if f.err != nil {
		return dockertypes.HijackedResponse{}, f.err
	}
	return dockertypes.HijackedResponse{}, nil
}

func newTermRequest(sessionID string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/ws/labs/"+sessionID+"/term", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("sessionID", sessionID)
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	return req.WithContext(ctx)
}

func TestTerminalHandler_InvalidSessionID(t *testing.T) {
	h := &TerminalHandler{Labs: &fakeLabSessionManager{}}
	req := newTermRequest("not-a-uuid")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTerminalHandler_SessionNotFound(t *testing.T) {
	h := &TerminalHandler{Labs: &fakeLabSessionManager{getErr: errors.New("not found")}}
	req := newTermRequest(uuid.New().String())
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

// No container_id in session metadata (lab not yet started) must
// return 503, not attempt a Docker call.
func TestTerminalHandler_NoContainerID(t *testing.T) {
	sessID := uuid.New()
	h := &TerminalHandler{Labs: &fakeLabSessionManager{
		session: &db.LabSession{ID: sessID, Status: "running", Metadata: json.RawMessage(`{}`)},
	}}
	req := newTermRequest(sessID.String())
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when no container_id in metadata, got %d: %s", rec.Code, rec.Body.String())
	}
}

// Malformed metadata JSON must be handled gracefully (treated as "no
// container id") rather than panicking.
func TestTerminalHandler_MalformedMetadata(t *testing.T) {
	sessID := uuid.New()
	h := &TerminalHandler{Labs: &fakeLabSessionManager{
		session: &db.LabSession{ID: sessID, Status: "running", Metadata: json.RawMessage(`not-json`)},
	}}
	req := newTermRequest(sessID.String())
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for malformed metadata, got %d: %s", rec.Code, rec.Body.String())
	}
}

// Docker adapter not wired must fail closed with 503, not panic on a
// nil dereference.
func TestTerminalHandler_DockerNotConfigured(t *testing.T) {
	sessID := uuid.New()
	h := &TerminalHandler{
		Labs: &fakeLabSessionManager{
			session: &db.LabSession{ID: sessID, Status: "running", Metadata: json.RawMessage(`{"container_id":"c-1"}`)},
		},
		Docker: nil,
	}
	req := newTermRequest(sessID.String())
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when Docker is not configured, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ExecStream failure must surface as a clean 500, not a panic, and
// must occur BEFORE the WebSocket upgrade so a proper HTTP error can
// still be written.
func TestTerminalHandler_ExecStreamFails(t *testing.T) {
	sessID := uuid.New()
	h := &TerminalHandler{
		Labs: &fakeLabSessionManager{
			session: &db.LabSession{ID: sessID, Status: "running", Metadata: json.RawMessage(`{"container_id":"c-1"}`)},
		},
		Docker: &fakeExecStreamer{err: errors.New("docker exec failed")},
	}
	req := newTermRequest(sessID.String())
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when ExecStream fails, got %d: %s", rec.Code, rec.Body.String())
	}
}

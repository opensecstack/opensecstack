package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestAuditLog_RecordsAuthenticatedUser(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	h := AuditLog(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := &Claims{Subject: "alice", Role: RoleAdmin}
		*r = *r.WithContext(WithClaims(r.Context(), claims))
		w.WriteHeader(http.StatusCreated)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}
	fields := entries[0].ContextMap()
	if fields["user_id"] != "alice" {
		t.Errorf("user_id = %v, want alice", fields["user_id"])
	}
	if fields["role"] != RoleAdmin {
		t.Errorf("role = %v, want %s", fields["role"], RoleAdmin)
	}
	if fields["status"] != int64(http.StatusCreated) {
		t.Errorf("status = %v, want %d", fields["status"], http.StatusCreated)
	}
	if fields["method"] != http.MethodPost {
		t.Errorf("method = %v, want POST", fields["method"])
	}
}

func TestAuditLog_AnonymousWhenNoClaims(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	h := AuditLog(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}
	fields := entries[0].ContextMap()
	if fields["user_id"] != "anonymous" {
		t.Errorf("user_id = %v, want anonymous", fields["user_id"])
	}
	if fields["status"] != int64(http.StatusOK) {
		t.Errorf("status = %v, want %d", fields["status"], http.StatusOK)
	}
}

func TestAuditLog_DefaultStatusIsOKWhenHandlerNeverCallsWriteHeader(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	// Handler writes a body without ever calling WriteHeader explicitly --
	// net/http defaults to 200, and the recorder should reflect that.
	h := AuditLog(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	fields := logs.All()[0].ContextMap()
	if fields["status"] != int64(http.StatusOK) {
		t.Errorf("status = %v, want %d", fields["status"], http.StatusOK)
	}
}

func TestAuditLog_NilLoggerDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nil logger panicked: %v", r)
		}
	}()
	h := AuditLog(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

// noopHandler is a minimal downstream handler used by the correlation ID tests.
var noopHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

// applyCorrelationID wraps noopHandler with the CorrelationID middleware,
// sends the provided request through it, and returns the recorded response.
func applyCorrelationID(req *http.Request) *httptest.ResponseRecorder {
	wrapped := CorrelationID(noopHandler)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	return rr
}

// isValidUUID reports whether s is a valid UUID string.
func isValidUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

// TestCorrelationID_NoInboundHeader verifies that when the request carries no
// X-Request-ID header a valid UUID is generated and set on the response.
func TestCorrelationID_NoInboundHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := applyCorrelationID(req)

	got := rr.Header().Get("X-Request-ID")
	if got == "" {
		t.Fatal("X-Request-ID response header is absent, want a UUID")
	}
	if !isValidUUID(got) {
		t.Errorf("X-Request-ID = %q is not a valid UUID", got)
	}
}

// TestCorrelationID_ValidInboundHeader verifies that a valid UUID supplied by
// the caller is echoed back unchanged in the response.
func TestCorrelationID_ValidInboundHeader(t *testing.T) {
	inbound := uuid.New().String()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", inbound)
	rr := applyCorrelationID(req)

	got := rr.Header().Get("X-Request-ID")
	if got != inbound {
		t.Errorf("X-Request-ID = %q, want %q (original inbound value)", got, inbound)
	}
}

// TestCorrelationID_InvalidInboundHeader verifies that an invalid (non-UUID)
// X-Request-ID header is discarded and replaced with a freshly generated UUID.
func TestCorrelationID_InvalidInboundHeader(t *testing.T) {
	invalidValues := []string{
		"not-a-uuid",
		"12345",
		"",
		"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
	}

	for _, bad := range invalidValues {
		t.Run("invalid="+bad, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if bad != "" {
				req.Header.Set("X-Request-ID", bad)
			}
			rr := applyCorrelationID(req)

			got := rr.Header().Get("X-Request-ID")
			if got == "" {
				t.Fatal("X-Request-ID response header is absent, want a new UUID")
			}
			if got == bad {
				t.Errorf("X-Request-ID = %q was not replaced (invalid value passed through)", got)
			}
			if !isValidUUID(got) {
				t.Errorf("X-Request-ID = %q is not a valid UUID", got)
			}
		})
	}
}

// TestCorrelationID_StoredInContext verifies that the correlation ID is stored
// in the request context so that GetCorrelationID can retrieve it downstream.
func TestCorrelationID_StoredInContext(t *testing.T) {
	inbound := uuid.New().String()

	var capturedID string
	captureHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = GetCorrelationID(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", inbound)

	wrapped := CorrelationID(captureHandler)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if capturedID != inbound {
		t.Errorf("GetCorrelationID = %q, want %q", capturedID, inbound)
	}
}

// TestGetCorrelationID_EmptyContext verifies that GetCorrelationID returns an
// empty string when called with a context that has no correlation ID stored.
func TestGetCorrelationID_EmptyContext(t *testing.T) {
	if got := GetCorrelationID(context.Background()); got != "" {
		t.Errorf("GetCorrelationID(empty context) = %q, want empty string", got)
	}
}

// TestCorrelationID_ResponseIDMatchesContext verifies that the ID written to
// the response header and the ID stored in the context are identical.
func TestCorrelationID_ResponseIDMatchesContext(t *testing.T) {
	var contextID string
	captureHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextID = GetCorrelationID(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	wrapped := CorrelationID(captureHandler)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	responseID := rr.Header().Get("X-Request-ID")
	if responseID != contextID {
		t.Errorf("response X-Request-ID %q != context correlation ID %q", responseID, contextID)
	}
}

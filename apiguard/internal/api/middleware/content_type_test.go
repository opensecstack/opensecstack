package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequireJSONContentType(t *testing.T) {
	makeNext := func() (http.Handler, *bool) {
		called := false
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})
		return h, &called
	}

	tests := []struct {
		name           string
		method         string
		contentType    string
		setHeader      bool
		wantStatus     int
		wantNextCalled bool
	}{
		{
			name:           "POST with application/json passes through",
			method:         http.MethodPost,
			contentType:    "application/json",
			setHeader:      true,
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:           "POST with application/json; charset=utf-8 passes through",
			method:         http.MethodPost,
			contentType:    "application/json; charset=utf-8",
			setHeader:      true,
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:           "POST with no Content-Type header passes through",
			method:         http.MethodPost,
			setHeader:      false,
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:           "POST with text/plain rejected",
			method:         http.MethodPost,
			contentType:    "text/plain",
			setHeader:      true,
			wantStatus:     http.StatusUnsupportedMediaType,
			wantNextCalled: false,
		},
		{
			name:           "PUT with text/xml rejected",
			method:         http.MethodPut,
			contentType:    "text/xml",
			setHeader:      true,
			wantStatus:     http.StatusUnsupportedMediaType,
			wantNextCalled: false,
		},
		{
			name:           "PATCH with text/plain rejected",
			method:         http.MethodPatch,
			contentType:    "text/plain",
			setHeader:      true,
			wantStatus:     http.StatusUnsupportedMediaType,
			wantNextCalled: false,
		},
		{
			name:           "GET with text/plain passes through (method not checked)",
			method:         http.MethodGet,
			contentType:    "text/plain",
			setHeader:      true,
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:           "DELETE with text/plain passes through (method not checked)",
			method:         http.MethodDelete,
			contentType:    "text/plain",
			setHeader:      true,
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			next, called := makeNext()
			handler := RequireJSONContentType(next)

			req := httptest.NewRequest(tc.method, "/api/test", nil)
			if tc.setHeader {
				req.Header.Set("Content-Type", tc.contentType)
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rr.Code, tc.wantStatus)
			}
			if *called != tc.wantNextCalled {
				t.Errorf("next called = %v, want %v", *called, tc.wantNextCalled)
			}
			if tc.wantStatus == http.StatusUnsupportedMediaType {
				if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
					t.Errorf("response Content-Type = %q, want application/json", ct)
				}
				if !strings.Contains(rr.Body.String(), "Content-Type must be application/json") {
					t.Errorf("body = %q, want it to contain the error message", rr.Body.String())
				}
			}
		})
	}
}

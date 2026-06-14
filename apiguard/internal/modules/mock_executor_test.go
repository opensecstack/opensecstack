package modules

import (
	"context"
	"net/http"
)

// mockExecutor records calls and returns a configured response sequence.
type mockExecutor struct {
	responses []*HTTPResponse
	calls     []*http.Request
	idx       int
}

func (m *mockExecutor) Do(ctx context.Context, req *http.Request) (*HTTPResponse, error) {
	m.calls = append(m.calls, req)
	if m.idx >= len(m.responses) {
		return &HTTPResponse{StatusCode: 404, Headers: make(http.Header)}, nil
	}
	r := m.responses[m.idx]
	m.idx++
	return r, nil
}

func resp(code int, body string, headers ...string) *HTTPResponse {
	h := make(http.Header)
	for i := 0; i+1 < len(headers); i += 2 {
		h.Set(headers[i], headers[i+1])
	}
	return &HTTPResponse{StatusCode: code, Headers: h, Body: []byte(body)}
}

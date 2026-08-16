package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/config"
)

func TestStreamChannelMessages_NoHub_Returns503(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/spaces/s/channels/c/stream", nil)
	w := httptest.NewRecorder()

	handlers.StreamChannelMessages(d)(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when ChannelHub is nil, got %d", w.Code)
	}
}

// stubHub is a minimal ChannelHubIface implementation for handler tests.
type stubHub struct{}

func (stubHub) Publish(channelID string, payload []byte)     {}
func (stubHub) Subscribe(channelID string) chan []byte       { return make(chan []byte) }
func (stubHub) Unsubscribe(channelID string, ch chan []byte) {}

func TestStreamChannelMessages_NoAuth_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}, ChannelHub: stubHub{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/spaces/s/channels/c/stream", nil)
	w := httptest.NewRecorder()

	handlers.StreamChannelMessages(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", w.Code)
	}
}

func TestStreamChannelMessages_BadTokenParam_Returns401(t *testing.T) {
	d := handlers.Deps{
		Cfg:        &config.Config{JWTSecret: "unit-test-secret"},
		ChannelHub: stubHub{},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/spaces/s/channels/c/stream?token=not-a-valid-jwt", nil)
	w := httptest.NewRecorder()

	handlers.StreamChannelMessages(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid token param, got %d", w.Code)
	}
}

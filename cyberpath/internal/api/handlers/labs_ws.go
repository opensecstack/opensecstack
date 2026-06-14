// WebSocket terminal relay for CyberPath lab sessions.
//
// GET /ws/labs/{sessionID}/term upgrades to WebSocket and pipes the client's
// input/output directly to the running lab container's shell via a Docker
// exec session. Each WebSocket message from the client is written verbatim to
// the container's stdin; every chunk of stdout from the container is forwarded
// as a binary WebSocket message to the client.
package handlers

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	dockertypes "github.com/docker/docker/api/types"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
)

// wsUpgrader allows any origin — TLS termination and origin enforcement are
// handled at the reverse-proxy layer.
var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(_ *http.Request) bool { return true },
}

// ExecStreamer is the subset of docker.Provisioner that TerminalHandler uses.
type ExecStreamer interface {
	ExecStream(ctx context.Context, containerID string) (dockertypes.HijackedResponse, error)
}

// TerminalHandler serves GET /ws/labs/{sessionID}/term.
// It upgrades the connection to WebSocket, locates the running container for
// the session, opens a Docker exec session, and relays bytes in both
// directions until either end closes.
type TerminalHandler struct {
	Labs   LabSessionManager
	Docker ExecStreamer
	Logger *zerolog.Logger
}

// ServeHTTP implements http.Handler.
func (h *TerminalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw := chi.URLParam(r, "sessionID")
	sessionID, err := uuid.Parse(raw)
	if err != nil {
		http.Error(w, "invalid session id", http.StatusBadRequest)
		return
	}

	session, err := h.Labs.GetSession(r.Context(), sessionID)
	if err != nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	// Extract the container ID stored in session metadata.
	var meta struct {
		ContainerID string `json:"container_id"`
	}
	if len(session.Metadata) > 0 {
		_ = json.Unmarshal(session.Metadata, &meta)
	}
	if meta.ContainerID == "" {
		http.Error(w, `{"error":{"code":"lab_not_running","message":"container not yet started"}}`, http.StatusServiceUnavailable)
		return
	}

	if h.Docker == nil {
		http.Error(w, "docker not available", http.StatusServiceUnavailable)
		return
	}

	// Open exec session before upgrading — if this fails we can still send
	// a proper HTTP error response.
	hijack, err := h.Docker.ExecStream(r.Context(), meta.ContainerID)
	if err != nil {
		h.log().Error().Err(err).Str("container_id", meta.ContainerID).Msg("ws.term: exec stream")
		http.Error(w, "could not open terminal", http.StatusInternalServerError)
		return
	}

	// Upgrade to WebSocket. After this point HTTP errors cannot be sent.
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade already wrote the error response.
		hijack.Close()
		return
	}

	done := make(chan struct{})

	// goroutine 1: WebSocket → container stdin
	go func() {
		defer func() {
			hijack.CloseWrite() //nolint:errcheck
			close(done)
		}()
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if _, err := hijack.Conn.Write(msg); err != nil {
				return
			}
		}
	}()

	// goroutine 2: container stdout → WebSocket (binary frames)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := hijack.Reader.Read(buf)
			if n > 0 {
				if wsErr := conn.WriteMessage(websocket.BinaryMessage, buf[:n]); wsErr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		conn.Close()
	}()

	// Wait for the client-write goroutine to finish (triggered by WS close or
	// container EOF), then clean up.
	<-done
	hijack.Close()
}

func (h *TerminalHandler) log() *zerolog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	z := zerolog.Nop()
	return &z
}

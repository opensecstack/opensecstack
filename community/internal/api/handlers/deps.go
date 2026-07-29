package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/community/internal/citadel"
	"github.com/opensecstack/community/internal/config"
	"github.com/opensecstack/community/internal/email"
	"github.com/opensecstack/community/internal/search"
)

// ChannelHubIface is the interface for the in-memory pub/sub hub used by
// real-time channel message streaming. Accepting an interface here avoids
// import cycles: the hub implementation lives in its own package and is wired
// at startup.
type ChannelHubIface interface {
	Publish(channelID string, payload []byte)
	Subscribe(channelID string) chan []byte
	Unsubscribe(channelID string, ch chan []byte)
}

type Deps struct {
	Pool       *pgxpool.Pool
	Cfg        *config.Config
	Citadel    *citadel.Client
	Marshal    *citadel.GovernanceClient
	Search     *search.Client
	Mailer     *email.Mailer
	Version    string
	ChannelHub ChannelHubIface
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return def
	}
	return n
}

var errNotFound = errors.New("not found")
var errForbidden = errors.New("forbidden")

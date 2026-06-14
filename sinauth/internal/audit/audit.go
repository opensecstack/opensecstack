package audit

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Entry struct {
	ID        string          `json:"id"`
	EventType string          `json:"event_type"`
	Actor     string          `json:"actor"`
	ClientID  string          `json:"client_id"`
	IPAddress string          `json:"ip_address"`
	UserAgent string          `json:"user_agent"`
	Metadata  json.RawMessage `json:"metadata"`
	CreatedAt time.Time       `json:"created_at"`
}

type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Log writes an audit entry asynchronously (fire-and-forget).
func (s *Store) Log(eventType, actor, clientID, ip, ua string, meta map[string]any) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var metaJSON []byte
		if meta != nil {
			metaJSON, _ = json.Marshal(meta)
		}
		s.pool.Exec(ctx, //nolint:errcheck
			`INSERT INTO audit_log (event_type, actor, client_id, ip_address, user_agent, metadata)
			 VALUES ($1,$2,$3,$4,$5,$6)`,
			eventType, actor, clientID, ip, ua, metaJSON,
		)
	}()
}

// List returns the most recent audit entries (newest first).
func (s *Store) List(ctx context.Context, limit int) ([]Entry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, event_type, actor, client_id, ip_address, user_agent, metadata, created_at
		 FROM audit_log ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Entry
	for rows.Next() {
		var e Entry
		var meta []byte
		if err := rows.Scan(&e.ID, &e.EventType, &e.Actor, &e.ClientID,
			&e.IPAddress, &e.UserAgent, &meta, &e.CreatedAt); err != nil {
			return nil, err
		}
		if meta != nil {
			e.Metadata = json.RawMessage(meta)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

package db

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PeerCSIRT struct {
	ID                 uuid.UUID  `json:"id"`
	Name               string     `json:"name"`
	Jurisdiction       string     `json:"jurisdiction"`
	ContactEndpoint    string     `json:"contact_endpoint"`
	Registry           string     `json:"registry"`
	Trust              string     `json:"trust"`
	Ed25519Fingerprint string     `json:"ed25519_fingerprint"`
	PGPKey             *string    `json:"pgp_key,omitempty"`
	LastHandshakeAt    *time.Time `json:"last_handshake_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
}

type PeerStore struct{ pool *pgxpool.Pool }

func NewPeerStore(pool *pgxpool.Pool) *PeerStore { return &PeerStore{pool: pool} }

func (s *PeerStore) Insert(ctx context.Context, p *PeerCSIRT) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	p.CreatedAt = time.Now().UTC()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO peer_csirts
		    (id, name, jurisdiction, contact_endpoint, registry, trust, ed25519_fingerprint, pgp_key, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`, p.ID, p.Name, p.Jurisdiction, p.ContactEndpoint, p.Registry, p.Trust, p.Ed25519Fingerprint, p.PGPKey, p.CreatedAt)
	return err
}

func (s *PeerStore) Get(ctx context.Context, id uuid.UUID) (*PeerCSIRT, error) {
	p := &PeerCSIRT{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, jurisdiction, contact_endpoint, registry, trust, ed25519_fingerprint,
		       pgp_key, last_handshake_at, created_at
		  FROM peer_csirts WHERE id = $1
	`, id).Scan(&p.ID, &p.Name, &p.Jurisdiction, &p.ContactEndpoint,
		&p.Registry, &p.Trust, &p.Ed25519Fingerprint,
		&p.PGPKey, &p.LastHandshakeAt, &p.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return p, err
}

func (s *PeerStore) UpdateHandshakeAt(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE peer_csirts SET last_handshake_at = now() WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PeerStore) List(ctx context.Context) ([]*PeerCSIRT, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, jurisdiction, contact_endpoint, registry, trust, ed25519_fingerprint,
		       pgp_key, last_handshake_at, created_at
		  FROM peer_csirts ORDER BY name ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*PeerCSIRT{}
	for rows.Next() {
		p := &PeerCSIRT{}
		if err := rows.Scan(&p.ID, &p.Name, &p.Jurisdiction, &p.ContactEndpoint,
			&p.Registry, &p.Trust, &p.Ed25519Fingerprint,
			&p.PGPKey, &p.LastHandshakeAt, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

type Escalation struct {
	ID         uuid.UUID
	IncidentID uuid.UUID
	PeerID     uuid.UUID
	SentAt     time.Time
	AckAt      *time.Time
	Response   map[string]any
}

type EscalationStore struct{ pool *pgxpool.Pool }

func NewEscalationStore(pool *pgxpool.Pool) *EscalationStore { return &EscalationStore{pool: pool} }

func (s *EscalationStore) Insert(ctx context.Context, e *Escalation) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.SentAt.IsZero() {
		e.SentAt = time.Now().UTC()
	}
	if e.Response == nil {
		e.Response = map[string]any{}
	}
	resp, err := json.Marshal(e.Response)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO escalations (id, incident_id, peer_id, sent_at, ack_at, response)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (incident_id, peer_id) DO NOTHING
	`, e.ID, e.IncidentID, e.PeerID, e.SentAt, e.AckAt, resp)
	return err
}

func (s *EscalationStore) ListForIncident(ctx context.Context, incidentID uuid.UUID) ([]*Escalation, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, incident_id, peer_id, sent_at, ack_at, response
		  FROM escalations WHERE incident_id = $1 ORDER BY sent_at DESC
	`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Escalation{}
	for rows.Next() {
		e := &Escalation{}
		var resp []byte
		if err := rows.Scan(&e.ID, &e.IncidentID, &e.PeerID, &e.SentAt, &e.AckAt, &resp); err != nil {
			return nil, err
		}
		if len(resp) > 0 {
			_ = json.Unmarshal(resp, &e.Response)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

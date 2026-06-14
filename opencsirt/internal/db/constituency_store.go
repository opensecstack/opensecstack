package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Constituency struct {
	ID                    uuid.UUID `json:"id"`
	Name                  string    `json:"name"`
	Sector                string    `json:"sector"`
	Country               string    `json:"country"`
	NIS2Status            string    `json:"kind"`            // web calls this "kind"
	TLPDefault            string    `json:"tlp_default"`
	PrimaryContactEmail   string    `json:"primary_contact"` // web calls this "primary_contact"
	SecondaryContactEmail *string   `json:"secondary_contact_email,omitempty"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

type ConstituencyStore struct{ pool *pgxpool.Pool }

func NewConstituencyStore(pool *pgxpool.Pool) *ConstituencyStore { return &ConstituencyStore{pool: pool} }

func (s *ConstituencyStore) Insert(ctx context.Context, c *Constituency) error {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	now := time.Now().UTC()
	c.CreatedAt = now
	c.UpdatedAt = now
	_, err := s.pool.Exec(ctx, `
		INSERT INTO constituencies
		    (id, name, sector, country, nis2_status, tlp_default,
		     primary_contact_email, secondary_contact_email,
		     created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	`, c.ID, c.Name, c.Sector, c.Country, c.NIS2Status, c.TLPDefault,
		c.PrimaryContactEmail, c.SecondaryContactEmail,
		c.CreatedAt, c.UpdatedAt)
	return err
}

func (s *ConstituencyStore) Get(ctx context.Context, id uuid.UUID) (*Constituency, error) {
	c := &Constituency{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, sector, country, nis2_status, tlp_default,
		       primary_contact_email, secondary_contact_email,
		       created_at, updated_at
		  FROM constituencies WHERE id = $1
	`, id).Scan(&c.ID, &c.Name, &c.Sector, &c.Country, &c.NIS2Status, &c.TLPDefault,
		&c.PrimaryContactEmail, &c.SecondaryContactEmail,
		&c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

func (s *ConstituencyStore) Update(ctx context.Context, c *Constituency) error {
	c.UpdatedAt = time.Now().UTC()
	tag, err := s.pool.Exec(ctx, `
		UPDATE constituencies
		   SET name = $2, sector = $3, country = $4, nis2_status = $5,
		       tlp_default = $6, primary_contact_email = $7,
		       secondary_contact_email = $8, updated_at = $9
		 WHERE id = $1
	`, c.ID, c.Name, c.Sector, c.Country, c.NIS2Status,
		c.TLPDefault, c.PrimaryContactEmail, c.SecondaryContactEmail, c.UpdatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *ConstituencyStore) List(ctx context.Context, limit, offset int) ([]*Constituency, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, sector, country, nis2_status, tlp_default,
		       primary_contact_email, secondary_contact_email,
		       created_at, updated_at
		  FROM constituencies
	     ORDER BY created_at DESC, id DESC
	     LIMIT $1 OFFSET $2
	`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]*Constituency, 0, limit)
	for rows.Next() {
		c := &Constituency{}
		if err := rows.Scan(&c.ID, &c.Name, &c.Sector, &c.Country, &c.NIS2Status, &c.TLPDefault,
			&c.PrimaryContactEmail, &c.SecondaryContactEmail,
			&c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM constituencies`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count query: %w", err)
	}
	return out, total, rows.Err()
}

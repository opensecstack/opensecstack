// Package db — role_store manages the `roles` RBAC catalogue.
// Read-only: rows are seeded by migration 0002 and not mutated at runtime.
package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Role mirrors a row in the `roles` table.
type Role struct {
	ID          string          `json:"id"`
	Description string          `json:"description"`
	Permissions json.RawMessage `json:"permissions"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// RoleStore is the read-only accessor for the seeded RBAC catalogue.
type RoleStore struct {
	Pool *pgxpool.Pool
}

// NewRoleStore wires a RoleStore to a pgx pool.
func NewRoleStore(pool *pgxpool.Pool) *RoleStore { return &RoleStore{Pool: pool} }

// Get returns a role by id (e.g. 'learner').
func (s *RoleStore) Get(ctx context.Context, id string) (*Role, error) {
	const op = "role.Get"
	var r Role
	err := s.Pool.QueryRow(ctx, `
		SELECT id, description, permissions, created_at, updated_at
		FROM roles WHERE id = $1`, id,
	).Scan(&r.ID, &r.Description, &r.Permissions, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("store/%s: %w", op, err)
	}
	return &r, nil
}

// List returns every role row, ordered by id (stable for UI listing).
func (s *RoleStore) List(ctx context.Context) ([]Role, error) {
	const op = "role.List"
	rows, err := s.Pool.Query(ctx, `
		SELECT id, description, permissions, created_at, updated_at
		FROM roles ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store/%s: %w", op, err)
	}
	defer rows.Close()

	out := make([]Role, 0, 4)
	for rows.Next() {
		var r Role
		if err := rows.Scan(&r.ID, &r.Description, &r.Permissions, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store/%s: scan: %w", op, err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store/%s: rows: %w", op, err)
	}
	return out, nil
}

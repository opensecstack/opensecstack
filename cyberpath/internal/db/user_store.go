// Package db — user_store manages the `users` table.
//
// Schema source: migrations 0001 (base columns) + 0005 (password_updated_at,
// mfa_secret_encrypted, idx_users_email_lower) + 0006 (deleted_at +
// idx_users_email_lower_live partial index).
//
// Login lookup is case-insensitive (`WHERE LOWER(email) = LOWER($1)`)
// and excludes soft-deleted rows; the partial index from 0006 backs it.
// SoftDelete sets deleted_at = now(); Restore clears it.
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

// User mirrors a row in `users`.
type User struct {
	ID                uuid.UUID
	TenantID          uuid.UUID
	Email             string
	DisplayName       string
	Locale            string
	Role              string
	PasswordHash      string
	CreatedAt         time.Time
	UpdatedAt         time.Time
	DeletedAt         *time.Time
	PasswordUpdatedAt *time.Time
}

// UserStore wraps a pgx pool for `users`.
type UserStore struct {
	Pool *pgxpool.Pool
}

// NewUserStore wires a UserStore.
func NewUserStore(pool *pgxpool.Pool) *UserStore { return &UserStore{Pool: pool} }

// ErrUserNotFound is returned when no row matches a Find lookup.
// Wraps pgx.ErrNoRows so callers can errors.Is either sentinel.
var ErrUserNotFound = errors.New("db/user_store: user not found")

const userColumns = `id, tenant_id, email, display_name, role, locale,
	COALESCE(password_hash, ''), created_at, updated_at, password_updated_at, deleted_at`

func scanUser(row pgx.Row) (*User, error) {
	var u User
	if err := row.Scan(
		&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.Role, &u.Locale,
		&u.PasswordHash, &u.CreatedAt, &u.UpdatedAt, &u.PasswordUpdatedAt, &u.DeletedAt,
	); err != nil {
		return nil, err
	}
	return &u, nil
}

// FindByEmail looks up a user by case-insensitive email match. Returns
// ErrUserNotFound (wrapping pgx.ErrNoRows) when no row exists.
func (s *UserStore) FindByEmail(ctx context.Context, email string) (*User, error) {
	const op = "db/user_store/FindByEmail"
	row := s.Pool.QueryRow(ctx, `
		SELECT `+userColumns+` FROM users
		WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL
		LIMIT 1`, email)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return u, nil
}

// FindByID looks up a user by primary key.
func (s *UserStore) FindByID(ctx context.Context, id uuid.UUID) (*User, error) {
	const op = "db/user_store/FindByID"
	row := s.Pool.QueryRow(ctx, `
		SELECT `+userColumns+` FROM users
		WHERE id = $1 AND deleted_at IS NULL
		LIMIT 1`, id)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return u, nil
}

// UpdatePasswordHash persists a new argon2id PHC hash and stamps
// password_updated_at. Used by silent rehash on login.
func (s *UserStore) UpdatePasswordHash(ctx context.Context, id uuid.UUID, hash string) error {
	const op = "db/user_store/UpdatePasswordHash"
	tag, err := s.Pool.Exec(ctx, `
		UPDATE users
		SET password_hash = $2, password_updated_at = now(), updated_at = now()
		WHERE id = $1`, id, hash)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%s: %w", op, ErrUserNotFound)
	}
	return nil
}

// Create inserts a new user row. On success u.ID and u.CreatedAt /
// u.UpdatedAt are populated.
func (s *UserStore) Create(ctx context.Context, u *User) error {
	const op = "db/user_store/Create"
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	if u.Locale == "" {
		u.Locale = "sq"
	}
	if u.Role == "" {
		u.Role = "learner"
	}
	row := s.Pool.QueryRow(ctx, `
		INSERT INTO users (id, tenant_id, email, display_name, role, locale, password_hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING created_at, updated_at`,
		u.ID, u.TenantID, u.Email, u.DisplayName, u.Role, u.Locale,
		nullableString(u.PasswordHash),
	)
	if err := row.Scan(&u.CreatedAt, &u.UpdatedAt); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// SoftDelete tombstones a user by stamping deleted_at = now().
// Idempotent — re-running on an already-deleted row leaves the prior
// timestamp intact and returns nil. Returns ErrUserNotFound only when
// no row with the given id exists at all.
func (s *UserStore) SoftDelete(ctx context.Context, id uuid.UUID) error {
	const op = "db/user_store/SoftDelete"
	tag, err := s.Pool.Exec(ctx, `
		UPDATE users
		SET deleted_at = now(), updated_at = now()
		WHERE id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if tag.RowsAffected() == 0 {
		// Either the row does not exist or it is already deleted.
		// Distinguish so callers can treat repeat-delete as success.
		var exists bool
		if err := s.Pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, id,
		).Scan(&exists); err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
		if !exists {
			return fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
	}
	return nil
}

// Restore clears deleted_at on a previously soft-deleted user. Returns
// ErrUserNotFound when no row with the given id exists. Restoring an
// already-live user is a no-op (returns nil).
func (s *UserStore) Restore(ctx context.Context, id uuid.UUID) error {
	const op = "db/user_store/Restore"
	tag, err := s.Pool.Exec(ctx, `
		UPDATE users
		SET deleted_at = NULL, updated_at = now()
		WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%s: %w", op, ErrUserNotFound)
	}
	return nil
}

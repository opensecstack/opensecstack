package user

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

func (s *Store) GetByUsername(ctx context.Context, username string) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, username, email, COALESCE(email_verified,false),
                COALESCE(display_name,''), COALESCE(avatar_url,''),
                COALESCE(password_hash,''), deactivated_at::text
         FROM users WHERE username=$1`, username,
	).Scan(&u.ID, &u.Username, &u.Email, &u.EmailVerified,
		&u.DisplayName, &u.AvatarURL, &u.PasswordHash, &u.DeactivatedAt)
	if err != nil {
		return nil, ErrNotFound
	}
	return &u, nil
}

func (s *Store) GetByID(ctx context.Context, id string) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, username, email, COALESCE(email_verified,false),
                COALESCE(display_name,''), COALESCE(avatar_url,''),
                COALESCE(password_hash,''), deactivated_at::text
         FROM users WHERE id=$1`, id,
	).Scan(&u.ID, &u.Username, &u.Email, &u.EmailVerified,
		&u.DisplayName, &u.AvatarURL, &u.PasswordHash, &u.DeactivatedAt)
	if err != nil {
		return nil, ErrNotFound
	}
	return &u, nil
}

func (s *Store) Create(ctx context.Context, u *User) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO users (username, email, password_hash, display_name)
         VALUES ($1, $2, $3, $4)
         RETURNING id`,
		u.Username, u.Email, u.PasswordHash, u.DisplayName,
	).Scan(&u.ID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrDuplicate
		}
		return err
	}
	return nil
}

func (s *Store) List(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, username, email, COALESCE(email_verified,false),
                COALESCE(display_name,''), COALESCE(avatar_url,''),
                COALESCE(password_hash,''), deactivated_at::text
         FROM users ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.EmailVerified,
			&u.DisplayName, &u.AvatarURL, &u.PasswordHash, &u.DeactivatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *Store) Deactivate(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET deactivated_at=now() WHERE id=$1`, id)
	return err
}

// IsPlatformAdmin reports whether the given user has platform-admin
// standing, i.e. is allowed past middleware.RequireAdmin. See
// migrations/019_platform_admin.sql.
func (s *Store) IsPlatformAdmin(ctx context.Context, id string) (bool, error) {
	var isAdmin bool
	err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(is_platform_admin, false) FROM users WHERE id=$1`, id,
	).Scan(&isAdmin)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return isAdmin, nil
}

// SetPlatformAdmin promotes or demotes the user with the given email to/from
// platform-admin standing. Used by the one-time bootstrap procedure
// documented in SECURITY.md to establish the first admin. Returns false if
// no user with that email exists.
func (s *Store) SetPlatformAdmin(ctx context.Context, email string, admin bool) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE users SET is_platform_admin=$2, updated_at=now() WHERE email=$1`, email, admin)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (s *Store) GetByEmail(ctx context.Context, email string) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, username, email, COALESCE(email_verified,false),
                COALESCE(display_name,''), COALESCE(avatar_url,''),
                COALESCE(password_hash,''), deactivated_at::text
         FROM users WHERE email=$1`, email,
	).Scan(&u.ID, &u.Username, &u.Email, &u.EmailVerified,
		&u.DisplayName, &u.AvatarURL, &u.PasswordHash, &u.DeactivatedAt)
	if err != nil {
		return nil, ErrNotFound
	}
	return &u, nil
}

func (s *Store) StoreVerificationToken(ctx context.Context, userID, token string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO email_verification_tokens (user_id, token) VALUES ($1, $2)`,
		userID, token)
	return err
}

func (s *Store) ConsumeVerificationToken(ctx context.Context, token string) (string, error) {
	var userID string
	err := s.pool.QueryRow(ctx,
		`SELECT user_id FROM email_verification_tokens
         WHERE token=$1 AND used=false AND expires_at > now()`, token,
	).Scan(&userID)
	if err != nil {
		return "", errors.New("token invalid or expired")
	}
	_, err = s.pool.Exec(ctx,
		`UPDATE email_verification_tokens SET used=true WHERE token=$1`, token)
	if err != nil {
		return "", err
	}
	return userID, nil
}

func (s *Store) MarkEmailVerified(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET email_verified=true WHERE id=$1`, userID)
	return err
}

func (s *Store) StorePasswordResetToken(ctx context.Context, userID, token string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE password_reset_tokens SET used=true WHERE user_id=$1 AND used=false`, userID)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO password_reset_tokens (user_id, token) VALUES ($1, $2)`,
		userID, token)
	return err
}

func (s *Store) ConsumePasswordResetToken(ctx context.Context, token string) (string, error) {
	var userID string
	err := s.pool.QueryRow(ctx,
		`SELECT user_id FROM password_reset_tokens
         WHERE token=$1 AND used=false AND expires_at > now()`, token,
	).Scan(&userID)
	if err != nil {
		return "", errors.New("token invalid or expired")
	}
	_, err = s.pool.Exec(ctx,
		`UPDATE password_reset_tokens SET used=true WHERE token=$1`, token)
	if err != nil {
		return "", err
	}
	return userID, nil
}

func (s *Store) UpdatePassword(ctx context.Context, userID, hash string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET password_hash=$2, updated_at=now() WHERE id=$1`, userID, hash)
	return err
}

// FindOrCreateBySocial finds a user by provider+socialID, falls back to email match,
// or creates a new account if neither exists. Returns the user and whether it was just created.
func (s *Store) FindOrCreateBySocial(ctx context.Context, provider, socialID, email, displayName, avatarURL string) (*User, error) {
	col := "google_id"
	if provider == "github" {
		col = "github_id"
	}

	// 1. Find by social ID.
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, username, email, COALESCE(email_verified,false),
		        COALESCE(display_name,''), COALESCE(avatar_url,''),
		        COALESCE(password_hash,''), deactivated_at::text
		 FROM users WHERE `+col+`=$1`, socialID,
	).Scan(&u.ID, &u.Username, &u.Email, &u.EmailVerified,
		&u.DisplayName, &u.AvatarURL, &u.PasswordHash, &u.DeactivatedAt)
	if err == nil {
		return &u, nil
	}

	// 2. Find by email and attach the social ID.
	if email != "" {
		err = s.pool.QueryRow(ctx,
			`UPDATE users SET `+col+`=$2, avatar_url=COALESCE(NULLIF(avatar_url,''),$3), updated_at=now()
			 WHERE email=$1
			 RETURNING id, username, email, COALESCE(email_verified,false),
			           COALESCE(display_name,''), COALESCE(avatar_url,''),
			           COALESCE(password_hash,''), deactivated_at::text`,
			email, socialID, avatarURL,
		).Scan(&u.ID, &u.Username, &u.Email, &u.EmailVerified,
			&u.DisplayName, &u.AvatarURL, &u.PasswordHash, &u.DeactivatedAt)
		if err == nil {
			return &u, nil
		}
	}

	// 3. Create new account (no password).
	username := sanitizeUsername(email, provider)
	err = s.pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, avatar_url, email_verified, `+col+`)
		 VALUES ($1, $2, $3, $4, true, $5)
		 ON CONFLICT (username) DO UPDATE SET username=EXCLUDED.username||'_'||floor(random()*9000+1000)::text
		 RETURNING id, username, email, COALESCE(email_verified,false),
		           COALESCE(display_name,''), COALESCE(avatar_url,''),
		           COALESCE(password_hash,''), deactivated_at::text`,
		username, email, displayName, avatarURL, socialID,
	).Scan(&u.ID, &u.Username, &u.Email, &u.EmailVerified,
		&u.DisplayName, &u.AvatarURL, &u.PasswordHash, &u.DeactivatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func sanitizeUsername(email, fallbackPrefix string) string {
	if email == "" {
		return fallbackPrefix + "_user"
	}
	// Use the local part of the email.
	for i, ch := range email {
		if ch == '@' {
			return email[:i]
		}
	}
	return fallbackPrefix + "_user"
}

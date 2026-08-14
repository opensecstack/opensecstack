package mfa

import (
	"context"
	"encoding/json"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WAUser implements webauthn.User for our users table.
type WAUser struct {
	ID          []byte
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
}

func (u *WAUser) WebAuthnID() []byte                         { return u.ID }
func (u *WAUser) WebAuthnName() string                       { return u.Name }
func (u *WAUser) WebAuthnDisplayName() string                { return u.DisplayName }
func (u *WAUser) WebAuthnIcon() string                       { return "" }
func (u *WAUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

// LoadWAUser fetches a user and all their WebAuthn credentials from the DB.
func LoadWAUser(ctx context.Context, pool *pgxpool.Pool, userID string) (*WAUser, error) {
	u := &WAUser{}
	// id::bytea is not a valid cast for a uuid column in Postgres (uuid and
	// bytea are unrelated types, and PG rejects the cast outright with
	// "cannot cast type uuid to bytea"). Since nothing in this codebase ever
	// populates users.webauthn_id, that column is always NULL, which meant
	// every single call to LoadWAUser failed with a SQL error — WebAuthn
	// login/registration was completely broken for every user. uuid_send()
	// returns the UUID's canonical 16-byte representation and is the
	// correct way to get a stable bytea fallback from a uuid column.
	err := pool.QueryRow(ctx,
		`SELECT COALESCE(webauthn_id, uuid_send(id)), username, COALESCE(display_name, username) FROM users WHERE id=$1`,
		userID,
	).Scan(&u.ID, &u.Name, &u.DisplayName)
	if err != nil {
		return nil, err
	}

	rows, err := pool.Query(ctx,
		`SELECT credential_id, public_key, aaguid, sign_count, transports, backup_eligible, backup_state
		 FROM webauthn_credentials WHERE user_id=$1`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var c webauthn.Credential
		var transports []string
		if err := rows.Scan(&c.ID, &c.PublicKey, &c.Authenticator.AAGUID, &c.Authenticator.SignCount,
			&transports, &c.Flags.BackupEligible, &c.Flags.BackupState); err != nil {
			return nil, err
		}
		for _, t := range transports {
			c.Transport = append(c.Transport, protocol.AuthenticatorTransport(t))
		}
		u.Credentials = append(u.Credentials, c)
	}
	return u, nil
}

// SaveCredential persists a newly registered WebAuthn credential.
func SaveCredential(ctx context.Context, pool *pgxpool.Pool, userID, name string, c *webauthn.Credential) error {
	transports := make([]string, len(c.Transport))
	for i, t := range c.Transport {
		transports[i] = string(t)
	}
	// aaguid is NOT NULL (with a 16-zero-byte default). Some attestation
	// paths can leave Authenticator.AAGUID nil/empty; passing that through
	// as an explicit NULL parameter overrides the column default and trips
	// the NOT NULL constraint, failing the whole registration. Fall back to
	// 16 zero bytes (the same value the column default would produce) so a
	// missing AAGUID degrades gracefully instead of erroring.
	aaguid := c.Authenticator.AAGUID
	if len(aaguid) == 0 {
		aaguid = make([]byte, 16)
	}
	_, err := pool.Exec(ctx,
		`INSERT INTO webauthn_credentials
		 (user_id, credential_id, public_key, aaguid, sign_count, name, transports, backup_eligible, backup_state)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		userID, c.ID, c.PublicKey, aaguid, c.Authenticator.SignCount,
		name, transports, c.Flags.BackupEligible, c.Flags.BackupState,
	)
	return err
}

// UpdateCredential updates the sign count after a successful assertion.
func UpdateCredential(ctx context.Context, pool *pgxpool.Pool, c *webauthn.Credential) {
	pool.Exec(ctx,
		`UPDATE webauthn_credentials SET sign_count=$1, last_used_at=now() WHERE credential_id=$2`,
		c.Authenticator.SignCount, c.ID,
	)
}

// StoreWASession persists a WebAuthn session challenge in the DB.
func StoreWASession(ctx context.Context, pool *pgxpool.Pool, userID string, sd *webauthn.SessionData) error {
	b, err := json.Marshal(sd)
	if err != nil {
		return err
	}
	// Upsert: one active session per user at a time.
	_, err = pool.Exec(ctx,
		`INSERT INTO webauthn_sessions (user_id, challenge, data)
		 VALUES ($1, $2, $3)
		 ON CONFLICT DO NOTHING`,
		userID, sd.Challenge, b,
	)
	return err
}

// LoadAndDeleteWASession retrieves and atomically removes the active WebAuthn session.
func LoadAndDeleteWASession(ctx context.Context, pool *pgxpool.Pool, userID string) (*webauthn.SessionData, error) {
	var b []byte
	err := pool.QueryRow(ctx,
		`DELETE FROM webauthn_sessions
		 WHERE id = (
		     SELECT id FROM webauthn_sessions
		     WHERE user_id=$1 AND expires_at > now()
		     ORDER BY created_at DESC LIMIT 1
		 ) RETURNING data`,
		userID,
	).Scan(&b)
	if err != nil {
		return nil, err
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(b, &sd); err != nil {
		return nil, err
	}
	return &sd, nil
}

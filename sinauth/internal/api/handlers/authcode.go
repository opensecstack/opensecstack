package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

// issueAuthCode inserts a new authorization code into the DB and returns the raw code.
// organizationID is nil for the pure-individual flow (no org context requested/validated);
// when non-nil it is the validated organization the user is a member of (ADR 005 v1.1).
func issueAuthCode(ctx context.Context, d Deps, clientID, userID, redirectURI string,
	scopes []string, challenge, challengeMethod, nonce string, organizationID *string) (string, error) {

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	code := hex.EncodeToString(b)

	_, err := d.Pool.Exec(ctx,
		`INSERT INTO authorization_codes
            (code, client_id, user_id, redirect_uri, scopes,
             code_challenge, code_challenge_method, nonce, organization_id, expires_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, now() + interval '5 minutes')`,
		code, clientID, userID, redirectURI, scopes, challenge, challengeMethod, nonce, organizationID,
	)
	return code, err
}

package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

// issueAuthCode inserts a new authorization code into the DB and returns the raw code.
func issueAuthCode(ctx context.Context, d Deps, clientID, userID, redirectURI string,
	scopes []string, challenge, challengeMethod, nonce string) (string, error) {

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	code := hex.EncodeToString(b)

	_, err := d.Pool.Exec(ctx,
		`INSERT INTO authorization_codes
            (code, client_id, user_id, redirect_uri, scopes,
             code_challenge, code_challenge_method, nonce, expires_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now() + interval '5 minutes')`,
		code, clientID, userID, redirectURI, scopes, challenge, challengeMethod, nonce,
	)
	return code, err
}

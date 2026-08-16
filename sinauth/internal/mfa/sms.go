package mfa

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SMSProvider is an abstraction over SMS gateway APIs.
type SMSProvider interface {
	Send(ctx context.Context, to, body string) error
}

// TwilioProvider sends SMS via the Twilio REST API.
type TwilioProvider struct {
	AccountSID string
	AuthToken  string
	From       string
}

func (t *TwilioProvider) Send(ctx context.Context, to, body string) error {
	apiURL := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", t.AccountSID)
	form := url.Values{
		"To":   {to},
		"From": {t.From},
		"Body": {body},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.SetBasicAuth(t.AccountSID, t.AuthToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("twilio error: %s", resp.Status)
	}
	return nil
}

// GenerateOTP returns a 6-digit numeric code.
func GenerateOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// StoreSMSOTP inserts a new OTP record, invalidating previous ones for this user.
func StoreSMSOTP(ctx context.Context, pool *pgxpool.Pool, userID, phone, code string) error {
	// Best-effort cleanup of previous codes — the real correctness guard is
	// the fresh INSERT below, whose error is returned to the caller.
	_, _ = pool.Exec(ctx, `UPDATE sms_otp SET used=true WHERE user_id=$1 AND used=false`, userID)
	_, err := pool.Exec(ctx,
		`INSERT INTO sms_otp (user_id, phone, code) VALUES ($1, $2, $3)`,
		userID, phone, code,
	)
	return err
}

// VerifySMSOTP checks the code and marks it used. Returns false if invalid or expired.
func VerifySMSOTP(ctx context.Context, pool *pgxpool.Pool, userID, code string) bool {
	var id string
	err := pool.QueryRow(ctx,
		`SELECT id FROM sms_otp
		 WHERE user_id=$1 AND code=$2 AND used=false AND expires_at > now()`,
		userID, code,
	).Scan(&id)
	if err != nil {
		return false
	}
	// If marking the code used fails, it must NOT be treated as a successful
	// verification — the same SMS code would otherwise stay valid (used=false)
	// and replayable for the rest of its expiry window.
	if _, err := pool.Exec(ctx, `UPDATE sms_otp SET used=true WHERE id=$1`, id); err != nil {
		return false
	}
	return true
}

// NoopSMSProvider logs to stdout — used in dev mode.
type NoopSMSProvider struct{}

func (n *NoopSMSProvider) Send(ctx context.Context, to, body string) error {
	fmt.Printf("[SMS NOOP] to=%s body=%s\n", to, body)
	return nil
}

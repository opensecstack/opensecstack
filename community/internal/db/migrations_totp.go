package db

const ddlTOTP = `
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT false;`

// totp_last_step tracks the most recent 30-second RFC 6238 time-step a
// user's TOTP code was successfully validated against (see
// internal/api/handlers/totp.go's ConsumeTOTPCode). pquerna/otp's
// totp.Validate alone has no anti-replay: with the library's default
// Skew:1, a valid code is accepted across a ~90-second sliding window with
// nothing preventing the same captured code from being replayed multiple
// times within it. Recording the last-consumed step and rejecting any
// validation whose step is not strictly greater closes that gap.
const ddlTOTPLastStep = `
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last_step BIGINT;`

// Argon2id password hashing with an HMAC-SHA256 server-side pepper.
//
// # Format
//
// Encoded hashes use the standard PHC string:
//
//	$argon2id$v=19$m=65536,t=3,p=4$<salt-b64>$<hash-b64>
//
// stored in users.password_hash (TEXT). The encoding is portable across
// Go / Python / JS argon2 libraries.
//
// # Pepper
//
// The pepper is a server-side secret that is HMAC-SHA256'd with the
// plaintext before the result is fed into Argon2id. This means a DB
// dump alone is not enough to crack passwords offline — the attacker
// also needs the pepper, which lives in a secrets manager / env var
// (CYBERPATH_AUTH_PEPPER), never in the database.
//
// HMAC is used (not raw concatenation) so the Argon2id input has a
// fixed length and uniform entropy regardless of the plaintext shape.
//
// # Pepper rotation procedure
//
// Peppers MUST be rotatable without forcing every user to reset.
// Procedure:
//
//  1. Generate the new pepper (32 bytes random, base64-encode it).
//  2. Deploy with both peppers configured: the new one as the active
//     verifier+hasher, the old one as the fallback. The Verifier tries
//     the new pepper first; on mismatch it tries the old, and on a
//     successful old-pepper match it transparently re-hashes the
//     password with the new pepper and persists the new encoded value
//     (silent rehash, same flow as NeedsRehash on Argon2id parameter
//     upgrades).
//  3. Wait at least one full login cycle for your population (in
//     practice: 90 days covers >99% of active users; force a password
//     reset for accounts that have not logged in by the cutoff).
//  4. Remove the old pepper from configuration.
//
// During step 2 BOTH peppers exist in memory. The old pepper SHOULD
// continue to live in the secrets manager (not just the env) so a
// rollback during the rotation window is possible.
//
// # Failure modes
//
// VerifyPassword returns (false, nil) on mismatch and (false, err)
// only when the encoded string is malformed. Callers MUST treat both
// as authentication failure but only log the err case as a warning
// — the mismatch case is normal user error.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. Tuned for ~64 MiB / ~50ms on commodity hardware.
// OWASP Password Storage Cheat Sheet (2024) recommended floor.
const (
	argonMemoryKiB  uint32 = 64 * 1024
	argonIterations uint32 = 3
	argonParallel   uint8  = 4
	argonSaltLen           = 16
	argonKeyLen     uint32 = 32
	argonVariant           = "argon2id"
	argonVersion           = argon2.Version // 0x13 / 19
)

// ErrMalformedHash is returned by VerifyPassword / NeedsRehash when the
// encoded string is not a valid PHC argon2id string.
var ErrMalformedHash = errors.New("auth: malformed password hash")

// HashPassword returns a PHC-formatted argon2id hash of pw. The pepper
// is mixed in via HMAC-SHA256 before Argon2id runs. A non-nil error
// indicates a salt-generation failure (extremely rare).
func HashPassword(pw string, pepper []byte) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: salt: %w", err)
	}
	digest := argon2.IDKey(
		peppered(pw, pepper),
		salt,
		argonIterations,
		argonMemoryKiB,
		argonParallel,
		argonKeyLen,
	)
	return encodeHash(salt, digest, argonMemoryKiB, argonIterations, argonParallel), nil
}

// VerifyPassword constant-time-compares pw against an encoded PHC hash.
// Returns (true, nil) on match, (false, nil) on mismatch, (false, err)
// only on parse failure. The pepper is the same value used at hash time.
func VerifyPassword(encoded, pw string, pepper []byte) (bool, error) {
	mem, iters, par, salt, want, err := decodeHash(encoded)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey(
		peppered(pw, pepper),
		salt,
		iters, mem, par,
		uint32(len(want)),
	)
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// VerifyPasswordWithFallback verifies pw against encoded using the
// primary pepper first, then (on mismatch) the previous pepper. The
// needsRehash flag is true when the primary pepper failed but the
// previous pepper succeeded — callers SHOULD then re-hash the password
// with the primary pepper and persist the new encoded value (silent
// rehash, see the package doc-comment "Pepper rotation procedure").
//
// Behaviour matrix:
//
//	primary OK                        → (true,  false, nil)
//	primary mismatch, previous OK     → (true,  true,  nil)
//	both mismatch                     → (false, false, nil)
//	parse error                       → (false, false, err)
//
// Passing a nil/empty previous slice collapses to plain VerifyPassword
// against primary.
func VerifyPasswordWithFallback(encoded, pw string, primary, previous []byte) (verified bool, needsRehash bool, err error) {
	ok, vErr := VerifyPassword(encoded, pw, primary)
	if vErr != nil {
		return false, false, vErr
	}
	if ok {
		return true, false, nil
	}
	if len(previous) == 0 {
		return false, false, nil
	}
	ok2, vErr := VerifyPassword(encoded, pw, previous)
	if vErr != nil {
		return false, false, vErr
	}
	if ok2 {
		return true, true, nil
	}
	return false, false, nil
}

// NeedsRehash reports whether encoded was produced with parameters
// weaker than the package's current targets. Malformed strings return
// true so the next successful login upgrades the row.
func NeedsRehash(encoded string) bool {
	mem, iters, par, _, hash, err := decodeHash(encoded)
	if err != nil {
		return true
	}
	if mem < argonMemoryKiB || iters < argonIterations || par < argonParallel {
		return true
	}
	if uint32(len(hash)) < argonKeyLen {
		return true
	}
	return false
}

// peppered returns HMAC-SHA256(pepper, plaintext). When pepper is empty
// the function falls back to the raw plaintext bytes so that local-dev
// configs without a configured pepper still work; production gating in
// config.Validate refuses to start without a pepper.
func peppered(pw string, pepper []byte) []byte {
	if len(pepper) == 0 {
		return []byte(pw)
	}
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(pw))
	return mac.Sum(nil)
}

func encodeHash(salt, digest []byte, mem, iters uint32, par uint8) string {
	return fmt.Sprintf(
		"$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argonVariant, argonVersion,
		mem, iters, par,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	)
}

func decodeHash(encoded string) (mem, iters uint32, par uint8, salt, hash []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != argonVariant {
		err = ErrMalformedHash
		return
	}
	var version int
	if _, e := fmt.Sscanf(parts[2], "v=%d", &version); e != nil || version != argonVersion {
		err = fmt.Errorf("%w: bad version %q", ErrMalformedHash, parts[2])
		return
	}
	if _, e := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &iters, &par); e != nil {
		err = fmt.Errorf("%w: bad params: %v", ErrMalformedHash, e)
		return
	}
	if salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		err = fmt.Errorf("%w: salt: %v", ErrMalformedHash, err)
		return
	}
	if hash, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil {
		err = fmt.Errorf("%w: hash: %v", ErrMalformedHash, err)
		return
	}
	return
}

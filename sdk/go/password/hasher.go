package password

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

// Constants defining the wire format.
const (
	variant     = "argon2id"
	encVersion  = argon2.Version // 0x13 / 19
	saltSize    = 16             // bytes
	defaultKey  = 32             // bytes
	pepperMinBytes = 16          // 128 bits of pepper entropy recommended
)

// Params tunes Argon2id's memory/time/parallelism cost.
//
// Defaults come from OWASP Password Storage Cheat Sheet (2024 review):
// 64 MiB RAM, 3 iterations, 1 lane. This clocks at roughly 50 ms on a
// commodity x86-64 server CPU and moves the attack cost on a leaked DB
// into the tens of thousands of USD per brute-forced password.
type Params struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	KeyLen      uint32 // output hash length in bytes
}

// Default returns the recommended Argon2id parameters.
func Default() Params {
	return Params{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 1,
		KeyLen:      defaultKey,
	}
}

// Hasher hashes and verifies secrets with Argon2id + an HMAC-SHA256 pepper.
// A Hasher is safe for concurrent use.
type Hasher struct {
	pepper []byte
	params Params
}

// Option configures a Hasher at construction time.
type Option func(*Hasher)

// WithParams overrides the Argon2id cost parameters.
func WithParams(p Params) Option {
	return func(h *Hasher) {
		if p.Memory > 0 {
			h.params.Memory = p.Memory
		}
		if p.Iterations > 0 {
			h.params.Iterations = p.Iterations
		}
		if p.Parallelism > 0 {
			h.params.Parallelism = p.Parallelism
		}
		if p.KeyLen > 0 {
			h.params.KeyLen = p.KeyLen
		}
	}
}

// ErrEmptyPepper is returned when NewHasher is called without a pepper.
var ErrEmptyPepper = errors.New("password: pepper must not be empty")

// ErrShortPepper is returned when the pepper has fewer than 16 bytes of
// material; Hasher refuses to run in this case because a short pepper
// offers little resistance to offline brute force if the DB is stolen.
var ErrShortPepper = errors.New("password: pepper too short (need >= 16 bytes)")

// ErrMalformedHash is returned when Verify or NeedsRehash is given a
// string that does not match the PHC Argon2id format.
var ErrMalformedHash = errors.New("password: malformed encoded hash")

// NewHasher constructs a Hasher. The pepper must be at least 16 bytes of
// high-entropy material (a random 32-byte base64 string is a good default).
// It should live in a secret manager or env var, never in the database.
func NewHasher(pepper string, opts ...Option) (*Hasher, error) {
	if pepper == "" {
		return nil, ErrEmptyPepper
	}
	if len(pepper) < pepperMinBytes {
		return nil, ErrShortPepper
	}
	h := &Hasher{
		pepper: []byte(pepper),
		params: Default(),
	}
	for _, opt := range opts {
		opt(h)
	}
	return h, nil
}

// Hash returns a PHC-formatted encoded hash of plain. The return value is
// safe to store in a database as an ordinary VARCHAR(128) column.
func (h *Hasher) Hash(plain string) (string, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: salt: %w", err)
	}
	digest := argon2.IDKey(
		h.peppered([]byte(plain)),
		salt,
		h.params.Iterations,
		h.params.Memory,
		h.params.Parallelism,
		h.params.KeyLen,
	)
	return encode(h.params, salt, digest), nil
}

// Verify checks a plaintext value against an encoded PHC string. It returns
// (true, nil) when the password matches, (false, nil) when it does not,
// and (false, err) only when the encoded string is malformed.
//
// The comparison is constant-time: Verify's runtime does not leak which
// byte of the hash mismatched.
func (h *Hasher) Verify(plain, encoded string) (bool, error) {
	params, salt, want, err := decode(encoded)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey(
		h.peppered([]byte(plain)),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		uint32(len(want)),
	)
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// NeedsRehash reports whether encoded was produced with parameters weaker
// than the current configuration — e.g. an older deployment with Memory=16
// MiB when the current policy is 64 MiB. Callers should run this after a
// successful Verify and, when true, re-hash the plaintext and persist the
// new encoded value.
//
// Any malformed encoded string returns true so that the next successful
// login upgrades the record out of the corrupt state.
func (h *Hasher) NeedsRehash(encoded string) bool {
	params, _, _, err := decode(encoded)
	if err != nil {
		return true
	}
	return params.Memory < h.params.Memory ||
		params.Iterations < h.params.Iterations ||
		params.Parallelism < h.params.Parallelism ||
		params.KeyLen < h.params.KeyLen
}

// peppered returns HMAC-SHA256(pepper, plaintext). Using HMAC instead of a
// raw concatenation guarantees that the Argon2id input has a fixed length
// and uniform entropy regardless of the plaintext length or structure.
func (h *Hasher) peppered(plain []byte) []byte {
	mac := hmac.New(sha256.New, h.pepper)
	mac.Write(plain)
	return mac.Sum(nil)
}

// encode produces the canonical PHC string:
//
//	$argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>
//
// Using RawStdEncoding matches what argon2-cffi (Python) and
// argon2-browser (JS) emit, so stored hashes are cross-language portable.
func encode(p Params, salt, digest []byte) string {
	return fmt.Sprintf(
		"$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		variant, encVersion,
		p.Memory, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	)
}

// decode parses a PHC Argon2id string. A return path that produces a nil
// error also guarantees that params.KeyLen == len(hash).
func decode(encoded string) (Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != variant {
		return Params{}, nil, nil, ErrMalformedHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != encVersion {
		return Params{}, nil, nil, fmt.Errorf("%w: unsupported version %q", ErrMalformedHash, parts[2])
	}

	var p Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: params: %v", ErrMalformedHash, err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: salt: %v", ErrMalformedHash, err)
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: hash: %v", ErrMalformedHash, err)
	}

	p.KeyLen = uint32(len(hash))
	return p, salt, hash, nil
}

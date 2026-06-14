package password

import (
	"errors"
	"strings"
	"testing"
)

// testPepper is 32 random bytes of base64 — representative of what a secret
// manager would hand us in prod.
const testPepper = "test-pepper-32-bytes-of-unit-entropy-here"

// fastParams keep each Argon2id round under ~5 ms so the test suite stays
// snappy. Prod uses Default() (64 MiB / t=3) which is ~50 ms.
func fastParams() Params {
	return Params{
		Memory:      8 * 1024, // 8 MiB
		Iterations:  1,
		Parallelism: 1,
		KeyLen:      32,
	}
}

func newFastHasher(t *testing.T) *Hasher {
	t.Helper()
	h, err := NewHasher(testPepper, WithParams(fastParams()))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// -------------------- constructor --------------------

func TestNewHasher_RejectsEmptyPepper(t *testing.T) {
	_, err := NewHasher("")
	if !errors.Is(err, ErrEmptyPepper) {
		t.Fatalf("err = %v, want ErrEmptyPepper", err)
	}
}

func TestNewHasher_RejectsShortPepper(t *testing.T) {
	_, err := NewHasher("too-short")
	if !errors.Is(err, ErrShortPepper) {
		t.Fatalf("err = %v, want ErrShortPepper", err)
	}
}

func TestNewHasher_AcceptsAdequatePepper(t *testing.T) {
	if _, err := NewHasher(testPepper); err != nil {
		t.Fatal(err)
	}
}

// -------------------- hash/verify round-trip --------------------

func TestHashVerify_Roundtrip(t *testing.T) {
	h := newFastHasher(t)
	encoded, err := h.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$") {
		t.Errorf("encoded = %q, want canonical PHC format", encoded)
	}
	ok, err := h.Verify("correct horse battery staple", encoded)
	if err != nil || !ok {
		t.Fatalf("Verify = (%v, %v), want (true, nil)", ok, err)
	}
}

func TestVerify_WrongPasswordFalse(t *testing.T) {
	h := newFastHasher(t)
	encoded, _ := h.Hash("swordfish")
	ok, err := h.Verify("tunafish", encoded)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if ok {
		t.Error("Verify returned true for wrong password")
	}
}

func TestVerify_WrongPepperFalse(t *testing.T) {
	h1, _ := NewHasher(testPepper, WithParams(fastParams()))
	h2, _ := NewHasher("different-pepper-also-long-enough", WithParams(fastParams()))

	encoded, _ := h1.Hash("same-password")
	ok, err := h2.Verify("same-password", encoded)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if ok {
		t.Error("hash should not verify under a different pepper — DB leak defence is broken")
	}
}

func TestHash_UniqueSaltPerCall(t *testing.T) {
	h := newFastHasher(t)
	a, _ := h.Hash("same-input")
	b, _ := h.Hash("same-input")
	if a == b {
		t.Error("two calls with the same password produced identical hashes — salt is not random")
	}
}

// -------------------- malformed input --------------------

func TestVerify_RejectsMalformed(t *testing.T) {
	h := newFastHasher(t)
	cases := []string{
		"",
		"not-a-phc-string",
		"$argon2id$only-two$parts",
		"$bcrypt$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=99$m=65536,t=3,p=1$c2FsdA$aGFzaA", // wrong version
		"$argon2id$v=19$memory=a,t=3,p=1$c2FsdA$aGFzaA", // wrong param format
		"$argon2id$v=19$m=65536,t=3,p=1$!!notbase64!!$aGFzaA",
	}
	for _, enc := range cases {
		_, err := h.Verify("x", enc)
		if !errors.Is(err, ErrMalformedHash) {
			t.Errorf("Verify(%q): err = %v, want ErrMalformedHash", enc, err)
		}
	}
}

// -------------------- NeedsRehash --------------------

func TestNeedsRehash_DetectsWeakerParams(t *testing.T) {
	weak, _ := NewHasher(testPepper, WithParams(Params{
		Memory: 4 * 1024, Iterations: 1, Parallelism: 1, KeyLen: 32,
	}))
	current, _ := NewHasher(testPepper, WithParams(Params{
		Memory: 8 * 1024, Iterations: 2, Parallelism: 1, KeyLen: 32,
	}))

	weakHash, _ := weak.Hash("x")
	if !current.NeedsRehash(weakHash) {
		t.Error("current hasher should flag a weaker-param hash for rehash")
	}
}

func TestNeedsRehash_AcceptsEqualParams(t *testing.T) {
	h := newFastHasher(t)
	encoded, _ := h.Hash("x")
	if h.NeedsRehash(encoded) {
		t.Error("hash produced with current params should not need rehash")
	}
}

func TestNeedsRehash_TrueForCorrupt(t *testing.T) {
	h := newFastHasher(t)
	if !h.NeedsRehash("corrupt") {
		t.Error("malformed hashes should be flagged for rehash — next login upgrades the record")
	}
}

// -------------------- cross-language format stability --------------------

// TestEncoding_MatchesPHC ensures the output string format stays compatible
// with argon2-cffi (Python) and argon2-browser (JS) so hashes written by
// one SDK language can be verified by another.
func TestEncoding_MatchesPHC(t *testing.T) {
	h := newFastHasher(t)
	encoded, _ := h.Hash("x")
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		t.Fatalf("parts = %d, want 6 (leading empty + algo + version + params + salt + hash)", len(parts))
	}
	if parts[1] != "argon2id" {
		t.Errorf("algo = %q, want argon2id", parts[1])
	}
	if !strings.HasPrefix(parts[2], "v=") {
		t.Errorf("version field = %q, want v=N", parts[2])
	}
	if !strings.Contains(parts[3], "m=") ||
		!strings.Contains(parts[3], "t=") ||
		!strings.Contains(parts[3], "p=") {
		t.Errorf("params field = %q, want m=N,t=N,p=N", parts[3])
	}
}

package webhook

import (
	"errors"
	"strconv"
	"testing"
	"time"
)

const testSecret = "super-secret-shared-key"

func TestNewVerifier_RejectsEmptySecret(t *testing.T) {
	_, err := NewVerifier("", 0)
	if !errors.Is(err, ErrEmptySecret) {
		t.Fatalf("err = %v, want ErrEmptySecret", err)
	}
}

func TestVerify_HappyPath(t *testing.T) {
	v, err := NewVerifier(testSecret, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"event":"hello"}`)
	now := time.Now()
	v.now = func() time.Time { return now }

	ts := now.Unix()
	sig := Sign(testSecret, ts, body)

	if err := v.Verify(body, sig, itoa(ts)); err != nil {
		t.Fatalf("Verify returned %v, want nil", err)
	}
}

func TestVerify_RejectsTamperedBody(t *testing.T) {
	v, _ := NewVerifier(testSecret, 5*time.Minute)
	now := time.Now()
	v.now = func() time.Time { return now }

	ts := now.Unix()
	sig := Sign(testSecret, ts, []byte(`{"a":1}`))

	// Attacker modifies body but reuses the signature.
	err := v.Verify([]byte(`{"a":2}`), sig, itoa(ts))
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("err = %v, want ErrInvalidSignature", err)
	}
}

func TestVerify_RejectsWrongSecret(t *testing.T) {
	v, _ := NewVerifier(testSecret, 5*time.Minute)
	now := time.Now()
	v.now = func() time.Time { return now }

	ts := now.Unix()
	sig := Sign("different-secret", ts, []byte(`{"a":1}`))

	err := v.Verify([]byte(`{"a":1}`), sig, itoa(ts))
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("err = %v, want ErrInvalidSignature", err)
	}
}

func TestVerify_RejectsStaleTimestamp(t *testing.T) {
	v, _ := NewVerifier(testSecret, 1*time.Minute)
	now := time.Now()
	v.now = func() time.Time { return now }

	// Timestamp 10 minutes in the past — well outside the 1-minute window.
	oldTS := now.Add(-10 * time.Minute).Unix()
	body := []byte(`{"a":1}`)
	sig := Sign(testSecret, oldTS, body)

	err := v.Verify(body, sig, itoa(oldTS))
	if !errors.Is(err, ErrStaleTimestamp) {
		t.Fatalf("err = %v, want ErrStaleTimestamp", err)
	}
}

func TestVerify_RejectsFutureTimestampOutsideWindow(t *testing.T) {
	v, _ := NewVerifier(testSecret, 1*time.Minute)
	now := time.Now()
	v.now = func() time.Time { return now }

	futureTS := now.Add(10 * time.Minute).Unix()
	body := []byte(`{"a":1}`)
	sig := Sign(testSecret, futureTS, body)

	err := v.Verify(body, sig, itoa(futureTS))
	if !errors.Is(err, ErrStaleTimestamp) {
		t.Fatalf("err = %v, want ErrStaleTimestamp", err)
	}
}

func TestVerify_RejectsMissingHeaders(t *testing.T) {
	v, _ := NewVerifier(testSecret, 5*time.Minute)

	if err := v.Verify([]byte(`{}`), "", "1700000000"); !errors.Is(err, ErrMissingSignature) {
		t.Errorf("missing sig: err = %v, want ErrMissingSignature", err)
	}
	if err := v.Verify([]byte(`{}`), "sha256=deadbeef", ""); !errors.Is(err, ErrMissingTimestamp) {
		t.Errorf("missing ts: err = %v, want ErrMissingTimestamp", err)
	}
}

func TestVerify_RejectsInvalidTimestamp(t *testing.T) {
	v, _ := NewVerifier(testSecret, 5*time.Minute)
	err := v.Verify([]byte(`{}`), "sha256=deadbeef", "not-a-number")
	if !errors.Is(err, ErrInvalidTimestamp) {
		t.Fatalf("err = %v, want ErrInvalidTimestamp", err)
	}
}

func TestVerify_SignaturePrefixOptional(t *testing.T) {
	// Callers sometimes strip the "sha256=" prefix — verifier must accept both.
	v, _ := NewVerifier(testSecret, 5*time.Minute)
	now := time.Now()
	v.now = func() time.Time { return now }

	ts := now.Unix()
	body := []byte(`{"a":1}`)
	full := Sign(testSecret, ts, body)

	// Strip prefix.
	raw := full[len(SignaturePrefix):]
	if err := v.Verify(body, raw, itoa(ts)); err != nil {
		t.Fatalf("raw hex signature rejected: %v", err)
	}
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}

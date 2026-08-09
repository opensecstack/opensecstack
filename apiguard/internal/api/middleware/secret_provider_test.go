package middleware

import (
	"bytes"
	"testing"
)

func TestNewSecretProvider(t *testing.T) {
	t.Run("single secret", func(t *testing.T) {
		sp := NewSecretProvider("secret-a")
		if sp.Len() != 1 {
			t.Fatalf("Len() = %d, want 1", sp.Len())
		}
		if !bytes.Equal(sp.Current(), []byte("secret-a")) {
			t.Fatalf("Current() = %q, want secret-a", sp.Current())
		}
	})

	t.Run("multiple secrets preserve order", func(t *testing.T) {
		sp := NewSecretProvider("active", "old1", "old2")
		if sp.Len() != 3 {
			t.Fatalf("Len() = %d, want 3", sp.Len())
		}
		if !bytes.Equal(sp.Current(), []byte("active")) {
			t.Fatalf("Current() = %q, want active", sp.Current())
		}
		all := sp.All()
		want := [][]byte{[]byte("active"), []byte("old1"), []byte("old2")}
		if len(all) != len(want) {
			t.Fatalf("All() len = %d, want %d", len(all), len(want))
		}
		for i := range want {
			if !bytes.Equal(all[i], want[i]) {
				t.Errorf("All()[%d] = %q, want %q", i, all[i], want[i])
			}
		}
	})

	t.Run("empty strings ignored", func(t *testing.T) {
		sp := NewSecretProvider("", "real", "")
		if sp.Len() != 1 {
			t.Fatalf("Len() = %d, want 1 (empty strings should be dropped)", sp.Len())
		}
		if !bytes.Equal(sp.Current(), []byte("real")) {
			t.Fatalf("Current() = %q, want real", sp.Current())
		}
	})

	t.Run("no secrets", func(t *testing.T) {
		sp := NewSecretProvider()
		if sp.Len() != 0 {
			t.Fatalf("Len() = %d, want 0", sp.Len())
		}
		if sp.Current() != nil {
			t.Fatalf("Current() = %v, want nil", sp.Current())
		}
	})
}

func TestSecretProvider_Rotate(t *testing.T) {
	sp := NewSecretProvider("original")

	sp.Rotate([]byte("new-key"))

	if !bytes.Equal(sp.Current(), []byte("new-key")) {
		t.Fatalf("Current() after rotate = %q, want new-key", sp.Current())
	}
	if sp.Len() != 2 {
		t.Fatalf("Len() after one rotate = %d, want 2", sp.Len())
	}
	all := sp.All()
	if !bytes.Equal(all[1], []byte("original")) {
		t.Fatalf("demoted secret = %q, want original", all[1])
	}
}

func TestSecretProvider_RotateDropsBeyondMax(t *testing.T) {
	sp := NewSecretProvider("s1")
	sp.Rotate([]byte("s2"))
	sp.Rotate([]byte("s3"))
	sp.Rotate([]byte("s4")) // should push out "s1"

	if sp.Len() != maxSecrets {
		t.Fatalf("Len() = %d, want %d (max secrets)", sp.Len(), maxSecrets)
	}
	all := sp.All()
	want := [][]byte{[]byte("s4"), []byte("s3"), []byte("s2")}
	for i := range want {
		if !bytes.Equal(all[i], want[i]) {
			t.Errorf("All()[%d] = %q, want %q", i, all[i], want[i])
		}
	}
	for _, s := range all {
		if bytes.Equal(s, []byte("s1")) {
			t.Fatal("oldest secret s1 should have been evicted after exceeding maxSecrets")
		}
	}
}

func TestSecretProvider_AllReturnsIndependentSlice(t *testing.T) {
	sp := NewSecretProvider("original", "grace")
	all := sp.All()
	all[0] = []byte("tampered") // reassign an element in the returned slice

	// Reassigning an element of the returned slice must not affect the
	// provider's internal state (All() copies the outer slice).
	if !bytes.Equal(sp.Current(), []byte("original")) {
		t.Fatalf("Current() = %q, want original (internal state must be unaffected by mutating All()'s result)", sp.Current())
	}
}

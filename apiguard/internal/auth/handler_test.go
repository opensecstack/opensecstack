package auth

import (
	"strings"
	"sync"
	"testing"
)

func TestNewHandler_NilSecret_GeneratesRandom(t *testing.T) {
	h, err := NewHandler(Config{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(h.secret) != 32 {
		t.Errorf("expected 32-byte secret, got %d bytes", len(h.secret))
	}
}

func TestNewHandler_ProvidedSecret_UsedAsIs(t *testing.T) {
	provided := []byte("my-fixed-test-secret-1234567890!")
	h, err := NewHandler(Config{}, provided)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(h.secret) != string(provided) {
		t.Errorf("expected secret %q, got %q", provided, h.secret)
	}
}

func TestGetConfig_ReturnsSetConfig(t *testing.T) {
	cfg := Config{
		Type:  TokenTypeBearer,
		Token: "my-token",
	}
	h, err := NewHandler(cfg, []byte("secret"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := h.GetConfig()
	if got.Type != cfg.Type {
		t.Errorf("expected type %q, got %q", cfg.Type, got.Type)
	}
	if got.Token != cfg.Token {
		t.Errorf("expected token %q, got %q", cfg.Token, got.Token)
	}
}

func TestGenerateOtherUserToken_NonEmptyValidJWT(t *testing.T) {
	h, err := NewHandler(Config{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	token, err := h.GenerateOtherUserToken("some-subject")
	if err != nil {
		t.Fatalf("unexpected error generating token: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Errorf("expected JWT with 3 parts separated by '.', got %d parts", len(parts))
	}
	for i, p := range parts {
		if p == "" {
			t.Errorf("JWT part %d is empty", i)
		}
	}
}

func TestGenerateOtherUserToken_Concurrent(t *testing.T) {
	h, err := NewHandler(Config{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errors := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			_, err := h.GenerateOtherUserToken("user")
			if err != nil {
				errors <- err
			}
		}(i)
	}
	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent GenerateOtherUserToken error: %v", err)
	}
}

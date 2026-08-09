package middleware

import "testing"

func TestNewLimiter_EmptyRedisURLFallsBackToInMemory(t *testing.T) {
	l := NewLimiter("", "", 0, 10, "test", nil, 1)
	defer l.Stop()

	if _, ok := l.(*RateLimiter); !ok {
		t.Fatalf("NewLimiter with empty redisURL = %T, want *RateLimiter", l)
	}
}

func TestNewLimiter_DefaultLocalhostURLFallsBackToInMemory(t *testing.T) {
	// The factory explicitly special-cases the default localhost URL so a
	// dev machine without Redis running doesn't hang on Ping.
	l := NewLimiter("redis://localhost:6379", "", 0, 10, "test", nil, 1)
	defer l.Stop()

	if _, ok := l.(*RateLimiter); !ok {
		t.Fatalf("NewLimiter with default redis URL = %T, want *RateLimiter", l)
	}
}

func TestNewLimiter_UnreachableRedisFallsBackToInMemory(t *testing.T) {
	// Port 1 is a non-default URL that will not have Redis listening, so
	// NewRedisRateLimiter's Ping should fail and NewLimiter should fall back.
	l := NewLimiter("redis://127.0.0.1:1", "", 0, 10, "test", nil, 1)
	defer l.Stop()

	if _, ok := l.(*RateLimiter); !ok {
		t.Fatalf("NewLimiter with unreachable redis URL = %T, want *RateLimiter", l)
	}
}

func TestNewLimiter_InvalidRedisURLFallsBackToInMemory(t *testing.T) {
	l := NewLimiter("not-a-valid-url", "", 0, 10, "test", nil, 1)
	defer l.Stop()

	if _, ok := l.(*RateLimiter); !ok {
		t.Fatalf("NewLimiter with invalid redis URL = %T, want *RateLimiter", l)
	}
}

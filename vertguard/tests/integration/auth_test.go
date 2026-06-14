package integration

import (
	"net/http"
	"testing"
	"time"

	"github.com/opensecstack/vertguard/internal/auth"
)

func TestAuth_NoToken(t *testing.T) {
	env := setupServer(t, false)
	defer env.cleanup()

	resp := doRequest(t, env, http.MethodPost, "/api/v1/prompt/scan", "", `{"input":"hi"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAuth_Malformed(t *testing.T) {
	env := setupServer(t, false)
	defer env.cleanup()

	resp := doRequest(t, env, http.MethodPost, "/api/v1/prompt/scan", "not.a.token", `{"input":"hi"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAuth_ViewerCannotScan(t *testing.T) {
	env := setupServer(t, false)
	defer env.cleanup()

	tok := mintToken(t, auth.RoleViewer, time.Hour)
	resp := doRequest(t, env, http.MethodPost, "/api/v1/prompt/scan", tok, `{"input":"hi"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer status = %d, want 403", resp.StatusCode)
	}
}

func TestAuth_OperatorCanScan(t *testing.T) {
	env := setupServer(t, false)
	defer env.cleanup()

	tok := mintToken(t, auth.RoleOperator, time.Hour)
	resp := doRequest(t, env, http.MethodPost, "/api/v1/prompt/scan", tok, `{"input":"hello world"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("operator status = %d, want 200", resp.StatusCode)
	}
}

func TestAuth_ExpiredToken(t *testing.T) {
	env := setupServer(t, false)
	defer env.cleanup()

	tok := mintToken(t, auth.RoleOperator, -time.Hour)
	resp := doRequest(t, env, http.MethodPost, "/api/v1/prompt/scan", tok, `{"input":"hi"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired status = %d, want 401", resp.StatusCode)
	}
}

func TestAuth_Rotation_DualSecrets(t *testing.T) {
	const (
		primary = "primary-rotation-secret-32-bytes-aaaaaaaaa"
		next    = "next-rotation-secret-32-bytes-min-bbbbbbbbb"
	)

	t.Run("primary still works", func(t *testing.T) {
		env := setupServerMultiSecret(t, primary, next)
		defer env.cleanup()

		tok := mintTokenWithSecret(t, primary, auth.RoleOperator, time.Hour)
		resp := doRequest(t, env, http.MethodPost, "/api/v1/prompt/scan", tok, `{"input":"hello"}`)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("primary status = %d, want 200", resp.StatusCode)
		}
	})

	t.Run("next is accepted", func(t *testing.T) {
		env := setupServerMultiSecret(t, primary, next)
		defer env.cleanup()

		tok := mintTokenWithSecret(t, next, auth.RoleOperator, time.Hour)
		resp := doRequest(t, env, http.MethodPost, "/api/v1/prompt/scan", tok, `{"input":"hello"}`)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("next-secret status = %d, want 200", resp.StatusCode)
		}
	})

	t.Run("foreign secret rejected", func(t *testing.T) {
		env := setupServerMultiSecret(t, primary, next)
		defer env.cleanup()

		tok := mintTokenWithSecret(t, "totally-different-secret-zzzzzzzzzzzz", auth.RoleOperator, time.Hour)
		resp := doRequest(t, env, http.MethodPost, "/api/v1/prompt/scan", tok, `{"input":"hello"}`)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("foreign-secret status = %d, want 401", resp.StatusCode)
		}
	})
}

func TestAuth_DevModeBypass(t *testing.T) {
	env := setupServer(t, true)
	defer env.cleanup()

	resp := doRequest(t, env, http.MethodPost, "/api/v1/prompt/scan", "", `{"input":"hi"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dev-mode status = %d, want 200", resp.StatusCode)
	}
}

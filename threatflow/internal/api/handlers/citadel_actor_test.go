package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/threatflow/internal/api/middleware"
	"github.com/opensecstack/threatflow/internal/auth"
)

// TestActorFromRequest_SinauthIdentityForwardsUserIDAndToken proves the
// call-site bug this task fixes stays fixed: when the caller authenticated
// via a real sinauth RS256 token, actorFromRequest must produce a non-empty,
// non-zero-value Actor.UserID (the sinauth UUID subject) AND forward the raw
// bearer token, so the Kerkese submitted to CITADEL carries genuine identity
// evidence instead of a zero value (see citadel adrs/005-sinauth-identity-bridge.md,
// which calls out apiguard's prior `Actor.UserID: 0` bug as the pattern to
// avoid; ThreatFlow's Evaluate() previously never set Actor.UserID at all).
func TestActorFromRequest_SinauthIdentityForwardsUserIDAndToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/iocs", nil)
	req.Header.Set("Authorization", "Bearer real-sinauth-jwt")
	id := &auth.Identity{
		Subject: "3f2e1a4c-5b6d-4e7f-8a9b-0c1d2e3f4a5b", // sinauth UUID
		Role:    auth.RoleOperator,
		Source:  "sinauth",
	}
	req = req.WithContext(middleware.ContextWithIdentity(req.Context(), id))

	actorUserID, actorRole, actorToken := actorFromRequest(req)

	if actorUserID == "" || actorUserID == "unauthenticated" {
		t.Fatalf("want non-empty, non-placeholder Actor.UserID, got %q", actorUserID)
	}
	if actorUserID != id.Subject {
		t.Errorf("Actor.UserID = %q, want sinauth subject %q", actorUserID, id.Subject)
	}
	if actorRole != string(auth.RoleOperator) {
		t.Errorf("Actor.Role = %q, want %q", actorRole, auth.RoleOperator)
	}
	if actorToken != "real-sinauth-jwt" {
		t.Errorf("ActorToken = %q, want the forwarded bearer token", actorToken)
	}
}

// TestActorFromRequest_APIKeyFallbackLeavesTokenEmpty proves the other half
// of the contract: ThreatFlow's own API-key/HS256 fallback identity has no
// real sinauth token behind it, so ActorToken must stay empty rather than
// forwarding a token that would fail verification (or worse, being
// fabricated). Actor.UserID must still be non-empty — the apikey/bootstrap
// subject is a real, if not sinauth-bridged, identity.
func TestActorFromRequest_APIKeyFallbackLeavesTokenEmpty(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/iocs", nil)
	req.Header.Set("Authorization", "Bearer some-hs256-jwt")
	id := &auth.Identity{
		Subject: "apikey:11111111-2222-3333-4444-555555555555",
		Role:    auth.RoleOperator,
		Source:  "api_key",
	}
	req = req.WithContext(middleware.ContextWithIdentity(req.Context(), id))

	actorUserID, _, actorToken := actorFromRequest(req)

	if actorUserID != id.Subject {
		t.Errorf("Actor.UserID = %q, want %q", actorUserID, id.Subject)
	}
	if actorToken != "" {
		t.Errorf("ActorToken = %q, want empty for non-sinauth fallback identity", actorToken)
	}
}

// TestActorFromRequest_NoIdentityFallsBackToUnauthenticated covers the dev
// mode where auth is disabled entirely (server.go's s.Auth == nil branch) —
// there is no middleware.Identity at all, so the Kerkese must still get a
// well-defined, non-zero-value Actor.UserID rather than an empty string.
func TestActorFromRequest_NoIdentityFallsBackToUnauthenticated(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/iocs", nil)

	actorUserID, actorRole, actorToken := actorFromRequest(req)

	if actorUserID != "unauthenticated" {
		t.Errorf("Actor.UserID = %q, want %q", actorUserID, "unauthenticated")
	}
	if actorRole != "operator" {
		t.Errorf("Actor.Role = %q, want %q", actorRole, "operator")
	}
	if actorToken != "" {
		t.Errorf("ActorToken = %q, want empty", actorToken)
	}
}

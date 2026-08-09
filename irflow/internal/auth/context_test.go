package auth

import (
	"context"
	"testing"
)

func TestWithClaims_ClaimsFromContext_RoundTrip(t *testing.T) {
	c := &Claims{Subject: "u1", Role: RoleOperator}
	ctx := WithClaims(context.Background(), c)

	got := ClaimsFromContext(ctx)
	if got == nil {
		t.Fatal("ClaimsFromContext returned nil, want claims")
	}
	if got.Subject != "u1" || got.Role != RoleOperator {
		t.Errorf("got claims %+v, want Subject=u1 Role=%s", got, RoleOperator)
	}
}

func TestClaimsFromContext_NoClaimsSet(t *testing.T) {
	got := ClaimsFromContext(context.Background())
	if got != nil {
		t.Errorf("ClaimsFromContext(bare context) = %+v, want nil", got)
	}
}

func TestClaimsFromContext_WrongTypeInContext(t *testing.T) {
	// A value stored under the same private key type but the wrong Go type
	// must not be type-asserted successfully -- ClaimsFromContext should
	// return nil rather than panic.
	ctx := context.WithValue(context.Background(), ctxKeyClaims, "not-a-claims-pointer")
	got := ClaimsFromContext(ctx)
	if got != nil {
		t.Errorf("ClaimsFromContext(wrong type) = %+v, want nil", got)
	}
}

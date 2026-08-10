// Tests for IRFlowCohortAdapter.tenantUUID — the only method on that
// adapter with pure logic (no pgx pool access), so it's unit-testable
// without a live DB.
package wireup

import (
	"testing"

	"github.com/google/uuid"
)

func TestTenantUUID_EmptyTenant_NoOverride(t *testing.T) {
	a := &IRFlowCohortAdapter{Tenant: uuid.Nil}
	_, err := a.tenantUUID("")
	if err == nil {
		t.Fatalf("expected error when tenant is empty and no override is configured")
	}
}

func TestTenantUUID_EmptyTenant_UsesOverride(t *testing.T) {
	override := uuid.New()
	a := &IRFlowCohortAdapter{Tenant: override}
	got, err := a.tenantUUID("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != override {
		t.Fatalf("expected override tenant %s, got %s", override, got)
	}
}

func TestTenantUUID_ExplicitTenant_Parsed(t *testing.T) {
	explicit := uuid.New()
	a := &IRFlowCohortAdapter{Tenant: uuid.New()} // override present but must NOT be used
	got, err := a.tenantUUID(explicit.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != explicit {
		t.Fatalf("expected explicit tenant %s to be used over override, got %s", explicit, got)
	}
}

func TestTenantUUID_ExplicitTenant_Invalid(t *testing.T) {
	a := &IRFlowCohortAdapter{Tenant: uuid.New()}
	_, err := a.tenantUUID("not-a-uuid")
	if err == nil {
		t.Fatalf("expected error for malformed tenant string")
	}
}

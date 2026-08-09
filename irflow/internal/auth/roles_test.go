package auth

import "testing"

// canRead/canWrite/canDelete/AllRoles/IsKnownRole are covered by
// TestPermissionMatrix and TestIsKnownRole in jwt_test.go. canApprove has no
// coverage there, so it gets its own test here.
func TestCanApprove(t *testing.T) {
	cases := map[string]bool{
		RoleAdmin:    true,
		RoleOperator: true,
		RoleVerifier: true,
		RoleService:  true,
		RoleViewer:   false,
		"wizard":     false,
	}
	for role, want := range cases {
		if got := canApprove(role); got != want {
			t.Errorf("canApprove(%q) = %v, want %v", role, got, want)
		}
	}
}

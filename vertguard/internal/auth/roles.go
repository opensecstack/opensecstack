// Package auth provides JWT verification and RBAC guards.
//
// VertGuard reuses the same 5-role pattern as IRFlow for
// ecosystem consistency.
package auth

// Role constants. Coarse RBAC; fine-grained scopes can be layered later.
const (
	RoleAdmin    = "admin"    // unrestricted
	RoleOperator = "operator" // scan + trigger + write
	RoleVerifier = "verifier" // verify actions; no write
	RoleViewer   = "viewer"   // read-only
	RoleService  = "service"  // machine-to-machine; equivalent to operator
)

// AllRoles returns the canonical list.
func AllRoles() []string {
	return []string{RoleAdmin, RoleOperator, RoleVerifier, RoleViewer, RoleService}
}

// IsKnownRole reports whether role is one of the canonical roles.
func IsKnownRole(role string) bool {
	for _, r := range AllRoles() {
		if r == role {
			return true
		}
	}
	return false
}

// canRead reports whether a role may call read-only endpoints.
func canRead(role string) bool {
	return IsKnownRole(role)
}

// canWrite reports whether a role may perform scans / mutations.
func canWrite(role string) bool {
	return role == RoleAdmin || role == RoleOperator || role == RoleService
}

// canAdmin reports whether a role may perform admin operations
// (pattern reload, atlas sync, etc.).
func canAdmin(role string) bool {
	return role == RoleAdmin
}

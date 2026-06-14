package auth

// Role constants. RBAC is intentionally coarse — fine-grained scope tokens
// can be layered on later without changing the token format.
const (
	// RoleAdmin has unrestricted access, including delete operations and
	// playbook management.
	RoleAdmin = "admin"

	// RoleOperator drives the incident response. Operators create incidents,
	// patch them, submit actions (as the operator half of SoD), attach IOCs,
	// and author playbooks. They cannot delete resources.
	RoleOperator = "operator"

	// RoleVerifier is the counterparty for Separation of Duties. Verifiers
	// have the same read access as operators and can verify actions, but
	// cannot initiate actions.
	RoleVerifier = "verifier"

	// RoleViewer is read-only. Typical uses: dashboards, auditors, executive
	// summaries.
	RoleViewer = "viewer"

	// RoleService is for machine-to-machine integrations (e.g. internal
	// frontend, playbook scheduler). Equivalent to operator for now.
	RoleService = "service"
)

// AllRoles returns the canonical list for validation.
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
	return role == RoleAdmin || role == RoleOperator || role == RoleVerifier ||
		role == RoleViewer || role == RoleService
}

// canWrite reports whether a role may mutate incidents/playbooks/IOCs.
func canWrite(role string) bool {
	return role == RoleAdmin || role == RoleOperator || role == RoleService
}

// canDelete reports whether a role may delete resources. Intentionally
// narrower than write — operators create, admins delete.
func canDelete(role string) bool {
	return role == RoleAdmin
}

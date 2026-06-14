package handlers

import (
	"net/http"

	"github.com/opensecstack/sinauth/internal/rbac"
)

// --- Group handlers ---

// ListGroups returns all groups.
// GET /admin/rbac/groups
func ListGroups(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		groups, err := d.RBAC.ListGroups(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		writeJSON(w, http.StatusOK, groups)
	}
}

// CreateGroup creates a new group.
// POST /admin/rbac/groups
func CreateGroup(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		if err := decodeJSON(r, &req); err != nil || req.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
			return
		}
		id, err := d.RBAC.CreateGroup(r.Context(), req.Name, req.Description)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create group"})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"id": id})
	}
}

// DeleteGroup removes a group.
// DELETE /admin/rbac/groups/{id}
func DeleteGroup(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := d.RBAC.DeleteGroup(r.Context(), id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "delete failed"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ListGroupMembers returns all members of a group.
// GET /admin/rbac/groups/{id}/members
func ListGroupMembers(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		members, err := d.RBAC.ListGroupMembers(r.Context(), id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		writeJSON(w, http.StatusOK, members)
	}
}

// AddGroupMember adds a user to a group.
// POST /admin/rbac/groups/{id}/members
func AddGroupMember(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		groupID := r.PathValue("id")
		var req struct {
			UserID string `json:"user_id"`
		}
		if err := decodeJSON(r, &req); err != nil || req.UserID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user_id required"})
			return
		}
		if err := d.RBAC.AddGroupMember(r.Context(), groupID, req.UserID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to add member"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// RemoveGroupMember removes a user from a group.
// DELETE /admin/rbac/groups/{id}/members/{userId}
func RemoveGroupMember(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		groupID := r.PathValue("id")
		userID := r.PathValue("userId")
		if err := d.RBAC.RemoveGroupMember(r.Context(), groupID, userID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "remove failed"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- Client Role handlers ---

// ListClientRoles returns all roles defined for a client.
// GET /admin/rbac/clients/{clientId}/roles
func ListClientRoles(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientID := r.PathValue("clientId")
		roles, err := d.RBAC.ListClientRoles(r.Context(), clientID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		writeJSON(w, http.StatusOK, roles)
	}
}

// CreateClientRole defines a new role for a client.
// POST /admin/rbac/clients/{clientId}/roles
func CreateClientRole(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientID := r.PathValue("clientId")
		var req struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		if err := decodeJSON(r, &req); err != nil || req.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
			return
		}
		id, err := d.RBAC.CreateClientRole(r.Context(), clientID, req.Name, req.Description)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create role"})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"id": id})
	}
}

// DeleteClientRole removes a role definition.
// DELETE /admin/rbac/roles/{id}
func DeleteClientRole(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := d.RBAC.DeleteClientRole(r.Context(), id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "delete failed"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// AssignUserRole grants a role to a user for a specific client.
// POST /admin/rbac/users/{userId}/roles
func AssignUserRole(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.PathValue("userId")
		var req struct {
			ClientID string `json:"client_id"`
			RoleName string `json:"role_name"`
		}
		if err := decodeJSON(r, &req); err != nil || req.ClientID == "" || req.RoleName == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "client_id and role_name required"})
			return
		}
		if err := d.RBAC.AssignUserRole(r.Context(), userID, req.ClientID, req.RoleName); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "assign failed"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// RevokeUserRole removes a role from a user.
// DELETE /admin/rbac/users/{userId}/roles
func RevokeUserRole(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.PathValue("userId")
		var req struct {
			ClientID string `json:"client_id"`
			RoleName string `json:"role_name"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := d.RBAC.RevokeUserRole(r.Context(), userID, req.ClientID, req.RoleName); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "revoke failed"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// GetUserEffectiveRoles returns the resolved roles for a user in a given client.
// GET /admin/rbac/users/{userId}/effective-roles?client_id=xxx
func GetUserEffectiveRoles(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.PathValue("userId")
		clientID := r.URL.Query().Get("client_id")
		if clientID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "client_id required"})
			return
		}
		roles, err := d.RBAC.GetEffectiveRoles(r.Context(), userID, clientID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		writeJSON(w, http.StatusOK, map[string][]string{"roles": roles})
	}
}

// AssignGroupRole grants a role to all members of a group for a client.
// POST /admin/rbac/groups/{id}/roles
func AssignGroupRole(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		groupID := r.PathValue("id")
		var req struct {
			ClientID string `json:"client_id"`
			RoleName string `json:"role_name"`
		}
		if err := decodeJSON(r, &req); err != nil || req.ClientID == "" || req.RoleName == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "client_id and role_name required"})
			return
		}
		if err := d.RBAC.AssignGroupRole(r.Context(), groupID, req.ClientID, req.RoleName); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "assign failed"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- Policy handlers ---

// ListPolicies returns all enabled policies.
// GET /admin/rbac/policies
func ListPolicies(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		policies, err := d.RBAC.ListPolicies(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		writeJSON(w, http.StatusOK, policies)
	}
}

// CreatePolicy creates a new policy rule.
// POST /admin/rbac/policies
func CreatePolicy(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var p rbac.Policy
		if err := decodeJSON(r, &p); err != nil || p.Name == "" || p.Type == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and type required"})
			return
		}
		id, err := d.RBAC.CreatePolicy(r.Context(), p)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create policy"})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"id": id})
	}
}

// DeletePolicy removes a policy.
// DELETE /admin/rbac/policies/{id}
func DeletePolicy(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := d.RBAC.DeletePolicy(r.Context(), id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "delete failed"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

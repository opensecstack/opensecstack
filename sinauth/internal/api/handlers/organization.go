package handlers

import (
	"context"
	"net/http"

	"github.com/opensecstack/sinauth/internal/api/middleware"
	"github.com/opensecstack/sinauth/internal/authz"
	"github.com/opensecstack/sinauth/internal/organization"
)

// callerCanManageOrg reports whether the authenticated caller (identified by
// callerUserID, taken from the bearer token's claims) may manage orgID's
// membership through the new self-service delegation path (see
// AddOwnOrganizationMember/RemoveOwnOrganizationMember below). A caller is
// allowed through EITHER because they are a platform admin (checked first,
// since it never depends on Permify/authz.Checker being configured) OR
// because d.Authz.Check reports they hold the organization's "manage"
// permission (owner/admin per the Permify schema's `organization.manage =
// owner or admin`).
//
// Security note (2026-07-29): the org-owner/admin fallback below is ONLY
// consulted when d.Cfg.PermifyEnabled is true, i.e. when SINAUTH_PERMIFY_URL
// is actually set and d.Authz is a real PermifyChecker. When Permify is not
// deployed — the default in this repo's own dev docker-compose today —
// authz.New returns a NoopChecker whose Check unconditionally reports
// (true, nil) for ANY subject/entity. Calling into that Noop here to make a
// real authorization decision would let any authenticated non-admin caller
// grant themselves ownership of an arbitrary organization (or evict its real
// owner) purely because Permify happens not to be wired up — the same
// privilege-escalation bug class fixed same-day in
// adrs/005-organization-identity.md, reopened via this new route. So: with
// Permify not enabled, only the platform-admin check above is authoritative;
// the delegation path denies outright rather than asking a checker that, by
// definition, cannot answer.
func callerCanManageOrg(ctx context.Context, d Deps, callerUserID, orgID string) (bool, error) {
	if d.UserSvc != nil {
		isAdmin, err := d.UserSvc.IsPlatformAdmin(ctx, callerUserID)
		if err == nil && isAdmin {
			return true, nil
		}
	}
	if d.Cfg == nil || !d.Cfg.PermifyEnabled {
		return false, nil
	}
	if d.Authz == nil {
		return false, nil
	}
	return d.Authz.Check(ctx,
		authz.Entity{Type: "user", ID: callerUserID},
		"manage",
		authz.Entity{Type: "organization", ID: orgID},
	)
}

// --- Organization handlers ---

// ListOrganizations returns all organizations.
// GET /admin/organizations
func ListOrganizations(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgs, err := d.OrgSvc.List(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		writeJSON(w, http.StatusOK, orgs)
	}
}

// CreateOrganization creates a new organization.
// POST /admin/organizations
func CreateOrganization(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			LegalName          string `json:"legal_name"`
			Slug               string `json:"slug"`
			OrgType            string `json:"org_type"`
			RegistrationNumber string `json:"registration_number"`
		}
		if err := decodeJSON(r, &req); err != nil || req.LegalName == "" || req.Slug == "" || req.OrgType == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "legal_name, slug and org_type required"})
			return
		}
		org, err := d.OrgSvc.Create(r.Context(), organization.Organization{
			LegalName:          req.LegalName,
			Slug:               req.Slug,
			OrgType:            req.OrgType,
			RegistrationNumber: req.RegistrationNumber,
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create organization"})
			return
		}
		writeJSON(w, http.StatusCreated, org)
	}
}

// GetOrganization returns a single organization.
// GET /admin/organizations/{id}
func GetOrganization(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		org, err := d.OrgSvc.Get(r.Context(), id)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, http.StatusOK, org)
	}
}

// DeleteOrganization removes an organization.
// DELETE /admin/organizations/{id}
func DeleteOrganization(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := d.OrgSvc.Delete(r.Context(), id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "delete failed"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ListOrganizationMembers returns all members of an organization.
// GET /admin/organizations/{id}/members
func ListOrganizationMembers(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		members, err := d.OrgSvc.ListMembers(r.Context(), id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		writeJSON(w, http.StatusOK, members)
	}
}

// AddOrganizationMember adds a user to an organization.
// POST /admin/organizations/{id}/members
//
// Unchanged: still gated purely by RequireAdmin at the route level (see
// server.go) — platform-admin standing only, exactly as before this
// workstream. The new, additive delegation path lives at
// AddOwnOrganizationMember below, on a separate route, so this route's
// reachability never regresses (see that function's doc comment for why a
// separate route was chosen over loosening this one).
func AddOrganizationMember(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("id")
		var req struct {
			UserID string `json:"user_id"`
			Role   string `json:"org_role"`
		}
		if err := decodeJSON(r, &req); err != nil || req.UserID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user_id required"})
			return
		}
		if err := d.OrgSvc.AddMember(r.Context(), orgID, req.UserID, req.Role); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to add member"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// RemoveOrganizationMember removes a user from an organization.
// DELETE /admin/organizations/{id}/members/{userId}
//
// Unchanged: still gated purely by RequireAdmin at the route level. See
// AddOrganizationMember's comment and RemoveOwnOrganizationMember below.
func RemoveOrganizationMember(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("id")
		userID := r.PathValue("userId")
		if err := d.OrgSvc.RemoveMember(r.Context(), orgID, userID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "remove failed"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- Self-service (per-organization delegation) ---
//
// AddOwnOrganizationMember/RemoveOwnOrganizationMember are the Phase-1
// Permify-integration deliverable: real per-organization delegation, so an
// org owner/admin can manage their OWN organization's membership without
// platform-admin standing (closing the gap ADR-005 v1.2 left open — see
// SECURITY.md and adrs/005-organization-identity.md, and the plan doc this
// workstream implements).
//
// These are deliberately wired on a SEPARATE route
// (/api/v1/organizations/{id}/members, BearerAuth only — see server.go)
// rather than loosening the existing /admin/organizations/{id}/members
// routes' RequireAdmin gate to BearerAuth-only-plus-handler-check. Reasoning:
// authz.Checker's documented fail-open behavior when no Permify engine is
// configured is a NoopChecker that always allows (see internal/authz —
// mirrors mfa.NoopSMSProvider's local/dev fallback contract). If the
// existing admin routes were loosened to rely on that check, any
// authenticated user would gain admin-route access whenever Permify isn't
// deployed (the default until an operator sets it up) — a straight
// regression of the RequireAdmin guarantee the 2026-07-26 security fix
// established (see server_admin_test.go). Keeping the admin routes on
// RequireAdmin exactly as before and adding this new capability on its own
// route means: (a) the admin routes' reachability is byte-for-byte
// unchanged, satisfying "purely additive, never fewer checks than today";
// (b) the new self-service route's own behavior is gated on
// d.Cfg.PermifyEnabled inside callerCanManageOrg (see its doc comment and
// the 2026-07-29 Security note in adrs/006-permify-authorization-engine.md):
// with Permify not deployed, the org-manage fallback is never consulted and
// the route is admin-only, exactly like the /admin/* routes it sits
// alongside; it only becomes permissive for org owners/admins once an
// operator deploys Permify for real. An earlier version of this route let
// the NoopChecker's unconditional allow answer the org-manage question
// directly whenever Permify wasn't deployed — a same-day-caught
// privilege-escalation regression, not the intended design; see the ADR-006
// security note for the incident and fix.

// AddOwnOrganizationMember adds a user to an organization the caller is
// authorized to manage (platform admin, or org owner/admin per
// authz.Checker — see callerCanManageOrg).
// POST /api/v1/organizations/{id}/members
func AddOwnOrganizationMember(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("id")

		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil || claims.Sub == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if ok, err := callerCanManageOrg(r.Context(), d, claims.Sub, orgID); err != nil || !ok {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}

		var req struct {
			UserID string `json:"user_id"`
			Role   string `json:"org_role"`
		}
		if err := decodeJSON(r, &req); err != nil || req.UserID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user_id required"})
			return
		}
		if err := d.OrgSvc.AddMember(r.Context(), orgID, req.UserID, req.Role); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to add member"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// RemoveOwnOrganizationMember removes a user from an organization the caller
// is authorized to manage (platform admin, or org owner/admin per
// authz.Checker — see callerCanManageOrg).
// DELETE /api/v1/organizations/{id}/members/{userId}
func RemoveOwnOrganizationMember(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("id")
		userID := r.PathValue("userId")

		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil || claims.Sub == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if ok, err := callerCanManageOrg(r.Context(), d, claims.Sub, orgID); err != nil || !ok {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}

		if err := d.OrgSvc.RemoveMember(r.Context(), orgID, userID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "remove failed"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// Package authz defines sinauth's authorization-engine abstraction — the
// Checker interface that internal/rbac.Store.Evaluate and the org-delegation
// checks in internal/api/handlers/organization.go call to make real, per-
// resource authorization decisions.
//
// There are two implementations: PermifyChecker (permify.go), which wraps
// the real Permify Go SDK (github.com/Permify/permify-go) and speaks to a
// deployed Permify instance over gRPC, and NoopChecker (noop.go), which
// always allows and never fails, for local/dev/test or a misconfigured
// deployment where SINAUTH_PERMIFY_URL is unset. See
// sinauth/permify/schema.perm for the entity/relation/permission model both
// implementations are checked against.
package authz

import (
	"context"

	"github.com/opensecstack/sinauth/internal/config"
)

// Entity identifies a subject or object in the authorization model — a
// user, organization, group, or client_role, addressed by its Permify
// entity type and ID. These four Type values are the complete vocabulary
// defined in sinauth/permify/schema.perm; do not introduce new ones without
// updating the schema first.
type Entity struct {
	Type string // "user", "organization", "group", "client_role"
	ID   string
}

// Relationship is a single Permify relation tuple: Subject holds Relation
// on Entity (e.g. user U is "owner" of organization O). Subject is
// typically {Type: "user", ID: userID}, matching the schema's `@user`
// relation references.
type Relationship struct {
	Entity   Entity
	Relation string // "owner", "admin", "member", "assignee"
	Subject  Entity
}

// Checker is sinauth's authorization-engine abstraction. Check answers
// "can subject perform permission on entity?"; WriteRelationship and
// DeleteRelationship maintain the tuple store that Check reads from.
//
// Implementations: PermifyChecker (real, backed by a Permify deployment)
// and NoopChecker (always-allow fallback — see noop.go for the fail-open
// rationale).
type Checker interface {
	// Check reports whether subject holds permission on entity.
	Check(ctx context.Context, subject Entity, permission string, entity Entity) (bool, error)

	// WriteRelationship creates or updates a relation tuple.
	WriteRelationship(ctx context.Context, rel Relationship) error

	// DeleteRelationship removes a relation tuple. It is not an error to
	// delete a relationship that does not exist.
	DeleteRelationship(ctx context.Context, rel Relationship) error
}

// New builds the Checker sinauth should use for a given config: a real
// PermifyChecker when cfg.PermifyEnabled (i.e. SINAUTH_PERMIFY_URL is set),
// a fail-open NoopChecker otherwise — mirroring cfg.SMSEnabled's
// Twilio-vs-noop selection. This is the single, centralized construction
// path; internal/api/server.go (the running server) and the
// `sinauth permify-sync` backfill CLI both call New so they always target
// the same Permify instance (or both fall back to Noop together).
func New(cfg *config.Config) Checker {
	if cfg.PermifyEnabled {
		return NewPermifyChecker(cfg.PermifyURL, cfg.PermifyTimeout)
	}
	return NewNoopChecker()
}

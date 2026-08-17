// Package organization implements ADR 005 v1.1: organizations as a second
// identity subject alongside individual users, with many-to-many membership.
package organization

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/sinauth/internal/authz"
)

// Organization is an identity subject representing a government, private,
// e-commerce, or NGO entity that individual users can act on behalf of.
type Organization struct {
	ID                 string     `json:"id"`
	LegalName          string     `json:"legal_name"`
	Slug               string     `json:"slug"`
	OrgType            string     `json:"org_type"`
	RegistrationNumber string     `json:"registration_number,omitempty"`
	VerifiedAt         *time.Time `json:"verified_at,omitempty"`
	VerifiedBy         string     `json:"verified_by,omitempty"`
	Status             string     `json:"status"`
	CreatedAt          time.Time  `json:"created_at"`
}

// Membership is a joined view of organization_members with enough
// organization info attached that a caller (e.g. the authorize flow) can
// resolve org_type / slug / legal_name without a second query.
type Membership struct {
	OrganizationID string    `json:"organization_id"`
	OrgRole        string    `json:"org_role"`
	OrgType        string    `json:"org_type"`
	Slug           string    `json:"slug"`
	LegalName      string    `json:"legal_name"`
	AddedAt        time.Time `json:"added_at"`
}

// Store handles all organization DB operations.
type Store struct {
	pool    *pgxpool.Pool
	checker authz.Checker
}

// NewStore builds a Store. checker is variadic/optional so call sites that
// don't care about Permify sync (e.g. existing tests) keep compiling
// unchanged; when omitted, Store falls back to authz.NoopChecker (Permify
// sync is skipped, matching pre-Permify behavior). Pass a real
// authz.Checker (see internal/api/server.go) to sync organization
// membership writes to Permify.
func NewStore(pool *pgxpool.Pool, checker ...authz.Checker) *Store {
	var c authz.Checker = authz.NoopChecker{}
	if len(checker) > 0 && checker[0] != nil {
		c = checker[0]
	}
	return &Store{pool: pool, checker: c}
}

// syncWrite/syncDelete are best-effort Permify relationship syncs performed
// after a successful SQL mutation. Postgres remains the sole authoritative
// store for organization membership data; if the Permify sync fails, we log
// it and continue rather than failing the caller's request or rolling back
// the SQL change that already succeeded. A sync failure only means
// authorization checks may be stale until the next successful write or a
// `sinauth permify-sync` backfill — it is never treated as a
// data-correctness error. This is a deliberate design choice, not an
// oversight: do not change this to propagate the error to callers.
func (s *Store) syncWrite(ctx context.Context, rel authz.Relationship) {
	if s.checker == nil {
		return
	}
	if err := s.checker.WriteRelationship(ctx, rel); err != nil {
		log.Printf("sinauth: organization: permify WriteRelationship failed (entity=%s:%s relation=%s subject=%s:%s): %v",
			rel.Entity.Type, rel.Entity.ID, rel.Relation, rel.Subject.Type, rel.Subject.ID, err)
	}
}

func (s *Store) syncDelete(ctx context.Context, rel authz.Relationship) {
	if s.checker == nil {
		return
	}
	if err := s.checker.DeleteRelationship(ctx, rel); err != nil {
		log.Printf("sinauth: organization: permify DeleteRelationship failed (entity=%s:%s relation=%s subject=%s:%s): %v",
			rel.Entity.Type, rel.Entity.ID, rel.Relation, rel.Subject.Type, rel.Subject.ID, err)
	}
}

// --- Organizations ---

func (s *Store) List(ctx context.Context) ([]Organization, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, legal_name, slug, org_type, COALESCE(registration_number,''),
		       verified_at, COALESCE(verified_by,''), status, created_at
		FROM organizations ORDER BY legal_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var orgs []Organization
	for rows.Next() {
		var o Organization
		if err := rows.Scan(&o.ID, &o.LegalName, &o.Slug, &o.OrgType, &o.RegistrationNumber,
			&o.VerifiedAt, &o.VerifiedBy, &o.Status, &o.CreatedAt); err != nil {
			return nil, err
		}
		orgs = append(orgs, o)
	}
	return orgs, rows.Err()
}

func (s *Store) Create(ctx context.Context, o Organization) (Organization, error) {
	var regNum, verifiedBy any
	if o.RegistrationNumber != "" {
		regNum = o.RegistrationNumber
	}
	if o.VerifiedBy != "" {
		verifiedBy = o.VerifiedBy
	}
	status := o.Status
	if status == "" {
		status = "pending"
	}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO organizations (legal_name, slug, org_type, registration_number, verified_by, status)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id, legal_name, slug, org_type, COALESCE(registration_number,''),
		          verified_at, COALESCE(verified_by,''), status, created_at`,
		o.LegalName, o.Slug, o.OrgType, regNum, verifiedBy, status,
	).Scan(&o.ID, &o.LegalName, &o.Slug, &o.OrgType, &o.RegistrationNumber,
		&o.VerifiedAt, &o.VerifiedBy, &o.Status, &o.CreatedAt)
	return o, err
}

func (s *Store) Get(ctx context.Context, id string) (Organization, error) {
	var o Organization
	err := s.pool.QueryRow(ctx, `
		SELECT id, legal_name, slug, org_type, COALESCE(registration_number,''),
		       verified_at, COALESCE(verified_by,''), status, created_at
		FROM organizations WHERE id=$1`, id,
	).Scan(&o.ID, &o.LegalName, &o.Slug, &o.OrgType, &o.RegistrationNumber,
		&o.VerifiedAt, &o.VerifiedBy, &o.Status, &o.CreatedAt)
	return o, err
}

func (s *Store) Delete(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, id)
	return err
}

// --- Membership ---

func (s *Store) ListMembers(ctx context.Context, orgID string) ([]Membership, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT om.organization_id, om.org_role, o.org_type, o.slug, o.legal_name, om.added_at
		FROM organization_members om
		JOIN organizations o ON o.id = om.organization_id
		WHERE om.organization_id=$1 ORDER BY om.added_at`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var members []Membership
	for rows.Next() {
		var m Membership
		if err := rows.Scan(&m.OrganizationID, &m.OrgRole, &m.OrgType, &m.Slug, &m.LegalName, &m.AddedAt); err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

func (s *Store) AddMember(ctx context.Context, orgID, userID, role string) error {
	if role == "" {
		role = "member"
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO organization_members (organization_id, user_id, org_role)
		VALUES ($1,$2,$3)
		ON CONFLICT (organization_id, user_id) DO UPDATE SET org_role = EXCLUDED.org_role`,
		orgID, userID, role,
	)
	if err != nil {
		return err
	}
	// NOTE: this is an upsert — if an existing member's role changes (e.g.
	// member -> admin), we write the new relation tuple but do not know (and
	// don't query for) the previous org_role here, so a stale tuple for the
	// old relation can be left in Permify until the next `sinauth
	// permify-sync` backfill. This only affects authorization freshness
	// (Postgres organization_members.org_role, the authoritative value, is
	// always correct), consistent with the best-effort sync semantics below.
	s.syncWrite(ctx, authz.Relationship{
		Entity:   authz.Entity{Type: "organization", ID: orgID},
		Relation: role,
		Subject:  authz.Entity{Type: "user", ID: userID},
	})
	return nil
}

func (s *Store) RemoveMember(ctx context.Context, orgID, userID string) error {
	// Look up the member's current org_role before deleting so we can issue
	// a matching DeleteRelationship — the relation name in Permify is the
	// org_role itself (owner/admin/member), not a fixed relation, so we need
	// to know which one to delete. Best-effort: if this lookup fails we
	// still proceed with the authoritative SQL delete and just skip the
	// Permify sync (logged), rather than blocking removal on a read.
	var role string
	lookupErr := s.pool.QueryRow(ctx,
		`SELECT org_role FROM organization_members WHERE organization_id=$1 AND user_id=$2`,
		orgID, userID,
	).Scan(&role)

	_, err := s.pool.Exec(ctx,
		`DELETE FROM organization_members WHERE organization_id=$1 AND user_id=$2`,
		orgID, userID,
	)
	if err != nil {
		return err
	}
	if lookupErr != nil {
		log.Printf("sinauth: organization: could not resolve org_role for permify sync on RemoveMember (org=%s user=%s): %v",
			orgID, userID, lookupErr)
		return nil
	}
	s.syncDelete(ctx, authz.Relationship{
		Entity:   authz.Entity{Type: "organization", ID: orgID},
		Relation: role,
		Subject:  authz.Entity{Type: "user", ID: userID},
	})
	return nil
}

// MembershipsForUser returns every organization a user belongs to, joined
// with enough organization info that the authorize flow can resolve
// org_type/slug/legal_name for token claims without a second query.
func (s *Store) MembershipsForUser(ctx context.Context, userID string) ([]Membership, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT om.organization_id, om.org_role, o.org_type, o.slug, o.legal_name, om.added_at
		FROM organization_members om
		JOIN organizations o ON o.id = om.organization_id
		WHERE om.user_id=$1 ORDER BY o.legal_name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var memberships []Membership
	for rows.Next() {
		var m Membership
		if err := rows.Scan(&m.OrganizationID, &m.OrgRole, &m.OrgType, &m.Slug, &m.LegalName, &m.AddedAt); err != nil {
			return nil, err
		}
		memberships = append(memberships, m)
	}
	return memberships, rows.Err()
}

package rbac

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/sinauth/internal/authz"
)

// Group represents a named collection of users.
type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// ClientRole is a role defined for a specific OAuth client.
type ClientRole struct {
	ID          string `json:"id"`
	ClientID    string `json:"client_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Policy is a rule evaluated at token issuance.
type Policy struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"`
	ClientID    string `json:"client_id,omitempty"`
	RoleName    string `json:"role_name,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// Store handles all RBAC DB operations.
type Store struct {
	pool    *pgxpool.Pool
	checker authz.Checker
}

// NewStore builds a Store. checker is variadic/optional so existing call
// sites (e.g. the ephemeral rbac.NewStore(d.Pool) used by
// handlers.effectiveAccessRoles, which only reads roles and never mutates
// relation tables) keep compiling unchanged; when omitted, Store falls back
// to authz.NoopChecker (i.e. Permify sync is skipped, matching pre-Permify
// behavior). Pass a real authz.Checker (see internal/api/server.go) from
// any call site that performs writes and wants them synced to Permify.
func NewStore(pool *pgxpool.Pool, checker ...authz.Checker) *Store {
	var c authz.Checker = authz.NoopChecker{}
	if len(checker) > 0 && checker[0] != nil {
		c = checker[0]
	}
	return &Store{pool: pool, checker: c}
}

// syncWrite performs a best-effort Permify relationship write after a
// successful SQL mutation. Postgres remains the sole authoritative store
// for RBAC data; if the Permify sync fails, we log it and continue rather
// than failing the caller's request or rolling back the SQL change that
// already succeeded. A sync failure only means authorization checks may be
// stale until the next successful write or a `sinauth permify-sync`
// backfill — it is never treated as a data-correctness error. This is a
// deliberate design choice, not an oversight: do not change this to
// propagate the error to callers.
func (s *Store) syncWrite(ctx context.Context, rel authz.Relationship) {
	if s.checker == nil {
		return
	}
	if err := s.checker.WriteRelationship(ctx, rel); err != nil {
		log.Printf("sinauth: rbac: permify WriteRelationship failed (entity=%s:%s relation=%s subject=%s:%s): %v",
			rel.Entity.Type, rel.Entity.ID, rel.Relation, rel.Subject.Type, rel.Subject.ID, err)
	}
}

// syncDelete is the delete-side counterpart to syncWrite — same best-effort,
// logged-not-fatal semantics. See syncWrite's comment for why.
func (s *Store) syncDelete(ctx context.Context, rel authz.Relationship) {
	if s.checker == nil {
		return
	}
	if err := s.checker.DeleteRelationship(ctx, rel); err != nil {
		log.Printf("sinauth: rbac: permify DeleteRelationship failed (entity=%s:%s relation=%s subject=%s:%s): %v",
			rel.Entity.Type, rel.Entity.ID, rel.Relation, rel.Subject.Type, rel.Subject.ID, err)
	}
}

// clientRoleID composes the stable composite ID used for the Permify
// client_role entity, since roles are named per-client (client_roles is
// unique on (client_id, name)/(user_id, client_id, role_name)) rather than
// having their own standalone UUID that user_client_roles references.
func clientRoleID(clientID, roleName string) string {
	return clientID + ":" + roleName
}

// --- Groups ---

func (s *Store) ListGroups(ctx context.Context) ([]Group, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name, description, created_at FROM groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var groups []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, nil
}

func (s *Store) CreateGroup(ctx context.Context, name, description string) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx,
		`INSERT INTO groups (name, description) VALUES ($1,$2) RETURNING id`,
		name, description,
	).Scan(&id)
	return id, err
}

func (s *Store) DeleteGroup(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM groups WHERE id=$1`, id)
	return err
}

func (s *Store) AddGroupMember(ctx context.Context, groupID, userID string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO group_members (group_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
		groupID, userID,
	)
	if err != nil {
		return err
	}
	s.syncWrite(ctx, authz.Relationship{
		Entity:   authz.Entity{Type: "group", ID: groupID},
		Relation: "member",
		Subject:  authz.Entity{Type: "user", ID: userID},
	})
	return nil
}

func (s *Store) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM group_members WHERE group_id=$1 AND user_id=$2`, groupID, userID)
	if err != nil {
		return err
	}
	s.syncDelete(ctx, authz.Relationship{
		Entity:   authz.Entity{Type: "group", ID: groupID},
		Relation: "member",
		Subject:  authz.Entity{Type: "user", ID: userID},
	})
	return nil
}

func (s *Store) ListGroupMembers(ctx context.Context, groupID string) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT u.username FROM users u
		 JOIN group_members gm ON gm.user_id = u.id
		 WHERE gm.group_id=$1 ORDER BY u.username`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var members []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			continue
		}
		members = append(members, m)
	}
	return members, nil
}

// --- Client Roles ---

func (s *Store) ListClientRoles(ctx context.Context, clientID string) ([]ClientRole, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, client_id, name, description FROM client_roles WHERE client_id=$1 ORDER BY name`,
		clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roles []ClientRole
	for rows.Next() {
		var r ClientRole
		if err := rows.Scan(&r.ID, &r.ClientID, &r.Name, &r.Description); err != nil {
			continue
		}
		roles = append(roles, r)
	}
	return roles, nil
}

func (s *Store) CreateClientRole(ctx context.Context, clientID, name, description string) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx,
		`INSERT INTO client_roles (client_id, name, description) VALUES ($1,$2,$3) RETURNING id`,
		clientID, name, description,
	).Scan(&id)
	return id, err
}

func (s *Store) DeleteClientRole(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM client_roles WHERE id=$1`, id)
	return err
}

// --- User role assignments ---

func (s *Store) AssignUserRole(ctx context.Context, userID, clientID, roleName string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO user_client_roles (user_id, client_id, role_name) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
		userID, clientID, roleName,
	)
	if err != nil {
		return err
	}
	s.syncWrite(ctx, authz.Relationship{
		Entity:   authz.Entity{Type: "client_role", ID: clientRoleID(clientID, roleName)},
		Relation: "assignee",
		Subject:  authz.Entity{Type: "user", ID: userID},
	})
	return nil
}

func (s *Store) RevokeUserRole(ctx context.Context, userID, clientID, roleName string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM user_client_roles WHERE user_id=$1 AND client_id=$2 AND role_name=$3`,
		userID, clientID, roleName,
	)
	if err != nil {
		return err
	}
	s.syncDelete(ctx, authz.Relationship{
		Entity:   authz.Entity{Type: "client_role", ID: clientRoleID(clientID, roleName)},
		Relation: "assignee",
		Subject:  authz.Entity{Type: "user", ID: userID},
	})
	return nil
}

// GetEffectiveRoles returns all roles for a user in a specific client,
// combining direct user assignments and group memberships.
func (s *Store) GetEffectiveRoles(ctx context.Context, userID, clientID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT role_name FROM (
			-- Direct user roles
			SELECT role_name FROM user_client_roles
			WHERE user_id=$1 AND client_id=$2
			UNION ALL
			-- Roles via group membership
			SELECT gcr.role_name FROM group_client_roles gcr
			JOIN group_members gm ON gm.group_id = gcr.group_id
			WHERE gm.user_id=$1 AND gcr.client_id=$2
		) combined ORDER BY role_name`,
		userID, clientID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roles []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			continue
		}
		roles = append(roles, r)
	}
	return roles, nil
}

// --- Group role assignments ---
//
// NOTE: AssignGroupRole/RevokeGroupRole (group_client_roles) are
// deliberately NOT synced to Permify here. The agreed Permify schema
// (sinauth/permify/schema.perm) models `client_role#assignee` as `@user`
// only — it has no relation for "role assigned to a whole group" — so
// there is no tuple shape to write a group-to-client_role assignment into
// without extending the schema. If/when the schema grows a userset-style
// relation (e.g. `assignee @user @group#member`), write-through sync for
// these two methods should be added to match.

func (s *Store) AssignGroupRole(ctx context.Context, groupID, clientID, roleName string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO group_client_roles (group_id, client_id, role_name) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
		groupID, clientID, roleName,
	)
	return err
}

func (s *Store) RevokeGroupRole(ctx context.Context, groupID, clientID, roleName string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM group_client_roles WHERE group_id=$1 AND client_id=$2 AND role_name=$3`,
		groupID, clientID, roleName,
	)
	return err
}

// --- Policies ---

func (s *Store) ListPolicies(ctx context.Context) ([]Policy, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, description, type, COALESCE(client_id,''), COALESCE(role_name,''), enabled
		 FROM policies WHERE enabled=true ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var policies []Policy
	for rows.Next() {
		var p Policy
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Type, &p.ClientID, &p.RoleName, &p.Enabled); err != nil {
			continue
		}
		policies = append(policies, p)
	}
	return policies, nil
}

func (s *Store) CreatePolicy(ctx context.Context, p Policy) (string, error) {
	var clientID, roleName *string
	if p.ClientID != "" {
		clientID = &p.ClientID
	}
	if p.RoleName != "" {
		roleName = &p.RoleName
	}
	var id string
	err := s.pool.QueryRow(ctx,
		`INSERT INTO policies (name, description, type, client_id, role_name) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		p.Name, p.Description, p.Type, clientID, roleName,
	).Scan(&id)
	return id, err
}

func (s *Store) DeletePolicy(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM policies WHERE id=$1`, id)
	return err
}

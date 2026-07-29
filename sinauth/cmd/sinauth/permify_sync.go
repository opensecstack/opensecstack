package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/sinauth/internal/authz"
	"github.com/opensecstack/sinauth/internal/config"
	"github.com/spf13/cobra"
)

// permifySyncCmd is the one-time backfill CLI path for populating Permify
// with relationship tuples for every pre-existing row in sinauth's relation
// tables (group_members, user_client_roles, organization_members) — the
// counterpart to the write-through sync now performed by rbac.Store and
// organization.Store on every new write. Safe to run multiple times:
// Permify relationship writes are tuple upserts (WriteRelationships is
// idempotent per Permify's API — writing the same tuple twice is a no-op,
// not an error), so re-running this after new rows have already been synced
// write-through is harmless.
//
// group_client_roles (group-level client-role assignments) is deliberately
// NOT backfilled here: the agreed Permify schema
// (sinauth/permify/schema.perm) models `client_role#assignee` as `@user`
// only, with no userset relation for "role assigned to a whole group", so
// there is no tuple shape to write those rows into. See the matching NOTE
// in internal/rbac/store.go.
var permifySyncCmd = &cobra.Command{
	Use:   "permify-sync",
	Short: "Backfill Permify relationship tuples from existing group/role/organization membership rows",
	Args:  cobra.NoArgs,
	RunE:  runPermifySync,
}

func runPermifySync(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DBURL)
	if err != nil {
		return fmt.Errorf("db connect: %w", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("db ping: %w", err)
	}

	// Same construction path internal/api/server.go uses to obtain a
	// Checker, so this CLI targets exactly the Permify instance (or Noop
	// fallback) the running server would use.
	checker := authz.New(cfg)

	written, failed := 0, 0

	groupTuples, err := groupMemberTuples(ctx, pool)
	if err != nil {
		return fmt.Errorf("query group_members: %w", err)
	}
	roleTuples, err := userClientRoleTuples(ctx, pool)
	if err != nil {
		return fmt.Errorf("query user_client_roles: %w", err)
	}
	orgTuples, err := organizationMemberTuples(ctx, pool)
	if err != nil {
		return fmt.Errorf("query organization_members: %w", err)
	}

	all := make([]authz.Relationship, 0, len(groupTuples)+len(roleTuples)+len(orgTuples))
	all = append(all, groupTuples...)
	all = append(all, roleTuples...)
	all = append(all, orgTuples...)

	for _, rel := range all {
		if err := checker.WriteRelationship(ctx, rel); err != nil {
			failed++
			fmt.Printf("sinauth: permify-sync: FAILED entity=%s:%s relation=%s subject=%s:%s: %v\n",
				rel.Entity.Type, rel.Entity.ID, rel.Relation, rel.Subject.Type, rel.Subject.ID, err)
			continue
		}
		written++
	}

	fmt.Printf("sinauth: permify-sync: wrote %d tuple(s) (group_members=%d, user_client_roles=%d, organization_members=%d), %d failed\n",
		written, len(groupTuples), len(roleTuples), len(orgTuples), failed)

	if failed > 0 {
		return fmt.Errorf("permify-sync: %d tuple write(s) failed", failed)
	}
	return nil
}

// groupMemberTuples reads every group_members row and builds the matching
// group#member relationship tuples.
func groupMemberTuples(ctx context.Context, pool *pgxpool.Pool) ([]authz.Relationship, error) {
	rows, err := pool.Query(ctx, `SELECT group_id, user_id FROM group_members`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tuples []authz.Relationship
	for rows.Next() {
		var groupID, userID string
		if err := rows.Scan(&groupID, &userID); err != nil {
			return nil, err
		}
		tuples = append(tuples, authz.Relationship{
			Entity:   authz.Entity{Type: "group", ID: groupID},
			Relation: "member",
			Subject:  authz.Entity{Type: "user", ID: userID},
		})
	}
	return tuples, rows.Err()
}

// userClientRoleTuples reads every user_client_roles row and builds the
// matching client_role#assignee relationship tuples, using the same
// clientID+":"+roleName composite entity ID rbac.Store's write-through sync
// uses (client_role has no standalone UUID of its own).
func userClientRoleTuples(ctx context.Context, pool *pgxpool.Pool) ([]authz.Relationship, error) {
	rows, err := pool.Query(ctx, `SELECT user_id, client_id, role_name FROM user_client_roles`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tuples []authz.Relationship
	for rows.Next() {
		var userID, clientID, roleName string
		if err := rows.Scan(&userID, &clientID, &roleName); err != nil {
			return nil, err
		}
		tuples = append(tuples, authz.Relationship{
			Entity:   authz.Entity{Type: "client_role", ID: clientID + ":" + roleName},
			Relation: "assignee",
			Subject:  authz.Entity{Type: "user", ID: userID},
		})
	}
	return tuples, rows.Err()
}

// organizationMemberTuples reads every organization_members row and builds
// the matching organization#<org_role> relationship tuples — the relation
// name is the row's own org_role (owner/admin/member), not a fixed value.
func organizationMemberTuples(ctx context.Context, pool *pgxpool.Pool) ([]authz.Relationship, error) {
	rows, err := pool.Query(ctx, `SELECT organization_id, user_id, org_role FROM organization_members`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tuples []authz.Relationship
	for rows.Next() {
		var orgID, userID, orgRole string
		if err := rows.Scan(&orgID, &userID, &orgRole); err != nil {
			return nil, err
		}
		tuples = append(tuples, authz.Relationship{
			Entity:   authz.Entity{Type: "organization", ID: orgID},
			Relation: orgRole,
			Subject:  authz.Entity{Type: "user", ID: userID},
		})
	}
	return tuples, rows.Err()
}

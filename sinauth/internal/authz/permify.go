package authz

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	v1 "buf.build/gen/go/permifyco/permify/protocolbuffers/go/base/v1"
	permifygrpc "github.com/Permify/permify-go/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// defaultTenantID is Permify's pre-inserted single-tenant convention (every
// fresh Permify instance already has a tenant with this ID — no
// Tenancy.Create call is required to use it). sinauth is single-tenant
// today, so this is fixed rather than derived from config; see the ADR for
// how a future multi-tenant deployment would revisit this.
const defaultTenantID = "t1"

// permifySchema is the authorization model written to Permify on first use.
// It MUST stay byte-for-byte identical to sinauth/permify/schema.perm — that
// file is the canonical, human-reviewed copy (and the one fed to Permify's
// schema validator / CLI); this constant is what actually gets sent over the
// wire, since Go's //go:embed cannot reach outside this package's directory
// tree to embed a file that lives at the repo's sinauth/permify/ path.
const permifySchema = `entity user {}

entity group {
    relation member @user

    permission view = member
}

entity client_role {
    relation assignee @user

    permission use = assignee
}

entity organization {
    relation owner @user
    relation admin @user
    relation member @user

    permission manage = owner or admin
    permission view = owner or admin or member
}
`

// PermifyChecker is the real Checker implementation, backed by a deployed
// Permify instance (https://permify.co) reached over gRPC via the official
// Go SDK (github.com/Permify/permify-go).
type PermifyChecker struct {
	client   *permifygrpc.Client
	tenantID string
	timeout  time.Duration

	mu            sync.RWMutex
	schemaVersion string
}

// NewPermifyChecker constructs a PermifyChecker pointed at a Permify gRPC
// endpoint (e.g. "permify:3478" in docker-compose, "localhost:3478"
// locally). Dialing is lazy/non-blocking (grpc.NewClient does not connect
// synchronously), so this does not fail just because Permify isn't up yet
// at sinauth startup — it mirrors mfa.TwilioProvider's construction, which
// also doesn't probe the remote service before returning.
//
// timeout bounds every individual Check/WriteRelationship/DeleteRelationship
// RPC (including the lazy schema write the first call triggers).
func NewPermifyChecker(endpoint string, timeout time.Duration) *PermifyChecker {
	// Permify's gRPC target is a bare host:port, not a URL — strip a
	// scheme if the operator configured SINAUTH_PERMIFY_URL as one
	// (e.g. "http://permify:3478"), so both forms work.
	target := endpoint
	if i := strings.Index(target, "://"); i >= 0 {
		target = target[i+3:]
	}

	client, err := permifygrpc.NewClient(
		permifygrpc.Config{Endpoint: target},
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		// grpc.NewClient only fails on a malformed target string, which
		// means misconfiguration, not a transient outage. Log loudly and
		// keep going with a nil client — every RPC below returns a clear
		// error instead of panicking sinauth startup over an auth
		// integration (same "never hard-fail on this dependency" stance
		// as the rest of this package).
		log.Printf("authz: failed to construct Permify client for %q: %v — all authz.Checker calls will error until this is fixed", endpoint, err)
	}

	return &PermifyChecker{
		client:   client,
		tenantID: defaultTenantID,
		timeout:  timeout,
	}
}

// Check reports whether subject holds permission on entity, per the schema
// in sinauth/permify/schema.perm.
func (c *PermifyChecker) Check(ctx context.Context, subject Entity, permission string, entity Entity) (bool, error) {
	if c.client == nil {
		return false, fmt.Errorf("authz: permify client not initialized")
	}

	if err := c.ensureSchema(ctx); err != nil {
		return false, err
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.client.Permission.Check(ctx, &v1.PermissionCheckRequest{
		TenantId: c.tenantID,
		Metadata: &v1.PermissionCheckRequestMetadata{
			SchemaVersion: c.getSchemaVersion(),
			Depth:         20,
		},
		Entity: &v1.Entity{
			Type: entity.Type,
			Id:   entity.ID,
		},
		Permission: permission,
		Subject: &v1.Subject{
			Type: subject.Type,
			Id:   subject.ID,
		},
	})
	if err != nil {
		return false, fmt.Errorf("authz: permify check: %w", err)
	}

	return resp.GetCan() == v1.CheckResult_CHECK_RESULT_ALLOWED, nil
}

// WriteRelationship creates or updates a relation tuple in Permify.
func (c *PermifyChecker) WriteRelationship(ctx context.Context, rel Relationship) error {
	if c.client == nil {
		return fmt.Errorf("authz: permify client not initialized")
	}

	if err := c.ensureSchema(ctx); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	_, err := c.client.Data.WriteRelationships(ctx, &v1.RelationshipWriteRequest{
		TenantId: c.tenantID,
		Metadata: &v1.RelationshipWriteRequestMetadata{
			SchemaVersion: c.getSchemaVersion(),
		},
		Tuples: []*v1.Tuple{
			{
				Entity: &v1.Entity{
					Type: rel.Entity.Type,
					Id:   rel.Entity.ID,
				},
				Relation: rel.Relation,
				Subject: &v1.Subject{
					Type: rel.Subject.Type,
					Id:   rel.Subject.ID,
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("authz: permify write relationship: %w", err)
	}
	return nil
}

// DeleteRelationship removes a relation tuple from Permify, matched by
// exact entity/relation/subject. It is not an error to delete a
// relationship that does not exist — Permify's DeleteRelationships is
// idempotent over its filter.
func (c *PermifyChecker) DeleteRelationship(ctx context.Context, rel Relationship) error {
	if c.client == nil {
		return fmt.Errorf("authz: permify client not initialized")
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	_, err := c.client.Data.DeleteRelationships(ctx, &v1.RelationshipDeleteRequest{
		TenantId: c.tenantID,
		Filter: &v1.TupleFilter{
			Entity: &v1.EntityFilter{
				Type: rel.Entity.Type,
				Ids:  []string{rel.Entity.ID},
			},
			Relation: rel.Relation,
			Subject: &v1.SubjectFilter{
				Type: rel.Subject.Type,
				Ids:  []string{rel.Subject.ID},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("authz: permify delete relationship: %w", err)
	}
	return nil
}

// ensureSchema lazily writes permifySchema on first use and caches the
// resulting schema version for subsequent Check/WriteRelationship calls.
// Safe for concurrent callers — only the first one to arrive performs the
// write.
func (c *PermifyChecker) ensureSchema(ctx context.Context) error {
	if c.getSchemaVersion() != "" {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.schemaVersion != "" {
		return nil // another goroutine won the race while we waited for the lock
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.client.Schema.Write(ctx, &v1.SchemaWriteRequest{
		TenantId: c.tenantID,
		Schema:   permifySchema,
	})
	if err != nil {
		return fmt.Errorf("authz: permify schema write: %w", err)
	}

	c.schemaVersion = resp.GetSchemaVersion()
	return nil
}

func (c *PermifyChecker) getSchemaVersion() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.schemaVersion
}

var _ Checker = (*PermifyChecker)(nil)

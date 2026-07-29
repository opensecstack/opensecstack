package permifysync

import (
	"context"
	"fmt"
	"strings"
	"time"

	v1 "buf.build/gen/go/permifyco/permify/protocolbuffers/go/base/v1"
	permifygrpc "github.com/Permify/permify-go/grpc"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// defaultTenantID mirrors sinauth/internal/authz.defaultTenantID — CITADEL
// reads the same ecosystem-wide Permify instance/tenant sinauth writes to,
// it does not own a separate schema or tenant.
const defaultTenantID = "t1"

// PermifyFetcher is the real MatrixFetcher, backed by a deployed Permify
// instance reached over gRPC (github.com/Permify/permify-go), the same
// client library and wire protocol sinauth's authz.PermifyChecker uses.
//
// # Why FetchRoleActionMatrix currently returns an (almost certainly) empty map
//
// The (role, action_type) shape Gate 2 needs — "can role R perform governed
// action type T" — is not modeled anywhere in sinauth/permify/schema.perm.
// That schema defines organization/group/client_role membership
// (organization#owner/admin/member, group#member, client_role#assignee); it
// has no entity or permission for CITADEL's action-type vocabulary
// (API_SCAN_INITIATE, INCIDENT_CREATE, DATA_EXPORT, ...). There is
// therefore no honest way to answer "does Permify allow role R to perform
// action type T" today — any non-empty answer would be fabricated, not
// derived.
//
// This fetcher takes the honest option: it performs a real bulk read
// (Data.ReadRelationships, filtered to client_role#assignee tuples) so the
// sync loop genuinely talks to Permify and can log what it currently knows
// about (which client_roles exist and are assigned) — useful signal for
// verifying connectivity and for later schema-extension work — but it does
// NOT translate that into fabricated (role, action_type) coverage. The
// returned matrix stays empty until sinauth's schema is extended (a later,
// explicitly deferred phase — see adrs/007-permify-gate2-snapshot.md) to
// actually assert per-action-type permissions. Until then, Gate 2's
// rbacMap check is the true source of truth; this snapshot's job is to add
// coverage honestly over time, not to appear complete before it is.
type PermifyFetcher struct {
	client   *permifygrpc.Client
	tenantID string
	timeout  time.Duration
	logger   zerolog.Logger
}

// NewPermifyFetcher constructs a PermifyFetcher pointed at a Permify gRPC
// endpoint (e.g. "permify:3478" in docker-compose). Dialing is lazy/
// non-blocking (grpc.NewClient does not connect synchronously), matching
// sinauth's authz.NewPermifyChecker — this does not fail just because
// Permify isn't up yet when CITADEL starts.
func NewPermifyFetcher(endpoint string, timeout time.Duration, logger zerolog.Logger) *PermifyFetcher {
	target := endpoint
	if i := strings.Index(target, "://"); i >= 0 {
		target = target[i+3:]
	}

	client, err := permifygrpc.NewClient(
		permifygrpc.Config{Endpoint: target},
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		logger.Error().Err(err).Str("endpoint", endpoint).
			Msg("permifysync: failed to construct Permify client — sync will error until this is fixed")
	}

	return &PermifyFetcher{
		client:   client,
		tenantID: defaultTenantID,
		timeout:  timeout,
		logger:   logger,
	}
}

// FetchRoleActionMatrix implements MatrixFetcher. See the PermifyFetcher
// doc comment for why this currently returns an empty (but genuinely
// fetched, not fabricated) matrix.
func (f *PermifyFetcher) FetchRoleActionMatrix(ctx context.Context) (map[RoleAction]bool, error) {
	if f.client == nil {
		return nil, fmt.Errorf("permifysync: permify client not initialized")
	}

	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	resp, err := f.client.Data.ReadRelationships(ctx, &v1.RelationshipReadRequest{
		TenantId: f.tenantID,
		Metadata: &v1.RelationshipReadRequestMetadata{},
		Filter: &v1.TupleFilter{
			Entity:   &v1.EntityFilter{Type: "client_role"},
			Relation: "assignee",
		},
		PageSize: 1000,
	})
	if err != nil {
		return nil, fmt.Errorf("permifysync: read relationships: %w", err)
	}

	knownRoles := make(map[string]struct{})
	for _, t := range resp.GetTuples() {
		if e := t.GetEntity(); e != nil {
			knownRoles[e.GetId()] = struct{}{}
		}
	}
	f.logger.Debug().
		Int("known_client_roles", len(knownRoles)).
		Msg("permifysync: fetched client_role#assignee tuples — schema does not yet model action-type coverage, snapshot stays empty")

	// Intentionally empty: see doc comment above. Nothing in
	// sinauth/permify/schema.perm asserts a (role, action_type) fact today.
	return map[RoleAction]bool{}, nil
}

var _ MatrixFetcher = (*PermifyFetcher)(nil)

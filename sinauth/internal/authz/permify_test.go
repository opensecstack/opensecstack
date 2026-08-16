package authz

// These tests exercise PermifyChecker against a fake implementation of the
// three generated gRPC client interfaces (PermissionClient, SchemaClient,
// DataClient) that github.com/Permify/permify-go's grpc.Client embeds — no
// real Permify instance or network connection is required or was available
// while writing this. Dependency injection is possible because
// permifygrpc.Client's fields (Permission/Schema/Data/...) are exported and
// typed as interfaces, not concrete structs, so a test can build a
// *permifygrpc.Client by hand with fakes in place of the real gRPC stubs and
// hand it to a PermifyChecker constructed directly (bypassing
// NewPermifyChecker's dialing, which this package's unexported fields make
// possible from within the same package).
//
// This does NOT verify wire-level behavior against a real Permify server
// (schema validation semantics, actual relation-graph evaluation, etc.) —
// only that PermifyChecker builds the correct requests, forwards responses/
// errors correctly, and caches the schema version as documented. The plan
// this work implements calls this out explicitly as an acceptable substitute
// when no live Permify instance is available.

import (
	"context"
	"errors"
	"testing"
	"time"

	basev1grpc "buf.build/gen/go/permifyco/permify/grpc/go/base/v1/basev1grpc"
	v1 "buf.build/gen/go/permifyco/permify/protocolbuffers/go/base/v1"
	permifygrpc "github.com/Permify/permify-go/grpc"
	"google.golang.org/grpc"
)

// fakePermissionClient implements basev1grpc.PermissionClient by embedding
// the (nil) interface and overriding only Check — any other method call
// would panic on the nil embedded interface, which is fine since these
// tests never exercise Expand/LookupEntity/etc.
type fakePermissionClient struct {
	basev1grpc.PermissionClient
	checkFunc func(ctx context.Context, in *v1.PermissionCheckRequest, opts ...grpc.CallOption) (*v1.PermissionCheckResponse, error)
}

func (f *fakePermissionClient) Check(ctx context.Context, in *v1.PermissionCheckRequest, opts ...grpc.CallOption) (*v1.PermissionCheckResponse, error) {
	return f.checkFunc(ctx, in, opts...)
}

type fakeSchemaClient struct {
	basev1grpc.SchemaClient
	writeFunc  func(ctx context.Context, in *v1.SchemaWriteRequest, opts ...grpc.CallOption) (*v1.SchemaWriteResponse, error)
	writeCalls int
}

func (f *fakeSchemaClient) Write(ctx context.Context, in *v1.SchemaWriteRequest, opts ...grpc.CallOption) (*v1.SchemaWriteResponse, error) {
	f.writeCalls++
	return f.writeFunc(ctx, in, opts...)
}

type fakeDataClient struct {
	basev1grpc.DataClient
	writeRelFunc  func(ctx context.Context, in *v1.RelationshipWriteRequest, opts ...grpc.CallOption) (*v1.RelationshipWriteResponse, error)
	deleteRelFunc func(ctx context.Context, in *v1.RelationshipDeleteRequest, opts ...grpc.CallOption) (*v1.RelationshipDeleteResponse, error)
}

func (f *fakeDataClient) WriteRelationships(ctx context.Context, in *v1.RelationshipWriteRequest, opts ...grpc.CallOption) (*v1.RelationshipWriteResponse, error) {
	return f.writeRelFunc(ctx, in, opts...)
}

func (f *fakeDataClient) DeleteRelationships(ctx context.Context, in *v1.RelationshipDeleteRequest, opts ...grpc.CallOption) (*v1.RelationshipDeleteResponse, error) {
	return f.deleteRelFunc(ctx, in, opts...)
}

// newTestChecker builds a PermifyChecker wired to fakes, bypassing
// NewPermifyChecker (which requires a real dial target).
func newTestChecker(perm *fakePermissionClient, schema *fakeSchemaClient, data *fakeDataClient) *PermifyChecker {
	return &PermifyChecker{
		client: &permifygrpc.Client{
			Permission: perm,
			Schema:     schema,
			Data:       data,
		},
		tenantID: defaultTenantID,
		timeout:  5 * time.Second,
	}
}

func TestPermifyChecker_Check_Allowed(t *testing.T) {
	schema := &fakeSchemaClient{writeFunc: func(ctx context.Context, in *v1.SchemaWriteRequest, opts ...grpc.CallOption) (*v1.SchemaWriteResponse, error) {
		if in.TenantId != "t1" {
			t.Errorf("schema write tenant_id = %q, want t1", in.TenantId)
		}
		if in.Schema != permifySchema {
			t.Errorf("schema write payload does not match permifySchema constant")
		}
		return &v1.SchemaWriteResponse{SchemaVersion: "v1-test"}, nil
	}}

	var gotReq *v1.PermissionCheckRequest
	perm := &fakePermissionClient{checkFunc: func(ctx context.Context, in *v1.PermissionCheckRequest, opts ...grpc.CallOption) (*v1.PermissionCheckResponse, error) {
		gotReq = in
		return &v1.PermissionCheckResponse{Can: v1.CheckResult_CHECK_RESULT_ALLOWED}, nil
	}}

	c := newTestChecker(perm, schema, &fakeDataClient{})

	allowed, err := c.Check(context.Background(),
		Entity{Type: "user", ID: "u1"}, "manage", Entity{Type: "organization", ID: "o1"})
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if !allowed {
		t.Fatal("Check returned false, want true for CHECK_RESULT_ALLOWED")
	}

	if gotReq.Entity.Type != "organization" || gotReq.Entity.Id != "o1" {
		t.Errorf("request entity = %+v, want organization:o1", gotReq.Entity)
	}
	if gotReq.Permission != "manage" {
		t.Errorf("request permission = %q, want manage", gotReq.Permission)
	}
	if gotReq.Subject.Type != "user" || gotReq.Subject.Id != "u1" {
		t.Errorf("request subject = %+v, want user:u1", gotReq.Subject)
	}
	if gotReq.Metadata.SchemaVersion != "v1-test" {
		t.Errorf("request schema_version = %q, want v1-test (cached from schema write)", gotReq.Metadata.SchemaVersion)
	}
	if schema.writeCalls != 1 {
		t.Errorf("schema.Write called %d times, want exactly 1", schema.writeCalls)
	}
}

func TestPermifyChecker_Check_Denied(t *testing.T) {
	schema := &fakeSchemaClient{writeFunc: func(ctx context.Context, in *v1.SchemaWriteRequest, opts ...grpc.CallOption) (*v1.SchemaWriteResponse, error) {
		return &v1.SchemaWriteResponse{SchemaVersion: "v1-test"}, nil
	}}
	perm := &fakePermissionClient{checkFunc: func(ctx context.Context, in *v1.PermissionCheckRequest, opts ...grpc.CallOption) (*v1.PermissionCheckResponse, error) {
		return &v1.PermissionCheckResponse{Can: v1.CheckResult_CHECK_RESULT_DENIED}, nil
	}}

	c := newTestChecker(perm, schema, &fakeDataClient{})

	allowed, err := c.Check(context.Background(),
		Entity{Type: "user", ID: "u1"}, "manage", Entity{Type: "organization", ID: "o1"})
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if allowed {
		t.Fatal("Check returned true, want false for CHECK_RESULT_DENIED")
	}
}

func TestPermifyChecker_Check_RPCError(t *testing.T) {
	schema := &fakeSchemaClient{writeFunc: func(ctx context.Context, in *v1.SchemaWriteRequest, opts ...grpc.CallOption) (*v1.SchemaWriteResponse, error) {
		return &v1.SchemaWriteResponse{SchemaVersion: "v1-test"}, nil
	}}
	wantErr := errors.New("boom")
	perm := &fakePermissionClient{checkFunc: func(ctx context.Context, in *v1.PermissionCheckRequest, opts ...grpc.CallOption) (*v1.PermissionCheckResponse, error) {
		return nil, wantErr
	}}

	c := newTestChecker(perm, schema, &fakeDataClient{})

	allowed, err := c.Check(context.Background(),
		Entity{Type: "user", ID: "u1"}, "manage", Entity{Type: "organization", ID: "o1"})
	if err == nil {
		t.Fatal("Check returned nil error, want the wrapped RPC error")
	}
	if allowed {
		t.Fatal("Check returned true on error, want false")
	}
}

func TestPermifyChecker_Check_SchemaWriteFailure(t *testing.T) {
	wantErr := errors.New("schema unreachable")
	schema := &fakeSchemaClient{writeFunc: func(ctx context.Context, in *v1.SchemaWriteRequest, opts ...grpc.CallOption) (*v1.SchemaWriteResponse, error) {
		return nil, wantErr
	}}
	perm := &fakePermissionClient{checkFunc: func(ctx context.Context, in *v1.PermissionCheckRequest, opts ...grpc.CallOption) (*v1.PermissionCheckResponse, error) {
		t.Fatal("Permission.Check should not be called when schema write failed")
		return nil, nil
	}}

	c := newTestChecker(perm, schema, &fakeDataClient{})

	_, err := c.Check(context.Background(),
		Entity{Type: "user", ID: "u1"}, "manage", Entity{Type: "organization", ID: "o1"})
	if err == nil {
		t.Fatal("Check returned nil error, want schema write failure surfaced")
	}
}

func TestPermifyChecker_WriteRelationship(t *testing.T) {
	schema := &fakeSchemaClient{writeFunc: func(ctx context.Context, in *v1.SchemaWriteRequest, opts ...grpc.CallOption) (*v1.SchemaWriteResponse, error) {
		return &v1.SchemaWriteResponse{SchemaVersion: "v1-test"}, nil
	}}

	var gotReq *v1.RelationshipWriteRequest
	data := &fakeDataClient{writeRelFunc: func(ctx context.Context, in *v1.RelationshipWriteRequest, opts ...grpc.CallOption) (*v1.RelationshipWriteResponse, error) {
		gotReq = in
		return &v1.RelationshipWriteResponse{SnapToken: "snap-1"}, nil
	}}

	c := newTestChecker(&fakePermissionClient{}, schema, data)

	rel := Relationship{
		Entity:   Entity{Type: "organization", ID: "o1"},
		Relation: "owner",
		Subject:  Entity{Type: "user", ID: "u1"},
	}
	if err := c.WriteRelationship(context.Background(), rel); err != nil {
		t.Fatalf("WriteRelationship returned error: %v", err)
	}

	if len(gotReq.Tuples) != 1 {
		t.Fatalf("wrote %d tuples, want 1", len(gotReq.Tuples))
	}
	tuple := gotReq.Tuples[0]
	if tuple.Entity.Type != "organization" || tuple.Entity.Id != "o1" {
		t.Errorf("tuple entity = %+v, want organization:o1", tuple.Entity)
	}
	if tuple.Relation != "owner" {
		t.Errorf("tuple relation = %q, want owner", tuple.Relation)
	}
	if tuple.Subject.Type != "user" || tuple.Subject.Id != "u1" {
		t.Errorf("tuple subject = %+v, want user:u1", tuple.Subject)
	}
}

func TestPermifyChecker_WriteRelationship_Error(t *testing.T) {
	schema := &fakeSchemaClient{writeFunc: func(ctx context.Context, in *v1.SchemaWriteRequest, opts ...grpc.CallOption) (*v1.SchemaWriteResponse, error) {
		return &v1.SchemaWriteResponse{SchemaVersion: "v1-test"}, nil
	}}
	wantErr := errors.New("write failed")
	data := &fakeDataClient{writeRelFunc: func(ctx context.Context, in *v1.RelationshipWriteRequest, opts ...grpc.CallOption) (*v1.RelationshipWriteResponse, error) {
		return nil, wantErr
	}}

	c := newTestChecker(&fakePermissionClient{}, schema, data)

	err := c.WriteRelationship(context.Background(), Relationship{
		Entity: Entity{Type: "organization", ID: "o1"}, Relation: "owner", Subject: Entity{Type: "user", ID: "u1"},
	})
	if err == nil {
		t.Fatal("WriteRelationship returned nil error, want the wrapped RPC error")
	}
}

func TestPermifyChecker_DeleteRelationship(t *testing.T) {
	var gotReq *v1.RelationshipDeleteRequest
	data := &fakeDataClient{deleteRelFunc: func(ctx context.Context, in *v1.RelationshipDeleteRequest, opts ...grpc.CallOption) (*v1.RelationshipDeleteResponse, error) {
		gotReq = in
		return &v1.RelationshipDeleteResponse{SnapToken: "snap-2"}, nil
	}}

	// DeleteRelationship does not require a schema version, so schema.Write
	// should never be called for it.
	schema := &fakeSchemaClient{writeFunc: func(ctx context.Context, in *v1.SchemaWriteRequest, opts ...grpc.CallOption) (*v1.SchemaWriteResponse, error) {
		t.Fatal("Schema.Write should not be called by DeleteRelationship")
		return nil, nil
	}}

	c := newTestChecker(&fakePermissionClient{}, schema, data)

	rel := Relationship{
		Entity:   Entity{Type: "organization", ID: "o1"},
		Relation: "admin",
		Subject:  Entity{Type: "user", ID: "u2"},
	}
	if err := c.DeleteRelationship(context.Background(), rel); err != nil {
		t.Fatalf("DeleteRelationship returned error: %v", err)
	}

	if gotReq.TenantId != "t1" {
		t.Errorf("delete request tenant_id = %q, want t1", gotReq.TenantId)
	}
	if gotReq.Filter.Entity.Type != "organization" || len(gotReq.Filter.Entity.Ids) != 1 || gotReq.Filter.Entity.Ids[0] != "o1" {
		t.Errorf("delete filter entity = %+v, want organization:[o1]", gotReq.Filter.Entity)
	}
	if gotReq.Filter.Relation != "admin" {
		t.Errorf("delete filter relation = %q, want admin", gotReq.Filter.Relation)
	}
	if gotReq.Filter.Subject.Type != "user" || len(gotReq.Filter.Subject.Ids) != 1 || gotReq.Filter.Subject.Ids[0] != "u2" {
		t.Errorf("delete filter subject = %+v, want user:[u2]", gotReq.Filter.Subject)
	}
}

func TestPermifyChecker_DeleteRelationship_Error(t *testing.T) {
	wantErr := errors.New("delete failed")
	data := &fakeDataClient{deleteRelFunc: func(ctx context.Context, in *v1.RelationshipDeleteRequest, opts ...grpc.CallOption) (*v1.RelationshipDeleteResponse, error) {
		return nil, wantErr
	}}

	c := newTestChecker(&fakePermissionClient{}, &fakeSchemaClient{}, data)

	err := c.DeleteRelationship(context.Background(), Relationship{
		Entity: Entity{Type: "organization", ID: "o1"}, Relation: "admin", Subject: Entity{Type: "user", ID: "u2"},
	})
	if err == nil {
		t.Fatal("DeleteRelationship returned nil error, want the wrapped RPC error")
	}
}

// TestPermifyChecker_NilClient covers NewPermifyChecker's documented
// behavior: a malformed endpoint that fails grpc.NewClient must not panic
// sinauth startup, and every subsequent Checker call must return a clear
// error instead of a nil-pointer panic.
func TestPermifyChecker_NilClient(t *testing.T) {
	c := &PermifyChecker{client: nil, tenantID: defaultTenantID, timeout: time.Second}
	ctx := context.Background()

	if _, err := c.Check(ctx, Entity{Type: "user", ID: "u1"}, "manage", Entity{Type: "organization", ID: "o1"}); err == nil {
		t.Fatal("Check with nil client returned nil error, want an error")
	}
	if err := c.WriteRelationship(ctx, Relationship{}); err == nil {
		t.Fatal("WriteRelationship with nil client returned nil error, want an error")
	}
	if err := c.DeleteRelationship(ctx, Relationship{}); err == nil {
		t.Fatal("DeleteRelationship with nil client returned nil error, want an error")
	}
}

// TestPermifyChecker_SatisfiesChecker is a compile-time-adjacent smoke test
// that *PermifyChecker can be used anywhere a Checker is expected. The
// assignment itself is the assertion — newTestChecker returns a concrete
// pointer type, which can never be a nil interface value here, so a
// runtime nil check would be dead code (staticcheck SA4023).
func TestPermifyChecker_SatisfiesChecker(t *testing.T) {
	var _ Checker = newTestChecker(&fakePermissionClient{}, &fakeSchemaClient{}, &fakeDataClient{})
}

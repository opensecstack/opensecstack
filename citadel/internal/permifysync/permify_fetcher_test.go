package permifysync

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestNewPermifyFetcher_StripsSchemeFromEndpoint(t *testing.T) {
	// grpc.NewClient dials lazily, so this must not block or error even
	// though nothing is listening — it only validates/parses the target.
	f := NewPermifyFetcher("grpc://127.0.0.1:1", 50*time.Millisecond, zerolog.Nop())
	if f == nil {
		t.Fatal("expected non-nil PermifyFetcher")
	}
	if f.client == nil {
		t.Fatal("expected client to be constructed for a well-formed endpoint")
	}
	if f.tenantID != defaultTenantID {
		t.Errorf("tenantID = %q, want %q", f.tenantID, defaultTenantID)
	}
}

func TestFetchRoleActionMatrix_UnreachableEndpointReturnsError(t *testing.T) {
	// Port 1 on localhost should refuse/timeout quickly rather than
	// succeed — proving FetchRoleActionMatrix propagates real transport
	// errors instead of silently returning an empty-but-"successful" map.
	f := NewPermifyFetcher("127.0.0.1:1", 300*time.Millisecond, zerolog.Nop())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	matrix, err := f.FetchRoleActionMatrix(ctx)
	if err == nil {
		t.Fatal("expected an error fetching from an unreachable Permify endpoint")
	}
	if !strings.Contains(err.Error(), "permifysync: read relationships") {
		t.Errorf("expected wrapped 'read relationships' error, got: %v", err)
	}
	if matrix != nil {
		t.Errorf("expected nil matrix on error, got %v", matrix)
	}
}

func TestFetchRoleActionMatrix_NilClientReturnsError(t *testing.T) {
	f := &PermifyFetcher{client: nil, tenantID: defaultTenantID, timeout: time.Second, logger: zerolog.Nop()}
	matrix, err := f.FetchRoleActionMatrix(context.Background())
	if err == nil {
		t.Fatal("expected error when Permify client was never initialized")
	}
	if !strings.Contains(err.Error(), "not initialized") {
		t.Errorf("expected 'not initialized' error, got: %v", err)
	}
	if matrix != nil {
		t.Errorf("expected nil matrix, got %v", matrix)
	}
}

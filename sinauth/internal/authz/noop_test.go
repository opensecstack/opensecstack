package authz

import (
	"context"
	"testing"
)

// TestNoopChecker_CheckAlwaysAllows asserts the fail-open contract documented
// on NoopChecker: Check must return (true, nil) for every input, since this
// is what preserves pre-Permify behavior (no per-resource gate) when Permify
// isn't configured.
func TestNoopChecker_CheckAlwaysAllows(t *testing.T) {
	c := NewNoopChecker()
	ctx := context.Background()

	cases := []struct {
		name       string
		subject    Entity
		permission string
		entity     Entity
	}{
		{"empty entities", Entity{}, "", Entity{}},
		{"user vs organization manage", Entity{Type: "user", ID: "u1"}, "manage", Entity{Type: "organization", ID: "o1"}},
		{"user vs group view", Entity{Type: "user", ID: "u1"}, "view", Entity{Type: "group", ID: "g1"}},
		{"user vs client_role use", Entity{Type: "user", ID: "u1"}, "use", Entity{Type: "client_role", ID: "c1:admin"}},
		{"unknown permission name", Entity{Type: "user", ID: "u1"}, "does-not-exist-in-schema", Entity{Type: "organization", ID: "o1"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allowed, err := c.Check(ctx, tc.subject, tc.permission, tc.entity)
			if err != nil {
				t.Fatalf("NoopChecker.Check returned error, want nil: %v", err)
			}
			if !allowed {
				t.Fatalf("NoopChecker.Check returned false, want true (fail-open)")
			}
		})
	}
}

// TestNoopChecker_WriteDeleteAreNoops asserts WriteRelationship and
// DeleteRelationship never error and have no observable side effects — there
// is no backing store for a NoopChecker to keep in sync.
func TestNoopChecker_WriteDeleteAreNoops(t *testing.T) {
	c := NewNoopChecker()
	ctx := context.Background()

	rel := Relationship{
		Entity:   Entity{Type: "organization", ID: "o1"},
		Relation: "owner",
		Subject:  Entity{Type: "user", ID: "u1"},
	}

	if err := c.WriteRelationship(ctx, rel); err != nil {
		t.Fatalf("WriteRelationship returned error, want nil: %v", err)
	}
	if err := c.DeleteRelationship(ctx, rel); err != nil {
		t.Fatalf("DeleteRelationship returned error, want nil: %v", err)
	}

	// Deleting something that was never written must also not error —
	// NoopChecker has no state to be inconsistent about.
	if err := c.DeleteRelationship(ctx, Relationship{}); err != nil {
		t.Fatalf("DeleteRelationship on empty relationship returned error, want nil: %v", err)
	}
}

// TestNoopChecker_SatisfiesChecker is a compile-time-adjacent smoke test
// that NoopChecker can be used anywhere a Checker is expected.
func TestNoopChecker_SatisfiesChecker(t *testing.T) {
	var c Checker = NewNoopChecker()
	if c == nil {
		t.Fatal("NewNoopChecker returned a nil Checker")
	}
}

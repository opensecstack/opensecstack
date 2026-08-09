package auth

import "testing"

func TestAllRoles(t *testing.T) {
	got := AllRoles()
	want := []string{RoleAdmin, RoleOperator, RoleVerifier, RoleViewer, RoleService}
	if len(got) != len(want) {
		t.Fatalf("AllRoles() len = %d, want %d", len(got), len(want))
	}
	for i, r := range want {
		if got[i] != r {
			t.Errorf("AllRoles()[%d] = %q, want %q", i, got[i], r)
		}
	}
}

func TestIsKnownRole(t *testing.T) {
	cases := []struct {
		role string
		want bool
	}{
		{RoleAdmin, true},
		{RoleOperator, true},
		{RoleVerifier, true},
		{RoleViewer, true},
		{RoleService, true},
		{"", false},
		{"superadmin", false},
		{"Admin", false}, // case-sensitive
	}
	for _, c := range cases {
		if got := IsKnownRole(c.role); got != c.want {
			t.Errorf("IsKnownRole(%q) = %v, want %v", c.role, got, c.want)
		}
	}
}

func TestCanRead(t *testing.T) {
	cases := []struct {
		role string
		want bool
	}{
		{RoleAdmin, true},
		{RoleOperator, true},
		{RoleVerifier, true},
		{RoleViewer, true},
		{RoleService, true},
		{"", false},
		{"bogus", false},
	}
	for _, c := range cases {
		if got := canRead(c.role); got != c.want {
			t.Errorf("canRead(%q) = %v, want %v", c.role, got, c.want)
		}
	}
}

func TestCanWrite(t *testing.T) {
	cases := []struct {
		role string
		want bool
	}{
		{RoleAdmin, true},
		{RoleOperator, true},
		{RoleService, true},
		{RoleVerifier, false},
		{RoleViewer, false},
		{"", false},
		{"bogus", false},
	}
	for _, c := range cases {
		if got := canWrite(c.role); got != c.want {
			t.Errorf("canWrite(%q) = %v, want %v", c.role, got, c.want)
		}
	}
}

func TestCanAdmin(t *testing.T) {
	cases := []struct {
		role string
		want bool
	}{
		{RoleAdmin, true},
		{RoleOperator, false},
		{RoleVerifier, false},
		{RoleViewer, false},
		{RoleService, false},
		{"", false},
	}
	for _, c := range cases {
		if got := canAdmin(c.role); got != c.want {
			t.Errorf("canAdmin(%q) = %v, want %v", c.role, got, c.want)
		}
	}
}

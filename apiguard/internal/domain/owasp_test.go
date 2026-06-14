package domain

import (
	"strings"
	"testing"
)

// TestDefaultModulesCount verifies that DefaultModules contains exactly the
// 10 OWASP API Security Top 10 (2023) entries.
func TestDefaultModulesCount(t *testing.T) {
	if len(DefaultModules) != 10 {
		t.Errorf("DefaultModules length = %d, want 10", len(DefaultModules))
	}
}

// TestDefaultModulesIDsNonEmpty checks that every module has a non-empty ID.
func TestDefaultModulesIDsNonEmpty(t *testing.T) {
	for i, m := range DefaultModules {
		if m.ID == "" {
			t.Errorf("DefaultModules[%d].ID is empty", i)
		}
	}
}

// TestDefaultModulesOWASPIdsNonEmpty checks that every module has a non-empty
// OWASPId field.
func TestDefaultModulesOWASPIdsNonEmpty(t *testing.T) {
	for i, m := range DefaultModules {
		if m.OWASPId == "" {
			t.Errorf("DefaultModules[%d].OWASPId is empty", i)
		}
	}
}

// TestDefaultModulesNamesNonEmpty checks that every module has a non-empty Name.
func TestDefaultModulesNamesNonEmpty(t *testing.T) {
	for i, m := range DefaultModules {
		if m.Name == "" {
			t.Errorf("DefaultModules[%d].Name is empty", i)
		}
	}
}

// TestDefaultModulesOWASPIdFormat verifies that every OWASPId follows the
// pattern "API<N>:2023".
func TestDefaultModulesOWASPIdFormat(t *testing.T) {
	for _, m := range DefaultModules {
		if !strings.HasPrefix(m.OWASPId, "API") {
			t.Errorf("module %q OWASPId %q does not start with 'API'", m.ID, m.OWASPId)
		}
		if !strings.HasSuffix(m.OWASPId, ":2023") {
			t.Errorf("module %q OWASPId %q does not end with ':2023'", m.ID, m.OWASPId)
		}
	}
}

// TestDefaultModulesExactOWASPIds checks that each of the ten API1:2023 through
// API10:2023 OWASPId values is present exactly once.
func TestDefaultModulesExactOWASPIds(t *testing.T) {
	wantIDs := []string{
		"API1:2023", "API2:2023", "API3:2023", "API4:2023", "API5:2023",
		"API6:2023", "API7:2023", "API8:2023", "API9:2023", "API10:2023",
	}

	counts := make(map[string]int, 10)
	for _, m := range DefaultModules {
		counts[m.OWASPId]++
	}

	for _, id := range wantIDs {
		n := counts[id]
		if n != 1 {
			t.Errorf("OWASPId %q appears %d times in DefaultModules, want exactly 1", id, n)
		}
	}
}

// TestDefaultModulesExactInternalIDs verifies that each well-known internal
// module ID (a1_bola through a10_unsafe_consumption) is present.
func TestDefaultModulesExactInternalIDs(t *testing.T) {
	wantIDs := []string{
		"a1_bola",
		"a2_auth",
		"a3_mass_assignment",
		"a4_rate_limit",
		"a5_function_auth",
		"a6_business_flow",
		"a7_ssrf",
		"a8_misconfiguration",
		"a9_inventory",
		"a10_unsafe_consumption",
	}

	found := make(map[string]bool, len(wantIDs))
	for _, m := range DefaultModules {
		found[m.ID] = true
	}

	for _, id := range wantIDs {
		if !found[id] {
			t.Errorf("expected module ID %q not found in DefaultModules", id)
		}
	}
}

// TestDefaultModulesIDsDistinct ensures no two modules share the same ID.
func TestDefaultModulesIDsDistinct(t *testing.T) {
	seen := make(map[string]int, len(DefaultModules))
	for _, m := range DefaultModules {
		seen[m.ID]++
	}
	for id, n := range seen {
		if n > 1 {
			t.Errorf("module ID %q appears %d times, want 1", id, n)
		}
	}
}

// TestDefaultModulesEnabledDefaults verifies the expected enablement state of
// each module according to the OWASP API Security Top 10 defaults:
// A1-A5, A7-A9 are enabled; A6 and A10 are disabled.
func TestDefaultModulesEnabledDefaults(t *testing.T) {
	cases := []struct {
		id      string
		enabled bool
	}{
		{"a1_bola", true},
		{"a2_auth", true},
		{"a3_mass_assignment", true},
		{"a4_rate_limit", true},
		{"a5_function_auth", true},
		{"a6_business_flow", false},
		{"a7_ssrf", true},
		{"a8_misconfiguration", true},
		{"a9_inventory", true},
		{"a10_unsafe_consumption", false},
	}

	// Build a lookup by ID for O(1) access.
	byID := make(map[string]OWASPModule, len(DefaultModules))
	for _, m := range DefaultModules {
		byID[m.ID] = m
	}

	for _, tc := range cases {
		m, ok := byID[tc.id]
		if !ok {
			t.Errorf("module %q not found in DefaultModules", tc.id)
			continue
		}
		if m.Enabled != tc.enabled {
			t.Errorf("module %q: Enabled = %v, want %v", tc.id, m.Enabled, tc.enabled)
		}
	}
}

// TestDefaultModulesDefaultFieldMatchesEnabled checks that the Default field
// mirrors the Enabled field for each module (they are set in tandem).
func TestDefaultModulesDefaultFieldMatchesEnabled(t *testing.T) {
	for _, m := range DefaultModules {
		if m.Default != m.Enabled {
			t.Errorf("module %q: Default (%v) != Enabled (%v), expected them to match",
				m.ID, m.Default, m.Enabled)
		}
	}
}

// TestOWASPModuleStruct verifies that an OWASPModule can be constructed and
// that all exported fields are accessible.
func TestOWASPModuleStruct(t *testing.T) {
	m := OWASPModule{
		ID:          "custom_module",
		OWASPId:     "API1:2023",
		Name:        "Custom Check",
		Description: "A custom security check.",
		Enabled:     true,
		Default:     false,
	}

	if m.ID != "custom_module" {
		t.Errorf("ID = %q, want custom_module", m.ID)
	}
	if m.OWASPId != "API1:2023" {
		t.Errorf("OWASPId = %q, want API1:2023", m.OWASPId)
	}
	if m.Name != "Custom Check" {
		t.Errorf("Name = %q, want Custom Check", m.Name)
	}
	if !m.Enabled {
		t.Error("Enabled should be true")
	}
	if m.Default {
		t.Error("Default should be false")
	}
}

// TestDefaultModulesOrderA1ToA10 verifies that the modules are listed in
// ascending OWASP number order (A1 first, A10 last).
func TestDefaultModulesOrderA1ToA10(t *testing.T) {
	if len(DefaultModules) < 10 {
		t.Skip("DefaultModules has fewer than 10 entries")
	}
	if DefaultModules[0].OWASPId != "API1:2023" {
		t.Errorf("DefaultModules[0].OWASPId = %q, want API1:2023", DefaultModules[0].OWASPId)
	}
	if DefaultModules[9].OWASPId != "API10:2023" {
		t.Errorf("DefaultModules[9].OWASPId = %q, want API10:2023", DefaultModules[9].OWASPId)
	}
}

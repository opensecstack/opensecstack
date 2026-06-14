package customrules

import (
	"testing"
)

func TestBuildEndpointURL_JoinsCorrectly(t *testing.T) {
	cases := []struct {
		target string
		path   string
		want   string
	}{
		{"https://api.example.com", "/v1/scans", "https://api.example.com/v1/scans"},
		{"https://api.example.com/", "/v1/scans", "https://api.example.com/v1/scans"},
		{"https://api.example.com", "/", "https://api.example.com/"},
		{"https://api.example.com/", "", "https://api.example.com"},
	}
	for _, tc := range cases {
		got := buildEndpointURL(tc.target, tc.path)
		if got != tc.want {
			t.Errorf("buildEndpointURL(%q, %q) = %q, want %q", tc.target, tc.path, got, tc.want)
		}
	}
}

func TestParseStatusCodes_ValidCodes(t *testing.T) {
	got := parseStatusCodes("401,403")
	if len(got) != 2 {
		t.Fatalf("expected 2 codes, got %d: %v", len(got), got)
	}
	if got[0] != 401 || got[1] != 403 {
		t.Errorf("codes = %v, want [401 403]", got)
	}
}

func TestParseStatusCodes_SingleCode(t *testing.T) {
	got := parseStatusCodes("200")
	if len(got) != 1 || got[0] != 200 {
		t.Errorf("expected [200], got %v", got)
	}
}

func TestParseStatusCodes_EmptyString(t *testing.T) {
	got := parseStatusCodes("")
	// Empty string: no valid codes
	if len(got) != 0 {
		t.Errorf("expected empty slice for empty input, got %v", got)
	}
}

func TestParseStatusCodes_IgnoresMalformed(t *testing.T) {
	got := parseStatusCodes("200,abc,403")
	if len(got) != 2 {
		t.Fatalf("expected 2 valid codes, got %d: %v", len(got), got)
	}
	if got[0] != 200 || got[1] != 403 {
		t.Errorf("codes = %v, want [200 403]", got)
	}
}

func TestParseStatusCodes_WithSpaces(t *testing.T) {
	got := parseStatusCodes("401, 403")
	if len(got) != 2 {
		t.Fatalf("expected 2 codes, got %d: %v", len(got), got)
	}
}

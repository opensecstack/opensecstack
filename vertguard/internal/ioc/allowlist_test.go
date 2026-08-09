package ioc

import "testing"

func TestNewAllowlist_ParsesCIDRsIPsAndDomains(t *testing.T) {
	a := NewAllowlist([]string{
		"10.0.0.0/8",
		"192.168.1.5",
		"2001:db8::1",
		"  Example.com  ",
		"",
	})
	if len(a.cidrs) != 3 {
		t.Fatalf("len(cidrs) = %d, want 3 (one CIDR + two widened bare IPs)", len(a.cidrs))
	}
	if len(a.domains) != 1 || a.domains[0] != "example.com" {
		t.Fatalf("domains = %v, want [example.com] (trimmed + lowercased)", a.domains)
	}
}

func TestAllowlist_Matches_NilReceiver(t *testing.T) {
	var a *Allowlist
	if a.Matches(KindIP, "10.0.0.1") {
		t.Error("nil Allowlist must never match (fail-closed to \"not allowlisted\")")
	}
}

func TestAllowlist_Matches_IP(t *testing.T) {
	a := NewAllowlist([]string{"10.0.0.0/8", "192.168.1.5"})

	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"inside CIDR", "10.1.2.3", true},
		{"outside CIDR", "8.8.8.8", false},
		{"exact bare IP match", "192.168.1.5", true},
		{"invalid IP", "not-an-ip", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := a.Matches(KindIP, tt.value); got != tt.want {
				t.Errorf("Matches(KindIP, %q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestAllowlist_Matches_CIDR(t *testing.T) {
	a := NewAllowlist([]string{"10.0.0.0/8"})

	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"subset of allowed range", "10.0.0.0/16", true},
		{"disjoint range", "172.16.0.0/12", false},
		{"malformed CIDR", "not-a-cidr", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := a.Matches(KindCIDR, tt.value); got != tt.want {
				t.Errorf("Matches(KindCIDR, %q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestAllowlist_Matches_Domain(t *testing.T) {
	a := NewAllowlist([]string{"example.com"})

	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"exact match", "example.com", true},
		{"subdomain match", "sub.example.com", true},
		{"case-insensitive", "EXAMPLE.com", true},
		{"unrelated domain", "example.net", false},
		{"suffix collision without dot boundary must not match", "notexample.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := a.Matches(KindDomain, tt.value); got != tt.want {
				t.Errorf("Matches(KindDomain, %q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestAllowlist_Matches_URL(t *testing.T) {
	a := NewAllowlist([]string{"example.com"})

	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"https URL on allowed domain", "https://example.com/path", true},
		{"URL with port and subdomain", "https://sub.example.com:8443/x", true},
		{"URL with userinfo", "https://user:pass@example.com/", true},
		{"URL on unrelated domain", "https://evil.com/example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := a.Matches(KindURL, tt.value); got != tt.want {
				t.Errorf("Matches(KindURL, %q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestAllowlist_Matches_UnknownKindDefaultsFalse(t *testing.T) {
	a := NewAllowlist([]string{"example.com", "10.0.0.0/8"})
	if a.Matches(KindHashSHA256, "deadbeef") {
		t.Error("Matches() with a non-network kind must default to false")
	}
}

func TestHostFromURL(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"https://example.com/path", "example.com"},
		{"http://example.com:8080/x?y=1", "example.com"},
		{"https://user:pass@example.com/", "example.com"},
		{"example.com", "example.com"},
		{"example.com/path", "example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := hostFromURL(tt.in); got != tt.want {
				t.Errorf("hostFromURL(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestItoa(t *testing.T) {
	tests := []struct {
		in   int
		want string
	}{
		{32, "32"},
		{128, "128"},
		{0, "0"},
		{7, "7"},
		{99, "99"},
	}
	for _, tt := range tests {
		if got := itoa(tt.in); got != tt.want {
			t.Errorf("itoa(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

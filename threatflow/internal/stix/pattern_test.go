package stix

import (
	"errors"
	"testing"
)

func TestParsePattern_Simple(t *testing.T) {
	cases := []struct {
		name, pattern, wantType, wantVal string
	}{
		{"ipv4", "[ipv4-addr:value = '1.2.3.4']", "ipv4-addr", "1.2.3.4"},
		{"domain", "[domain-name:value = 'evil.example']", "domain-name", "evil.example"},
		{"file-hash", "[file:hashes.SHA-256 = 'abc123']", "file", "abc123"},
		{"url", `[url:value = "http://bad.example/path"]`, "url", "http://bad.example/path"},
		{"padded", "   [  email-addr:value  =  'a@b.c'  ]   ", "email-addr", "a@b.c"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			typ, val, err := PrimaryIOC(c.pattern)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if typ != c.wantType {
				t.Errorf("type = %q, want %q", typ, c.wantType)
			}
			if val != c.wantVal {
				t.Errorf("val = %q, want %q", val, c.wantVal)
			}
		})
	}
}

func TestParsePattern_Unsupported(t *testing.T) {
	unsupported := []string{
		"[ipv4-addr:value = '1.1.1.1'] AND [domain-name:value = 'x.y']",
		"[ipv4-addr:value MATCHES '.*']",
		"",
		"not a pattern",
	}
	for _, p := range unsupported {
		_, _, err := PrimaryIOC(p)
		if err == nil {
			t.Errorf("pattern %q: expected error", p)
		}
		// Non-empty unsupported patterns must map to ErrUnsupportedPattern
		// explicitly; the empty-string case has its own dedicated error
		// message and is exempt.
		if p != "" && err != nil && !errors.Is(err, ErrUnsupportedPattern) {
			t.Errorf("pattern %q: err = %v, want ErrUnsupportedPattern", p, err)
		}
	}
}

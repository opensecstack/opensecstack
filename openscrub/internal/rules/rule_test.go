package rules

import (
	"testing"
)

func intp(n int) *int { return &n }

func TestCreateRequestValidate(t *testing.T) {
	cases := []struct {
		name    string
		req     CreateRequest
		wantErr bool
	}{
		{"blocklist ok", CreateRequest{Type: TypeBlocklist, CIDR: "198.51.100.0/24", TTLSeconds: 3600}, false},
		{"blocklist v6 ok", CreateRequest{Type: TypeBlocklist, CIDR: "2001:db8::/32", TTLSeconds: 3600}, false},
		{"blocklist with pps rejected", CreateRequest{Type: TypeBlocklist, CIDR: "1.2.3.0/24", PPS: intp(100), TTLSeconds: 60}, true},
		{"blocklist with port rejected", CreateRequest{Type: TypeBlocklist, CIDR: "1.2.3.0/24", Port: intp(443), TTLSeconds: 60}, true},
		{"blocklist bad cidr", CreateRequest{Type: TypeBlocklist, CIDR: "not-cidr", TTLSeconds: 60}, true},
		{"ratelimit ok", CreateRequest{Type: TypeRatelimit, CIDR: "203.0.113.5/32", PPS: intp(500), TTLSeconds: 600}, false},
		{"ratelimit needs pps", CreateRequest{Type: TypeRatelimit, CIDR: "203.0.113.5/32", TTLSeconds: 600}, true},
		{"ratelimit zero pps", CreateRequest{Type: TypeRatelimit, CIDR: "203.0.113.5/32", PPS: intp(0), TTLSeconds: 600}, true},
		{"syncookie ok", CreateRequest{Type: TypeSynCookie, Port: intp(443), TTLSeconds: 86400}, false},
		{"syncookie needs port", CreateRequest{Type: TypeSynCookie, TTLSeconds: 86400}, true},
		{"syncookie port out of range", CreateRequest{Type: TypeSynCookie, Port: intp(70000), TTLSeconds: 86400}, true},
		{"syncookie with cidr rejected", CreateRequest{Type: TypeSynCookie, CIDR: "1.2.3.0/24", Port: intp(80), TTLSeconds: 60}, true},
		{"unknown type", CreateRequest{Type: "wat", CIDR: "1.2.3.0/24", TTLSeconds: 60}, true},
		{"ttl zero", CreateRequest{Type: TypeBlocklist, CIDR: "1.2.3.0/24", TTLSeconds: 0}, true},
		{"ttl too big", CreateRequest{Type: TypeBlocklist, CIDR: "1.2.3.0/24", TTLSeconds: 31 * 24 * 3600}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.req.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("got err=%v want err=%v", err, tc.wantErr)
			}
		})
	}
}

func TestParseCIDRMasksHostBits(t *testing.T) {
	p, err := ParseCIDR("198.51.100.42/24")
	if err != nil {
		t.Fatal(err)
	}
	if p.String() != "198.51.100.0/24" {
		t.Fatalf("got %q want 198.51.100.0/24", p.String())
	}
}

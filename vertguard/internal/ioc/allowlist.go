package ioc

import (
	"net"
	"strings"
)

// Allowlist guards the puller against ingesting IOCs that overlap with
// operator-trusted CIDRs / domains. An overlap is a hard reject — the
// puller logs a skipped row in the audit instead of writing the IOC.
type Allowlist struct {
	cidrs   []*net.IPNet
	domains []string // exact + suffix-match (".example.com" matches "x.example.com")
}

// NewAllowlist parses a flat list of entries. CIDRs are kept as
// *net.IPNet; bare IPs are widened to /32 or /128. Anything else is
// treated as a domain.
func NewAllowlist(entries []string) *Allowlist {
	a := &Allowlist{}
	for _, raw := range entries {
		s := strings.TrimSpace(strings.ToLower(raw))
		if s == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(s); err == nil {
			a.cidrs = append(a.cidrs, n)
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			_, n, _ := net.ParseCIDR(ip.String() + "/" + itoa(bits))
			if n != nil {
				a.cidrs = append(a.cidrs, n)
				continue
			}
		}
		a.domains = append(a.domains, s)
	}
	return a
}

// Matches reports whether the given IOC overlaps the allowlist.
// Unknown kinds default to false (fail-open for non-network kinds is
// fine — the allowlist is scoped to network indicators).
func (a *Allowlist) Matches(kind Kind, value string) bool {
	if a == nil {
		return false
	}
	v := strings.TrimSpace(strings.ToLower(value))
	switch kind {
	case KindIP:
		ip := net.ParseIP(v)
		if ip == nil {
			return false
		}
		for _, n := range a.cidrs {
			if n.Contains(ip) {
				return true
			}
		}
	case KindCIDR:
		ip, n, err := net.ParseCIDR(v)
		if err != nil {
			return false
		}
		for _, allow := range a.cidrs {
			if allow.Contains(ip) || allow.Contains(n.IP) {
				return true
			}
		}
	case KindDomain, KindURL:
		host := v
		if kind == KindURL {
			host = hostFromURL(v)
		}
		for _, d := range a.domains {
			if host == d || strings.HasSuffix(host, "."+strings.TrimPrefix(d, ".")) {
				return true
			}
		}
	}
	return false
}

func hostFromURL(u string) string {
	// Cheap host extraction — avoids dragging net/url into the
	// hot-path purely for a lower-cased hostname.
	s := u
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	return s
}

func itoa(n int) string {
	if n == 32 {
		return "32"
	}
	if n == 128 {
		return "128"
	}
	// Fallback — only used when bits is set above; kept tiny on purpose.
	digits := []byte{}
	if n == 0 {
		return "0"
	}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// Package rules is the domain model for OpenScrub mitigation rules.
//
// A rule is one of:
//   - "blocklist"  — drop all traffic matching the CIDR
//   - "ratelimit"  — cap PPS for a single source IP (CIDR /32 or /128)
//
// Rules carry a TTL. The rules.Service is responsible for installing them
// in the data plane on create, removing them on TTL expiry, and emitting
// `openscrub.rule_change` events to CITADEL for every transition.
package rules

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// Type is the rule kind.
type Type string

const (
	TypeBlocklist Type = "blocklist"
	TypeRatelimit Type = "ratelimit"
	// TypeSynCookie toggles XDP SYN-cookie generation for a TCP listener
	// port (no CIDR; the rule keys off `port`).
	TypeSynCookie Type = "syncookie"
)

// Source identifies who created the rule.
const (
	SourceOperator   = "operator"
	SourceThreatFlow = "threatflow"
	SourceSystem     = "system"
)

// Rule is the canonical in-memory representation. The cidr is stored as
// a string in the canonical netip.Prefix form ("198.51.100.0/24",
// "2001:db8::/32") so the DB CIDR column and the Rust MapWriter prefix
// types both round-trip cleanly.
type Rule struct {
	ID         uuid.UUID  `json:"id"`
	Type       Type       `json:"type"`
	CIDR       string     `json:"cidr,omitempty"`
	PPS        *int       `json:"pps,omitempty"`
	Port       *int       `json:"port,omitempty"`
	TTLSeconds int        `json:"ttl_seconds"`
	Source     string     `json:"source"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	CreatedBy  *uuid.UUID `json:"created_by,omitempty"`
}

// CreateRequest is the JSON body of POST /api/v1/rules.
type CreateRequest struct {
	Type       Type   `json:"type"`
	CIDR       string `json:"cidr,omitempty"`
	PPS        *int   `json:"pps,omitempty"`
	Port       *int   `json:"port,omitempty"`
	TTLSeconds int    `json:"ttl_seconds"`
	Source     string `json:"source,omitempty"`
}

// Validate enforces the invariants the data plane relies on. The full
// matrix is also checked at the DB layer (see migration 0001).
func (r CreateRequest) Validate() error {
	switch r.Type {
	case TypeBlocklist:
		if r.PPS != nil {
			return errors.New("pps is only valid for ratelimit rules")
		}
		if r.Port != nil {
			return errors.New("port is only valid for syncookie rules")
		}
		p, err := ParseCIDR(r.CIDR)
		if err != nil {
			return fmt.Errorf("cidr: %w", err)
		}
		// /0 is catastrophic (drops the entire internet, including the
		// operator's own session). Force operators to scope blocklists.
		if p.Bits() == 0 {
			return errors.New("blocklist /0 rejected — refuse to drop all traffic")
		}
	case TypeRatelimit:
		if r.PPS == nil || *r.PPS <= 0 {
			return errors.New("ratelimit rules require pps > 0")
		}
		// Cap PPS to a sane upper bound — values above this likely
		// reflect a unit confusion (Mbps vs pps) or a typo, and would
		// disable the limiter in practice (the bucket capacity scales
		// with rate_pps and overflows the u32 used by the eBPF map).
		const maxPPS = 1_000_000_000
		if *r.PPS > maxPPS {
			return fmt.Errorf("ratelimit pps %d exceeds cap of %d", *r.PPS, maxPPS)
		}
		if r.Port != nil {
			return errors.New("port is only valid for syncookie rules")
		}
		p, err := ParseCIDR(r.CIDR)
		if err != nil {
			return fmt.Errorf("cidr: %w", err)
		}
		// The XDP ratelimit map is keyed by a single source IP; a wider
		// prefix would silently collapse to its network address (e.g.
		// 10.0.0.0/24 → only 10.0.0.0 is rate-limited). Force the
		// caller to be explicit instead of producing a misleading rule.
		if (p.Addr().Is4() && p.Bits() != 32) || (p.Addr().Is6() && p.Bits() != 128) {
			return errors.New("ratelimit cidr must be a host prefix (/32 or /128)")
		}
	case TypeSynCookie:
		if r.Port == nil || *r.Port <= 0 || *r.Port > 65535 {
			return errors.New("syncookie rules require port in 1..65535")
		}
		if r.CIDR != "" {
			return errors.New("cidr is not valid for syncookie rules")
		}
		if r.PPS != nil {
			return errors.New("pps is not valid for syncookie rules")
		}
	default:
		return fmt.Errorf("unknown rule type %q", r.Type)
	}
	if r.TTLSeconds <= 0 {
		return errors.New("ttl_seconds must be > 0")
	}
	if r.TTLSeconds > 30*24*3600 {
		return errors.New("ttl_seconds capped at 30 days")
	}
	return nil
}

// ParseCIDR returns the canonical netip.Prefix or an error.
func ParseCIDR(s string) (netip.Prefix, error) {
	if s == "" {
		return netip.Prefix{}, errors.New("empty")
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return p.Masked(), nil
}

// IsExpired reports whether the rule has passed its TTL relative to now.
func (r Rule) IsExpired(now time.Time) bool {
	return !r.ExpiresAt.IsZero() && !now.Before(r.ExpiresAt)
}

// Package ioc implements VG-006 — the persistent IOC store and the
// scheduled community-feed puller.
//
// Design mirrors openscrub/internal/ioc: each Source runs on its own
// ticker, writes one ioc_pull_audit row per Tick, increments per-source
// metrics, and is fail-safe when the upstream is unreachable (audit
// row carries the error string and the next tick retries).
package ioc

import (
	"time"

	"github.com/google/uuid"
)

// Kind enumerates the IOC types the store accepts. Mirrors the CHECK
// constraint on the iocs table.
type Kind string

const (
	KindIP         Kind = "ip"
	KindCIDR       Kind = "cidr"
	KindDomain     Kind = "domain"
	KindURL        Kind = "url"
	KindHashSHA256 Kind = "hash_sha256"
	KindHashMD5    Kind = "hash_md5"
)

// ValidKind reports whether k is one of the known kinds.
func ValidKind(k Kind) bool {
	switch k {
	case KindIP, KindCIDR, KindDomain, KindURL, KindHashSHA256, KindHashMD5:
		return true
	}
	return false
}

// IOC is the persisted indicator. Tenant defaults to "" — the unique
// constraint includes tenant so different tenants may carry the same
// (kind, value) pair without collision.
type IOC struct {
	ID         uuid.UUID
	Kind       Kind
	Value      string
	Source     string
	Confidence float64
	Tags       []string
	FirstSeen  time.Time
	LastSeen   time.Time
	ExpiresAt  *time.Time
	Tenant     string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// PullAudit is one ioc_pull_audit row.
type PullAudit struct {
	ID         uuid.UUID
	Source     string
	StartedAt  time.Time
	FinishedAt time.Time
	Fetched    int
	Inserted   int
	Updated    int
	Skipped    int
	Error      string
}

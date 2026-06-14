package ratelimit

import (
	"context"
	"time"
)

// Kind constants — mirror the bucket key prefix (`sub:` / `ip:`) in
// keyFor so a stored Override slots straight into the snapshot map.
const (
	KindSub = "sub"
	KindIP  = "ip"
)

// Override is one per-key quota entry. Mirrors the rate_limit_overrides
// table 1:1.
type Override struct {
	Kind      string     `json:"kind"`
	Value     string     `json:"value"`
	RPS       float64    `json:"rps"`
	Burst     int        `json:"burst"`
	Reason    string     `json:"reason,omitempty"`
	CreatedBy string     `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// IsActive reports whether the override should still apply at t.
func (o Override) IsActive(t time.Time) bool {
	if o.ExpiresAt == nil {
		return true
	}
	return t.Before(*o.ExpiresAt)
}

// OverrideStore is the persistence contract — mirrors the denylist
// Store shape so the admin handler composes the same way.
type OverrideStore interface {
	List(ctx context.Context) ([]Override, error)
	Add(ctx context.Context, o Override) error
	Remove(ctx context.Context, kind, value string) error
}

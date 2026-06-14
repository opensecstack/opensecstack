// Package webhook implements VG-015: persistent outbound webhook
// delivery with 3-slot HMAC rotation and an outbox pattern.
//
// The legacy in-process publisher in internal/threatfeed/webhook is
// kept intact for the ThreatFlow re-fanout path; this package is the
// durable, multi-tenant, rotation-aware delivery surface targeted by
// v1.0 customer-facing event subscribers.
package webhook

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// SlotPrimary, SlotNext, SlotPrevious index positions in
// Subscriber.HMACSecrets / KeyIDs. Mirrors the CITADEL client + JWT
// auth rotation contract: primary signs, next is preloaded for the
// upcoming roll, previous is retained so verifiers downstream still
// accept in-flight signatures from the previous secret.
const (
	SlotPrimary  = 0
	SlotNext     = 1
	SlotPrevious = 2
	NumSlots     = 3
)

// Subscriber is a persisted outbound webhook target.
type Subscriber struct {
	ID          uuid.UUID `json:"id"`
	Tenant      string    `json:"tenant"`
	URL         string    `json:"url"`
	EventTypes  []string  `json:"event_types"`
	HMACSecrets []string  `json:"-"` // never serialised
	KeyIDs      []string  `json:"key_ids"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Matches reports whether the subscriber wants this event type.
// Empty EventTypes means all.
func (s *Subscriber) Matches(eventType string) bool {
	if len(s.EventTypes) == 0 {
		return true
	}
	for _, t := range s.EventTypes {
		if t == eventType {
			return true
		}
	}
	return false
}

// PrimarySecret returns (secret, key_id) for the primary slot. Empty
// secret means the subscriber has no signing key configured — the
// dispatcher refuses to sign with "" and the delivery is failed loudly
// rather than silently sending an unsigned body.
func (s *Subscriber) PrimarySecret() (string, string) {
	if len(s.HMACSecrets) == 0 {
		return "", ""
	}
	secret := s.HMACSecrets[SlotPrimary]
	kid := ""
	if len(s.KeyIDs) > SlotPrimary {
		kid = s.KeyIDs[SlotPrimary]
	}
	return secret, kid
}

// PublicView strips secrets and exposes only key_ids + last-4-chars
// hints. Returned by the admin List endpoint.
type PublicView struct {
	ID         uuid.UUID `json:"id"`
	Tenant     string    `json:"tenant"`
	URL        string    `json:"url"`
	EventTypes []string  `json:"event_types"`
	KeyIDs     []string  `json:"key_ids"`
	// SecretHints[i] is the last 4 chars of HMACSecrets[i] or "" if
	// the slot is empty. Lets operators visually confirm a rotation
	// without exposing the secret.
	SecretHints []string  `json:"secret_hints"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ToPublic builds a PublicView from a Subscriber.
func (s *Subscriber) ToPublic() PublicView {
	hints := make([]string, NumSlots)
	for i := 0; i < NumSlots; i++ {
		if i < len(s.HMACSecrets) {
			hints[i] = lastFour(s.HMACSecrets[i])
		}
	}
	return PublicView{
		ID:          s.ID,
		Tenant:      s.Tenant,
		URL:         s.URL,
		EventTypes:  s.EventTypes,
		KeyIDs:      s.KeyIDs,
		SecretHints: hints,
		Enabled:     s.Enabled,
		CreatedAt:   s.CreatedAt,
		UpdatedAt:   s.UpdatedAt,
	}
}

func lastFour(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 4 {
		return s
	}
	return s[len(s)-4:]
}

// Event is the wire payload pushed to subscribers. Mirrors the shape
// of the existing IOCEvent + citadel.Evidence so handlers don't have
// to translate.
type Event struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Tenant    string          `json:"tenant,omitempty"`
	Data      json.RawMessage `json:"data"`
	Timestamp time.Time       `json:"timestamp"`
	Source    string          `json:"source"`
}

// OutboxRow is one pending or delivered outbox entry.
type OutboxRow struct {
	ID            uuid.UUID
	SubscriberID  uuid.UUID
	EventID       string
	EventType     string
	Payload       []byte
	Attempts      int
	LastError     string
	NextAttemptAt time.Time
	DeliveredAt   *time.Time
	CreatedAt     time.Time
}

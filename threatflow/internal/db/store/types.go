// Package store provides typed CRUD access to ThreatFlow tables.
package store

import (
	"time"

	"github.com/google/uuid"
)

// IOC is a row from the iocs table.
type IOC struct {
	ID          uuid.UUID  `json:"id"`
	StixID      string     `json:"stix_id"`
	Type        string     `json:"type"`
	Value       string     `json:"value"`
	Pattern     string     `json:"pattern"`
	PatternHash string     `json:"pattern_hash"`
	FeedID      *uuid.UUID `json:"feed_id,omitempty"`
	Source      string     `json:"source,omitempty"`
	Confidence  int        `json:"confidence"`
	Description string     `json:"description,omitempty"`
	Tags        []string   `json:"tags"`
	FirstSeen   time.Time  `json:"first_seen"`
	LastSeen    time.Time  `json:"last_seen"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Revoked     bool       `json:"revoked"`
	CVE         string     `json:"cve,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// IOCFilter narrows a List query.
type IOCFilter struct {
	Type       string
	Value      string
	FeedID     *uuid.UUID
	Tag        string
	MinConf    int
	Revoked    *bool
	Search     string
	Limit      int
	Offset     int
}

// Feed is a row from the feeds table.
type Feed struct {
	ID              uuid.UUID  `json:"id"`
	Name            string     `json:"name"`
	FeedType        string     `json:"feed_type"`
	URL             string     `json:"url,omitempty"`
	PollInterval    string     `json:"poll_interval"`
	ConfidenceBase  int        `json:"confidence_base"`
	AccuracyRatio   float64    `json:"accuracy_ratio"`
	LastPollAt      *time.Time `json:"last_poll_at,omitempty"`
	LastPollCount   int        `json:"last_poll_count"`
	ErrorCount      int        `json:"error_count"`
	Enabled         bool       `json:"enabled"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

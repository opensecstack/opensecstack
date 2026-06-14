// Package db — shared store helpers.
// Tiny adapter helpers for nullable pgx parameters used across the stores.
package db

import (
	"time"

	"github.com/google/uuid"
)

// nullableUUID returns nil for a nil pointer so pgx writes SQL NULL
// instead of the zero-UUID. Use when binding optional FK columns.
func nullableUUID(u *uuid.UUID) any {
	if u == nil {
		return nil
	}
	return *u
}

// nullableTime returns nil for a nil pointer so pgx writes SQL NULL.
func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}

// nullableString returns nil for an empty string so pgx writes SQL NULL.
// Use only for columns where empty-string and NULL must be distinct.
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullableInt returns nil for a nil pointer so pgx writes SQL NULL.
func nullableInt(i *int) any {
	if i == nil {
		return nil
	}
	return *i
}

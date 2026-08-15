package db

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// Pure unit tests for the nullable* adapter helpers — no DB required.

func TestNullableUUID(t *testing.T) {
	if got := nullableUUID(nil); got != nil {
		t.Fatalf("nullableUUID(nil) = %v, want nil", got)
	}

	id := uuid.New()
	got := nullableUUID(&id)
	gotUUID, ok := got.(uuid.UUID)
	if !ok {
		t.Fatalf("nullableUUID(&id) returned %T, want uuid.UUID", got)
	}
	if gotUUID != id {
		t.Fatalf("nullableUUID(&id) = %v, want %v", gotUUID, id)
	}
}

func TestNullableTime(t *testing.T) {
	if got := nullableTime(nil); got != nil {
		t.Fatalf("nullableTime(nil) = %v, want nil", got)
	}

	tm := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	got := nullableTime(&tm)
	gotTime, ok := got.(time.Time)
	if !ok {
		t.Fatalf("nullableTime(&tm) returned %T, want time.Time", got)
	}
	if !gotTime.Equal(tm) {
		t.Fatalf("nullableTime(&tm) = %v, want %v", gotTime, tm)
	}
}

func TestNullableString(t *testing.T) {
	if got := nullableString(""); got != nil {
		t.Fatalf("nullableString(\"\") = %v, want nil", got)
	}
	if got := nullableString("hello"); got != "hello" {
		t.Fatalf("nullableString(\"hello\") = %v, want \"hello\"", got)
	}
}

func TestNullableInt(t *testing.T) {
	if got := nullableInt(nil); got != nil {
		t.Fatalf("nullableInt(nil) = %v, want nil", got)
	}

	n := 42
	got := nullableInt(&n)
	gotInt, ok := got.(int)
	if !ok {
		t.Fatalf("nullableInt(&n) returned %T, want int", got)
	}
	if gotInt != 42 {
		t.Fatalf("nullableInt(&n) = %v, want 42", gotInt)
	}
}

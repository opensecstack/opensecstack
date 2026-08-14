//go:build integration

package store

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestIntegration_Feed_CreateGetByNameAndID(t *testing.T) {
	pool := testDB(t)
	s := NewFeedStore(pool)
	ctx := context.Background()

	f := &Feed{
		Name:           "abuse-ch",
		FeedType:       "taxii21",
		URL:            "https://example.test/taxii",
		ConfidenceBase: 50,
		AccuracyRatio:  0.9,
		Enabled:        true,
	}
	mustOK(t, s.Create(ctx, f), "create")
	if f.PollInterval == "" {
		t.Error("expected default poll_interval to be populated")
	}

	byID, err := s.Get(ctx, f.ID)
	mustOK(t, err, "get by id")
	if byID.Name != "abuse-ch" || byID.URL != "https://example.test/taxii" {
		t.Errorf("unexpected feed by id: %+v", byID)
	}

	byName, err := s.GetByName(ctx, "abuse-ch")
	mustOK(t, err, "get by name")
	if byName.ID != f.ID {
		t.Errorf("byName.ID = %s, want %s", byName.ID, f.ID)
	}

	if _, err := s.Get(ctx, uuid.New()); err != ErrNotFound {
		t.Errorf("want ErrNotFound for unknown id, got %v", err)
	}
	if _, err := s.GetByName(ctx, "does-not-exist"); err != ErrNotFound {
		t.Errorf("want ErrNotFound for unknown name, got %v", err)
	}
}

func TestIntegration_Feed_CreateDefaultsPollIntervalWhenEmpty(t *testing.T) {
	pool := testDB(t)
	s := NewFeedStore(pool)
	ctx := context.Background()

	f := &Feed{Name: "no-interval", FeedType: "csv", Enabled: true}
	mustOK(t, s.Create(ctx, f), "create")

	got, err := s.Get(ctx, f.ID)
	mustOK(t, err, "get")
	if got.URL != "" {
		t.Errorf("URL = %q, want empty", got.URL)
	}
	if got.PollInterval == "" {
		t.Error("expected non-empty default poll interval")
	}
}

func TestIntegration_Feed_List(t *testing.T) {
	pool := testDB(t)
	s := NewFeedStore(pool)
	ctx := context.Background()

	mustOK(t, s.Create(ctx, &Feed{Name: "feed-a", FeedType: "csv", Enabled: true}), "create a")
	mustOK(t, s.Create(ctx, &Feed{Name: "feed-b", FeedType: "csv", Enabled: false}), "create b")

	all, err := s.List(ctx, false)
	mustOK(t, err, "list all")
	if len(all) != 2 {
		t.Fatalf("len(all) = %d, want 2", len(all))
	}

	enabledOnly, err := s.List(ctx, true)
	mustOK(t, err, "list enabled")
	if len(enabledOnly) != 1 || enabledOnly[0].Name != "feed-a" {
		t.Errorf("enabledOnly = %+v, want [feed-a]", enabledOnly)
	}
}

func TestIntegration_Feed_RecordPoll(t *testing.T) {
	pool := testDB(t)
	s := NewFeedStore(pool)
	ctx := context.Background()

	f := &Feed{Name: "poll-me", FeedType: "csv", Enabled: true}
	mustOK(t, s.Create(ctx, f), "create")

	mustOK(t, s.RecordPoll(ctx, f.ID, 0, false), "record failure")
	got, err := s.Get(ctx, f.ID)
	mustOK(t, err, "get after failure")
	if got.ErrorCount != 1 {
		t.Errorf("ErrorCount = %d, want 1", got.ErrorCount)
	}

	mustOK(t, s.RecordPoll(ctx, f.ID, 42, true), "record success")
	got, err = s.Get(ctx, f.ID)
	mustOK(t, err, "get after success")
	if got.ErrorCount != 0 {
		t.Errorf("ErrorCount after success = %d, want 0", got.ErrorCount)
	}
	if got.LastPollCount != 42 {
		t.Errorf("LastPollCount = %d, want 42", got.LastPollCount)
	}
	if got.LastPollAt == nil {
		t.Error("expected LastPollAt to be set")
	}

	if err := s.RecordPoll(ctx, uuid.New(), 1, true); err != ErrNotFound {
		t.Errorf("record poll on unknown id: want ErrNotFound, got %v", err)
	}
}

func TestIntegration_Feed_SetEnabledAndDelete(t *testing.T) {
	pool := testDB(t)
	s := NewFeedStore(pool)
	ctx := context.Background()

	f := &Feed{Name: "toggle-me", FeedType: "csv", Enabled: true}
	mustOK(t, s.Create(ctx, f), "create")

	mustOK(t, s.SetEnabled(ctx, f.ID, false), "disable")
	got, err := s.Get(ctx, f.ID)
	mustOK(t, err, "get after disable")
	if got.Enabled {
		t.Error("expected Enabled=false")
	}

	if err := s.SetEnabled(ctx, uuid.New(), true); err != ErrNotFound {
		t.Errorf("set enabled on unknown id: want ErrNotFound, got %v", err)
	}

	mustOK(t, s.Delete(ctx, f.ID), "delete")
	if _, err := s.Get(ctx, f.ID); err != ErrNotFound {
		t.Errorf("get after delete: want ErrNotFound, got %v", err)
	}
	if err := s.Delete(ctx, f.ID); err != ErrNotFound {
		t.Errorf("delete twice: want ErrNotFound, got %v", err)
	}
}

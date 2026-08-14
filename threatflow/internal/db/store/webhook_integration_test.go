//go:build integration

package store

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func TestIntegration_Webhook_CreateGetListSubscriber(t *testing.T) {
	pool := testDB(t)
	s := NewWebhookStore(pool)
	ctx := context.Background()

	sub := &WebhookSubscriber{
		Name:          "slack-sec",
		Platform:      "apiguard",
		URL:           "https://hooks.example.test/abc",
		Secret:        "shh",
		EventTypes:    []string{"ioc.created"},
		MinConfidence: 50,
		Enabled:       true,
	}
	mustOK(t, s.CreateSubscriber(ctx, sub), "create subscriber")
	if sub.ID.String() == "" {
		t.Fatal("expected subscriber ID to be populated")
	}

	got, err := s.GetSubscriber(ctx, sub.ID)
	mustOK(t, err, "get subscriber")
	if got.Name != "slack-sec" || got.Platform != "apiguard" {
		t.Errorf("unexpected subscriber: %+v", got)
	}
	if len(got.EventTypes) != 1 || got.EventTypes[0] != "ioc.created" {
		t.Errorf("EventTypes = %v", got.EventTypes)
	}

	if _, err := s.GetSubscriber(ctx, uuid.New()); err != ErrNotFound {
		t.Errorf("want ErrNotFound for unknown id, got %v", err)
	}

	all, err := s.ListSubscribers(ctx, false)
	mustOK(t, err, "list all")
	if len(all) != 1 {
		t.Fatalf("len(all) = %d, want 1", len(all))
	}
}

func TestIntegration_Webhook_CreateSubscriber_NilEventTypesDefaultsToEmptySlice(t *testing.T) {
	pool := testDB(t)
	s := NewWebhookStore(pool)
	ctx := context.Background()

	sub := &WebhookSubscriber{
		Name: "wildcard", Platform: "external", URL: "https://example.test", Secret: "s",
		MinConfidence: 0, Enabled: true,
	}
	mustOK(t, s.CreateSubscriber(ctx, sub), "create subscriber with nil event types")

	got, err := s.GetSubscriber(ctx, sub.ID)
	mustOK(t, err, "get subscriber")
	if len(got.EventTypes) != 0 {
		t.Errorf("EventTypes = %v, want empty", got.EventTypes)
	}
}

func TestIntegration_Webhook_ListSubscribers_EnabledOnly(t *testing.T) {
	pool := testDB(t)
	s := NewWebhookStore(pool)
	ctx := context.Background()

	mustOK(t, s.CreateSubscriber(ctx, &WebhookSubscriber{
		Name: "on", Platform: "external", URL: "https://on.example", Secret: "s", Enabled: true,
	}), "create enabled")
	mustOK(t, s.CreateSubscriber(ctx, &WebhookSubscriber{
		Name: "off", Platform: "external", URL: "https://off.example", Secret: "s", Enabled: false,
	}), "create disabled")

	enabled, err := s.ListSubscribers(ctx, true)
	mustOK(t, err, "list enabled")
	if len(enabled) != 1 || enabled[0].Name != "on" {
		t.Errorf("enabled = %+v, want [on]", enabled)
	}
}

func TestIntegration_Webhook_MatchingSubscribers(t *testing.T) {
	pool := testDB(t)
	s := NewWebhookStore(pool)
	ctx := context.Background()

	mustOK(t, s.CreateSubscriber(ctx, &WebhookSubscriber{
		Name: "specific", Platform: "external", URL: "https://a.example", Secret: "s",
		EventTypes: []string{"ioc.created"}, MinConfidence: 70, Enabled: true,
	}), "create specific")
	mustOK(t, s.CreateSubscriber(ctx, &WebhookSubscriber{
		Name: "wildcard", Platform: "external", URL: "https://b.example", Secret: "s",
		EventTypes: []string{}, MinConfidence: 0, Enabled: true,
	}), "create wildcard")
	mustOK(t, s.CreateSubscriber(ctx, &WebhookSubscriber{
		Name: "disabled", Platform: "external", URL: "https://c.example", Secret: "s",
		EventTypes: []string{"ioc.created"}, MinConfidence: 0, Enabled: false,
	}), "create disabled")

	matches, err := s.MatchingSubscribers(ctx, "ioc.created", 80)
	mustOK(t, err, "matching subscribers")
	names := map[string]bool{}
	for _, m := range matches {
		names[m.Name] = true
	}
	if !names["specific"] || !names["wildcard"] {
		t.Errorf("expected specific+wildcard to match, got %+v", names)
	}
	if names["disabled"] {
		t.Error("disabled subscriber must not match")
	}

	lowConf, err := s.MatchingSubscribers(ctx, "ioc.created", 10)
	mustOK(t, err, "matching low confidence")
	for _, m := range lowConf {
		if m.Name == "specific" {
			t.Error("specific subscriber requires confidence >= 70, should not match at 10")
		}
	}
}

func TestIntegration_Webhook_SetEnabledAndDeleteSubscriber(t *testing.T) {
	pool := testDB(t)
	s := NewWebhookStore(pool)
	ctx := context.Background()

	sub := &WebhookSubscriber{Name: "toggle", Platform: "external", URL: "https://x.example", Secret: "s", Enabled: true}
	mustOK(t, s.CreateSubscriber(ctx, sub), "create")

	mustOK(t, s.SetEnabled(ctx, sub.ID, false), "disable")
	got, err := s.GetSubscriber(ctx, sub.ID)
	mustOK(t, err, "get after disable")
	if got.Enabled {
		t.Error("expected Enabled=false")
	}
	if err := s.SetEnabled(ctx, uuid.New(), true); err != ErrNotFound {
		t.Errorf("set enabled unknown id: want ErrNotFound, got %v", err)
	}

	mustOK(t, s.DeleteSubscriber(ctx, sub.ID), "delete")
	if _, err := s.GetSubscriber(ctx, sub.ID); err != ErrNotFound {
		t.Errorf("get after delete: want ErrNotFound, got %v", err)
	}
	if err := s.DeleteSubscriber(ctx, sub.ID); err != ErrNotFound {
		t.Errorf("delete twice: want ErrNotFound, got %v", err)
	}
}

func TestIntegration_Webhook_RecordDeliveryUpsertsAndAccumulatesAttempts(t *testing.T) {
	pool := testDB(t)
	s := NewWebhookStore(pool)
	ctx := context.Background()

	sub := &WebhookSubscriber{Name: "deliveries", Platform: "external", URL: "https://d.example", Secret: "s", Enabled: true}
	mustOK(t, s.CreateSubscriber(ctx, sub), "create subscriber")

	eventID := uuid.New()
	d := &WebhookDelivery{
		SubscriberID: sub.ID,
		EventType:    "ioc.created",
		EventID:      eventID,
		Payload:      json.RawMessage(`{"foo":"bar"}`),
		Status:       "pending",
		AttemptCount: 1,
	}
	mustOK(t, s.RecordDelivery(ctx, d), "record delivery 1")
	if d.AttemptCount != 1 {
		t.Errorf("AttemptCount = %d, want 1", d.AttemptCount)
	}

	// Second attempt for the same (subscriber, event) upserts and bumps
	// attempt_count server-side regardless of the AttemptCount we pass in.
	failStatus := 500
	d2 := &WebhookDelivery{
		SubscriberID: sub.ID,
		EventType:    "ioc.created",
		EventID:      eventID,
		Status:       "failed",
		LastStatus:   &failStatus,
		LastError:    "connection refused",
	}
	mustOK(t, s.RecordDelivery(ctx, d2), "record delivery 2 (retry)")
	if d2.ID != d.ID {
		t.Errorf("expected same delivery row on upsert, got %s vs %s", d.ID, d2.ID)
	}
	if d2.AttemptCount != 2 {
		t.Errorf("AttemptCount after retry = %d, want 2", d2.AttemptCount)
	}

	recent, err := s.RecentDeliveries(ctx, sub.ID, 10)
	mustOK(t, err, "recent deliveries")
	if len(recent) != 1 {
		t.Fatalf("len(recent) = %d, want 1", len(recent))
	}
	if recent[0].Status != "failed" || recent[0].LastError != "connection refused" {
		t.Errorf("unexpected delivery: %+v", recent[0])
	}

	stats, err := s.DeliveryStats(ctx)
	mustOK(t, err, "delivery stats")
	if stats["failed"] != 1 {
		t.Errorf("stats[failed] = %d, want 1", stats["failed"])
	}
}

func TestIntegration_Webhook_RecordDelivery_EmptyPayloadDefaultsToEmptyObject(t *testing.T) {
	pool := testDB(t)
	s := NewWebhookStore(pool)
	ctx := context.Background()

	sub := &WebhookSubscriber{Name: "empty-payload", Platform: "external", URL: "https://e.example", Secret: "s", Enabled: true}
	mustOK(t, s.CreateSubscriber(ctx, sub), "create subscriber")

	d := &WebhookDelivery{
		SubscriberID: sub.ID,
		EventType:    "ioc.created",
		EventID:      uuid.New(),
		Status:       "delivered",
	}
	mustOK(t, s.RecordDelivery(ctx, d), "record delivery with no payload")

	recent, err := s.RecentDeliveries(ctx, sub.ID, 1)
	mustOK(t, err, "recent deliveries")
	if len(recent) != 1 || string(recent[0].Payload) != "{}" {
		t.Errorf("expected empty-object payload, got %+v", recent)
	}
}

package playbook

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// TestService_Patch_UpdatesAllFields exercises every optional field branch
// in Service.Patch (Description, Version, Status, Trigger, Steps) — the
// existing TestService_Patch_UpdatesOnlyProvidedFields only covers Name.
func TestService_Patch_UpdatesAllFields(t *testing.T) {
	svc, store := newTestService()
	store.playbooks["pb-full"] = &Playbook{
		ID:          "pb-full",
		Name:        "Original",
		Description: "orig desc",
		Version:     "1.0",
		Status:      PlaybookStatusDraft,
		Trigger:     Trigger{EventType: "old.event"},
		Steps:       []Step{{ID: "s0", Name: "old step"}},
	}

	newDesc := "new desc"
	newVersion := "2.0"
	newStatus := PlaybookStatusActive
	newTrigger := Trigger{EventType: "apiguard.finding.critical", Severity: "P1"}
	newSteps := []Step{{ID: "s1", Name: "new step", Type: StepTypeNotify}}

	pb, err := svc.Patch(context.Background(), "pb-full", &PatchPlaybookRequest{
		Description: &newDesc,
		Version:     &newVersion,
		Status:      &newStatus,
		Trigger:     &newTrigger,
		Steps:       &newSteps,
	})
	if err != nil {
		t.Fatalf("Patch() error = %v", err)
	}
	if pb.Description != newDesc {
		t.Errorf("Description = %q, want %q", pb.Description, newDesc)
	}
	if pb.Version != newVersion {
		t.Errorf("Version = %q, want %q", pb.Version, newVersion)
	}
	if pb.Status != newStatus {
		t.Errorf("Status = %q, want %q", pb.Status, newStatus)
	}
	if pb.Trigger.EventType != "apiguard.finding.critical" || pb.Trigger.Severity != "P1" {
		t.Errorf("Trigger = %+v, want event_type=apiguard.finding.critical severity=P1", pb.Trigger)
	}
	if len(pb.Steps) != 1 || pb.Steps[0].ID != "s1" {
		t.Errorf("Steps = %+v, want a single step with ID=s1", pb.Steps)
	}
	// Name was not supplied — must be left untouched.
	if pb.Name != "Original" {
		t.Errorf("Name = %q, want unchanged %q", pb.Name, "Original")
	}

	// Verify persistence, not just the returned value.
	stored := store.playbooks["pb-full"]
	if stored.Status != PlaybookStatusActive || stored.Version != "2.0" {
		t.Errorf("stored playbook = %+v, want persisted updates", stored)
	}
}

// Patch must propagate a store.Update failure rather than silently
// succeeding — Update wraps and returns the error.
func TestService_Patch_StoreUpdateErrorPropagates(t *testing.T) {
	store := newMockStore()
	store.playbooks["pb-1"] = &Playbook{ID: "pb-1", Name: "X"}
	failing := &failOnUpdateStore{mockStore: store}
	svc := NewService(failing, NewExecutor(zap.NewNop()), zap.NewNop())

	newName := "Y"
	_, err := svc.Patch(context.Background(), "pb-1", &PatchPlaybookRequest{Name: &newName})
	if err == nil {
		t.Fatal("expected an error when the store's Update fails, got nil")
	}
}

type failOnUpdateStore struct {
	*mockStore
}

func (f *failOnUpdateStore) Update(_ context.Context, _ *Playbook) error {
	return errUpdateBoom
}

type boomError struct{ msg string }

func (e *boomError) Error() string { return e.msg }

var errUpdateBoom = &boomError{msg: "update boom"}

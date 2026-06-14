package incident

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Mock governance clients
// ---------------------------------------------------------------------------

type mockMarshal struct {
	mu      sync.Mutex
	calls   int
	lastReq MarshalRequest
	result  *MarshalResult
	err     error
}

func (m *mockMarshal) Evaluate(_ context.Context, req MarshalRequest) (*MarshalResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	m.lastReq = req
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

type mockWORM struct {
	mu     sync.Mutex
	calls  int
	events []WORMEvent
	result *WORMReceipt
	err    error
}

func (m *mockWORM) Emit(_ context.Context, e WORMEvent) (*WORMReceipt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	m.events = append(m.events, e)
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

type mockNIS2 struct {
	mu        sync.Mutex
	calls     int
	lastInc   Incident
	err       error
	waitReady chan struct{}
}

func (m *mockNIS2) NotifyIncident(_ context.Context, inc *Incident) error {
	m.mu.Lock()
	m.calls++
	m.lastInc = *inc
	m.mu.Unlock()
	if m.waitReady != nil {
		m.waitReady <- struct{}{}
	}
	return m.err
}

// ---------------------------------------------------------------------------
// SubmitAction + MARSHAL
// ---------------------------------------------------------------------------

func TestSubmitAction_MarshalExecuteAllowsAction(t *testing.T) {
	store := newMockStore()
	seed := &Incident{ID: "inc-1", Title: "seed", Severity: SeverityP2, Status: StatusOpen, Source: SourceManual}
	store.incidents[seed.ID] = seed

	m := &mockMarshal{result: &MarshalResult{Outcome: MarshalOutcomeExecute, WORMEntryID: "worm-42"}}
	svc := NewService(store, WithMarshal(m))

	action, err := svc.SubmitAction(context.Background(), "inc-1", &SubmitActionRequest{
		ActionType:  "contain",
		OperatorID:  "alice",
		VerifierID:  "bob",
		Description: "block endpoint",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if action.MarshalDecision != MarshalOutcomeExecute {
		t.Errorf("MarshalDecision = %s, want %s", action.MarshalDecision, MarshalOutcomeExecute)
	}
	if action.WORMEntryID != "worm-42" {
		t.Errorf("WORMEntryID = %s, want worm-42", action.WORMEntryID)
	}
	if m.calls != 1 {
		t.Errorf("marshal called %d times, want 1", m.calls)
	}
	if len(store.actions["inc-1"]) != 1 {
		t.Errorf("got %d stored actions, want 1", len(store.actions["inc-1"]))
	}
}

func TestSubmitAction_MarshalRefuseRejectsAction(t *testing.T) {
	store := newMockStore()
	store.incidents["inc-1"] = &Incident{ID: "inc-1", Status: StatusOpen, Severity: SeverityP2}

	m := &mockMarshal{result: &MarshalResult{
		Outcome: MarshalOutcomeRefuse,
		Reasons: []string{"operator role lacks containment privilege"},
	}}
	svc := NewService(store, WithMarshal(m))

	_, err := svc.SubmitAction(context.Background(), "inc-1", &SubmitActionRequest{
		ActionType: "contain",
		OperatorID: "alice",
		VerifierID: "bob",
	})
	if !errors.Is(err, ErrMarshalRefused) {
		t.Fatalf("err = %v, want ErrMarshalRefused", err)
	}
	if got := store.actions["inc-1"]; len(got) != 0 {
		t.Errorf("refused action should not be stored, got %d", len(got))
	}
}

func TestSubmitAction_MarshalHardStopRejectsAction(t *testing.T) {
	store := newMockStore()
	store.incidents["inc-1"] = &Incident{ID: "inc-1", Status: StatusOpen, Severity: SeverityP1}

	m := &mockMarshal{result: &MarshalResult{Outcome: MarshalOutcomeHardStop}}
	svc := NewService(store, WithMarshal(m))

	_, err := svc.SubmitAction(context.Background(), "inc-1", &SubmitActionRequest{
		ActionType: "deploy_patch",
		OperatorID: "alice",
		VerifierID: "bob",
	})
	if !errors.Is(err, ErrMarshalHardStop) {
		t.Fatalf("err = %v, want ErrMarshalHardStop", err)
	}
}

func TestSubmitAction_NoMarshalWorksAsBefore(t *testing.T) {
	store := newMockStore()
	svc := NewService(store) // no marshal → local-only

	action, err := svc.SubmitAction(context.Background(), "inc-1", &SubmitActionRequest{
		ActionType: "contain",
		OperatorID: "alice",
		VerifierID: "bob",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if action.MarshalDecision != "" {
		t.Errorf("MarshalDecision should be empty when no marshal, got %s", action.MarshalDecision)
	}
}

// ---------------------------------------------------------------------------
// Create + WORM
// ---------------------------------------------------------------------------

func TestCreate_EmitsWORMAnchor(t *testing.T) {
	store := newMockStore()
	w := &mockWORM{result: &WORMReceipt{WORMEntryID: "worm-create-1", ChainHash: "abc", SequenceNum: 7}}
	svc := NewService(store, WithWORM(w))

	inc, err := svc.Create(context.Background(), &CreateIncidentRequest{
		Title:    "test",
		Severity: SeverityP2,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if w.calls != 1 {
		t.Fatalf("worm called %d times, want 1", w.calls)
	}
	if w.events[0].EventType != "incident.created" {
		t.Errorf("event_type = %s, want incident.created", w.events[0].EventType)
	}
	if inc.WORMEntryID != "worm-create-1" {
		t.Errorf("incident.WORMEntryID = %s, want worm-create-1", inc.WORMEntryID)
	}
}

func TestCreate_WORMFailureDoesNotBlockIncident(t *testing.T) {
	store := newMockStore()
	w := &mockWORM{err: errors.New("citadel down")}
	svc := NewService(store, WithWORM(w))

	inc, err := svc.Create(context.Background(), &CreateIncidentRequest{
		Title:    "test",
		Severity: SeverityP2,
	})
	if err != nil {
		t.Fatalf("create should succeed even when WORM fails, got %v", err)
	}
	if inc.WORMEntryID != "" {
		t.Errorf("WORMEntryID should be empty when emit fails, got %s", inc.WORMEntryID)
	}
}

// ---------------------------------------------------------------------------
// Create + NIS2
// ---------------------------------------------------------------------------

func TestCreate_NIS2NotifiedAsyncForP1(t *testing.T) {
	store := newMockStore()
	ready := make(chan struct{}, 1)
	n := &mockNIS2{waitReady: ready}
	svc := NewService(store, WithNIS2(n))

	_, err := svc.Create(context.Background(), &CreateIncidentRequest{
		Title:    "breach",
		Severity: SeverityP1,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	select {
	case <-ready:
	case <-time.After(1 * time.Second):
		t.Fatal("NIS2 NotifyIncident was not called within 1s")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.calls != 1 {
		t.Errorf("nis2 called %d times, want 1", n.calls)
	}
	if n.lastInc.Severity != SeverityP1 {
		t.Errorf("notified severity = %s, want P1", n.lastInc.Severity)
	}
}

func TestCreate_NIS2SkippedForP4(t *testing.T) {
	store := newMockStore()
	n := &mockNIS2{}
	svc := NewService(store, WithNIS2(n))

	_, err := svc.Create(context.Background(), &CreateIncidentRequest{
		Title:    "minor",
		Severity: SeverityP4,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Give a moment for any stray goroutine; P4 has no NIS2 threshold so no
	// call should happen.
	time.Sleep(50 * time.Millisecond)
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.calls != 0 {
		t.Errorf("P4 must not trigger NIS2 notification, got %d calls", n.calls)
	}
}

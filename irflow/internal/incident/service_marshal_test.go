package incident

import (
	"context"
	"errors"
	"testing"
)

// ---------------------------------------------------------------------------
// Mock MARSHAL / NIS2 clients for exercising CITADEL governance integration
// in ApproveAction and NIS2 notification in Create.
// ---------------------------------------------------------------------------

// stubMarshal returns a fixed outcome (or error) for every Evaluate call, and
// records the request it was called with so tests can assert on what IRFlow
// actually sent to CITADEL (real operator/verifier identities, never
// client-supplied values).
type stubMarshal struct {
	result  *MarshalResult
	err     error
	lastReq MarshalRequest
	calls   int
}

func (m *stubMarshal) Evaluate(_ context.Context, req MarshalRequest) (*MarshalResult, error) {
	m.calls++
	m.lastReq = req
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

type stubNIS2 struct {
	err   error
	calls int
	last  *Incident
}

func (n *stubNIS2) NotifyIncident(_ context.Context, inc *Incident) error {
	n.calls++
	cp := *inc
	n.last = &cp
	return n.err
}

func proposeForApproval(t *testing.T, svc *Service, incidentID string) *PendingAction {
	t.Helper()
	pa, err := svc.ProposeAction(context.Background(), incidentID, "user-alice", "operator", &ProposeActionRequest{
		ActionType:  "block_ip",
		Description: "Block malicious IP at edge",
	})
	if err != nil {
		t.Fatalf("ProposeAction: %v", err)
	}
	return pa
}

// ---------------------------------------------------------------------------
// MARSHAL unreachable / erroring — this is the fail-closed guarantee: if
// CITADEL cannot be evaluated at all, the action must NOT be silently
// approved. An unreachable governance engine is not the same as EXECUTE.
// ---------------------------------------------------------------------------

func TestApproveAction_MarshalError_FailsClosed(t *testing.T) {
	store := newMockStore()
	marshal := &stubMarshal{err: errors.New("dial tcp: connection refused")}
	svc := NewService(store, WithMarshal(marshal))
	ctx := context.Background()

	inc, _ := svc.Create(ctx, &CreateIncidentRequest{Title: "Marshal unreachable", Severity: SeverityP1})
	pa := proposeForApproval(t, svc, inc.ID)

	action, err := svc.ApproveAction(ctx, inc.ID, pa.ID, "user-bob", "verifier", "bob-token")
	if err == nil {
		t.Fatal("expected an error when MARSHAL is unreachable, got nil (fail-open bug)")
	}
	if action != nil {
		t.Errorf("expected nil action when MARSHAL evaluation fails, got %+v", action)
	}
	if len(store.actions[inc.ID]) != 0 {
		t.Errorf("action must not be persisted when MARSHAL evaluation errors, got %d stored", len(store.actions[inc.ID]))
	}

	// The pending action must remain pending (not silently approved) so a
	// retry is possible once CITADEL is reachable again.
	updated, gErr := svc.GetPendingAction(ctx, inc.ID, pa.ID)
	if gErr != nil {
		t.Fatalf("GetPendingAction: %v", gErr)
	}
	if updated.Status != PendingActionStatusPending {
		t.Errorf("pending Status = %q, want %q (must remain retryable, not silently decided)",
			updated.Status, PendingActionStatusPending)
	}
}

// ApproveAction must look up the incident to scope the MARSHAL request's
// ProjectID; if that lookup fails (incident vanished between propose and
// approve), the approval must fail rather than submit a request with an
// empty/wrong ProjectID.
func TestApproveAction_MarshalConfigured_IncidentLookupFailurePropagates(t *testing.T) {
	store := newMockStore()
	marshal := &stubMarshal{result: &MarshalResult{Outcome: MarshalOutcomeExecute}}
	svc := NewService(store, WithMarshal(marshal))
	ctx := context.Background()

	inc, _ := svc.Create(ctx, &CreateIncidentRequest{Title: "Vanishing incident", Severity: SeverityP2})
	pa := proposeForApproval(t, svc, inc.ID)

	// Simulate the incident disappearing between propose and approve.
	delete(store.incidents, inc.ID)

	action, err := svc.ApproveAction(ctx, inc.ID, pa.ID, "user-bob", "verifier", "bob-token")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
	if action != nil {
		t.Errorf("expected nil action, got %+v", action)
	}
	if marshal.calls != 0 {
		t.Errorf("MARSHAL must not be called when the incident lookup fails, got %d calls", marshal.calls)
	}
}

// ---------------------------------------------------------------------------
// ProposeAction / GetPendingAction edge cases.
// ---------------------------------------------------------------------------

func TestProposeAction_UnknownIncident_ReturnsNotFound(t *testing.T) {
	svc, _ := newTestService()
	_, err := svc.ProposeAction(context.Background(), "does-not-exist", "user-alice", "operator", &ProposeActionRequest{ActionType: "contain"})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestGetPendingAction_WrongIncidentID_ReturnsNotFound(t *testing.T) {
	// A caller must not be able to fetch a pending action by ID alone while
	// supplying an unrelated incident ID in the URL.
	svc, _ := newTestService()
	ctx := context.Background()

	incA, _ := svc.Create(ctx, &CreateIncidentRequest{Title: "Incident A", Severity: SeverityP2})
	incB, _ := svc.Create(ctx, &CreateIncidentRequest{Title: "Incident B", Severity: SeverityP2})

	pa := proposeForApproval(t, svc, incA.ID)

	if _, err := svc.GetPendingAction(ctx, incB.ID, pa.ID); !errors.Is(err, ErrPendingActionNotFound) {
		t.Fatalf("expected ErrPendingActionNotFound when scoped to wrong incident, got: %v", err)
	}
}

func TestApproveAction_WrongIncidentID_ReturnsNotFound(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	incA, _ := svc.Create(ctx, &CreateIncidentRequest{Title: "Incident A", Severity: SeverityP2})
	incB, _ := svc.Create(ctx, &CreateIncidentRequest{Title: "Incident B", Severity: SeverityP2})

	pa := proposeForApproval(t, svc, incA.ID)

	if _, err := svc.ApproveAction(ctx, incB.ID, pa.ID, "user-bob", "verifier", "tok"); !errors.Is(err, ErrPendingActionNotFound) {
		t.Fatalf("expected ErrPendingActionNotFound, got: %v", err)
	}
}

func TestRejectAction_UnknownPendingAction_ReturnsNotFound(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	inc, _ := svc.Create(ctx, &CreateIncidentRequest{Title: "X", Severity: SeverityP2})

	if _, err := svc.RejectAction(ctx, inc.ID, "nonexistent-pa", "user-bob", "verifier"); !errors.Is(err, ErrPendingActionNotFound) {
		t.Fatalf("expected ErrPendingActionNotFound, got: %v", err)
	}
}

func TestRejectAction_SelfRejectionRejected(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	inc, _ := svc.Create(ctx, &CreateIncidentRequest{Title: "X", Severity: SeverityP2})
	pa := proposeForApproval(t, svc, inc.ID)

	if _, err := svc.RejectAction(ctx, inc.ID, pa.ID, "user-alice", "operator"); !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("expected ErrSelfApproval, got: %v", err)
	}
}

func TestRejectAction_AlreadyDecided(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	inc, _ := svc.Create(ctx, &CreateIncidentRequest{Title: "X", Severity: SeverityP2})
	pa := proposeForApproval(t, svc, inc.ID)

	if _, err := svc.RejectAction(ctx, inc.ID, pa.ID, "user-bob", "verifier"); err != nil {
		t.Fatalf("first RejectAction: %v", err)
	}
	if _, err := svc.RejectAction(ctx, inc.ID, pa.ID, "user-carol", "verifier"); !errors.Is(err, ErrAlreadyDecided) {
		t.Fatalf("expected ErrAlreadyDecided, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// NIS2 async notification.
// ---------------------------------------------------------------------------

func TestNotifyNIS2Async_SetsNotifiedAtOnSuccess(t *testing.T) {
	store := newMockStore()
	nis2 := &stubNIS2{}
	svc := NewService(store, WithNIS2(nis2))

	inc := Incident{ID: "inc-nis2-1", Severity: SeverityP1, ProjectID: "proj-1"}
	store.incidents[inc.ID] = &inc

	// notifyNIS2Async is normally launched via `go` from Create; call it
	// synchronously here so the test can assert deterministically.
	svc.notifyNIS2Async(inc)

	if nis2.calls != 1 {
		t.Fatalf("expected NotifyIncident to be called once, got %d", nis2.calls)
	}
	updated := store.incidents["inc-nis2-1"]
	if updated.NIS2NotifiedAt == nil {
		t.Error("expected NIS2NotifiedAt to be set after a successful notification")
	}
}

func TestNotifyNIS2Async_LeavesNotifiedAtNilOnFailure(t *testing.T) {
	store := newMockStore()
	nis2 := &stubNIS2{err: errors.New("compass unreachable")}
	svc := NewService(store, WithNIS2(nis2))

	inc := Incident{ID: "inc-nis2-2", Severity: SeverityP1, ProjectID: "proj-1"}
	store.incidents[inc.ID] = &inc

	svc.notifyNIS2Async(inc)

	if nis2.calls != 1 {
		t.Fatalf("expected NotifyIncident to be called once, got %d", nis2.calls)
	}
	updated := store.incidents["inc-nis2-2"]
	if updated.NIS2NotifiedAt != nil {
		t.Error("NIS2NotifiedAt must remain nil when the notification failed")
	}
}

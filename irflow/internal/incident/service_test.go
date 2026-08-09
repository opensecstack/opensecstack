package incident

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/opensecstack/opensecstack/irflow/internal/metrics"
)

// ---------------------------------------------------------------------------
// In-memory mock store
// ---------------------------------------------------------------------------

// mockStore implements Store entirely in memory for unit testing.
type mockStore struct {
	incidents      map[string]*Incident
	actions        map[string][]IncidentAction
	iocs           map[string][]IOCEnrichment
	timeline       map[string][]TimelineEntry
	pendingActions map[string]*PendingAction
}

func newMockStore() *mockStore {
	return &mockStore{
		incidents:      make(map[string]*Incident),
		actions:        make(map[string][]IncidentAction),
		iocs:           make(map[string][]IOCEnrichment),
		timeline:       make(map[string][]TimelineEntry),
		pendingActions: make(map[string]*PendingAction),
	}
}

func (m *mockStore) Create(_ context.Context, inc *Incident) error {
	if inc.ID == "" {
		return errors.New("incident ID must be set before calling Create")
	}
	cp := *inc
	m.incidents[inc.ID] = &cp
	return nil
}

func (m *mockStore) Get(_ context.Context, id string) (*Incident, error) {
	inc, ok := m.incidents[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *inc
	return &cp, nil
}

func (m *mockStore) List(_ context.Context, opts ListOptions) ([]Incident, int, error) {
	var all []Incident
	for _, inc := range m.incidents {
		if opts.Status != "" && string(inc.Status) != opts.Status {
			continue
		}
		if opts.Severity != "" && string(inc.Severity) != opts.Severity {
			continue
		}
		if opts.Source != "" && string(inc.Source) != opts.Source {
			continue
		}
		all = append(all, *inc)
	}

	// Stable sort by created_at descending for deterministic pagination.
	sort.Slice(all, func(i, j int) bool {
		return all[i].CreatedAt.After(all[j].CreatedAt)
	})

	total := len(all)

	// Apply pagination.
	offset := (opts.Page - 1) * opts.PerPage
	if offset < 0 {
		offset = 0
	}
	if offset >= len(all) {
		return []Incident{}, total, nil
	}
	end := offset + opts.PerPage
	if end > len(all) {
		end = len(all)
	}

	return all[offset:end], total, nil
}

func (m *mockStore) Update(_ context.Context, inc *Incident) error {
	if _, ok := m.incidents[inc.ID]; !ok {
		return ErrNotFound
	}
	cp := *inc
	m.incidents[inc.ID] = &cp
	return nil
}

func (m *mockStore) Delete(_ context.Context, id string) error {
	if _, ok := m.incidents[id]; !ok {
		return ErrNotFound
	}
	delete(m.incidents, id)
	return nil
}

func (m *mockStore) AddAction(_ context.Context, action *IncidentAction) error {
	cp := *action
	m.actions[action.IncidentID] = append(m.actions[action.IncidentID], cp)
	return nil
}

func (m *mockStore) ListActions(_ context.Context, incidentID string) ([]IncidentAction, error) {
	return m.actions[incidentID], nil
}

func (m *mockStore) CreatePendingAction(_ context.Context, pa *PendingAction) error {
	cp := *pa
	m.pendingActions[pa.ID] = &cp
	return nil
}

func (m *mockStore) GetPendingAction(_ context.Context, id string) (*PendingAction, error) {
	pa, ok := m.pendingActions[id]
	if !ok {
		return nil, ErrPendingActionNotFound
	}
	cp := *pa
	return &cp, nil
}

func (m *mockStore) UpdatePendingAction(_ context.Context, pa *PendingAction) error {
	if _, ok := m.pendingActions[pa.ID]; !ok {
		return ErrPendingActionNotFound
	}
	cp := *pa
	m.pendingActions[pa.ID] = &cp
	return nil
}

func (m *mockStore) ListPendingActions(_ context.Context, incidentID string) ([]PendingAction, error) {
	var out []PendingAction
	for _, pa := range m.pendingActions {
		if pa.IncidentID == incidentID {
			out = append(out, *pa)
		}
	}
	return out, nil
}

func (m *mockStore) AddIOC(_ context.Context, ioc *IOCEnrichment) error {
	cp := *ioc
	m.iocs[ioc.IncidentID] = append(m.iocs[ioc.IncidentID], cp)
	return nil
}

func (m *mockStore) ListIOCs(_ context.Context, incidentID string) ([]IOCEnrichment, error) {
	return m.iocs[incidentID], nil
}

func (m *mockStore) AddTimelineEntry(_ context.Context, entry *TimelineEntry) error {
	cp := *entry
	m.timeline[entry.IncidentID] = append(m.timeline[entry.IncidentID], cp)
	return nil
}

func (m *mockStore) GetTimeline(_ context.Context, incidentID string) ([]TimelineEntry, error) {
	return m.timeline[incidentID], nil
}

func (m *mockStore) Stats(_ context.Context) (*Stats, error) {
	stats := &Stats{
		BySeverity: map[string]int{},
		ByStatus:   map[string]int{},
		BySource:   map[string]int{},
	}
	for _, inc := range m.incidents {
		stats.Total++
		stats.BySeverity[string(inc.Severity)]++
		stats.ByStatus[string(inc.Status)]++
		stats.BySource[string(inc.Source)]++
	}
	return stats, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestService() (*Service, *mockStore) {
	store := newMockStore()
	svc := NewService(store)
	return svc, store
}

func ptr[T any](v T) *T { return &v }

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestCreateIncident_Success(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	req := &CreateIncidentRequest{
		Title:    "Server compromise detected",
		Severity: SeverityP1,
		Source:   SourceAPIGuard,
	}

	inc, err := svc.Create(ctx, req)
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	if inc.ID == "" {
		t.Fatal("expected non-empty ID")
	}
	if inc.Title != req.Title {
		t.Errorf("Title = %q, want %q", inc.Title, req.Title)
	}
	if inc.Source != SourceAPIGuard {
		t.Errorf("Source = %q, want %q", inc.Source, SourceAPIGuard)
	}
}

func TestCreateIncident_SetsStatusOpen(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	inc, err := svc.Create(ctx, &CreateIncidentRequest{
		Title:    "Test incident",
		Severity: SeverityP2,
	})
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	if inc.Status != StatusOpen {
		t.Errorf("Status = %q, want %q", inc.Status, StatusOpen)
	}
}

func TestCreateIncident_DefaultSourceManual(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	inc, err := svc.Create(ctx, &CreateIncidentRequest{
		Title:    "Manual incident",
		Severity: SeverityP3,
		// Source intentionally omitted.
	})
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	if inc.Source != SourceManual {
		t.Errorf("Source = %q, want %q", inc.Source, SourceManual)
	}
}

func TestGetIncident_Found(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	created, _ := svc.Create(ctx, &CreateIncidentRequest{
		Title:    "Find me",
		Severity: SeverityP2,
	})

	got, err := svc.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if got.Title != "Find me" {
		t.Errorf("Title = %q, want %q", got.Title, "Find me")
	}
}

func TestGetIncident_NotFound(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	_, err := svc.Get(ctx, "nonexistent-id")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestListIncidents_Empty(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	results, total, err := svc.List(ctx, 1, 20, "", "", "")
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if total != 0 {
		t.Errorf("total = %d, want 0", total)
	}
	if len(results) != 0 {
		t.Errorf("len(results) = %d, want 0", len(results))
	}
}

func TestListIncidents_WithPagination(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	// Create 5 incidents with staggered timestamps.
	for i := 0; i < 5; i++ {
		_, err := svc.Create(ctx, &CreateIncidentRequest{
			Title:    "Incident",
			Severity: SeverityP3,
		})
		if err != nil {
			t.Fatalf("Create returned error: %v", err)
		}
		// Small sleep to ensure distinct timestamps for ordering.
		time.Sleep(time.Millisecond)
	}

	// Page 1 of 2.
	page1, total, err := svc.List(ctx, 1, 2, "", "", "")
	if err != nil {
		t.Fatalf("List page 1 returned error: %v", err)
	}
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
	if len(page1) != 2 {
		t.Errorf("len(page1) = %d, want 2", len(page1))
	}

	// Page 3 of 2 (last page, 1 item).
	page3, _, err := svc.List(ctx, 3, 2, "", "", "")
	if err != nil {
		t.Fatalf("List page 3 returned error: %v", err)
	}
	if len(page3) != 1 {
		t.Errorf("len(page3) = %d, want 1", len(page3))
	}
}

func TestListIncidents_FilterByStatus(t *testing.T) {
	svc, store := newTestService()
	ctx := context.Background()

	// Create two incidents, then close one via direct store manipulation.
	inc1, _ := svc.Create(ctx, &CreateIncidentRequest{Title: "Open one", Severity: SeverityP3})
	inc2, _ := svc.Create(ctx, &CreateIncidentRequest{Title: "Closed one", Severity: SeverityP3})

	// Transition inc2 to closed via the store.
	stored := store.incidents[inc2.ID]
	stored.Status = StatusClosed

	results, total, err := svc.List(ctx, 1, 20, string(StatusOpen), "", "")
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if results[0].ID != inc1.ID {
		t.Errorf("expected incident %s, got %s", inc1.ID, results[0].ID)
	}
}

func TestListIncidents_FilterBySeverity(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	svc.Create(ctx, &CreateIncidentRequest{Title: "P1 incident", Severity: SeverityP1})
	svc.Create(ctx, &CreateIncidentRequest{Title: "P3 incident", Severity: SeverityP3})

	results, total, err := svc.List(ctx, 1, 20, "", string(SeverityP1), "")
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(results) != 1 || results[0].Severity != SeverityP1 {
		t.Errorf("expected 1 P1 incident, got %d results", len(results))
	}
}

func TestPatchIncident_UpdateTitle(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	inc, _ := svc.Create(ctx, &CreateIncidentRequest{
		Title:    "Original title",
		Severity: SeverityP2,
	})

	patched, err := svc.Patch(ctx, inc.ID, &PatchIncidentRequest{
		Title: ptr("Updated title"),
	})
	if err != nil {
		t.Fatalf("Patch returned error: %v", err)
	}
	if patched.Title != "Updated title" {
		t.Errorf("Title = %q, want %q", patched.Title, "Updated title")
	}
}

func TestPatchIncident_ValidTransition(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	inc, _ := svc.Create(ctx, &CreateIncidentRequest{
		Title:    "Transition test",
		Severity: SeverityP1,
	})

	// open -> investigating is valid.
	patched, err := svc.Patch(ctx, inc.ID, &PatchIncidentRequest{
		Status: ptr(StatusInvestigating),
	})
	if err != nil {
		t.Fatalf("Patch returned error: %v", err)
	}
	if patched.Status != StatusInvestigating {
		t.Errorf("Status = %q, want %q", patched.Status, StatusInvestigating)
	}
}

func TestPatchIncident_InvalidTransition(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	// Create an incident and transition it to closed.
	inc, _ := svc.Create(ctx, &CreateIncidentRequest{
		Title:    "Closed incident",
		Severity: SeverityP3,
	})

	// open -> closed is valid.
	_, err := svc.Patch(ctx, inc.ID, &PatchIncidentRequest{
		Status: ptr(StatusClosed),
	})
	if err != nil {
		t.Fatalf("Patch to closed returned error: %v", err)
	}

	// closed -> open is NOT valid (closed is terminal).
	_, err = svc.Patch(ctx, inc.ID, &PatchIncidentRequest{
		Status: ptr(StatusOpen),
	})
	if !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("expected ErrInvalidTransition, got: %v", err)
	}
}

func TestPatchIncident_NotFound(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	_, err := svc.Patch(ctx, "nonexistent-id", &PatchIncidentRequest{
		Title: ptr("Updated"),
	})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestPatchIncident_SetsContainedAt(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	inc, _ := svc.Create(ctx, &CreateIncidentRequest{
		Title:    "Containment test",
		Severity: SeverityP1,
	})

	// open -> investigating -> contained
	svc.Patch(ctx, inc.ID, &PatchIncidentRequest{Status: ptr(StatusInvestigating)})
	patched, err := svc.Patch(ctx, inc.ID, &PatchIncidentRequest{Status: ptr(StatusContained)})
	if err != nil {
		t.Fatalf("Patch returned error: %v", err)
	}
	if patched.ContainedAt == nil {
		t.Error("expected ContainedAt to be set")
	}
}

func TestPatchIncident_SetsClosedAt(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	inc, _ := svc.Create(ctx, &CreateIncidentRequest{
		Title:    "Close test",
		Severity: SeverityP4,
	})

	patched, err := svc.Patch(ctx, inc.ID, &PatchIncidentRequest{
		Status: ptr(StatusClosed),
	})
	if err != nil {
		t.Fatalf("Patch returned error: %v", err)
	}
	if patched.ClosedAt == nil {
		t.Error("expected ClosedAt to be set")
	}
}

func TestDeleteIncident_Success(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	inc, _ := svc.Create(ctx, &CreateIncidentRequest{
		Title:    "Delete me",
		Severity: SeverityP4,
	})

	if err := svc.Delete(ctx, inc.ID); err != nil {
		t.Fatalf("Delete returned error: %v", err)
	}

	_, err := svc.Get(ctx, inc.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound after delete, got: %v", err)
	}
}

func TestDeleteIncident_NotFound(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	err := svc.Delete(ctx, "nonexistent-id")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestProposeAndApproveAction_Success(t *testing.T) {
	svc, store := newTestService()
	ctx := context.Background()

	inc, _ := svc.Create(ctx, &CreateIncidentRequest{
		Title:    "Action test",
		Severity: SeverityP1,
	})

	pa, err := svc.ProposeAction(ctx, inc.ID, "user-alice", "operator", &ProposeActionRequest{
		ActionType:  "contain",
		Description: "Isolated affected host",
	})
	if err != nil {
		t.Fatalf("ProposeAction returned error: %v", err)
	}
	if pa.Status != PendingActionStatusPending {
		t.Errorf("Status = %q, want %q", pa.Status, PendingActionStatusPending)
	}
	if pa.OperatorUserID != "user-alice" {
		t.Errorf("OperatorUserID = %q, want user-alice", pa.OperatorUserID)
	}

	action, err := svc.ApproveAction(ctx, inc.ID, pa.ID, "user-bob", "verifier", "bob-token")
	if err != nil {
		t.Fatalf("ApproveAction returned error: %v", err)
	}
	if action.ID == "" {
		t.Error("expected non-empty action ID")
	}
	if action.IncidentID != inc.ID {
		t.Errorf("IncidentID = %q, want %q", action.IncidentID, inc.ID)
	}
	if action.OperatorID != "user-alice" || action.VerifierID != "user-bob" {
		t.Errorf("OperatorID/VerifierID = %q/%q, want user-alice/user-bob", action.OperatorID, action.VerifierID)
	}

	// Verify the action was stored.
	stored := store.actions[inc.ID]
	if len(stored) != 1 {
		t.Fatalf("expected 1 stored action, got %d", len(stored))
	}

	// The pending action record itself should now reflect the approval.
	updated, err := svc.GetPendingAction(ctx, inc.ID, pa.ID)
	if err != nil {
		t.Fatalf("GetPendingAction returned error: %v", err)
	}
	if updated.Status != PendingActionStatusApproved {
		t.Errorf("pending Status = %q, want %q", updated.Status, PendingActionStatusApproved)
	}
	if updated.ActionID != action.ID {
		t.Errorf("pending ActionID = %q, want %q", updated.ActionID, action.ID)
	}
}

func TestApproveAction_SelfApprovalRejected(t *testing.T) {
	// Separation of Duties, enforced at the service layer: the same
	// authenticated identity can never be both Operator and Verifier.
	svc, _ := newTestService()
	ctx := context.Background()

	inc, _ := svc.Create(ctx, &CreateIncidentRequest{
		Title:    "SoD test",
		Severity: SeverityP1,
	})

	pa, err := svc.ProposeAction(ctx, inc.ID, "user-alice", "operator", &ProposeActionRequest{
		ActionType:  "contain",
		Description: "Self-verified action",
	})
	if err != nil {
		t.Fatalf("ProposeAction returned error: %v", err)
	}

	_, err = svc.ApproveAction(ctx, inc.ID, pa.ID, "user-alice", "operator", "alice-token")
	if !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("expected ErrSelfApproval, got: %v", err)
	}
}

func TestApproveAction_AlreadyDecided(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	inc, _ := svc.Create(ctx, &CreateIncidentRequest{
		Title:    "Already decided test",
		Severity: SeverityP2,
	})

	pa, _ := svc.ProposeAction(ctx, inc.ID, "user-alice", "operator", &ProposeActionRequest{ActionType: "contain"})
	if _, err := svc.ApproveAction(ctx, inc.ID, pa.ID, "user-bob", "verifier", "bob-token"); err != nil {
		t.Fatalf("first ApproveAction returned error: %v", err)
	}

	// A second decision attempt (by anyone) must fail — the pending action
	// has already been decided.
	if _, err := svc.ApproveAction(ctx, inc.ID, pa.ID, "user-carol", "verifier", "carol-token"); !errors.Is(err, ErrAlreadyDecided) {
		t.Fatalf("expected ErrAlreadyDecided, got: %v", err)
	}
}

func TestRejectAction_Success(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	inc, _ := svc.Create(ctx, &CreateIncidentRequest{
		Title:    "Reject test",
		Severity: SeverityP2,
	})

	pa, _ := svc.ProposeAction(ctx, inc.ID, "user-alice", "operator", &ProposeActionRequest{ActionType: "contain"})

	rejected, err := svc.RejectAction(ctx, inc.ID, pa.ID, "user-bob", "verifier")
	if err != nil {
		t.Fatalf("RejectAction returned error: %v", err)
	}
	if rejected.Status != PendingActionStatusRejected {
		t.Errorf("Status = %q, want %q", rejected.Status, PendingActionStatusRejected)
	}
	if rejected.VerifierUserID != "user-bob" {
		t.Errorf("VerifierUserID = %q, want user-bob", rejected.VerifierUserID)
	}
}

func TestAddIOC_Success(t *testing.T) {
	svc, store := newTestService()
	ctx := context.Background()

	inc, _ := svc.Create(ctx, &CreateIncidentRequest{
		Title:    "IOC test",
		Severity: SeverityP2,
	})

	ioc := &IOCEnrichment{
		IOCType:    "ip",
		IOCValue:   "192.168.1.100",
		Confidence: 0.95,
		Source:     "threatflow",
	}

	created, err := svc.AddIOC(ctx, inc.ID, ioc)
	if err != nil {
		t.Fatalf("AddIOC returned error: %v", err)
	}
	if created.ID == "" {
		t.Error("expected non-empty IOC ID")
	}
	if created.IncidentID != inc.ID {
		t.Errorf("IncidentID = %q, want %q", created.IncidentID, inc.ID)
	}

	stored := store.iocs[inc.ID]
	if len(stored) != 1 {
		t.Fatalf("expected 1 stored IOC, got %d", len(stored))
	}
}

func TestAddTimelineEntry_Success(t *testing.T) {
	svc, store := newTestService()
	ctx := context.Background()

	inc, _ := svc.Create(ctx, &CreateIncidentRequest{
		Title:    "timeline entry test",
		Severity: SeverityP2,
	})

	entry := &TimelineEntry{
		EntryType: "cyberpath_remediation_completed",
		ActorID:   "cyberpath",
		Summary:   "CyberPath remediation training completed for cohort cohort-1",
	}

	created, err := svc.AddTimelineEntry(ctx, inc.ID, entry)
	if err != nil {
		t.Fatalf("AddTimelineEntry returned error: %v", err)
	}
	if created.ID == "" {
		t.Error("expected non-empty timeline entry ID")
	}
	if created.IncidentID != inc.ID {
		t.Errorf("IncidentID = %q, want %q", created.IncidentID, inc.ID)
	}

	stored := store.timeline[inc.ID]
	if len(stored) != 1 {
		t.Fatalf("expected 1 stored timeline entry, got %d", len(stored))
	}
	if stored[0].EntryType != "cyberpath_remediation_completed" {
		t.Errorf("EntryType = %q, want cyberpath_remediation_completed", stored[0].EntryType)
	}
}

func TestListIOCs_Success(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	inc, _ := svc.Create(ctx, &CreateIncidentRequest{
		Title:    "IOC list test",
		Severity: SeverityP2,
	})

	svc.AddIOC(ctx, inc.ID, &IOCEnrichment{IOCType: "ip", IOCValue: "10.0.0.1", Confidence: 0.9, Source: "threatflow"})
	svc.AddIOC(ctx, inc.ID, &IOCEnrichment{IOCType: "domain", IOCValue: "evil.example.com", Confidence: 0.8, Source: "manual"})

	iocs, err := svc.ListIOCs(ctx, inc.ID)
	if err != nil {
		t.Fatalf("ListIOCs returned error: %v", err)
	}
	if len(iocs) != 2 {
		t.Errorf("len(iocs) = %d, want 2", len(iocs))
	}
}

func TestGetTimeline_Success(t *testing.T) {
	svc, store := newTestService()
	ctx := context.Background()

	inc, _ := svc.Create(ctx, &CreateIncidentRequest{
		Title:    "Timeline test",
		Severity: SeverityP1,
	})

	// Manually seed timeline entries in the mock store.
	store.timeline[inc.ID] = []TimelineEntry{
		{
			ID:         "tl-1",
			IncidentID: inc.ID,
			EntryType:  "status_change",
			ActorID:    "system",
			Summary:    "Incident opened",
			CreatedAt:  time.Now().UTC(),
		},
		{
			ID:         "tl-2",
			IncidentID: inc.ID,
			EntryType:  "action",
			ActorID:    "user-alice",
			Summary:    "Containment action taken",
			CreatedAt:  time.Now().UTC().Add(time.Minute),
		},
	}

	entries, err := svc.GetTimeline(ctx, inc.ID)
	if err != nil {
		t.Fatalf("GetTimeline returned error: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("len(entries) = %d, want 2", len(entries))
	}
}

func TestValidTransitions_AllStates(t *testing.T) {
	// Verify the transition map covers all expected states and edges.
	tests := []struct {
		from  Status
		to    Status
		valid bool
	}{
		// From open.
		{StatusOpen, StatusInvestigating, true},
		{StatusOpen, StatusClosed, true},
		{StatusOpen, StatusContained, false},
		{StatusOpen, StatusEradicating, false},
		{StatusOpen, StatusRecovering, false},

		// From investigating.
		{StatusInvestigating, StatusContained, true},
		{StatusInvestigating, StatusClosed, true},
		{StatusInvestigating, StatusOpen, false},
		{StatusInvestigating, StatusEradicating, false},

		// From contained.
		{StatusContained, StatusEradicating, true},
		{StatusContained, StatusClosed, true},
		{StatusContained, StatusOpen, false},
		{StatusContained, StatusInvestigating, false},

		// From eradicating.
		{StatusEradicating, StatusRecovering, true},
		{StatusEradicating, StatusClosed, true},
		{StatusEradicating, StatusOpen, false},

		// From recovering.
		{StatusRecovering, StatusClosed, true},
		{StatusRecovering, StatusOpen, false},
		{StatusRecovering, StatusInvestigating, false},

		// From closed (terminal).
		{StatusClosed, StatusOpen, false},
		{StatusClosed, StatusInvestigating, false},
		{StatusClosed, StatusContained, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.from)+"->"+string(tt.to), func(t *testing.T) {
			got := isValidTransition(tt.from, tt.to)
			if got != tt.valid {
				t.Errorf("isValidTransition(%s, %s) = %v, want %v", tt.from, tt.to, got, tt.valid)
			}
		})
	}
}

func TestNIS2Thresholds_P1(t *testing.T) {
	// P1 incidents require a 24-hour initial notification per NIS2 Art. 23.
	threshold, ok := NIS2Thresholds[SeverityP1]
	if !ok {
		t.Fatal("P1 threshold not found in NIS2Thresholds")
	}
	if threshold != 24*time.Hour {
		t.Errorf("P1 threshold = %v, want %v", threshold, 24*time.Hour)
	}
}

func TestNIS2Thresholds_P4_NoNotification(t *testing.T) {
	threshold, ok := NIS2Thresholds[SeverityP4]
	if !ok {
		t.Fatal("P4 threshold not found in NIS2Thresholds")
	}
	if threshold != 0 {
		t.Errorf("P4 threshold = %v, want 0 (no mandatory notification)", threshold)
	}
}

func TestCreateIncident_SetsNIS2Required(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	// P1 should require NIS2 notification.
	inc, err := svc.Create(ctx, &CreateIncidentRequest{
		Title:    "Critical incident",
		Severity: SeverityP1,
	})
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	if !inc.NIS2NotifyRequired {
		t.Error("expected NIS2NotifyRequired = true for P1")
	}

	// P4 should NOT require NIS2 notification.
	inc2, err := svc.Create(ctx, &CreateIncidentRequest{
		Title:    "Low incident",
		Severity: SeverityP4,
	})
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	if inc2.NIS2NotifyRequired {
		t.Error("expected NIS2NotifyRequired = false for P4")
	}
}

func TestProposeAndApproveAction_WithEvidence(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	inc, _ := svc.Create(ctx, &CreateIncidentRequest{
		Title:    "Evidence test",
		Severity: SeverityP2,
	})

	evidence := json.RawMessage(`{"screenshots":["s3://bucket/screenshot1.png"],"logs":"see splunk query XYZ"}`)
	pa, err := svc.ProposeAction(ctx, inc.ID, "user-alice", "operator", &ProposeActionRequest{
		ActionType:  "eradicate",
		Description: "Removed malware from host",
		Evidence:    evidence,
	})
	if err != nil {
		t.Fatalf("ProposeAction returned error: %v", err)
	}

	action, err := svc.ApproveAction(ctx, inc.ID, pa.ID, "user-bob", "verifier", "bob-token")
	if err != nil {
		t.Fatalf("ApproveAction returned error: %v", err)
	}
	if action.Evidence == nil {
		t.Error("expected evidence to be preserved")
	}
	if !strings.Contains(string(action.Evidence), "screenshot1.png") {
		t.Error("evidence content not preserved correctly")
	}
}

func TestListPendingActions_ReturnsAllRegardlessOfStatus(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	inc, _ := svc.Create(ctx, &CreateIncidentRequest{Title: "PA list test", Severity: SeverityP2})

	pa1, err := svc.ProposeAction(ctx, inc.ID, "user-alice", "operator", &ProposeActionRequest{
		ActionType: "isolate", Description: "Isolate host A",
	})
	if err != nil {
		t.Fatalf("ProposeAction 1: %v", err)
	}
	if _, err := svc.ApproveAction(ctx, inc.ID, pa1.ID, "user-bob", "verifier", "tok"); err != nil {
		t.Fatalf("ApproveAction: %v", err)
	}
	if _, err := svc.ProposeAction(ctx, inc.ID, "user-alice", "operator", &ProposeActionRequest{
		ActionType: "block", Description: "Block IP",
	}); err != nil {
		t.Fatalf("ProposeAction 2: %v", err)
	}

	pending, err := svc.ListPendingActions(ctx, inc.ID)
	if err != nil {
		t.Fatalf("ListPendingActions returned error: %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("got %d pending actions, want 2 (one approved, one still open)", len(pending))
	}

	statuses := map[string]bool{}
	for _, pa := range pending {
		statuses[string(pa.Status)] = true
	}
	if !statuses[string(PendingActionStatusApproved)] {
		t.Error("expected an approved entry in the list")
	}
	if !statuses[string(PendingActionStatusPending)] {
		t.Error("expected a still-pending entry in the list")
	}
}

func TestListPendingActions_EmptyForUnknownIncident(t *testing.T) {
	svc, _ := newTestService()
	pending, err := svc.ListPendingActions(context.Background(), "does-not-exist")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("got %d pending actions, want 0", len(pending))
	}
}

func TestStats_AggregatesAcrossIncidents(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	if _, err := svc.Create(ctx, &CreateIncidentRequest{Title: "A", Severity: SeverityP1}); err != nil {
		t.Fatalf("create A: %v", err)
	}
	if _, err := svc.Create(ctx, &CreateIncidentRequest{Title: "B", Severity: SeverityP1}); err != nil {
		t.Fatalf("create B: %v", err)
	}
	if _, err := svc.Create(ctx, &CreateIncidentRequest{Title: "C", Severity: SeverityP3}); err != nil {
		t.Fatalf("create C: %v", err)
	}

	stats, err := svc.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats returned error: %v", err)
	}
	if stats.Total != 3 {
		t.Errorf("Total = %d, want 3", stats.Total)
	}
	if stats.BySeverity[string(SeverityP1)] != 2 {
		t.Errorf("BySeverity[P1] = %d, want 2", stats.BySeverity[string(SeverityP1)])
	}
	if stats.BySeverity[string(SeverityP3)] != 1 {
		t.Errorf("BySeverity[P3] = %d, want 1", stats.BySeverity[string(SeverityP3)])
	}
	if stats.ByStatus[string(StatusOpen)] != 3 {
		t.Errorf("ByStatus[open] = %d, want 3", stats.ByStatus[string(StatusOpen)])
	}
}

// failingWORM always errors, forcing Create's synchronous
// "worm emit failed for incident.created" warning path.
type failingWORM struct{}

func (failingWORM) Emit(_ context.Context, _ WORMEvent) (*WORMReceipt, error) {
	return nil, errors.New("worm unavailable")
}

func TestWithLogger_ReplacesDefaultNopLogger(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	store := newMockStore()
	svc := NewService(store, WithLogger(logger), WithWORM(failingWORM{}))

	// A failed WORM emit logs a warning synchronously inside Create -- an
	// observable side effect that proves the custom logger (not the default
	// zap.NewNop()) is actually wired in.
	ctx := context.Background()
	if _, err := svc.Create(ctx, &CreateIncidentRequest{Title: "worm failure test", Severity: SeverityP3}); err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}
	if entries[0].Message != "worm emit failed for incident.created" {
		t.Errorf("log message = %q, want %q", entries[0].Message, "worm emit failed for incident.created")
	}
}

func TestWithMetrics_AcceptsNilSafely(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("WithMetrics(nil) usage panicked: %v", r)
		}
	}()
	store := newMockStore()
	svc := NewService(store, WithMetrics(nil))
	if _, err := svc.Create(context.Background(), &CreateIncidentRequest{Title: "x", Severity: SeverityP3}); err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
}

func TestWithMetrics_RecordsIncidentCreated(t *testing.T) {
	m := metrics.New(nil)
	store := newMockStore()
	svc := NewService(store, WithMetrics(m))

	if _, err := svc.Create(context.Background(), &CreateIncidentRequest{
		Title: "metrics test", Severity: SeverityP2, Source: SourceManual,
	}); err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	var found bool
	for _, f := range families {
		if f.GetName() != "irflow_incidents_created_total" {
			continue
		}
		for _, metric := range f.GetMetric() {
			for _, lbl := range metric.GetLabel() {
				if lbl.GetName() == "severity" && lbl.GetValue() == string(SeverityP2) {
					found = true
					if got := metric.GetCounter().GetValue(); got != 1 {
						t.Errorf("irflow_incidents_created_total{severity=P2} = %v, want 1", got)
					}
				}
			}
		}
	}
	if !found {
		t.Fatal("expected irflow_incidents_created_total{severity=P2} to be recorded via WithMetrics")
	}
}

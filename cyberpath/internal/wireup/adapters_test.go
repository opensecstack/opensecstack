package wireup

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/opensecstack/cyberpath/internal/db"
	"github.com/opensecstack/cyberpath/internal/metrics"
)

func TestDbUserToHandler_NilInput(t *testing.T) {
	if got := dbUserToHandler(nil); got != nil {
		t.Fatalf("dbUserToHandler(nil) = %+v, want nil", got)
	}
}

func TestDbUserToHandler_MapsAllFields(t *testing.T) {
	id := uuid.New()
	tenantID := uuid.New()
	deletedAt := time.Now()
	u := &db.User{
		ID:           id,
		TenantID:     tenantID,
		Email:        "user@example.com",
		DisplayName:  "Test User",
		Locale:       "en-US",
		Role:         "learner",
		PasswordHash: "$argon2id$...",
		DeletedAt:    &deletedAt,
	}

	got := dbUserToHandler(u)
	if got == nil {
		t.Fatalf("dbUserToHandler: got nil for non-nil input")
	}
	if got.ID != id.String() {
		t.Errorf("ID: got %q, want %q", got.ID, id.String())
	}
	if got.TenantID != tenantID.String() {
		t.Errorf("TenantID: got %q, want %q", got.TenantID, tenantID.String())
	}
	if got.Email != "user@example.com" {
		t.Errorf("Email: got %q", got.Email)
	}
	if got.DisplayName != "Test User" {
		t.Errorf("DisplayName: got %q", got.DisplayName)
	}
	if got.Locale != "en-US" {
		t.Errorf("Locale: got %q", got.Locale)
	}
	if got.Role != "learner" {
		t.Errorf("Role: got %q", got.Role)
	}
	if got.PasswordHash != "$argon2id$..." {
		t.Errorf("PasswordHash: got %q", got.PasswordHash)
	}
	if got.DeletedAt != &deletedAt {
		t.Errorf("DeletedAt: pointer not passed through as-is")
	}
}

func TestDbUserToHandler_NilDeletedAt(t *testing.T) {
	u := &db.User{ID: uuid.New(), TenantID: uuid.New(), Email: "a@b.com"}
	got := dbUserToHandler(u)
	if got.DeletedAt != nil {
		t.Fatalf("DeletedAt: got %v, want nil", got.DeletedAt)
	}
}

func TestUuidPtrToString(t *testing.T) {
	if got := uuidPtrToString(nil); got != "" {
		t.Fatalf("uuidPtrToString(nil) = %q, want empty string", got)
	}
	id := uuid.New()
	if got := uuidPtrToString(&id); got != id.String() {
		t.Fatalf("uuidPtrToString(&id) = %q, want %q", got, id.String())
	}
}

// ── WorkerMetricsAdapter ─────────────────────────────────────────────

func gatherValue(t *testing.T, reg *metrics.Registry, name string, wantLabels map[string]string) (float64, bool) {
	t.Helper()
	families, err := reg.Prometheus().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, fam := range families {
		if fam.GetName() != name {
			continue
		}
		for _, m := range fam.GetMetric() {
			labels := make(map[string]string, len(m.GetLabel()))
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			match := true
			for k, v := range wantLabels {
				if labels[k] != v {
					match = false
					break
				}
			}
			if !match {
				continue
			}
			if c := m.GetCounter(); c != nil {
				return c.GetValue(), true
			}
			if g := m.GetGauge(); g != nil {
				return g.GetValue(), true
			}
			if h := m.GetHistogram(); h != nil {
				return float64(h.GetSampleCount()), true
			}
		}
	}
	return 0, false
}

func TestWorkerMetricsAdapter_DelegatesToCollectors(t *testing.T) {
	reg := metrics.New()
	a := WorkerMetrics(reg)

	a.IncEnqueued("citadel", "lesson_completed")
	a.IncDelivered("citadel", "lesson_completed")
	a.IncFailed("citadel", "lesson_completed", true)
	a.IncFailed("citadel", "lesson_completed", false)
	a.IncDLQ()
	a.IncInFlight()
	a.IncInFlight()
	a.DecInFlight()
	a.ObserveDeliveryDuration("citadel", "lesson_completed", 0.25)

	if v, ok := gatherValue(t, reg, "cyberpath_outbox_enqueued_total", map[string]string{"destination": "citadel", "event_type": "lesson_completed"}); !ok || v != 1 {
		t.Errorf("OutboxEnqueuedTotal: got %v ok=%v, want 1", v, ok)
	}
	if v, ok := gatherValue(t, reg, "cyberpath_outbox_delivered_total", map[string]string{"destination": "citadel", "event_type": "lesson_completed"}); !ok || v != 1 {
		t.Errorf("OutboxDeliveredTotal: got %v ok=%v, want 1", v, ok)
	}
	if v, ok := gatherValue(t, reg, "cyberpath_outbox_failed_total", map[string]string{"destination": "citadel", "event_type": "lesson_completed", "retryable": "true"}); !ok || v != 1 {
		t.Errorf("OutboxFailedTotal retryable=true: got %v ok=%v, want 1", v, ok)
	}
	if v, ok := gatherValue(t, reg, "cyberpath_outbox_failed_total", map[string]string{"destination": "citadel", "event_type": "lesson_completed", "retryable": "false"}); !ok || v != 1 {
		t.Errorf("OutboxFailedTotal retryable=false: got %v ok=%v, want 1", v, ok)
	}
	if v, ok := gatherValue(t, reg, "cyberpath_outbox_dlq_depth", nil); !ok || v != 1 {
		t.Errorf("OutboxDLQDepth: got %v ok=%v, want 1", v, ok)
	}
	if v, ok := gatherValue(t, reg, "cyberpath_outbox_in_flight", nil); !ok || v != 1 {
		t.Errorf("OutboxInFlight: got %v ok=%v, want 1 (2 inc, 1 dec)", v, ok)
	}
	if v, ok := gatherValue(t, reg, "cyberpath_outbox_delivery_duration_seconds", map[string]string{"destination": "citadel", "event_type": "lesson_completed"}); !ok || v != 1 {
		t.Errorf("OutboxDeliveryDuration sample count: got %v ok=%v, want 1", v, ok)
	}
}

func TestWorkerMetricsAdapter_NilSafe(t *testing.T) {
	// A nil *WorkerMetricsAdapter (or one with a nil Inner) must not panic
	// — every method should be a documented no-op guard.
	var nilAdapter *WorkerMetricsAdapter
	nilAdapter.IncEnqueued("d", "e")
	nilAdapter.IncDelivered("d", "e")
	nilAdapter.IncFailed("d", "e", true)
	nilAdapter.IncDLQ()
	nilAdapter.IncInFlight()
	nilAdapter.DecInFlight()
	nilAdapter.ObserveDeliveryDuration("d", "e", 1.0)

	emptyAdapter := &WorkerMetricsAdapter{}
	emptyAdapter.IncEnqueued("d", "e")
	emptyAdapter.IncDelivered("d", "e")
	emptyAdapter.IncFailed("d", "e", false)
	emptyAdapter.IncDLQ()
	emptyAdapter.IncInFlight()
	emptyAdapter.DecInFlight()
	emptyAdapter.ObserveDeliveryDuration("d", "e", 1.0)
	// No assertions beyond "did not panic" — this test's entire purpose is
	// proving the nil-guard branches in each method are exercised and safe.
}

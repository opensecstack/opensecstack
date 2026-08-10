package citadel

// publishConfirmation's fast path (confirm channel has room) is
// already exercised indirectly by the retry-loop tests in
// client_retry_test.go. These tests target the slow path directly —
// a full confirm channel — which was previously untested (20%
// coverage): both the "drains before the timeout" and "times out and
// counts as lost" branches.

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/rs/zerolog"

	"github.com/opensecstack/openscrub/internal/metrics"
)

// TestPublishConfirmationDrainsWithinTimeoutWhenSlotFreesUp proves that
// when the confirm channel is momentarily full, publishConfirmation
// blocks (rather than dropping immediately) and successfully delivers
// once a slot frees up before ConfirmDrainTimeout elapses.
func TestPublishConfirmationDrainsWithinTimeoutWhenSlotFreesUp(t *testing.T) {
	c := New(Config{RetryBufferSize: 1, ConfirmDrainTimeout: 2 * time.Second}, zerolog.Nop())
	// Fill the (size-1) confirm channel so the fast path's non-blocking
	// send fails and publishConfirmation must take the slow path.
	c.confirm <- DeliveryConfirmation{EventID: "occupant"}

	done := make(chan struct{})
	go func() {
		c.publishConfirmation(DeliveryConfirmation{EventID: "evt-slow", Delivered: true})
		close(done)
	}()

	// Give the goroutine time to enter the slow path's blocking select,
	// then free up room by draining the occupant.
	time.Sleep(50 * time.Millisecond)
	occupant := <-c.confirm

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("publishConfirmation did not return after the channel drained")
	}
	if occupant.EventID != "occupant" {
		t.Fatalf("unexpected first confirmation: %+v", occupant)
	}

	select {
	case got := <-c.confirm:
		if got.EventID != "evt-slow" {
			t.Fatalf("expected evt-slow to have been delivered, got %+v", got)
		}
	default:
		t.Fatal("expected evt-slow to have landed on the confirm channel")
	}
}

// TestPublishConfirmationTimesOutAndCountsLostWhenDrainerStalled
// proves the bounded-timeout guarantee: if nothing ever drains the
// confirm channel, publishConfirmation must give up after
// ConfirmDrainTimeout (not block forever) and bump the
// confirm_dropped metric so the loss is operator-visible.
func TestPublishConfirmationTimesOutAndCountsLostWhenDrainerStalled(t *testing.T) {
	const timeout = 30 * time.Millisecond
	c := New(Config{RetryBufferSize: 1, ConfirmDrainTimeout: timeout}, zerolog.Nop())
	c.confirm <- DeliveryConfirmation{EventID: "occupant"} // never drained

	before := testutil.ToFloat64(metrics.CitadelEmitTotal.WithLabelValues("confirm_dropped"))

	start := time.Now()
	c.publishConfirmation(DeliveryConfirmation{EventID: "evt-lost", Delivered: true})
	elapsed := time.Since(start)

	if elapsed < timeout {
		t.Fatalf("returned after %v, want >= ConfirmDrainTimeout (%v)", elapsed, timeout)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("publishConfirmation blocked for %v — timeout guarantee not honored", elapsed)
	}

	after := testutil.ToFloat64(metrics.CitadelEmitTotal.WithLabelValues("confirm_dropped"))
	if after != before+1 {
		t.Fatalf("confirm_dropped counter = %v, want %v", after, before+1)
	}

	// The occupant is still the only thing on the channel — evt-lost
	// must NOT have been force-appended once the timeout fired.
	select {
	case got := <-c.confirm:
		if got.EventID != "occupant" {
			t.Fatalf("expected only the occupant on the channel, got %+v", got)
		}
	default:
		t.Fatal("expected the occupant still queued")
	}
}

// TestPublishConfirmationDefaultTimeoutAppliedWhenUnset proves
// ConfirmDrainTimeout=0 (the zero value most Config literals in
// non-test code will have) falls back to defaultConfirmDrainTimeout
// rather than a useless zero-duration timer that fires immediately.
func TestPublishConfirmationDefaultTimeoutAppliedWhenUnset(t *testing.T) {
	c := New(Config{RetryBufferSize: 1}, zerolog.Nop()) // ConfirmDrainTimeout left at zero
	c.confirm <- DeliveryConfirmation{EventID: "occupant"}

	done := make(chan struct{})
	go func() {
		c.publishConfirmation(DeliveryConfirmation{EventID: "evt"})
		close(done)
	}()

	// If the zero value were used as-is (no fallback), the slow path's
	// timer would fire almost instantly. Assert it does NOT return
	// within a short window, proving the ~5s default is in effect.
	select {
	case <-done:
		t.Fatal("publishConfirmation returned too quickly — default ConfirmDrainTimeout not applied")
	case <-time.After(200 * time.Millisecond):
	}

	// Drain to let the goroutine finish and avoid leaking it past the
	// test (it will succeed once we read the occupant).
	<-c.confirm
	<-done
}

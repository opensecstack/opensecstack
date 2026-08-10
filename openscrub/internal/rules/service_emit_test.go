package rules

// Targets the low-coverage branches of service.go that the existing
// service_test.go / service_extra_test.go suites don't reach:
// emitChange's outcome/error matrix, installInPlane/removeFromPlane's
// validation-error and unknown-type branches, and translateNotFound's
// pass-through case. installInPlane/removeFromPlane are exercised
// directly (unexported, same package) with Rule values that could
// never reach them through the public Create/Delete API — those paths
// are still reachable in production via a corrupt/legacy DB row whose
// Type or Port/PPS no longer matches what CreateRequest.Validate would
// have allowed at insert time.

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/openscrub/internal/citadel"
	"github.com/opensecstack/openscrub/internal/dataplane"
	"github.com/opensecstack/openscrub/internal/metrics"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// outcomeEmitter is a scriptable CitadelEmitter stub so emitChange's
// per-outcome branches can be driven deterministically.
type outcomeEmitter struct {
	outcome citadel.SubmitOutcome
	err     error
	calls   int
}

func (o *outcomeEmitter) Submit(context.Context, any) (citadel.SubmitOutcome, error) {
	o.calls++
	return o.outcome, o.err
}

func TestEmitChangeNilEmitterIsNoOp(t *testing.T) {
	svc := New(Deps{Repo: NewMemoryRepo(), Plane: dataplane.NewNoopClient(), Logger: zerolog.Nop()})
	// emitter left nil (Deps.Emitter zero value) — must not panic.
	svc.emitChange(context.Background(), Rule{ID: uuid.New()}, citadel.OpInsert, "op", "")
}

func TestEmitChangeDeliveredIncrementsDeliveredMetric(t *testing.T) {
	em := &outcomeEmitter{outcome: citadel.SubmitDelivered}
	svc := New(Deps{Repo: NewMemoryRepo(), Plane: dataplane.NewNoopClient(), Emitter: em, Logger: zerolog.Nop()})
	before := testutil.ToFloat64(metrics.CitadelEmitTotal.WithLabelValues("delivered"))

	svc.emitChange(context.Background(), Rule{ID: uuid.New()}, citadel.OpInsert, "op", "")

	after := testutil.ToFloat64(metrics.CitadelEmitTotal.WithLabelValues("delivered"))
	if after != before+1 {
		t.Fatalf("delivered counter = %v, want %v", after, before+1)
	}
	if em.calls != 1 {
		t.Fatalf("expected exactly 1 Submit call, got %d", em.calls)
	}
}

func TestEmitChangeQueuedIncrementsQueuedMetric(t *testing.T) {
	em := &outcomeEmitter{outcome: citadel.SubmitQueued}
	svc := New(Deps{Repo: NewMemoryRepo(), Plane: dataplane.NewNoopClient(), Emitter: em, Logger: zerolog.Nop()})
	before := testutil.ToFloat64(metrics.CitadelEmitTotal.WithLabelValues("queued"))

	svc.emitChange(context.Background(), Rule{ID: uuid.New()}, citadel.OpWithdraw, "op", "")

	after := testutil.ToFloat64(metrics.CitadelEmitTotal.WithLabelValues("queued"))
	if after != before+1 {
		t.Fatalf("queued counter = %v, want %v", after, before+1)
	}
}

// TestEmitChangePermanentFailureLabelsFailed proves a non-Queued
// outcome combined with a non-nil error is bucketed under the
// "failed" label rather than silently succeeding.
func TestEmitChangePermanentFailureLabelsFailed(t *testing.T) {
	em := &outcomeEmitter{outcome: citadel.SubmitDelivered, err: errors.New("citadel 400: bad request")}
	svc := New(Deps{Repo: NewMemoryRepo(), Plane: dataplane.NewNoopClient(), Emitter: em, Logger: zerolog.Nop()})
	before := testutil.ToFloat64(metrics.CitadelEmitTotal.WithLabelValues("failed"))

	svc.emitChange(context.Background(), Rule{ID: uuid.New()}, citadel.OpInsert, "op", "")

	after := testutil.ToFloat64(metrics.CitadelEmitTotal.WithLabelValues("failed"))
	if after != before+1 {
		t.Fatalf("failed counter = %v, want %v", after, before+1)
	}
}

// TestEmitChangeDroppedOnEnqueueFailureLabelsDropped proves the
// SubmitDropped+err combination is bucketed under "dropped", not
// "failed" — ops needs to distinguish "buffer overflow" from a
// generic permanent failure.
func TestEmitChangeDroppedOnEnqueueFailureLabelsDropped(t *testing.T) {
	em := &outcomeEmitter{outcome: citadel.SubmitDropped, err: errors.New("retry buffer overflow")}
	svc := New(Deps{Repo: NewMemoryRepo(), Plane: dataplane.NewNoopClient(), Emitter: em, Logger: zerolog.Nop()})
	before := testutil.ToFloat64(metrics.CitadelEmitTotal.WithLabelValues("dropped"))

	svc.emitChange(context.Background(), Rule{ID: uuid.New()}, citadel.OpInsert, "op", "")

	after := testutil.ToFloat64(metrics.CitadelEmitTotal.WithLabelValues("dropped"))
	if after != before+1 {
		t.Fatalf("dropped counter (err+SubmitDropped) = %v, want %v", after, before+1)
	}
}

// TestEmitChangeDryRunCountsAsDelivered proves SubmitDryRun (used in
// standalone/no-BaseURL deployments) is treated as a successful
// delivery for metrics purposes, matching the documented "no real
// CITADEL endpoint to wait on" semantics.
func TestEmitChangeDryRunCountsAsDelivered(t *testing.T) {
	em := &outcomeEmitter{outcome: citadel.SubmitDryRun}
	svc := New(Deps{Repo: NewMemoryRepo(), Plane: dataplane.NewNoopClient(), Emitter: em, Logger: zerolog.Nop()})
	before := testutil.ToFloat64(metrics.CitadelEmitTotal.WithLabelValues("delivered"))

	svc.emitChange(context.Background(), Rule{ID: uuid.New()}, citadel.OpExpire, "system", "ttl elapsed")

	after := testutil.ToFloat64(metrics.CitadelEmitTotal.WithLabelValues("delivered"))
	if after != before+1 {
		t.Fatalf("delivered counter (dry-run) = %v, want %v", after, before+1)
	}
}

// TestInstallInPlaneRatelimitMissingPPSErrors proves the r.PPS == nil
// guard on the ratelimit branch — a corrupt/legacy row that reaches
// installInPlane without a PPS value must error rather than send a
// meaningless zero-value RPC to the dataplane.
func TestInstallInPlaneRatelimitMissingPPSErrors(t *testing.T) {
	svc := New(Deps{Repo: NewMemoryRepo(), Plane: dataplane.NewNoopClient(), Logger: zerolog.Nop()})
	err := svc.installInPlane(context.Background(), Rule{Type: TypeRatelimit, CIDR: "203.0.113.5/32"})
	if err == nil {
		t.Fatal("expected error for ratelimit rule missing pps")
	}
}

// TestInstallInPlaneSynCookieInvalidPortErrors covers both edges of
// the 1..65535 port validation on install.
func TestInstallInPlaneSynCookieInvalidPortErrors(t *testing.T) {
	svc := New(Deps{Repo: NewMemoryRepo(), Plane: dataplane.NewNoopClient(), Logger: zerolog.Nop()})
	for _, port := range []int{0, -1, 65536, 100000} {
		p := port
		if err := svc.installInPlane(context.Background(), Rule{Type: TypeSynCookie, Port: &p}); err == nil {
			t.Fatalf("port %d: expected error, got nil", port)
		}
	}
	if err := svc.installInPlane(context.Background(), Rule{Type: TypeSynCookie, Port: nil}); err == nil {
		t.Fatal("nil port: expected error, got nil")
	}
}

// TestInstallInPlaneUnknownTypeErrors covers the default branch.
func TestInstallInPlaneUnknownTypeErrors(t *testing.T) {
	svc := New(Deps{Repo: NewMemoryRepo(), Plane: dataplane.NewNoopClient(), Logger: zerolog.Nop()})
	if err := svc.installInPlane(context.Background(), Rule{Type: Type("bogus")}); err == nil {
		t.Fatal("expected error for unknown rule type")
	}
}

// TestInstallInPlaneBadCIDRErrors covers the ParseCIDR failure branch
// shared by blocklist and ratelimit.
func TestInstallInPlaneBadCIDRErrors(t *testing.T) {
	svc := New(Deps{Repo: NewMemoryRepo(), Plane: dataplane.NewNoopClient(), Logger: zerolog.Nop()})
	if err := svc.installInPlane(context.Background(), Rule{Type: TypeBlocklist, CIDR: "not-a-cidr"}); err == nil {
		t.Fatal("expected CIDR parse error")
	}
	pps := 10
	if err := svc.installInPlane(context.Background(), Rule{Type: TypeRatelimit, CIDR: "not-a-cidr", PPS: &pps}); err == nil {
		t.Fatal("expected CIDR parse error")
	}
}

// TestRemoveFromPlaneMirrorsInstallValidation proves removeFromPlane
// (installInPlane's inverse) enforces the same guards: bad CIDR,
// invalid syncookie port, and unknown type all error rather than
// silently no-op'ing (which would leave the dataplane's shadow state
// diverging from what the rules table believes was removed).
func TestRemoveFromPlaneMirrorsInstallValidation(t *testing.T) {
	svc := New(Deps{Repo: NewMemoryRepo(), Plane: dataplane.NewNoopClient(), Logger: zerolog.Nop()})

	if err := svc.removeFromPlane(context.Background(), Rule{Type: TypeBlocklist, CIDR: "nope"}); err == nil {
		t.Fatal("expected CIDR parse error (blocklist)")
	}
	pps := 5
	if err := svc.removeFromPlane(context.Background(), Rule{Type: TypeRatelimit, CIDR: "nope", PPS: &pps}); err == nil {
		t.Fatal("expected CIDR parse error (ratelimit)")
	}
	if err := svc.removeFromPlane(context.Background(), Rule{Type: TypeSynCookie, Port: nil}); err == nil {
		t.Fatal("expected error for missing syncookie port")
	}
	badPort := 70000
	if err := svc.removeFromPlane(context.Background(), Rule{Type: TypeSynCookie, Port: &badPort}); err == nil {
		t.Fatal("expected error for out-of-range syncookie port")
	}
	if err := svc.removeFromPlane(context.Background(), Rule{Type: Type("bogus")}); err == nil {
		t.Fatal("expected error for unknown rule type")
	}
}

// TestRemoveFromPlaneRatelimitClearsByAddr proves the happy path
// clears via ClearRatelimit keyed on the prefix's address (not the
// prefix itself), matching installInPlane's SetRatelimit call shape.
func TestRemoveFromPlaneRatelimitClearsByAddr(t *testing.T) {
	plane := dataplane.NewNoopClient()
	svc := New(Deps{Repo: NewMemoryRepo(), Plane: plane, Logger: zerolog.Nop()})
	pps := 500
	r := Rule{Type: TypeRatelimit, CIDR: "203.0.113.9/32", PPS: &pps}
	if err := svc.installInPlane(context.Background(), r); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := svc.removeFromPlane(context.Background(), r); err != nil {
		t.Fatalf("remove: %v", err)
	}
	snap, _ := plane.Snapshot(context.Background())
	if len(snap.Ratelimits) != 0 {
		t.Fatalf("expected ratelimit cleared, got %+v", snap.Ratelimits)
	}
}

// TestTranslateNotFoundPassesThroughOtherErrors proves translateNotFound
// only rewrites errors that wrap ErrNotFound — any other repo error
// (e.g. a real connection failure) must reach the caller verbatim so
// it isn't misreported as a 404.
func TestTranslateNotFoundPassesThroughOtherErrors(t *testing.T) {
	svc := New(Deps{Repo: NewMemoryRepo(), Plane: dataplane.NewNoopClient(), Logger: zerolog.Nop()})
	other := errors.New("connection reset by peer")
	if got := svc.translateNotFound(other); got != other {
		t.Fatalf("translateNotFound(other) = %v, want passthrough of %v", got, other)
	}
	if got := svc.translateNotFound(nil); got != nil {
		t.Fatalf("translateNotFound(nil) = %v, want nil", got)
	}
	wrapped := errors.New("db: " + ErrNotFound.Error())
	// A same-text-but-not-wrapped error must NOT be rewritten to
	// ErrNotFound — only errors.Is-true wraps qualify. Confirms the
	// doc comment's claim about avoiding a string-match footgun.
	if got := svc.translateNotFound(wrapped); got != wrapped {
		t.Fatalf("translateNotFound(string-alike) = %v, want passthrough (no string-matching)", got)
	}
}

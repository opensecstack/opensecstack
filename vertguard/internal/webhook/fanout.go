package webhook

import (
	"context"
	"encoding/json"

	"github.com/opensecstack/vertguard/internal/citadel"
)

// FanoutEmitter wraps a citadel.WORMEmitter (anything with EmitAsync)
// so every CITADEL evidence emit also fans out to subscribed external
// webhooks. Chosen over a separate EventBus / outbox-tailing daemon
// because all detection handlers (prompt, phishing, identity, media,
// threatfeed, webhook_threatflow) already accept the WORMEmitter
// interface — wrapping at the constructor edge means zero handler
// edits and zero new handler-side error paths.
//
// Trade-off: the fanout shares the request goroutine. The dispatcher
// itself enqueues to the outbox before any HTTP hop, so the
// blocking surface here is bounded by one DB INSERT per matching
// subscriber. The actual HTTP delivery is best-effort inline + outbox
// retry — the request goroutine is not held for retries.
type FanoutEmitter struct {
	Inner      WORMEmitterInner
	Dispatcher *Dispatcher
	Source     string // populates Event.Source ("vertguard" by default)
}

// WORMEmitterInner mirrors handlers.WORMEmitter without importing the
// handlers package (would cause a cycle).
type WORMEmitterInner interface {
	EmitAsync(ctx context.Context, ev citadel.Evidence) bool
}

// NewFanoutEmitter wires the wrapper.
func NewFanoutEmitter(inner WORMEmitterInner, d *Dispatcher) *FanoutEmitter {
	return &FanoutEmitter{Inner: inner, Dispatcher: d, Source: "vertguard"}
}

// EmitAsync forwards to the inner WORM client AND publishes the same
// evidence to the outbound webhook dispatcher. Failures in either path
// are independent — a CITADEL outage must not block customer webhook
// delivery, and vice versa.
func (f *FanoutEmitter) EmitAsync(ctx context.Context, ev citadel.Evidence) bool {
	ok := true
	if f.Inner != nil {
		ok = f.Inner.EmitAsync(ctx, ev)
	}
	if f.Dispatcher != nil {
		// Marshal evidence body into Event.Data; the handler-facing
		// shape is preserved so subscribers see the same fields the
		// audit trail records.
		data, err := json.Marshal(ev)
		if err == nil {
			f.Dispatcher.Publish(ctx, Event{
				ID:        ev.CorrelationID,
				Type:      ev.EventType,
				Tenant:    ev.Tenant,
				Data:      data,
				Timestamp: ev.Timestamp,
				Source:    f.Source,
			})
		}
	}
	return ok
}

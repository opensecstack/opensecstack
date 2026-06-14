package rules

// MitigationLifecycle manages the (insert → finalize) lifespan of a
// `mitigations` row for each active rule. It is the production code
// path that BLOCKER 1 (third-pass review) flagged as missing — without
// it, migration 0002's snapshot columns + state machine were theatre
// because no caller ever wrote a row, the watcher's `PendingForEmit`
// returned nothing, and CITADEL never received `openscrub.mitigation`
// events.
//
// Design — best-effort global delta (v1.0.0):
//
//   The XDP/eBPF program in v1.0.0 exposes only *global* PERCPU
//   counters (packets_passed / packets_dropped / packets_ratelimited /
//   packets_malformed / syn_cookies_sent — see
//   rust/dataplane/src/stats.rs). There is no per-rule counter map yet.
//   To still surface a non-zero "drops observed during this rule's
//   lifetime" figure on the CITADEL evidence event, the lifecycle:
//
//     1. On Create — capture the global packets_dropped at start time
//        and write it to mitigations.start_packets_dropped (column
//        added in migration 0003).
//     2. On Delete / TTL sweep — capture the global packets_dropped
//        again, set ended_at = now, and store
//        packets_dropped = GREATEST(0, end - start) on the row. The
//        clamp guards against a loader restart between the two reads
//        (which would reset the counter to zero and yield a negative
//        delta that is meaningless).
//
//   Caveat — concurrent rules over-attribute by ~N×:
//
//     The delta is read off the same global packets_dropped counter
//     for every active rule. Two rules created at the same instant
//     each capture the same start_packets_dropped value, so when they
//     finalize they each report (end - start) — which is the SUM of
//     the drops they both contributed to plus everything every other
//     concurrent rule caused. With N concurrently-active rules each
//     reported delta is therefore inflated by roughly N× relative to
//     the true per-rule contribution.
//
//     This is NOT a "best-effort minor inaccuracy" — the figure is a
//     hard upper bound that approaches "all drops on this node during
//     the window" as N grows. Operators with N>1 active rules at any
//     time MUST treat packets_dropped as window-scoped, not
//     rule-scoped. Auditors looking at CITADEL evidence should read
//     it as "this rule was active while at least this much traffic
//     was dropped at the node", which is the WORM-correct claim.
//
//     The fix lands in v1.1 with the per-rule PERCPU_HASH counter
//     map; until then the lifecycle accepts the over-count rather
//     than reporting zero (which would defeat the whole evidence
//     pipeline). Tracked in ROADMAP.md "v1.1.0 — per-rule counters".
//
// v1.1 successor — per-rule PERCPU_HASH counter map keyed by rule_id.
// At that point migration 0004 drops the start_* columns and the
// lifecycle reads the per-rule counter directly at finalize time. The
// CITADEL event schema does not change.
//
// Recovery on restart:
//
//   On startup, RecoverActive() compares the rules table with the open
//   (ended_at IS NULL) mitigation rows and inserts a fresh row for any
//   active rule that has no open row. The fresh row's start counter is
//   "now", so the next finalize reports the post-restart delta — the
//   pre-restart drops are intentionally lost rather than double-counted
//   (CITADEL events are idempotent only by id, and we cannot fabricate
//   an id that the previous incarnation might have already used).

import (
	"context"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/openscrub/internal/dataplane"
	"github.com/opensecstack/openscrub/internal/metrics"
)

// MitigationLifecycle is the contract Service uses; an interface so
// tests can inject a stub without pulling the db package.
type MitigationLifecycle interface {
	OnRuleCreated(ctx context.Context, r Rule)
	OnRuleDeleted(ctx context.Context, r Rule)
	RecoverActive(ctx context.Context, active []Rule)
}

// MitigationStore is the persistence surface the lifecycle needs.
// *db.MitigationStore satisfies this; it is restated here so the rules
// package does not import db (avoids an import cycle and lets unit
// tests stub it).
type MitigationStore interface {
	Insert(ctx context.Context, m MitigationInsert) error
	FinalizeForRule(ctx context.Context, ruleID uuid.UUID, endedAt time.Time, endPackets, endBytes int64) error
	OpenRuleIDs(ctx context.Context) (map[uuid.UUID]struct{}, error)
}

// MitigationInsert is the minimum payload needed to record the start of
// an evidence window. Keeps the rules package free of pgx types.
type MitigationInsert struct {
	ID                  uuid.UUID
	RuleID              uuid.UUID
	RuleCIDR            string
	RuleType            string
	RuleSource          string
	StartedAt           time.Time
	StartPacketsDropped int64
	StartBytesDropped   int64
	SrcIP               *netip.Addr
}

// NoopLifecycle is the safe default when no DB / store is configured
// (dev mode). Methods are no-ops — the rules service still functions
// and CITADEL just receives the rule_change events without mitigation
// pairs.
type NoopLifecycle struct{}

func (NoopLifecycle) OnRuleCreated(context.Context, Rule)           {}
func (NoopLifecycle) OnRuleDeleted(context.Context, Rule)           {}
func (NoopLifecycle) RecoverActive(context.Context, []Rule)         {}

// LifecycleDeps wires a real lifecycle.
type LifecycleDeps struct {
	Store  MitigationStore
	Plane  dataplane.Client
	Logger zerolog.Logger
	Now    func() time.Time
}

// Lifecycle is the production implementation.
type Lifecycle struct {
	store  MitigationStore
	plane  dataplane.Client
	log    zerolog.Logger
	now    func() time.Time
}

// NewLifecycle builds a Lifecycle from its deps.
func NewLifecycle(d LifecycleDeps) *Lifecycle {
	now := d.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Lifecycle{
		store: d.Store,
		plane: d.Plane,
		log:   d.Logger.With().Str("component", "mitigation-lifecycle").Logger(),
		now:   now,
	}
}

// OnRuleCreated records the start of a mitigation window for r. Best
// effort — failures are logged but never block the rule create path
// (the rule is already in the dataplane; a missing mitigation row is a
// loss of evidence, not a loss of mitigation).
func (l *Lifecycle) OnRuleCreated(ctx context.Context, r Rule) {
	if l == nil || l.store == nil {
		return
	}
	startPackets, startBytes := l.readDrops(ctx)
	l.insertWithSnapshot(ctx, r, startPackets, startBytes)
}

// insertWithSnapshot writes the mitigation row using a caller-supplied
// (packets_dropped, bytes_dropped) snapshot. RecoverActive uses this to
// share a single Stats RPC across N rules — under the prior code each
// recovered rule incurred its own 1s-bounded Stats call, which made the
// 5s startup budget overflow as soon as the active set passed five rules.
func (l *Lifecycle) insertWithSnapshot(ctx context.Context, r Rule, startPackets, startBytes int64) error {
	ins := MitigationInsert{
		ID:                  uuid.New(),
		RuleID:              r.ID,
		RuleCIDR:            r.CIDR,
		RuleType:            string(r.Type),
		RuleSource:          r.Source,
		StartedAt:           l.now(),
		StartPacketsDropped: startPackets,
		StartBytesDropped:   startBytes,
	}
	if err := l.store.Insert(ctx, ins); err != nil {
		l.log.Warn().Err(err).Str("rule_id", r.ID.String()).
			Msg("could not insert mitigation row (CITADEL evidence will be missing for this rule)")
		return err
	}
	return nil
}

// OnRuleDeleted finalizes any open mitigation row for r so the watcher
// can pick it up and emit a CITADEL event.
func (l *Lifecycle) OnRuleDeleted(ctx context.Context, r Rule) {
	if l == nil || l.store == nil {
		return
	}
	endPackets, endBytes := l.readDrops(ctx)
	if err := l.store.FinalizeForRule(ctx, r.ID, l.now(), endPackets, endBytes); err != nil {
		l.log.Warn().Err(err).Str("rule_id", r.ID.String()).
			Msg("could not finalize mitigation row (watcher will not emit CITADEL event for this rule)")
	}
}

// RecoverActive catches up after a process restart: any rule still in
// the rules table with no open mitigation row gets a fresh row whose
// start counter is "now". Idempotent — safe to call repeatedly.
//
// Performance contract: a single Stats RPC is issued upfront and shared
// across every recovered rule. Earlier revisions called OnRuleCreated
// per rule, each of which issued its own 1s-bounded Stats RPC — with
// 100 active rules that produced a 100s sequential delay that blew past
// the startup budget and aborted recovery mid-loop. This contract is
// covered by TestRecoverActiveSharesStatsSnapshot.
//
// Resilience: per-rule insert failures are counted (via the
// `openscrub_mitigations_recovery_failed_total` counter) and logged but
// never abort the loop — a single transient DB error must not deny the
// rest of the active set its evidence row.
func (l *Lifecycle) RecoverActive(ctx context.Context, active []Rule) {
	if l == nil || l.store == nil {
		return
	}
	open, err := l.store.OpenRuleIDs(ctx)
	if err != nil {
		l.log.Warn().Err(err).Msg("could not list open mitigations on startup; skipping recovery")
		metrics.MitigationsRecoveryFailedTotal.Add(float64(len(active)))
		return
	}
	// Single Stats RPC for the whole batch. If it fails the snapshot is
	// (0, 0) — the watcher's later finalize delta is then a true
	// post-restart figure, which is the documented v1.0.0 behavior.
	startPackets, startBytes := l.readDrops(ctx)

	var (
		recovered    int
		alreadyOpen  int
		failed       int
	)
	for _, r := range active {
		if _, ok := open[r.ID]; ok {
			alreadyOpen++
			continue
		}
		if err := l.insertWithSnapshot(ctx, r, startPackets, startBytes); err != nil {
			failed++
			metrics.MitigationsRecoveryFailedTotal.Inc()
			continue
		}
		recovered++
	}
	l.log.Info().
		Int("recovered", recovered).
		Int("already_open", alreadyOpen).
		Int("failed", failed).
		Int("total_active", len(active)).
		Msg("mitigation recovery complete")
}

// readDrops fetches the global packets_dropped + bytes_dropped from the
// dataplane. Returns zeros on any error so a transient stats RPC blip
// degrades to "this row reports zero drops" rather than blocking the
// rule create / delete path.
//
// Note: the v1.0.0 Stats struct exposes packet counters only — there is
// no per-bucket bytes counter. We pass zero as bytes for now; v1.1 adds
// a bytes counter alongside the per-rule map (migration 0004) and this
// helper switches to the per-rule path.
func (l *Lifecycle) readDrops(ctx context.Context) (int64, int64) {
	if l.plane == nil {
		return 0, 0
	}
	probeCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	s, err := l.plane.Stats(probeCtx)
	if err != nil {
		l.log.Debug().Err(err).Msg("dataplane stats unavailable; using 0 for mitigation counter")
		return 0, 0
	}
	// The PacketsDropped counter is uint64; the DB column is BIGINT.
	// Saturate at math.MaxInt64 in the unlikely event of a counter that
	// actually exceeds 9.2e18. Realistically impossible at line rate
	// over a node lifetime, but cheap to be correct.
	const maxInt64 = int64(^uint64(0) >> 1)
	pkt := int64(s.PacketsDropped)
	if s.PacketsDropped > uint64(maxInt64) {
		pkt = maxInt64
	}
	return pkt, 0
}

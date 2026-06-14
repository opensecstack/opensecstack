// Package breaker implements a small three-state circuit breaker
// (closed → open → half-open). It guards outbound RPCs (CITADEL
// WORM emit, ThreatFlow webhooks, ATLAS sync) so that an upstream
// outage doesn't cascade into wedged goroutines and exhausted retry
// budgets.
//
// Trip rules:
//   - Closed: every Failure increments a counter; on N consecutive
//     failures the breaker opens for `coolDown`.
//   - Open: every call short-circuits with ErrOpen.
//   - Half-open: a single trial call is allowed. Success closes the
//     breaker; failure re-opens it for another `coolDown`.
package breaker

import (
	"errors"
	"sync"
	"time"
)

// State enumerates the breaker's runtime state.
type State int

const (
	StateClosed State = iota
	StateOpen
	StateHalfOpen
)

func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half_open"
	default:
		return "unknown"
	}
}

// ErrOpen is returned by Execute when the breaker is open.
var ErrOpen = errors.New("breaker: circuit open")

// Config tunes a Breaker.
type Config struct {
	Name           string
	FailThreshold int           // consecutive failures that trip
	CoolDown      time.Duration // open → half-open delay
	Now           func() time.Time
}

// Breaker is safe for concurrent use.
type Breaker struct {
	cfg        Config
	mu         sync.Mutex
	state      State
	consecFail int
	openedAt   time.Time
}

// New returns a closed breaker.
func New(cfg Config) *Breaker {
	if cfg.FailThreshold <= 0 {
		cfg.FailThreshold = 5
	}
	if cfg.CoolDown <= 0 {
		cfg.CoolDown = 30 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Breaker{cfg: cfg}
}

// State returns the current state.
func (b *Breaker) State() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refreshLocked()
	return b.state
}

// Execute calls fn iff the breaker permits it. Returns ErrOpen when
// the breaker is open (no call made). Updates state based on the
// returned error.
func (b *Breaker) Execute(fn func() error) error {
	b.mu.Lock()
	b.refreshLocked()
	if b.state == StateOpen {
		b.mu.Unlock()
		return ErrOpen
	}
	b.mu.Unlock()

	err := fn()

	b.mu.Lock()
	defer b.mu.Unlock()
	if err != nil {
		b.consecFail++
		if b.state == StateHalfOpen || b.consecFail >= b.cfg.FailThreshold {
			b.state = StateOpen
			b.openedAt = b.cfg.Now()
		}
		return err
	}
	b.consecFail = 0
	b.state = StateClosed
	return nil
}

func (b *Breaker) refreshLocked() {
	if b.state == StateOpen && b.cfg.Now().Sub(b.openedAt) >= b.cfg.CoolDown {
		b.state = StateHalfOpen
	}
}

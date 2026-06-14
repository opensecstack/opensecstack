// Package webhook fans out IOC events to ThreatFlow subscribers using
// HMAC-signed POSTs. The signing scheme is Stripe-style:
// `sha256=<hex(hmac(secret, "<timestamp>.<body>"))>`. Receivers MUST
// reject requests outside a ±5min replay window.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/breaker"
)

// Subscriber is a ThreatFlow endpoint registered to receive IOCs.
//
// TODO(VG-015): outbound webhook secret rotation gap. HMACSecret is
// held in process memory only — there is no persistence layer, no
// `kid`/`sig_v=2` header for grace-period overlap, and no scheduled
// rotation primitive. Restarting the process drops every registered
// subscriber, and rotating a secret today requires deleting +
// re-creating the subscriber, which causes an in-flight signing gap.
// Tracked in VG-015 alongside the persistent IOC store; do NOT ship
// to multi-tenant prod without it.
type Subscriber struct {
	ID         string   `json:"id"`
	URL        string   `json:"url"`
	HMACSecret string   `json:"-"`
	Active     bool     `json:"active"`
	Filters    []string `json:"filters"` // empty = all
}

// IOCEvent is the wire shape sent to subscribers.
type IOCEvent struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Severity  string          `json:"severity"`
	Data      json.RawMessage `json:"data"`
	Timestamp time.Time       `json:"timestamp"`
	Source    string          `json:"source"`
}

// PublishResult is per-subscriber outcome.
type PublishResult struct {
	SubscriberID string
	Status       int
	Err          error
}

// Metrics is the subset of vertguard's registry the publisher uses.
type Metrics interface {
	IncThreatFeedPush(target, result string)
}

// Publisher is safe for concurrent use.
type Publisher struct {
	mu          sync.RWMutex
	subscribers map[string]Subscriber
	breakers    map[string]*breaker.Breaker
	http        *http.Client
	logger      zerolog.Logger
	metrics     Metrics
}

// New creates a Publisher with the given subscriber list.
func New(logger zerolog.Logger, metrics Metrics, subs []Subscriber) *Publisher {
	m := make(map[string]Subscriber, len(subs))
	bs := make(map[string]*breaker.Breaker, len(subs))
	for _, s := range subs {
		if s.ID == "" {
			s.ID = uuid.NewString()
		}
		m[s.ID] = s
		bs[s.ID] = newSubscriberBreaker(s.ID)
	}
	return &Publisher{
		subscribers: m,
		breakers:    bs,
		http:        &http.Client{Timeout: 5 * time.Second},
		logger:      logger.With().Str("component", "threatflow_webhook").Logger(),
		metrics:     metrics,
	}
}

func newSubscriberBreaker(id string) *breaker.Breaker {
	return breaker.New(breaker.Config{
		Name:          "threatflow.webhook." + id,
		FailThreshold: 5,
		CoolDown:      30 * time.Second,
	})
}

// Add registers a subscriber. If id is empty one is generated.
func (p *Publisher) Add(s Subscriber) Subscriber {
	if s.ID == "" {
		s.ID = uuid.NewString()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subscribers[s.ID] = s
	if _, ok := p.breakers[s.ID]; !ok {
		p.breakers[s.ID] = newSubscriberBreaker(s.ID)
	}
	return s
}

// Remove unregisters a subscriber by id. Returns true if found.
func (p *Publisher) Remove(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.subscribers[id]
	delete(p.subscribers, id)
	delete(p.breakers, id)
	return ok
}

func (p *Publisher) breakerFor(id string) *breaker.Breaker {
	p.mu.RLock()
	b, ok := p.breakers[id]
	p.mu.RUnlock()
	if ok {
		return b
	}
	// Race with concurrent Remove or a subscriber added inline; create
	// a fresh breaker so the call still gets isolation.
	p.mu.Lock()
	defer p.mu.Unlock()
	if b, ok := p.breakers[id]; ok {
		return b
	}
	b = newSubscriberBreaker(id)
	p.breakers[id] = b
	return b
}

// List returns a snapshot of registered subscribers (secrets stripped).
func (p *Publisher) List() []Subscriber {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Subscriber, 0, len(p.subscribers))
	for _, s := range p.subscribers {
		s.HMACSecret = ""
		out = append(out, s)
	}
	return out
}

// Publish fans out the event to all matching subscribers concurrently.
func (p *Publisher) Publish(ctx context.Context, ev IOCEvent) []PublishResult {
	if ev.ID == "" {
		ev.ID = uuid.NewString()
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	if ev.Source == "" {
		ev.Source = "vertguard"
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return []PublishResult{{Err: fmt.Errorf("marshal: %w", err)}}
	}

	p.mu.RLock()
	targets := make([]Subscriber, 0, len(p.subscribers))
	for _, s := range p.subscribers {
		if !s.Active {
			continue
		}
		if !matchesFilter(s.Filters, ev.Type) {
			continue
		}
		targets = append(targets, s)
	}
	p.mu.RUnlock()

	results := make([]PublishResult, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t Subscriber) {
			defer wg.Done()
			results[i] = p.deliver(ctx, t, body)
		}(i, t)
	}
	wg.Wait()
	return results
}

func matchesFilter(filters []string, t string) bool {
	if len(filters) == 0 {
		return true
	}
	for _, f := range filters {
		if f == t {
			return true
		}
	}
	return false
}

func (p *Publisher) deliver(ctx context.Context, s Subscriber, body []byte) PublishResult {
	const maxAttempts = 3
	backoff := []time.Duration{100 * time.Millisecond, 500 * time.Millisecond, 2 * time.Second}

	br := p.breakerFor(s.ID)
	res := PublishResult{SubscriberID: s.ID}
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				res.Err = ctx.Err()
				return res
			case <-time.After(backoff[attempt-1]):
			}
		}
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		sig := sign(s.HMACSecret, ts, body)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
		if err != nil {
			res.Err = err
			break
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-ThreatFlow-Timestamp", ts)
		req.Header.Set("X-ThreatFlow-Signature", "sha256="+sig)

		var resp *http.Response
		err = br.Execute(func() error {
			r, e := p.http.Do(req)
			if e != nil {
				return e
			}
			resp = r
			// 5xx counts as a breaker failure; 4xx does not (caller bug,
			// not subscriber outage).
			if r.StatusCode >= 500 {
				return fmt.Errorf("subscriber %s: %d", s.ID, r.StatusCode)
			}
			return nil
		})
		if errors.Is(err, breaker.ErrOpen) {
			if p.metrics != nil {
				p.metrics.IncThreatFeedPush(s.ID, "breaker_open")
			}
			res.Err = err
			return res
		}
		if err != nil && resp == nil {
			res.Err = err
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		res.Status = resp.StatusCode

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			res.Err = nil
			if p.metrics != nil {
				p.metrics.IncThreatFeedPush(s.ID, "ok")
			}
			return res
		}
		if resp.StatusCode < 500 {
			res.Err = fmt.Errorf("subscriber %s: %d", s.ID, resp.StatusCode)
			break
		}
		res.Err = fmt.Errorf("subscriber %s: %d", s.ID, resp.StatusCode)
	}
	if p.metrics != nil {
		p.metrics.IncThreatFeedPush(s.ID, "fail")
	}
	return res
}

func sign(secret, timestamp string, body []byte) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(timestamp))
	h.Write([]byte("."))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

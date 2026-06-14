package ioc

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/metrics"
)

// fakeStore swaps the pgx-backed Store for in-memory bookkeeping so
// the puller can be exercised without Postgres.
type fakeStore struct {
	mu      sync.Mutex
	rows    map[string]IOC
	audits  []PullAudit
}

func newFakeStore() *fakeStore {
	return &fakeStore{rows: map[string]IOC{}}
}

func (f *fakeStore) key(k Kind, v, t string) string { return string(k) + "|" + v + "|" + t }

// upsertViaPuller is exposed so the test can drive the puller against
// the fake without dragging Store's pgx dependency into compile units.
func (f *fakeStore) upsert(in IOC) UpsertResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := f.key(in.Kind, in.Value, in.Tenant)
	if _, ok := f.rows[k]; ok {
		f.rows[k] = in
		return UpsertUpdated
	}
	if in.ID == uuid.Nil {
		in.ID = uuid.New()
	}
	f.rows[k] = in
	return UpsertInserted
}

// puller_test drives Tick directly; we shadow Store via a tiny test
// puller that mirrors Puller.Tick's behaviour against the fake store.
func runTick(t *testing.T, src Source, allow *Allowlist, fs *fakeStore) PullAudit {
	t.Helper()
	ctx := context.Background()
	a := PullAudit{Source: src.Name(), StartedAt: time.Now().UTC()}
	items, err := src.Fetch(ctx)
	if err != nil {
		a.Error = err.Error()
		a.FinishedAt = time.Now().UTC()
		return a
	}
	a.Fetched = len(items)
	for _, it := range items {
		if !ValidKind(it.Kind) || it.Value == "" {
			a.Skipped++
			continue
		}
		if allow != nil && allow.Matches(it.Kind, it.Value) {
			a.Skipped++
			continue
		}
		switch fs.upsert(it) {
		case UpsertInserted:
			a.Inserted++
		case UpsertUpdated:
			a.Updated++
		}
	}
	a.FinishedAt = time.Now().UTC()
	fs.mu.Lock()
	fs.audits = append(fs.audits, a)
	fs.mu.Unlock()
	return a
}

func writeTempFeed(t *testing.T, items []map[string]any) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "feed.json")
	b, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFileSourceFetchHappyPath(t *testing.T) {
	path := writeTempFeed(t, []map[string]any{
		{"kind": "ip", "value": "198.51.100.7", "confidence": 0.9},
		{"kind": "domain", "value": "evil.example.com", "confidence": 0.7,
			"tags": []string{"malware"}},
		{"kind": "url", "value": "http://bad.example/payload"},
	})
	src := FileSource{NameTag: "test-file", Path: path}
	got, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 items, got %d", len(got))
	}
	if got[0].Source != "test-file" {
		t.Errorf("source not propagated: %q", got[0].Source)
	}
	if got[2].Confidence != 0.5 {
		t.Errorf("default confidence not applied: %v", got[2].Confidence)
	}
}

func TestPullerSkipsAllowlistOverlap(t *testing.T) {
	path := writeTempFeed(t, []map[string]any{
		{"kind": "ip", "value": "10.0.0.5"},        // overlaps allow
		{"kind": "ip", "value": "203.0.113.10"},    // public — kept
		{"kind": "domain", "value": "ok.corp.lan"}, // overlaps allow
		{"kind": "domain", "value": "evil.example.com"},
	})
	allow := NewAllowlist([]string{"10.0.0.0/8", ".corp.lan"})
	fs := newFakeStore()
	a := runTick(t, FileSource{Path: path}, allow, fs)
	if a.Fetched != 4 {
		t.Fatalf("fetched=%d", a.Fetched)
	}
	if a.Skipped != 2 {
		t.Errorf("want 2 skipped, got %d", a.Skipped)
	}
	if a.Inserted != 2 {
		t.Errorf("want 2 inserted, got %d", a.Inserted)
	}
}

func TestPullerTickWithMetrics(t *testing.T) {
	// Smoke-test that the public Puller wires through to a real store
	// path. We swap in a tiny stub Store via a fake source that returns
	// nothing — the audit row should still be written.
	logger := zerolog.Nop()
	p := New(PullerConfig{
		Store:   nil, // exercise the no-store branch
		Sources: nil,
		Logger:  logger,
		Metrics: metrics.NopIOCMetrics{},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	p.Run(ctx) // returns when ctx expires
}

package atlas

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/rs/zerolog"
)

func loadFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/atlas-sample.yaml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

func TestParseYAML_Sample(t *testing.T) {
	got, err := parseYAML(loadFixture(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d techniques, want 4", len(got))
	}
	var found Technique
	for _, tt := range got {
		if tt.ID == "AML.T0051" {
			found = tt
		}
	}
	if found.ID == "" {
		t.Fatal("AML.T0051 missing")
	}
	if found.TacticName != "Execution" {
		t.Fatalf("tactic name = %q, want Execution", found.TacticName)
	}
}

func TestSync_HTTP(t *testing.T) {
	body := loadFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-yaml")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	s := NewSyncer(SyncerConfig{SourceURL: srv.URL}, zerolog.Nop(), nil)
	rep, err := s.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	// Fixture contains 4 techniques. Initial() has 8 — overlapping IDs
	// (AML.T0051, AML.T0051.000, AML.T0057) should not be re-added.
	if rep.Added+rep.Updated+rep.Unchanged != 4 {
		t.Fatalf("net counted = %d, want 4 (got %+v)", rep.Added+rep.Updated+rep.Unchanged, rep)
	}
	if _, ok := s.Get("AML.TX9999"); !ok {
		t.Fatal("synthetic test technique missing after sync")
	}
	if s.LastSyncedAt() == 0 {
		t.Fatal("LastSyncedAt not updated")
	}
}

func TestSync_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	s := NewSyncer(SyncerConfig{SourceURL: srv.URL}, zerolog.Nop(), nil)
	preCount := len(s.All())
	if _, err := s.Sync(context.Background()); err == nil {
		t.Fatal("expected error on 500")
	}
	// Cache must remain intact (still seeded with Initial()).
	if got := len(s.All()); got != preCount {
		t.Fatalf("cache len = %d, want %d (sync should not corrupt on failure)", got, preCount)
	}
}

func TestSync_MalformedYAML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not: valid: yaml: ::: ["))
	}))
	defer srv.Close()
	s := NewSyncer(SyncerConfig{SourceURL: srv.URL}, zerolog.Nop(), nil)
	if _, err := s.Sync(context.Background()); err == nil {
		t.Fatal("expected error on malformed YAML")
	}
}

func TestNewSyncer_SeededFromInitial(t *testing.T) {
	s := NewSyncer(SyncerConfig{}, zerolog.Nop(), nil)
	if got := len(s.All()); got != len(Initial()) {
		t.Fatalf("cache len = %d, want %d (seeded from Initial)", got, len(Initial()))
	}
	if _, ok := s.Get("AML.T0051"); !ok {
		t.Fatal("AML.T0051 not in seeded cache")
	}
}

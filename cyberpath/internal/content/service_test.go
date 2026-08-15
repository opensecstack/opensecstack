package content

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNewService(t *testing.T) {
	s := NewService("some/dir", nil)
	if s.ContentDir != "some/dir" {
		t.Errorf("ContentDir = %q", s.ContentDir)
	}
	if s.lastHash == nil {
		t.Error("lastHash map not initialised")
	}
}

func TestLint_HappyPath(t *testing.T) {
	root, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	s := NewService(root, nil)
	results, err := s.Lint(context.Background(), "")
	if err != nil {
		t.Fatalf("Lint: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("want 1 lint result, got %d", len(results))
	}
	if results[0].TrackID != "sample-track" {
		t.Errorf("TrackID = %q", results[0].TrackID)
	}
	if results[0].HasErrors() {
		t.Errorf("unexpected errors: %+v", results[0].Diagnostics)
	}
}

func TestLint_ExplicitDirOverridesContentDir(t *testing.T) {
	root, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	s := NewService("/does/not/exist", nil)
	results, err := s.Lint(context.Background(), root)
	if err != nil {
		t.Fatalf("Lint: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("want 1 lint result, got %d", len(results))
	}
}

func TestLint_LoadError(t *testing.T) {
	s := NewService("testdata/does-not-exist-dir", nil)
	if _, err := s.Lint(context.Background(), ""); err == nil {
		t.Fatal("expected error for missing dir")
	}
}

func TestLintResult_HasErrors(t *testing.T) {
	clean := LintResult{Diagnostics: []ValidationError{{Severity: "warning"}}}
	if clean.HasErrors() {
		t.Error("warning-only result should not HasErrors")
	}
	dirty := LintResult{Diagnostics: []ValidationError{{Severity: "warning"}, {Severity: "error"}}}
	if !dirty.HasErrors() {
		t.Error("expected HasErrors true")
	}
	empty := LintResult{}
	if empty.HasErrors() {
		t.Error("empty diagnostics should not HasErrors")
	}
}

func TestReload_LoadError(t *testing.T) {
	s := NewService("testdata/does-not-exist-dir", nil)
	_, err := s.Reload(context.Background(), uuid.Nil)
	if err == nil {
		t.Fatal("expected error for missing content dir")
	}
}

func TestReload_NilPublisherFailsPublish(t *testing.T) {
	root, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	s := NewService(root, nil) // no publisher configured
	_, err = s.Reload(context.Background(), uuid.Nil)
	if err == nil || !strings.Contains(err.Error(), "publisher is nil") {
		t.Errorf("expected 'publisher is nil' error, got %v", err)
	}
}

// TestReload_TracksFailedPublish exercises the report.Failed accumulation
// branch. Validation happens before any DB connection is opened, so a
// Strict publisher pointed at an invalid track fails without needing a
// live database — see TestPublish_ValidationFailure for why this is safe.
func TestReload_TracksFailedPublish(t *testing.T) {
	dir := t.TempDir()
	trackDir := filepath.Join(dir, "broken-track")
	if err := os.MkdirAll(trackDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Missing required fields (title, description, nis2, modules) so
	// ValidateTrack returns "error" severity diagnostics and Strict
	// publishing refuses — this never reaches BeginTx.
	yaml := "id: broken-track\nversion: 1.0.0\n"
	if err := os.WriteFile(filepath.Join(trackDir, "track.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatalf("write track.yaml: %v", err)
	}

	pool := unconnectedTestPool(t)
	defer pool.Close()

	s := NewService(dir, NewPublisher(pool, nil, nil))
	report, err := s.Reload(context.Background(), uuid.Nil)
	if err != nil {
		t.Fatalf("Reload returned top-level error, want per-track Failed entry: %v", err)
	}
	if len(report.Failed) != 1 {
		t.Fatalf("report.Failed = %+v, want 1 entry", report.Failed)
	}
	if report.Failed[0].ID != "broken-track" {
		t.Errorf("failed track id = %q", report.Failed[0].ID)
	}
	if len(report.Published) != 0 {
		t.Errorf("expected no published tracks, got %+v", report.Published)
	}
}

// TestReload_EndToEnd copies testdata/sample-track into a scratch content
// dir (rewritten with a unique track/lab id) and drives Service.Reload
// for real: first pass must publish, second pass (unchanged content)
// must report Unchanged and skip re-publishing, third pass (content
// edited on disk) must publish again.
func TestReload_EndToEnd(t *testing.T) {
	pool := connectTestDB(t)
	defer pool.Close()

	srcRoot, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	dstRoot := t.TempDir()
	suffix := strings.ReplaceAll(uuid.New().String(), "-", "")[:12]
	trackID := "content-test-" + suffix
	labID := "content-test-lab-" + suffix
	if err := copySampleTrackWithUniqueIDs(srcRoot, dstRoot, trackID, labID); err != nil {
		t.Fatalf("copy fixture: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = pool.Exec(ctx, `DELETE FROM lab_definitions WHERE id = $1`, labID)
		_, _ = pool.Exec(ctx, `DELETE FROM content_versions WHERE entity_id = $1 OR entity_id = $2`, trackID, labID)
		_, _ = pool.Exec(ctx, `DELETE FROM content_versions WHERE entity_type IN ('module','lesson','quiz')`)
		_, _ = pool.Exec(ctx, `DELETE FROM tracks WHERE slug = $1`, trackID)
	}()

	p := NewPublisher(pool, nil, nil)
	s := NewService(dstRoot, p)

	report, err := s.Reload(context.Background(), uuid.Nil)
	if err != nil {
		t.Fatalf("Reload (pass 1): %v", err)
	}
	if len(report.Published) != 1 || report.Published[0] != trackID {
		t.Fatalf("pass 1 report.Published = %+v, want [%s]", report.Published, trackID)
	}
	if len(report.Failed) != 0 {
		t.Fatalf("pass 1 report.Failed = %+v", report.Failed)
	}

	report2, err := s.Reload(context.Background(), uuid.Nil)
	if err != nil {
		t.Fatalf("Reload (pass 2): %v", err)
	}
	if len(report2.Unchanged) != 1 || report2.Unchanged[0] != trackID {
		t.Fatalf("pass 2 report.Unchanged = %+v, want [%s]", report2.Unchanged, trackID)
	}
	if len(report2.Published) != 0 {
		t.Fatalf("pass 2 should not re-publish unchanged track, got %+v", report2.Published)
	}

	// Edit the on-disk track title so its content hash changes, then
	// confirm the third pass republishes it.
	trackYAMLPath := filepath.Join(dstRoot, trackID, "track.yaml")
	raw, err := os.ReadFile(trackYAMLPath)
	if err != nil {
		t.Fatalf("read track.yaml: %v", err)
	}
	edited := strings.Replace(string(raw), `en: "Sample track"`, `en: "Sample track (v2)"`, 1)
	if edited == string(raw) {
		t.Fatal("edit did not change track.yaml content — fixture title text assumption is stale")
	}
	if err := os.WriteFile(trackYAMLPath, []byte(edited), 0o644); err != nil {
		t.Fatalf("write track.yaml: %v", err)
	}

	report3, err := s.Reload(context.Background(), uuid.Nil)
	if err != nil {
		t.Fatalf("Reload (pass 3): %v", err)
	}
	if len(report3.Published) != 1 || report3.Published[0] != trackID {
		t.Fatalf("pass 3 report.Published = %+v, want [%s] after content edit", report3.Published, trackID)
	}
}

// unconnectedTestPool returns a pgxpool.Pool constructed from a DSN
// pointing at an address nothing listens on. pgxpool.New only parses the
// DSN and does not dial, so this is safe to use for exercising code paths
// that never reach BeginTx/Acquire (e.g. Strict validation refusal).
func unconnectedTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://nouser@127.0.0.1:1/nodb")
	if err != nil {
		t.Fatalf("pgxpool.New (lazy, no dial expected): %v", err)
	}
	return pool
}

// copySampleTrackWithUniqueIDs copies testdata/sample-track into
// dstRoot/<trackID>, rewriting track.yaml's id and the lab's id/version
// directory reference so parallel test runs never collide on globally
// unique keys (lab_definitions.id has no track scoping).
func copySampleTrackWithUniqueIDs(srcRoot, dstRoot, trackID, labID string) error {
	srcTrack := filepath.Join(srcRoot, "sample-track")
	dstTrack := filepath.Join(dstRoot, trackID)
	if err := copyDir(srcTrack, dstTrack); err != nil {
		return err
	}

	trackYAML := filepath.Join(dstTrack, "track.yaml")
	raw, err := os.ReadFile(trackYAML)
	if err != nil {
		return err
	}
	updated := strings.Replace(string(raw), "id: sample-track", "id: "+trackID, 1)
	if err := os.WriteFile(trackYAML, []byte(updated), 0o644); err != nil {
		return err
	}

	labYAML := filepath.Join(dstTrack, "labs", "sample-lab", "lab.yaml")
	labRaw, err := os.ReadFile(labYAML)
	if err != nil {
		return err
	}
	labUpdated := strings.Replace(string(labRaw), "id: sample-lab", "id: "+labID, 1)
	return os.WriteFile(labYAML, []byte(labUpdated), 0o644)
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode())
	})
}

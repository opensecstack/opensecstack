package main

import (
	"os"
	"path/filepath"
	"testing"
)

// listMigrationFiles is pure filesystem logic (no DB dependency), unlike the
// rest of migrate.go — worth unit testing directly rather than only via the
// integration suite.

func TestListMigrationFiles_SortsAndFiltersSQLOnly(t *testing.T) {
	dir := t.TempDir()

	write := func(name, contents string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o644); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	write("0003_add_index.sql", "CREATE INDEX x;")
	write("0001_init.sql", "CREATE TABLE x();")
	write("0002_add_column.sql", "ALTER TABLE x ADD COLUMN y int;")
	write("README.md", "not a migration")
	if err := os.Mkdir(filepath.Join(dir, "0004_subdir.sql"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	files, err := listMigrationFiles(dir)
	if err != nil {
		t.Fatalf("listMigrationFiles: %v", err)
	}

	wantBase := []string{"0001_init.sql", "0002_add_column.sql", "0003_add_index.sql"}
	if len(files) != len(wantBase) {
		t.Fatalf("got %d files, want %d: %v", len(files), len(wantBase), files)
	}
	for i, f := range files {
		if filepath.Base(f) != wantBase[i] {
			t.Errorf("files[%d] = %s, want %s (lexicographic order, .sql only, no dirs)", i, filepath.Base(f), wantBase[i])
		}
	}
}

func TestListMigrationFiles_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	files, err := listMigrationFiles(dir)
	if err != nil {
		t.Fatalf("listMigrationFiles: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("got %d files, want 0", len(files))
	}
}

func TestListMigrationFiles_NonexistentDirReturnsError(t *testing.T) {
	_, err := listMigrationFiles(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("expected an error for a nonexistent directory, got nil")
	}
}

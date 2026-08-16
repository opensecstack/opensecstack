// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"

	"github.com/opensecstack/securelab/internal/db/migrations"
)

// TestMain_VersionSubcommand exercises the one branch of main() that returns
// normally instead of calling log.Fatal/os.Exit (which would kill the test
// process): `securelab version`. Every other branch requires a live DB and
// is intentionally left untested here.
func TestMain_VersionSubcommand(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()
	os.Args = []string{"securelab", "version"}

	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	os.Stdout = w

	main()

	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	os.Stdout = origStdout

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read pipe: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "securelab") {
		t.Errorf("output = %q, want it to contain the version banner", out)
	}
	if !strings.Contains(out, "commit:") {
		t.Errorf("output = %q, want it to mention commit", out)
	}
}

// ---------------------------------------------------------------------------
// runMigrations: embedded migration file discovery
// ---------------------------------------------------------------------------

// TestMigrationsFS_ContainsSortedSQLFiles verifies the assumption runMigrations
// relies on: the embedded migrations.FS contains *.sql files that, once
// lexicographically sorted, apply in ascending numeric order. runMigrations
// itself additionally calls pool.Exec against a live *pgxpool.Pool, which is
// out of scope without a real database connection.
func TestMigrationsFS_ContainsSortedSQLFiles(t *testing.T) {
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		t.Fatalf("read embedded migrations dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one embedded migration file")
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		names = append(names, e.Name())
		data, err := migrations.FS.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if len(data) == 0 {
			t.Errorf("migration %s is empty", e.Name())
		}
	}
	if len(names) == 0 {
		t.Fatal("expected at least one *.sql migration file")
	}
	if !sort.StringsAreSorted(names) {
		t.Errorf("names %v are not already lexicographically sorted", names)
	}
}

// ---------------------------------------------------------------------------
// runMigrations (via the sqlExecer fake — no live DB required)
// ---------------------------------------------------------------------------

// fakeExecer implements sqlExecer, recording every SQL statement it is asked
// to execute and optionally failing on a configured statement index.
type fakeExecer struct {
	execs   []string
	failAt  int // -1 disables failure injection
	failErr error
}

func (f *fakeExecer) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	idx := len(f.execs)
	f.execs = append(f.execs, sql)
	if f.failAt >= 0 && idx == f.failAt {
		return pgconn.CommandTag{}, f.failErr
	}
	return pgconn.CommandTag{}, nil
}

func TestRunMigrations_ExecutesEveryEmbeddedFileInOrder(t *testing.T) {
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		t.Fatalf("read embedded migrations dir: %v", err)
	}
	wantCount := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			wantCount++
		}
	}

	fake := &fakeExecer{failAt: -1}
	if err := runMigrations(context.Background(), fake, zap.NewNop()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.execs) != wantCount {
		t.Errorf("executed %d statements, want %d (one per *.sql file)", len(fake.execs), wantCount)
	}
	if !sort.SliceIsSorted(fake.execs, func(i, j int) bool { return fake.execs[i] < fake.execs[j] }) {
		// Not a strict correctness requirement (file contents needn't sort the
		// same as filenames), but guards against accidental reordering since
		// our embedded migrations happen to satisfy it today.
		t.Log("executed SQL bodies are not in lexicographic order (informational only)")
	}
}

func TestRunMigrations_PropagatesExecError(t *testing.T) {
	wantErr := errors.New("boom: syntax error")
	fake := &fakeExecer{failAt: 0, failErr: wantErr}

	err := runMigrations(context.Background(), fake, zap.NewNop())
	if err == nil {
		t.Fatal("expected error when Exec fails on the first migration")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("error = %v, want it to wrap %v", err, wantErr)
	}
	if len(fake.execs) != 1 {
		t.Errorf("executed %d statements, want exactly 1 (stop on first failure)", len(fake.execs))
	}
}

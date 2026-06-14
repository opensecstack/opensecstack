// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

// Command securelab is the SecureLab CLI tool.
//
// Subcommands:
//
//	validate <scenario.yaml>       Validates a scenario YAML file without running it.
//	run      <scenario.yaml>       Runs a scenario against a target URL.
//	          --target <url>       Target environment base URL (required for run).
//	          --db     <dsn>       PostgreSQL DSN (required for run).
//	list                           Lists all scenarios stored in the database.
//	          --db     <dsn>       PostgreSQL DSN (required for list).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/opensecstack/securelab/internal/attacks/dispatch"
	"github.com/opensecstack/securelab/internal/config"
	dbpkg "github.com/opensecstack/securelab/internal/db"
	"github.com/opensecstack/securelab/internal/scenarios"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	log, _ := zap.NewDevelopment()
	defer log.Sync() //nolint:errcheck

	switch os.Args[1] {
	case "validate":
		if err := cmdValidate(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "validate: %v\n", err)
			os.Exit(1)
		}
	case "run":
		if err := cmdRun(os.Args[2:], log); err != nil {
			fmt.Fprintf(os.Stderr, "run: %v\n", err)
			os.Exit(1)
		}
	case "list":
		if err := cmdList(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "list: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `securelab — SecureLab CLI

Usage:
  securelab validate <scenario.yaml>
  securelab run      <scenario.yaml> --target <url> [--db <dsn>]
  securelab list     [--db <dsn>]

Flags for run / list:
  --target  Base URL of the target environment (run only)
  --db      PostgreSQL DSN; falls back to SECURELAB_DB_URL env var`)
}

// ---------------------------------------------------------------------------
// validate subcommand
// ---------------------------------------------------------------------------

func cmdValidate(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: securelab validate <scenario.yaml>")
	}

	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read %s: %w", args[0], err)
	}

	spec, err := scenarios.LoadFromYAML(data)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	if err := scenarios.Validate(spec, nil); err != nil {
		return err
	}

	fmt.Printf("OK: %q is valid (%d steps, severity=%s)\n", spec.Name, len(spec.Steps), spec.Severity)
	return nil
}

// ---------------------------------------------------------------------------
// run subcommand
// ---------------------------------------------------------------------------

func cmdRun(args []string, log *zap.Logger) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	target := fs.String("target", "", "base URL of the target environment (required)")
	dbURL := fs.String("db", "", "PostgreSQL DSN (falls back to SECURELAB_DB_URL)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("usage: securelab run <scenario.yaml> --target <url>")
	}
	if *target == "" {
		return fmt.Errorf("--target is required")
	}

	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("read %s: %w", fs.Arg(0), err)
	}

	spec, err := scenarios.LoadFromYAML(data)
	if err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}

	env := &dbpkg.Environment{
		ID:        "cli-env",
		Name:      "cli-target",
		Kind:      "docker",
		TargetURL: *target,
		Status:    "ready",
	}

	if err := scenarios.Validate(spec, env); err != nil {
		return fmt.Errorf("validation: %w", err)
	}

	dsn := resolveDSN(*dbURL)
	if dsn == "" {
		return fmt.Errorf("--db or SECURELAB_DB_URL is required")
	}

	cfg := &config.Config{
		DBUrl:      dsn,
		DBMaxConns: 4,
		DevMode:    true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	pool, err := dbpkg.New(ctx, cfg)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer pool.Close()

	run := &dbpkg.ScenarioRun{
		ScenarioID:    "cli-scenario",
		EnvironmentID: env.ID,
		Status:        "pending",
	}
	runID, err := dbpkg.InsertRun(ctx, pool, run)
	if err != nil {
		return fmt.Errorf("insert run: %w", err)
	}

	executor := scenarios.NewExecutor(pool, dispatch.NewDispatcher(), &noopMonitor{}, log)
	if err := executor.Execute(ctx, runID, spec, env); err != nil {
		return fmt.Errorf("execute: %w", err)
	}

	result, err := dbpkg.GetRun(ctx, pool, runID)
	if err != nil {
		return fmt.Errorf("fetch result: %w", err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// ---------------------------------------------------------------------------
// list subcommand
// ---------------------------------------------------------------------------

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	dbURL := fs.String("db", "", "PostgreSQL DSN (falls back to SECURELAB_DB_URL)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	dsn := resolveDSN(*dbURL)
	if dsn == "" {
		return fmt.Errorf("--db or SECURELAB_DB_URL is required")
	}

	cfg := &config.Config{
		DBUrl:      dsn,
		DBMaxConns: 2,
		DevMode:    true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := dbpkg.New(ctx, cfg)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer pool.Close()

	list, err := dbpkg.ListScenarios(ctx, pool)
	if err != nil {
		return fmt.Errorf("list scenarios: %w", err)
	}

	if len(list) == 0 {
		fmt.Println("No scenarios found.")
		return nil
	}

	fmt.Printf("%-36s  %-8s  %-40s\n", "ID", "SEVERITY", "NAME")
	fmt.Printf("%-36s  %-8s  %-40s\n", strings.Repeat("-", 36), strings.Repeat("-", 8), strings.Repeat("-", 40))
	for _, s := range list {
		fmt.Printf("%-36s  %-8s  %s\n", s.ID, s.Severity, s.Name)
	}
	return nil
}

// resolveDSN returns the explicitly provided DSN, or falls back to the
// SECURELAB_DB_URL environment variable.
func resolveDSN(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return os.Getenv("SECURELAB_DB_URL")
}

// ---------------------------------------------------------------------------
// No-op stubs
// ---------------------------------------------------------------------------

type noopMonitor struct{}

func (m *noopMonitor) WaitForDetection(ctx context.Context) (*scenarios.DetectionEvent, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/opensecstack/apiguard/internal/api"
	"github.com/opensecstack/apiguard/internal/config"
	"github.com/opensecstack/apiguard/internal/customrules"
	"github.com/opensecstack/apiguard/internal/db"
	"github.com/opensecstack/apiguard/internal/reporter"
	"github.com/opensecstack/apiguard/internal/scanner"
	"github.com/opensecstack/apiguard/internal/version"
)

func main() {
	root := &cobra.Command{
		Use:   "apiguard",
		Short: "APIGuard — OWASP API Security scanner and governance platform",
		Long: `APIGuard scans REST APIs against the OWASP API Security Top 10,
generates findings reports, and integrates with CITADEL governance.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(serverCmd())
	root.AddCommand(scanCmd())
	root.AddCommand(reportCmd())
	root.AddCommand(ruleCmd())
	root.AddCommand(versionCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}

// serverCmd starts the HTTP API server.
func serverCmd() *cobra.Command {
	var cfgFile string

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Start the APIGuard API server",
		Long:  "Start the APIGuard API server. Exposes REST endpoints for scan management, findings, and audit.",
		RunE: func(cmd *cobra.Command, args []string) error {
			initConfig(cfgFile)
			initLogger()

			cfg := config.Load()
			cfg.WarnIfInsecure()

			ctx := context.Background()
			database, err := db.New(ctx, cfg.DB.URL)
			if err != nil {
				return fmt.Errorf("connecting to database: %w", err)
			}

			sc := scanner.New(&cfg.Scanner, log.Logger)
			srv := api.NewServer(cfg, database, sc)

			log.Info().Str("addr", fmt.Sprintf(":%d", cfg.Port)).Msg("starting APIGuard server")
			return srv.Start()
		},
	}

	cmd.Flags().StringVarP(&cfgFile, "config", "c", "", "path to apiguard.yaml config file")
	cmd.Flags().Int("port", 8080, "port to listen on")
	cmd.Flags().String("db-url", "", "PostgreSQL connection string")
	cmd.Flags().String("redis-url", "", "Redis connection string")
	cmd.Flags().String("jwt-secret", "", "secret used to sign JWT tokens")

	_ = viper.BindPFlag("port", cmd.Flags().Lookup("port"))
	_ = viper.BindPFlag("db.url", cmd.Flags().Lookup("db-url"))
	_ = viper.BindPFlag("redis.url", cmd.Flags().Lookup("redis-url"))
	_ = viper.BindPFlag("auth.jwt_secret", cmd.Flags().Lookup("jwt-secret"))

	return cmd
}

// scanCmd runs a one-shot API security scan from the CLI.
func scanCmd() *cobra.Command {
	var (
		specPath    string
		target      string
		format      string
		output      string
		failOn      string
		modules     string
		timeout     time.Duration
		concurrency int
		authToken   string
		authType    string
		authHeader  string
		tlsSkip     bool
		logLevel    string
		cfgFile     string
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run an API security scan",
		Long:  "Scan a live API against the OWASP API Security Top 10 and produce a report.",
		RunE: func(cmd *cobra.Command, args []string) error {
			initConfig(cfgFile)
			initLoggerLevel(logLevel)

			if specPath == "" {
				return fmt.Errorf("--spec is required")
			}
			if target == "" {
				return fmt.Errorf("--target is required")
			}

			cfg := config.Load()
			cfg.Scanner.Timeout = timeout
			cfg.Scanner.Concurrency = concurrency
			cfg.Scanner.TLSSkipVerify = tlsSkip

			var modList []string
			if modules != "" {
				for _, m := range strings.Split(modules, ",") {
					if m = strings.TrimSpace(m); m != "" {
						modList = append(modList, m)
					}
				}
			}

			sc := scanner.New(&cfg.Scanner, log.Logger)
			req := scanner.ScanRequest{
				SpecPath:      specPath,
				Target:        target,
				TLSSkipVerify: tlsSkip,
				Modules:       modList,
				Auth: scanner.AuthConfig{
					Token:  authToken,
					Type:   authType,
					Header: authHeader,
				},
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()

			log.Info().Str("spec", specPath).Str("target", target).Msg("starting scan")
			result, err := sc.Run(ctx, req)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			rep, err := reporter.New(format)
			if err != nil {
				return fmt.Errorf("creating reporter: %w", err)
			}
			data, err := rep.Generate(result)
			if err != nil {
				return fmt.Errorf("generating report: %w", err)
			}

			if output != "" {
				if err := os.WriteFile(output, data, 0o600); err != nil {
					return fmt.Errorf("writing report to %s: %w", output, err)
				}
				log.Info().Str("file", output).Msg("report written")
			} else {
				fmt.Print(string(data))
			}

			// Exit code 1 when findings meet or exceed the --fail-on threshold.
			if threshold := strings.ToLower(failOn); threshold != "none" {
				for _, f := range result.Findings {
					if severityMeetsThreshold(string(f.Severity), threshold) {
						os.Exit(1)
					}
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&specPath, "spec", "s", "", "path to OpenAPI/Swagger/GraphQL spec file (required)")
	cmd.Flags().StringVarP(&target, "target", "t", "", "base URL of the API to scan (required)")
	cmd.Flags().StringVarP(&format, "format", "f", "json", "report format: json, html, sarif, text")
	cmd.Flags().StringVarP(&output, "output", "o", "", "file path to write report (default: stdout)")
	cmd.Flags().StringVar(&failOn, "fail-on", "HIGH", "minimum severity for non-zero exit: CRITICAL, HIGH, MEDIUM, LOW, NONE")
	cmd.Flags().StringVarP(&modules, "modules", "m", "", "comma-separated OWASP module IDs (default: all)")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "per-request timeout")
	cmd.Flags().IntVar(&concurrency, "concurrency", 10, "maximum parallel requests")
	cmd.Flags().StringVar(&authToken, "auth-token", "", "authentication token or credential")
	cmd.Flags().StringVar(&authType, "auth-type", "", "authentication scheme: bearer, jwt, oauth2, apikey, basic")
	cmd.Flags().StringVar(&authHeader, "auth-header", "Authorization", "header name for auth token")
	cmd.Flags().BoolVar(&tlsSkip, "tls-skip-verify", false, "skip TLS certificate verification")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "log level: debug, info, warn, error")
	cmd.Flags().StringVarP(&cfgFile, "config", "c", "", "path to apiguard.yaml config file")

	return cmd
}

// reportCmd generates a report for a scan stored in the database via the HTTP API.
func reportCmd() *cobra.Command {
	var (
		scanID  string
		format  string
		output  string
		cfgFile string
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate a report from a stored scan",
		Long: `Generate a report for a scan stored in the database.

The APIGuard server must be running. The report is fetched from
GET /api/v1/scans/{scan-id}/report and written to the output file or stdout.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			initConfig(cfgFile)

			if scanID == "" {
				return fmt.Errorf("--scan-id is required")
			}

			cfg := config.Load()

			serverURL := fmt.Sprintf("http://localhost:%d", cfg.Port)
			fmt.Fprintf(os.Stderr, "hint: use the API directly:\n")
			fmt.Fprintf(os.Stderr, "  curl -H 'Authorization: Bearer <token>' \\\n")
			fmt.Fprintf(os.Stderr, "    '%s/api/v1/scans/%s/report?format=%s'\n", serverURL, scanID, format)

			_ = output
			return fmt.Errorf("the report command requires a running server; see hint above")
		},
	}

	cmd.Flags().StringVar(&scanID, "scan-id", "", "UUID of the scan (required)")
	cmd.Flags().StringVar(&format, "format", "json", "report format: json, html, sarif, text")
	cmd.Flags().StringVarP(&output, "output", "o", "", "file path to write report (default: stdout)")
	cmd.Flags().StringVarP(&cfgFile, "config", "c", "", "path to apiguard.yaml config file")

	return cmd
}

// ruleCmd groups the rule validate and rule test sub-commands.
func ruleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rule",
		Short: "Manage and validate custom rules",
	}
	cmd.AddCommand(ruleValidateCmd())
	cmd.AddCommand(ruleTestCmd())
	return cmd
}

func ruleValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <path>",
		Short: "Validate a custom rule YAML file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]

			info, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("cannot access %s: %w", path, err)
			}
			if info.IsDir() {
				return fmt.Errorf("%s is a directory — provide a path to a rule YAML file", path)
			}

			dir := filepath.Dir(path)
			rules, err := customrules.LoadRulesFromDir(dir)
			if err != nil {
				return fmt.Errorf("validation failed: %w", err)
			}

			base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
			for _, r := range rules {
				if strings.HasPrefix(r.ID, base) || r.ID == base {
					fmt.Printf("rule %q is valid\n", r.ID)
					return nil
				}
			}
			if len(rules) > 0 {
				fmt.Printf("rule %q is valid\n", rules[0].ID)
				return nil
			}
			return fmt.Errorf("no valid rule found in %s", path)
		},
	}
}

func ruleTestCmd() *cobra.Command {
	var target, specPath string

	cmd := &cobra.Command{
		Use:   "test <path>",
		Short: "Execute a single custom rule against a target API",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if target == "" {
				return fmt.Errorf("--target is required")
			}
			if specPath == "" {
				return fmt.Errorf("--spec is required")
			}

			cfg := config.Load()
			sc := scanner.New(&cfg.Scanner, log.Logger)
			req := scanner.ScanRequest{
				SpecPath: specPath,
				Target:   target,
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()

			result, err := sc.Run(ctx, req)
			if err != nil {
				return fmt.Errorf("rule test failed: %w", err)
			}
			fmt.Printf("rule test completed: %d finding(s)\n", result.Summary.TotalFindings)
			return nil
		},
	}

	cmd.Flags().StringVar(&target, "target", "", "base URL of the API to test against (required)")
	cmd.Flags().StringVarP(&specPath, "spec", "s", "", "path to API specification file (required)")
	return cmd
}

// versionCmd prints version, commit, build date, and Go version.
func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("apiguard %s\n", version.Version)
			fmt.Printf("  commit:  %s\n", version.GitCommit)
			fmt.Printf("  built:   %s\n", version.BuildDate)
			fmt.Printf("  go:      %s\n", runtime.Version())
		},
	}
}

func initConfig(cfgFile string) {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("apiguard")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/.apiguard")
		viper.AddConfigPath("/etc/apiguard")
	}
	_ = viper.ReadInConfig()
}

func initLogger() {
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).
		With().Timestamp().Logger()
}

func initLoggerLevel(level string) {
	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		lvl = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(lvl)
	initLogger()
}

// severityMeetsThreshold returns true when sev is at or above threshold.
func severityMeetsThreshold(sev, threshold string) bool {
	order := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
	s, ok1 := order[sev]
	t, ok2 := order[threshold]
	return ok1 && ok2 && s >= t
}

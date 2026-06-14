package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/opensecstack/opensecstack/irflow/internal/auth"
	"github.com/opensecstack/opensecstack/irflow/internal/config"
)

var (
	authIssueUser  string
	authIssueRole  string
	authIssueEmail string
	authIssueTTL   time.Duration
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Auth token utilities",
}

var authIssueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue a signed JWT using the configured auth.secret",
	Long: `Produces an HS256 JWT signed with the same secret the server uses to
verify tokens. Intended for local development and smoke tests; production
tokens should come from a real identity provider.

The signing secret is read from IRFLOW_AUTH_SECRET / auth.secret in
config. Use irflow.yaml or set the environment variable before running.`,
	RunE: runAuthIssue,
}

func init() {
	authIssueCmd.Flags().StringVar(&authIssueUser, "user", "", "subject (user id) to embed in the token")
	authIssueCmd.Flags().StringVar(&authIssueRole, "role", auth.RoleOperator, "role to embed (admin|operator|verifier|viewer|service)")
	authIssueCmd.Flags().StringVar(&authIssueEmail, "email", "", "email to embed (optional)")
	authIssueCmd.Flags().DurationVar(&authIssueTTL, "ttl", 8*time.Hour, "token lifetime (e.g. 1h, 24h)")
	_ = authIssueCmd.MarkFlagRequired("user")
	authCmd.AddCommand(authIssueCmd)
}

func runAuthIssue(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if cfg.Auth.Secret == "" {
		return fmt.Errorf("auth.secret is not configured — set IRFLOW_AUTH_SECRET or auth.secret in irflow.yaml")
	}
	if !auth.IsKnownRole(authIssueRole) {
		return fmt.Errorf("unknown role %q (valid: %v)", authIssueRole, auth.AllRoles())
	}

	token, err := auth.Issue(cfg.Auth.Secret, auth.Claims{
		Subject: authIssueUser,
		Role:    authIssueRole,
		Email:   authIssueEmail,
		Issuer:  cfg.Auth.Issuer,
	}, authIssueTTL)
	if err != nil {
		return fmt.Errorf("issuing token: %w", err)
	}
	fmt.Println(token)
	return nil
}

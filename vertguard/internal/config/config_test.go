package config

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// TestEnforceProductionGate verifies the prod-env gate trips for each
// individual insecure default and stays silent in non-prod environments.
// Closes security-checklist.md row 2.10.
func TestEnforceProductionGate(t *testing.T) {
	secureDB := DBConfig{SSLMode: "require"}
	secureAuth := AuthConfig{Secret: "x", DevMode: false}

	tests := []struct {
		name      string
		env       map[string]string
		cfg       Config
		wantErr   bool
		wantInMsg []string
	}{
		{
			name:    "no env set — gate is inert",
			env:     nil,
			cfg:     Config{Auth: AuthConfig{DevMode: true}, DB: DBConfig{SSLMode: "disable"}},
			wantErr: false,
		},
		{
			name:    "VG_ENV=development — gate is inert",
			env:     map[string]string{"VG_ENV": "development"},
			cfg:     Config{Auth: AuthConfig{DevMode: true}, DB: DBConfig{SSLMode: "disable"}},
			wantErr: false,
		},
		{
			name:    "VG_ENV=production with secure config — passes",
			env:     map[string]string{"VG_ENV": "production"},
			cfg:     Config{Auth: secureAuth, DB: secureDB},
			wantErr: false,
		},
		{
			name:      "VG_ENV=production + dev_mode=true — refuses",
			env:       map[string]string{"VG_ENV": "production"},
			cfg:       Config{Auth: AuthConfig{Secret: "x", DevMode: true}, DB: secureDB},
			wantErr:   true,
			wantInMsg: []string{"dev_mode"},
		},
		{
			name:      "VG_ENV=production + empty secret — refuses",
			env:       map[string]string{"VG_ENV": "production"},
			cfg:       Config{Auth: AuthConfig{Secret: ""}, DB: secureDB},
			wantErr:   true,
			wantInMsg: []string{"auth.secret"},
		},
		{
			name:      "VG_ENV=prod + ssl_mode=disable — refuses",
			env:       map[string]string{"VG_ENV": "prod"},
			cfg:       Config{Auth: secureAuth, DB: DBConfig{SSLMode: "disable"}},
			wantErr:   true,
			wantInMsg: []string{"ssl_mode"},
		},
		{
			name:      "GO_ENV=production fallback also trips",
			env:       map[string]string{"GO_ENV": "production"},
			cfg:       Config{Auth: AuthConfig{Secret: "x", DevMode: true}, DB: secureDB},
			wantErr:   true,
			wantInMsg: []string{"dev_mode"},
		},
		{
			name: "VG_ENV=production reports all triggers in one error",
			env:  map[string]string{"VG_ENV": "production"},
			cfg: Config{
				Auth: AuthConfig{Secret: "", DevMode: true},
				DB:   DBConfig{SSLMode: "disable"},
			},
			wantErr:   true,
			wantInMsg: []string{"dev_mode", "auth.secret", "ssl_mode"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withCleanEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}

			err := tc.cfg.EnforceProductionGate()
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr {
				if !errors.Is(err, ErrInsecureProdConfig) {
					t.Errorf("error not wrapping ErrInsecureProdConfig: %v", err)
				}
				for _, want := range tc.wantInMsg {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error %q missing expected substring %q", err.Error(), want)
					}
				}
			}
		})
	}
}

func TestIsProductionEnv(t *testing.T) {
	cases := []struct {
		val  string
		want bool
	}{
		{"production", true},
		{"prod", true},
		{"PRODUCTION", true},
		{"  prod  ", true},
		{"staging", false},
		{"development", false},
	}
	for _, c := range cases {
		t.Run(c.val, func(t *testing.T) {
			withCleanEnv(t)
			t.Setenv("VG_ENV", c.val)
			if got := IsProductionEnv(); got != c.want {
				t.Errorf("VG_ENV=%q: IsProductionEnv()=%v want %v", c.val, got, c.want)
			}
		})
	}

	t.Run("unset returns false", func(t *testing.T) {
		withCleanEnv(t)
		if IsProductionEnv() {
			t.Errorf("expected false when neither VG_ENV nor GO_ENV is set")
		}
	})
}

// withCleanEnv unsets VG_ENV and GO_ENV for the duration of the test
// and restores them on cleanup. Necessary because t.Setenv only sets;
// it cannot represent "unset".
func withCleanEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{"VG_ENV", "GO_ENV"} {
		prev, had := os.LookupEnv(key)
		_ = os.Unsetenv(key)
		k, p, h := key, prev, had
		t.Cleanup(func() {
			if h {
				_ = os.Setenv(k, p)
			} else {
				_ = os.Unsetenv(k)
			}
		})
	}
}

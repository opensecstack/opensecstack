package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

// withCleanEnv2 unsets a set of env vars for the duration of the test and
// restores whatever was there afterwards. Distinct name from the
// withCleanEnv helper in config_test.go (which only handles VG_ENV/GO_ENV)
// since it takes an arbitrary key list.
func withCleanEnvVars(t *testing.T, keys ...string) {
	t.Helper()
	for _, key := range keys {
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

func TestDBConfig_URL(t *testing.T) {
	d := DBConfig{User: "vg", Password: "secret", Host: "db.internal", Port: 5432, Name: "vertguard", SSLMode: "require"}
	got := d.URL()
	want := "postgres://vg:secret@db.internal:5432/vertguard?sslmode=require"
	if got != want {
		t.Errorf("URL() = %q, want %q", got, want)
	}
}

func TestAuthConfig_ActiveSecrets(t *testing.T) {
	tests := []struct {
		name string
		cfg  AuthConfig
		want []string
	}{
		{"none set", AuthConfig{}, []string{}},
		{"primary only", AuthConfig{Secret: "p"}, []string{"p"}},
		{"all three in priority order", AuthConfig{Secret: "p", SecretNext: "n", SecretPrevious: "prev"}, []string{"p", "n", "prev"}},
		{"next and previous without primary", AuthConfig{SecretNext: "n", SecretPrevious: "prev"}, []string{"n", "prev"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.ActiveSecrets()
			if len(got) != len(tt.want) {
				t.Fatalf("ActiveSecrets() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("ActiveSecrets()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestAuthConfig_ActiveSecretSlots(t *testing.T) {
	cfg := AuthConfig{Secret: "p", SecretPrevious: "prev"}
	got := cfg.ActiveSecretSlots()
	want := []string{"primary", "previous"}
	if len(got) != len(want) {
		t.Fatalf("ActiveSecretSlots() = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("ActiveSecretSlots()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCitadelConfig_EffectiveHMACSecrets(t *testing.T) {
	tests := []struct {
		name string
		cfg  CitadelConfig
		want []string
	}{
		{"multi-slot list wins", CitadelConfig{HMACSecrets: []string{"a", "b"}, HMACSecret: "legacy"}, []string{"a", "b"}},
		{"filters empty entries from multi-slot", CitadelConfig{HMACSecrets: []string{"a", "", "b"}}, []string{"a", "b"}},
		{"falls back to HMACSecret", CitadelConfig{HMACSecret: "legacy"}, []string{"legacy"}},
		{"falls back to KeySecret", CitadelConfig{KeySecret: "old"}, []string{"old"}},
		{"nothing set returns nil", CitadelConfig{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.EffectiveHMACSecrets()
			if len(got) != len(tt.want) {
				t.Fatalf("EffectiveHMACSecrets() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestCitadelConfig_EffectiveKeyIDs(t *testing.T) {
	if got := (CitadelConfig{KeyIDs: []string{"k1", "k2"}}).EffectiveKeyIDs(); len(got) != 2 || got[0] != "k1" {
		t.Errorf("EffectiveKeyIDs() with multi-slot = %v, want [k1 k2]", got)
	}
	if got := (CitadelConfig{KeyID: "legacy"}).EffectiveKeyIDs(); len(got) != 1 || got[0] != "legacy" {
		t.Errorf("EffectiveKeyIDs() fallback = %v, want [legacy]", got)
	}
	if got := (CitadelConfig{}).EffectiveKeyIDs(); got != nil {
		t.Errorf("EffectiveKeyIDs() empty = %v, want nil", got)
	}
}

func TestCitadelConfig_CitadelHMACRotationCollision(t *testing.T) {
	tests := []struct {
		name string
		cfg  CitadelConfig
		want bool
	}{
		{"no config", CitadelConfig{}, false},
		{"only legacy scalar", CitadelConfig{HMACSecret: "x"}, false},
		{"only multi-slot", CitadelConfig{HMACSecrets: []string{"x"}}, false},
		{"both set — collision", CitadelConfig{HMACSecret: "x", HMACSecrets: []string{"y"}}, true},
		{"legacy KeySecret plus multi-slot — collision", CitadelConfig{KeySecret: "x", HMACSecrets: []string{"y"}}, true},
		{"multi-slot all empty strings does not count", CitadelConfig{HMACSecret: "x", HMACSecrets: []string{""}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.CitadelHMACRotationCollision(); got != tt.want {
				t.Errorf("CitadelHMACRotationCollision() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCitadelConfig_EffectiveBaseURL(t *testing.T) {
	if got := (CitadelConfig{BaseURL: "https://base", APIURL: "https://api"}).EffectiveBaseURL(); got != "https://base" {
		t.Errorf("EffectiveBaseURL() = %q, want base to win", got)
	}
	if got := (CitadelConfig{APIURL: "https://api"}).EffectiveBaseURL(); got != "https://api" {
		t.Errorf("EffectiveBaseURL() fallback = %q, want https://api", got)
	}
}

func TestCitadelConfig_EffectiveHMACSecret(t *testing.T) {
	if got := (CitadelConfig{HMACSecret: "new", KeySecret: "old"}).EffectiveHMACSecret(); got != "new" {
		t.Errorf("EffectiveHMACSecret() = %q, want new to win", got)
	}
	if got := (CitadelConfig{KeySecret: "old"}).EffectiveHMACSecret(); got != "old" {
		t.Errorf("EffectiveHMACSecret() fallback = %q, want old", got)
	}
}

func TestPromptConfig_ApplyDefaults(t *testing.T) {
	p := PromptConfig{}
	p.ApplyDefaults()
	if p.MaxInputSize != promptMaxInputSizeDefault {
		t.Errorf("MaxInputSize = %d, want default %d", p.MaxInputSize, promptMaxInputSizeDefault)
	}
	if p.CleanThreshold != 0.3 || p.BlockThreshold != 0.7 {
		t.Errorf("thresholds = (%v, %v), want (0.3, 0.7)", p.CleanThreshold, p.BlockThreshold)
	}

	// Explicit non-zero values must not be clobbered.
	p2 := PromptConfig{MaxInputSize: 2048, CleanThreshold: 0.1, BlockThreshold: 0.9}
	p2.ApplyDefaults()
	if p2.MaxInputSize != 2048 {
		t.Errorf("MaxInputSize was overwritten: got %d, want 2048", p2.MaxInputSize)
	}
	if p2.CleanThreshold != 0.1 || p2.BlockThreshold != 0.9 {
		t.Errorf("thresholds overwritten: got (%v, %v)", p2.CleanThreshold, p2.BlockThreshold)
	}
}

func TestPromptConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     PromptConfig
		wantErr bool
		wantSub string
	}{
		{"valid", PromptConfig{MaxInputSize: 1 << 20, CleanThreshold: 0.3, BlockThreshold: 0.7}, false, ""},
		{"max_input_size too small", PromptConfig{MaxInputSize: 1, CleanThreshold: 0.3, BlockThreshold: 0.7}, true, "max_input_size"},
		{"max_input_size too large", PromptConfig{MaxInputSize: 1 << 30, CleanThreshold: 0.3, BlockThreshold: 0.7}, true, "max_input_size"},
		{"clean_threshold negative", PromptConfig{MaxInputSize: 1 << 20, CleanThreshold: -0.1, BlockThreshold: 0.7}, true, "clean_threshold"},
		{"block_threshold above 1", PromptConfig{MaxInputSize: 1 << 20, CleanThreshold: 0.3, BlockThreshold: 1.5}, true, "block_threshold"},
		{"clean >= block", PromptConfig{MaxInputSize: 1 << 20, CleanThreshold: 0.8, BlockThreshold: 0.7}, true, "must be <"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("Validate() error = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate() unexpected error: %v", err)
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q missing substring %q", err.Error(), tt.wantSub)
			}
		})
	}
}

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"a,b,c", []string{"a", "b", "c"}},
		{" a , b ,c ", []string{"a", "b", "c"}},
		{"a,,b", []string{"a", "b"}},
		{"", []string{}},
		{"solo", []string{"solo"}},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := splitCSV(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("splitCSV(%q) = %v, want %v", tt.in, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitCSV(%q)[%d] = %q, want %q", tt.in, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestWarnIfInsecure(t *testing.T) {
	tests := []struct {
		name     string
		cfg      Config
		wantSubs []string
		wantNone []string
	}{
		{
			name:     "fully secure config warns nothing security-related",
			cfg:      Config{Auth: AuthConfig{Secret: "x"}, DB: DBConfig{SSLMode: "require"}, Citadel: CitadelConfig{APIURL: "https://citadel"}, ThreatFlow: ThreatFlowConfig{APIURL: "https://tf"}},
			wantNone: []string{"AUTH_SECRET", "DEV_MODE", "SSL_MODE"},
		},
		{
			name:     "empty secret warns",
			cfg:      Config{Auth: AuthConfig{Secret: ""}},
			wantSubs: []string{"VERTGUARD_AUTH_SECRET is empty"},
		},
		{
			name:     "dev mode warns",
			cfg:      Config{Auth: AuthConfig{Secret: "x", DevMode: true}},
			wantSubs: []string{"VERTGUARD_AUTH_DEV_MODE is true"},
		},
		{
			name:     "secret rotation in progress warns",
			cfg:      Config{Auth: AuthConfig{Secret: "x", SecretNext: "n"}},
			wantSubs: []string{"SECRET_NEXT is set"},
		},
		{
			name:     "ssl disable warns",
			cfg:      Config{Auth: AuthConfig{Secret: "x"}, DB: DBConfig{SSLMode: "disable"}},
			wantSubs: []string{"DB_SSL_MODE is 'disable'"},
		},
		{
			name:     "ml enabled without grpc url warns",
			cfg:      Config{Auth: AuthConfig{Secret: "x"}, ML: MLConfig{Enabled: true, GRPCURL: ""}},
			wantSubs: []string{"ML_ENABLED is true but"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warns := tt.cfg.WarnIfInsecure()
			joined := strings.Join(warns, "\n")
			for _, sub := range tt.wantSubs {
				if !strings.Contains(joined, sub) {
					t.Errorf("warnings %v missing expected substring %q", warns, sub)
				}
			}
			for _, sub := range tt.wantNone {
				if strings.Contains(joined, sub) {
					t.Errorf("warnings %v unexpectedly contain %q", warns, sub)
				}
			}
		})
	}
}

func TestLoad_Defaults(t *testing.T) {
	withCleanEnvVars(t,
		"VERTGUARD_CONFIG_PATH", "VERTGUARD_SERVER_PORT", "VERTGUARD_AUTH_SECRET",
		"VERTGUARD_CITADEL_HMAC_SECRETS", "VERTGUARD_CITADEL_KEY_IDS", "VERTGUARD_IOC_ALLOWLIST",
		"VERTGUARD_PROMPT_RULES_PATH", "VERTGUARD_PROMPT_ML_BINARY", "VERTGUARD_PROMPT_ML_TIMEOUT",
		"VERTGUARD_MEETING_ZOOM_CLIENT_ID", "VERTGUARD_MEETING_TEAMS_CLIENT_ID", "VERTGUARD_MEETING_WEBEX_CLIENT_ID",
	)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Server.Port != 8091 {
		t.Errorf("Server.Port = %d, want default 8091", cfg.Server.Port)
	}
	if cfg.Prompt.MaxInputSize != promptMaxInputSizeDefault {
		t.Errorf("Prompt.MaxInputSize = %d, want default %d (ApplyDefaults should have run)", cfg.Prompt.MaxInputSize, promptMaxInputSizeDefault)
	}
	if len(cfg.Meetings) != 3 {
		t.Fatalf("len(Meetings) = %d, want 3 (zoom, teams, webex always appended)", len(cfg.Meetings))
	}
	for _, m := range cfg.Meetings {
		if m.Enabled {
			t.Errorf("meeting platform %v Enabled=true with no client ID set", m.Platform)
		}
	}
}

func TestLoad_EnvOverridesAndCSVSplitting(t *testing.T) {
	withCleanEnvVars(t, "VERTGUARD_CONFIG_PATH")

	t.Setenv("VERTGUARD_SERVER_PORT", "9999")
	t.Setenv("VERTGUARD_CITADEL_HMAC_SECRETS", "primary, next ,previous")
	t.Setenv("VERTGUARD_CITADEL_KEY_IDS", "k1,k2")
	t.Setenv("VERTGUARD_IOC_ALLOWLIST", "10.0.0.0/8, example.com")
	t.Setenv("VERTGUARD_PROMPT_RULES_PATH", "/custom/rules.json")
	t.Setenv("VERTGUARD_PROMPT_ML_BINARY", "/custom/ml-bin")
	t.Setenv("VERTGUARD_PROMPT_ML_TIMEOUT", "3s")
	t.Setenv("VERTGUARD_MEETING_ZOOM_CLIENT_ID", "zoom-id")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Server.Port != 9999 {
		t.Errorf("Server.Port = %d, want 9999 from env override", cfg.Server.Port)
	}
	wantSecrets := []string{"primary", "next", "previous"}
	if len(cfg.Citadel.HMACSecrets) != 3 {
		t.Fatalf("Citadel.HMACSecrets = %v, want %v", cfg.Citadel.HMACSecrets, wantSecrets)
	}
	for i, s := range wantSecrets {
		if cfg.Citadel.HMACSecrets[i] != s {
			t.Errorf("HMACSecrets[%d] = %q, want %q", i, cfg.Citadel.HMACSecrets[i], s)
		}
	}
	if len(cfg.Citadel.KeyIDs) != 2 || cfg.Citadel.KeyIDs[0] != "k1" {
		t.Errorf("Citadel.KeyIDs = %v, want [k1 k2]", cfg.Citadel.KeyIDs)
	}
	if len(cfg.IOC.Allowlist) != 2 || cfg.IOC.Allowlist[1] != "example.com" {
		t.Errorf("IOC.Allowlist = %v, want [10.0.0.0/8 example.com]", cfg.IOC.Allowlist)
	}
	if cfg.Prompt.RulePackPath != "/custom/rules.json" {
		t.Errorf("Prompt.RulePackPath = %q, want /custom/rules.json", cfg.Prompt.RulePackPath)
	}
	if cfg.Prompt.MLBinaryPath != "/custom/ml-bin" {
		t.Errorf("Prompt.MLBinaryPath = %q, want /custom/ml-bin", cfg.Prompt.MLBinaryPath)
	}
	if cfg.Prompt.MLTimeout != 3*time.Second {
		t.Errorf("Prompt.MLTimeout = %v, want 3s", cfg.Prompt.MLTimeout)
	}

	foundZoom := false
	for _, m := range cfg.Meetings {
		if m.ClientID == "zoom-id" {
			foundZoom = true
			if !m.Enabled {
				t.Error("zoom meeting platform should be Enabled when ClientID is set")
			}
		}
	}
	if !foundZoom {
		t.Error("expected a meeting platform entry with ClientID=zoom-id")
	}
}

func TestLoad_InvalidPromptConfigRejected(t *testing.T) {
	withCleanEnvVars(t, "VERTGUARD_CONFIG_PATH")
	// clean_threshold > block_threshold must be rejected by Load() via
	// Prompt.Validate() after ApplyDefaults normalises the rest.
	t.Setenv("VERTGUARD_PROMPT_CLEAN_THRESHOLD", "0.9")
	t.Setenv("VERTGUARD_PROMPT_BLOCK_THRESHOLD", "0.1")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want error for inverted prompt thresholds")
	}
	if !strings.Contains(err.Error(), "validate prompt config") {
		t.Errorf("error = %v, want it to be wrapped as \"validate prompt config\"", err)
	}
}

func TestLoad_InvalidConfigPath(t *testing.T) {
	withCleanEnvVars(t)
	t.Setenv("VERTGUARD_CONFIG_PATH", "/this/path/does/not/exist.yaml")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want error for missing config file")
	}
	if !strings.Contains(err.Error(), "read config") {
		t.Errorf("error = %v, want it to be wrapped as \"read config\"", err)
	}
}

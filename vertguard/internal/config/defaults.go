package config

import (
	"strings"
	"time"

	"github.com/spf13/viper"
)

// envReplacer maps nested config keys ("server.port") to env-var
// suffix format ("SERVER_PORT"), so VERTGUARD_SERVER_PORT → server.port.
func envReplacer() *strings.Replacer {
	return strings.NewReplacer(".", "_")
}

// setDefaults populates sane default values before env overrides apply.
func setDefaults(v *viper.Viper) {
	// Server
	v.SetDefault("server.port", 8091)
	v.SetDefault("server.dashboard_port", 3009)
	v.SetDefault("server.log_level", "info")
	v.SetDefault("server.read_timeout", 30*time.Second)
	v.SetDefault("server.write_timeout", 30*time.Second)
	v.SetDefault("server.drain_grace", 5*time.Second)

	// Database
	v.SetDefault("db.host", "localhost")
	v.SetDefault("db.port", 5438)
	v.SetDefault("db.name", "vertguard")
	v.SetDefault("db.user", "vertguard")
	v.SetDefault("db.ssl_mode", "disable")
	v.SetDefault("db.max_open_conns", 25)

	// Auth
	v.SetDefault("auth.token_ttl", 8*time.Hour)
	v.SetDefault("auth.issuer", "vertguard")
	v.SetDefault("auth.dev_mode", false)
	v.SetDefault("auth.sinauth_url", "http://localhost:8100")

	// CITADEL
	v.SetDefault("citadel.dry_run", false)
	v.SetDefault("citadel.queue_max", 10000)
	// Multi-slot rotation defaults: empty slices so viper's env handling
	// treats VERTGUARD_CITADEL_HMAC_SECRETS / VERTGUARD_CITADEL_KEY_IDS
	// as comma-separated string lists rather than single values.
	v.SetDefault("citadel.hmac_secrets", []string{})
	v.SetDefault("citadel.key_ids", []string{})

	// DB pool floor — keep zero so the db pkg can derive a default from
	// MaxConns when not explicitly overridden.
	v.SetDefault("db.min_conns", 0)

	// Prompt injection (Module 3)
	v.SetDefault("prompt.clean_threshold", 0.3)
	v.SetDefault("prompt.block_threshold", 0.7)
	v.SetDefault("prompt.max_input_size", int64(1048576)) // 1 MiB
	v.SetDefault("prompt.pattern_registry_path", "/etc/vertguard/patterns/")
	v.SetDefault("prompt.rule_pack_path", "")
	v.SetDefault("prompt.ml_binary_path", "")
	v.SetDefault("prompt.ml_timeout", 2*time.Second)
	v.SetDefault("prompt.max_input_bytes", 0)

	// Threat feed (Module 4)
	v.SetDefault("threatfeed.sources_path", "/etc/vertguard/sources.yaml")
	v.SetDefault("threatfeed.atlas_sync_cron", "0 0 * * 0")
	v.SetDefault("threatfeed.community_sync_cron", "0 6 * * *")
	v.SetDefault("threatfeed.push_interval", 15*time.Minute)
	v.SetDefault("threatfeed.reconcile_cron", "0 4 * * *")
	v.SetDefault("threatfeed.min_confidence", 0.5)

	// Media (Module 1 — C2PA in Phase 4.2)
	v.SetDefault("media.binary_path", "/usr/local/bin/c2pa-verify")
	v.SetDefault("media.timeout", 10*time.Second)
	v.SetDefault("media.c2pa_truststore", "/etc/vertguard/c2pa-truststore")
	v.SetDefault("media.c2pa_ocsp_enabled", false)
	v.SetDefault("media.max_size", int64(104857600)) // 100 MiB
	v.SetDefault("media.content_retention", false)
	v.SetDefault("media.trust_anchors_dir", "")
	v.SetDefault("media.revocation_list_path", "")
	v.SetDefault("media.reload_interval", 60*time.Second)
	v.SetDefault("media.require_trust", false)

	// Module 5 (Phase 4.2 — rule-based phishing v1)
	v.SetDefault("phishing.enabled", false)
	v.SetDefault("phishing.clean_threshold", 0.3)
	v.SetDefault("phishing.block_threshold", 0.7)
	v.SetDefault("phishing.max_input_size", int64(1048576)) // 1 MiB

	// Module 6 (Phase 4.3 — Identity Verification, rule-based v1)
	v.SetDefault("identity.enabled", false)
	v.SetDefault("identity.realtime_enabled", false)
	v.SetDefault("identity.clean_threshold", 0.3)
	v.SetDefault("identity.block_threshold", 0.7)
	v.SetDefault("identity.max_input_size", int64(65536)) // 64 KiB
	v.SetDefault("identity.replay_window", 10*time.Minute)
	v.SetDefault("identity.replay_threshold", 5)

	// ML (Phase 4.2+)
	v.SetDefault("ml.grpc_url", "localhost:50051")
	v.SetDefault("ml.models_path", "/var/lib/vertguard/models/")
	v.SetDefault("ml.gpu_enabled", false)
	v.SetDefault("ml.max_batch_size", 16)
	v.SetDefault("ml.enabled", false)
	v.SetDefault("ml.timeout", 1*time.Second)
	v.SetDefault("ml.always_score", false)

	// IOC store (VG-006)
	v.SetDefault("ioc.enabled", false)
	v.SetDefault("ioc.interval", 1*time.Hour)
	v.SetDefault("ioc.sweep_interval", 1*time.Hour)
	v.SetDefault("ioc.allowlist", []string{})
	v.SetDefault("ioc.abusech_enabled", false)

	// Webhook outbound dispatcher (VG-015)
	v.SetDefault("webhook.enabled", false)
	v.SetDefault("webhook.max_retries", 3)
	v.SetDefault("webhook.backoff_base", 200*time.Millisecond)
	v.SetDefault("webhook.outbox_flush_interval", 5*time.Second)
	v.SetDefault("webhook.request_timeout", 5*time.Second)
	// Aliases so the documented env vars map onto the config keys above.
	_ = v.BindEnv("webhook.request_timeout", "VERTGUARD_WEBHOOK_TIMEOUT")
	_ = v.BindEnv("webhook.outbox_flush_interval", "VERTGUARD_WEBHOOK_OUTBOX_INTERVAL")
	_ = v.BindEnv("webhook.enabled", "VERTGUARD_WEBHOOK_ENABLED")
}

package config

import (
	"strings"
	"time"

	"github.com/spf13/viper"
)

// envReplacer maps "server.port" → "SERVER_PORT" so CYBERPATH_SERVER_PORT
// resolves to server.port.
func envReplacer() *strings.Replacer {
	return strings.NewReplacer(".", "_")
}

// setDefaults populates sane defaults before env overrides apply.
func setDefaults(v *viper.Viper) {
	// Server
	v.SetDefault("server.http_addr", ":8086")
	v.SetDefault("server.web_port", 3006)
	v.SetDefault("server.log_level", "info")
	v.SetDefault("server.read_timeout", 30*time.Second)
	v.SetDefault("server.write_timeout", 30*time.Second)
	v.SetDefault("server.request_id_header", "X-Request-Id")
	v.SetDefault("server.drain_grace", 5*time.Second)

	// DB
	v.SetDefault("db.host", "localhost")
	v.SetDefault("db.port", 5439)
	v.SetDefault("db.name", "cyberpath")
	v.SetDefault("db.user", "cyberpath")
	v.SetDefault("db.ssl_mode", "require")
	v.SetDefault("db.max_open_conns", 25)
	v.SetDefault("db.migrate_on_boot", true)

	// Auth
	v.SetDefault("auth.token_ttl", 8*time.Hour)
	v.SetDefault("auth.issuer", "cyberpath")
	v.SetDefault("auth.dev_mode", false)
	// auth.pepper / auth.pepper_previous default to "" — the password
	// hasher falls back to no-pepper mode in dev. Production gating
	// should require auth.pepper via Validate (CYBERPATH_AUTH_PEPPER /
	// CYBERPATH_AUTH_PEPPER_PREVIOUS).
	v.SetDefault("auth.pepper", "")
	v.SetDefault("auth.pepper_previous", "")
	// sinauth RS256 SSO — env CYBERPATH_AUTH_SINAUTH_URL.
	v.SetDefault("auth.sinauth_url", "http://localhost:8100")

	// Citadel
	v.SetDefault("citadel.dry_run", false)
	v.SetDefault("citadel.enabled", false)

	// Sandbox
	v.SetDefault("sandbox.runtime", "docker")
	v.SetDefault("sandbox.cpu_quota", "1.0")
	v.SetDefault("sandbox.memory_mib", 512)
	v.SetDefault("sandbox.network", "none")

	// Content
	v.SetDefault("content.path", "/var/lib/cyberpath/content")

	// I18n
	v.SetDefault("i18n.locales", []string{"sq", "en"})
	v.SetDefault("i18n.default", "sq")

	// Cert
	v.SetDefault("cert.issuer_name", "CyberPath")

	// Observability
	v.SetDefault("observability.metrics_enabled", true)
	v.SetDefault("observability.tracing_enabled", false)
}

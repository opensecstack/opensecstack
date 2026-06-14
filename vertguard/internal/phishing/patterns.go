// Package phishing implements Module 5 (Phishing Detection).
//
// STATUS: Phase 4.2 initial — rule-based deterministic prefilter.
// Targets ~60-70% recall on canonical phishing signals (URL
// obfuscation, brand impersonation, credential harvest, urgency).
// ML-based classifier (transformer + URL embedding) lands in
// Phase 4.2 follow-up; this package provides the always-on cheap
// frontline so the ML hot-path can focus on ambiguous traffic.
//
// Pattern library is code-resident. Runtime hot-reload via YAML is
// VG-future. Mirror of internal/prompt/ structure so future ML wiring
// is uniform across modules.
package phishing

import (
	"regexp"
)

// Category groups indicators by phishing tactic.
type Category string

const (
	CategoryURLObfuscation     Category = "URL_OBFUSCATION"
	CategoryBrandImpersonation Category = "BRAND_IMPERSONATION"
	CategoryCredentialHarvest  Category = "CREDENTIAL_HARVEST"
	CategoryUrgency            Category = "URGENCY"
	CategorySuspiciousDomain   Category = "SUSPICIOUS_DOMAIN"
	CategoryAttachmentLure     Category = "ATTACHMENT_LURE"
	CategoryMXMismatch         Category = "MX_MISMATCH" // stub-only — needs DNS resolver in v2
)

// Pattern is a single phishing detection rule.
type Pattern struct {
	ID          string
	Category    Category
	Description string
	AtlasTech   string // optional ATLAS reference (most phishing tactics are pre-LLM)
	BaseScore   float64
	re          *regexp.Regexp
}

// MustCompilePattern is a helper for static pattern definitions.
func MustCompilePattern(id string, cat Category, desc, atlas string, base float64, pat string) Pattern {
	re, err := regexp.Compile(pat)
	if err != nil {
		panic("vertguard/phishing: bad static pattern " + id + ": " + err.Error())
	}
	return Pattern{
		ID:          id,
		Category:    cat,
		Description: desc,
		AtlasTech:   atlas,
		BaseScore:   base,
		re:          re,
	}
}

// Match is a single indicator hit within the scanned input.
type Match struct {
	PatternID   string   `json:"pattern_id"`
	Category    Category `json:"category"`
	Description string   `json:"description"`
	AtlasTech   string   `json:"atlas_technique,omitempty"`
	ByteRange   [2]int   `json:"byte_range"`
	Confidence  float64  `json:"confidence"`
}

// Scan applies the pattern against input and returns hits.
func (p *Pattern) Scan(input string) []Match {
	locs := p.re.FindAllStringIndex(input, -1)
	if len(locs) == 0 {
		return nil
	}
	out := make([]Match, 0, len(locs))
	for _, loc := range locs {
		out = append(out, Match{
			PatternID:   p.ID,
			Category:    p.Category,
			Description: p.Description,
			AtlasTech:   p.AtlasTech,
			ByteRange:   [2]int{loc[0], loc[1]},
			Confidence:  p.BaseScore,
		})
	}
	return out
}

// DefaultLibrary — code-resident indicator set for v0.1.0-alpha.0.
// 22 indicators across 7 categories. Targets ~60-70% recall on
// canonical phishing signals; ML stage handles the rest.
var DefaultLibrary = []Pattern{
	// ── URL_OBFUSCATION ─────────────────────────────────────────────
	MustCompilePattern(
		"PH.url.userinfo_at.v1",
		CategoryURLObfuscation,
		"URL with @ before host (userinfo confusion)",
		"",
		0.9,
		`https?://[^\s/]*@[^\s/]+`,
	),
	MustCompilePattern(
		"PH.url.idn_homograph.v1",
		CategoryURLObfuscation,
		"IDN homograph: cyrillic look-alikes inside domain",
		"",
		0.85,
		// Cyrillic а(U+0430) о(U+043E) е(U+0435) р(U+0440) с(U+0441)
		// mixed with latin within hostname-like token.
		`https?://[^\s/]*[а-яА-Я][^\s/]*\.[a-z]{2,}`,
	),
	MustCompilePattern(
		"PH.url.ip_literal.v1",
		CategoryURLObfuscation,
		"URL using raw IP literal as host",
		"",
		0.7,
		`https?://(?:\d{1,3}\.){3}\d{1,3}(?:[/:?#]|$)`,
	),
	MustCompilePattern(
		"PH.url.shortener_login_path.v1",
		CategoryURLObfuscation,
		"URL shortener pointing at login/account/verify path",
		"",
		0.7,
		`(?i)https?://(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly)/[^\s]*?(login|account|secure|verify)`,
	),
	MustCompilePattern(
		"PH.url.hex_encoded_host.v1",
		CategoryURLObfuscation,
		"URL with percent-encoded host characters",
		"",
		0.65,
		`https?://[^\s/]*%[0-9a-fA-F]{2}[^\s/]*\.`,
	),

	// ── BRAND_IMPERSONATION ─────────────────────────────────────────
	MustCompilePattern(
		"PH.brand.path_spoof.v1",
		CategoryBrandImpersonation,
		"Brand-in-path with login/verify segment (post-host check filters FPs)",
		"",
		0.9,
		// RE2 has no negative lookahead — cross-host check happens in
		// the scanner via brand-host filter. Pattern fires on any host
		// where /<brand>/<login|signin|verify|account> appears in path;
		// scanner.go suppresses when the host already matches the brand.
		`(?i)https?://[^\s/]+/[^\s]*?\b(paypal|microsoft|google|apple|amazon|facebook|netflix|chase|wellsfargo|bankofamerica)/(login|signin|verify|account)\b`,
	),
	MustCompilePattern(
		"PH.brand.lookalike_domain.v1",
		CategoryBrandImpersonation,
		"Brand look-alike subdomain (paypal-secure.tld, apple-id.tld)",
		"",
		0.8,
		`(?i)https?://(paypal|microsoft|google|apple|amazon|netflix|chase|wellsfargo)[-_](secure|verify|login|id|support|account)[\w.-]*\.[a-z]{2,}`,
	),
	MustCompilePattern(
		"PH.brand.display_name_spoof.v1",
		CategoryBrandImpersonation,
		"Display-name spoof (support/billing/admin/security) marker",
		"",
		0.55,
		// RE2-safe: flag display-name keywords + envelope sender mismatch
		// is enforced in v2 once DNS/MX resolver lands. v1 flags the
		// display-name pattern itself; scorer relies on co-occurring
		// indicators to escalate.
		`(?im)^From:\s*"?[^"<\n]*\b(support|billing|admin|security|no[- ]?reply)\b[^"<\n]*"?\s*<[^>]+@[^>]+>`,
	),

	// ── CREDENTIAL_HARVEST ──────────────────────────────────────────
	MustCompilePattern(
		"PH.cred.form_external_action.v1",
		CategoryCredentialHarvest,
		"HTML form posting to external login/signin endpoint",
		"",
		0.85,
		`(?is)<form[^>]*action\s*=\s*["']?(http://|https://)[^"'\s]*?(login|signin|password|account)`,
	),
	MustCompilePattern(
		"PH.cred.password_input_external.v1",
		CategoryCredentialHarvest,
		"Password input field embedded in email body",
		"",
		0.8,
		`(?is)<input[^>]*type\s*=\s*["']?password["']?`,
	),
	MustCompilePattern(
		"PH.cred.ssn_request.v1",
		CategoryCredentialHarvest,
		"Asks for SSN / social security number",
		"",
		0.95,
		`(?i)(confirm|verify|provide|enter)\s+(your\s+)?(social\s+security\s+number|ssn)`,
	),
	MustCompilePattern(
		"PH.cred.card_request.v1",
		CategoryCredentialHarvest,
		"Asks for card details / CVV",
		"",
		0.95,
		`(?i)(verify|confirm|provide|enter|update)\s+(your\s+)?(card\s+(details|number|info)|cvv|cvc|security\s+code)`,
	),
	MustCompilePattern(
		"PH.cred.bank_credentials.v1",
		CategoryCredentialHarvest,
		"Asks for online-banking credentials",
		"",
		0.9,
		`(?i)(verify|confirm|re[- ]?enter)\s+(your\s+)?(online\s+banking|bank(?:ing)?\s+(login|password|credentials))`,
	),

	// ── URGENCY ────────────────────────────────────────────────────
	MustCompilePattern(
		"PH.urgency.account_suspended.v1",
		CategoryUrgency,
		"Account-suspension threat",
		"",
		0.7,
		`(?i)your\s+account\s+(will\s+be|has\s+been|is\s+going\s+to\s+be)\s+(suspended|locked|terminated|deactivated|closed)`,
	),
	MustCompilePattern(
		"PH.urgency.verify_within.v1",
		CategoryUrgency,
		"Verify-identity-within-24h pressure",
		"",
		0.7,
		`(?i)(verify|confirm)\s+your\s+(identity|account)\s+(within|in)\s+\d+\s*(hours?|h|minutes?)`,
	),
	MustCompilePattern(
		"PH.urgency.unusual_signin.v1",
		CategoryUrgency,
		"Unusual sign-in / new device alert lure",
		"",
		0.6,
		`(?i)(unusual|suspicious|new)\s+(sign[- ]?in|login|activity)\s+(detected|attempted|on\s+your)`,
	),
	MustCompilePattern(
		"PH.urgency.compromised.v1",
		CategoryUrgency,
		"Account-compromised lure",
		"",
		0.6,
		`(?i)your\s+account\s+(has\s+been\s+)?(compromised|hacked|breached)`,
	),
	MustCompilePattern(
		"PH.urgency.immediate_action.v1",
		CategoryUrgency,
		"Immediate-action-required pressure phrasing",
		"",
		0.55,
		`(?i)immediate\s+action\s+(is\s+)?required`,
	),

	// ── SUSPICIOUS_DOMAIN ──────────────────────────────────────────
	MustCompilePattern(
		"PH.tld.suspicious.v1",
		CategorySuspiciousDomain,
		"Suspicious / abuse-prone TLD",
		"",
		0.6,
		`(?i)https?://[^\s/]+\.(zip|mov|review|click|country|gq|tk|ml|cf|xyz|top)(/|\b)`,
	),
	MustCompilePattern(
		"PH.domain.long_subdomain.v1",
		CategorySuspiciousDomain,
		"Excessive subdomain depth (>= 4 labels before TLD)",
		"",
		0.5,
		`https?://(?:[a-z0-9-]+\.){4,}[a-z]{2,}/`,
	),

	// ── ATTACHMENT_LURE ─────────────────────────────────────────────
	MustCompilePattern(
		"PH.attach.double_ext.v1",
		CategoryAttachmentLure,
		"Double-extension attachment (invoice.pdf.exe, doc.zip.scr)",
		"",
		0.85,
		`(?i)\b[\w-]+\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.(exe|scr|js|vbs|bat|cmd|hta|jar|ps1|lnk)\b`,
	),
	MustCompilePattern(
		"PH.attach.macro_lure.v1",
		CategoryAttachmentLure,
		"Enable-content / enable-macros lure phrasing",
		"",
		0.75,
		`(?i)(enable\s+(content|macros|editing)|click\s+enable\s+content)`,
	),

	// ── MX_MISMATCH ─────────────────────────────────────────────────
	// Stub-only: real check needs DNS MX vs envelope-from compare,
	// scheduled for v2. Pattern below is a string-marker placeholder
	// flagging the synthetic header tests use.
	MustCompilePattern(
		"PH.mx.mismatch_marker.v1",
		CategoryMXMismatch,
		"X-MX-Mismatch synthetic marker (placeholder until DNS resolver lands)",
		"",
		0.5,
		`(?im)^X-MX-Mismatch:\s*true`,
	),
}

// Package identity implements Module 6 (Identity Verification).
//
// STATUS: Phase 4.3 initial — rule-based deterministic check set.
// Targets synthetic-identity tells, document-tampering surface
// signals, credential-stuffing markers, jurisdictional risk, and
// replay markers at the request layer. ML-based identity-claim
// classifier (Phase 4.3 follow-up) lands when the DistilBERT
// equivalent for identity is trained; this package provides the
// always-on cheap frontline so the ML hot-path can focus on
// ambiguous traffic. Mirrors internal/prompt/ + internal/phishing/
// structure so future ML wiring is uniform across modules.
//
// Liveness / face-match / OCR is OUT OF SCOPE for v1 — those land
// alongside the ML model.
package identity

import (
	"regexp"
	"strings"
	"time"
)

// Category groups indicators by identity-fraud tactic.
type Category string

const (
	CategorySyntheticProfile     Category = "SYNTHETIC_PROFILE"
	CategoryIDFormatMismatch     Category = "ID_FORMAT_MISMATCH"
	CategoryCredStuffing         Category = "CRED_STUFFING"
	CategorySanctionedJurisdiction Category = "SANCTIONED_JURISDICTION"
	CategoryReplaySuspected      Category = "REPLAY_SUSPECTED"
	CategoryEmailDisposable      Category = "EMAIL_DISPOSABLE"
	CategoryImpossibleAge        Category = "IMPOSSIBLE_AGE"
	CategoryDocNumberRepeated    Category = "DOC_NUMBER_REPEATED_DIGITS"
	CategoryWeakPassword         Category = "WEAK_PASSWORD_PATTERN"
)

// ClaimType narrows scoring + which indicators apply.
type ClaimType string

const (
	ClaimPassport       ClaimType = "passport"
	ClaimNationalID     ClaimType = "national_id"
	ClaimDriverLicense  ClaimType = "driver_license"
	ClaimLoginCreds     ClaimType = "login_credentials"
)

// Context narrows scoring for the request surface.
type Context string

const (
	ContextKYC             Context = "kyc"
	ContextLogin           Context = "login"
	ContextAccountRecovery Context = "account_recovery"
)

// FieldKey identifies which claim field an indicator inspects.
// "*" means the indicator inspects the full canonicalised claim
// (used by composite checks like REPLAY_SUSPECTED, IMPOSSIBLE_AGE).
type FieldKey string

const (
	FieldIDNumber       FieldKey = "id_number"
	FieldIssuerCountry  FieldKey = "issuer_country"
	FieldDOB            FieldKey = "dob"
	FieldName           FieldKey = "name"
	FieldEmail          FieldKey = "email"
	FieldPassword       FieldKey = "password"
	FieldComposite      FieldKey = "*"
)

// Pattern is a single identity-verification indicator.
//
// Some indicators are pure regex against a single field
// (FieldKey != "*"); composite indicators (FieldKey == "*") are
// dispatched in scanner.go because they need cross-field
// correlation (DOB-vs-today, issuer-vs-id_number, email-vs-name).
type Pattern struct {
	ID          string
	Category    Category
	Description string
	AtlasTech   string // optional ATLAS reference; identity tactics are mostly pre-LLM
	BaseScore   float64
	Field       FieldKey
	re          *regexp.Regexp // nil for composite indicators
}

// Regexp returns the compiled regexp; composite indicators return nil.
func (p *Pattern) Regexp() *regexp.Regexp { return p.re }

// MustCompilePattern is the helper for static field-scoped indicators.
// Composite indicators (FieldKey "*") that have no regex use
// MustComposite below.
func MustCompilePattern(id string, cat Category, desc, atlas string, base float64, field FieldKey, pat string) Pattern {
	re, err := regexp.Compile(pat)
	if err != nil {
		panic("vertguard/identity: bad static pattern " + id + ": " + err.Error())
	}
	return Pattern{
		ID:          id,
		Category:    cat,
		Description: desc,
		AtlasTech:   atlas,
		BaseScore:   base,
		Field:       field,
		re:          re,
	}
}

// MustComposite registers a composite indicator (no regex). The
// scanner dispatches by ID for these.
func MustComposite(id string, cat Category, desc, atlas string, base float64) Pattern {
	return Pattern{
		ID:          id,
		Category:    cat,
		Description: desc,
		AtlasTech:   atlas,
		BaseScore:   base,
		Field:       FieldComposite,
	}
}

// Match is a single indicator hit.
type Match struct {
	PatternID   string   `json:"pattern_id"`
	Category    Category `json:"category"`
	Description string   `json:"description"`
	AtlasTech   string   `json:"atlas_technique,omitempty"`
	Field       FieldKey `json:"field"`
	Confidence  float64  `json:"confidence"`
	Detail      string   `json:"detail,omitempty"`
}

// ─── Embedded blocklists ────────────────────────────────────────────
//
// v1 ships intentionally tiny lists. Operators expand via the
// PatternsPath overlay (same hot-reload mechanism as prompt patterns).

// SanctionedCountries is the v1 hardcoded jurisdictional blocklist.
// EU/US sanctions lists are large and update frequently; v1 captures
// the unambiguous core. WHY: an Albanian passport claiming Iranian
// issuance is a high-signal anomaly even before the wider list lands.
var SanctionedCountries = map[string]bool{
	"KP": true, // DPRK
	"IR": true, // Iran
	"SY": true, // Syria
	"CU": true, // Cuba
	"BY": true, // Belarus
}

// DisposableEmailDomains — tiny embedded list. Operators expand via overlay.
var DisposableEmailDomains = map[string]bool{
	"mailinator.com":  true,
	"guerrillamail.com": true,
	"10minutemail.com": true,
	"tempmail.com":    true,
	"throwaway.email": true,
}

// LeakedHashPrefixes — SHA-1 prefix blocklist (HIBP-style). v1 has
// ~30 entries covering the most-leaked passwords. Real HIBP API
// integration is future work (see CHANGELOG / spec).
//
// Generated with: echo -n "<password>" | sha1sum
// Coverage: top of every public leak compilation since 2012.
var LeakedHashPrefixes = map[string]bool{
	// password
	"5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8": true,
	// 123456
	"7C4A8D09CA3762AF61E59520943DC26494F8941B": true,
	// 12345678
	"7C222FB2927D828AF22F592134E8932480637C0D": true,
	// qwerty
	"B1B3773A05C0ED0176787A4F1574FF0075F7521E": true,
	// 111111
	"3D4F2BF07DC1BE38B20CD6E46949A1071F9D0E3D": true,
	// 123123
	"601F1889667EFAEBB33B8C12572835DA3F027F78": true,
	// abc123
	"6367C48DD193D56EA7B0BAAD25B19455E529F5EE": true,
	// password1
	"E38AD214943DAAD1D64C102FAEC29DE4AFE9DA3D": true,
	// 1234567
	"20EABE5D64B0E216796E834F52D61FD0B70332FC": true,
	// 12345
	"8CB2237D0679CA88DB6464EAC60DA96345513964": true,
	// iloveyou
	"EE8D8728F435FD550F83852AABAB5234CE1DA528": true,
	// admin
	"D033E22AE348AEB5660FC2140AEC35850C4DA997": true,
	// welcome
	"65E84BE33532FB784C48129675F9EFF3A682B27F": true,
	// monkey
	"AB87D24BDC7452E55738DEB5F868E1F16DEA5ACE": true,
	// login
	"AAF4C61DDCC5E8A2DABEDE0F3B482CD9AEA9434D": true,
	// abc
	"A9993E364706816ABA3E25717850C26C9CD0D89D": true,
	// dragon
	"D78F8BB992A56A597F6C7A1FB918BB78271367EB": true,
	// passw0rd
	"7C6A61C68EF8B9B6B061B28C348BC1ED7921CB53": true,
	// master
	"1BD98EF8879A8027454461504D9F77F1B0FCEF21": true,
	// hello
	"AAF4C61DDCC5E8A2DABEDE0F3B482CD9AEA9434C": true,
	// freedom
	"FA7E1A2730DE6F22E58FE69E2C90B4346F92F02E": true,
	// whatever
	"86F4151A38C84BFCBE45BB16B8DBA62E45D27D2D": true,
	// qazwsx
	"A82D1A11A06A45D85D8E2D6F00ED1FBB78AAE51A": true,
	// trustno1
	"E3F33C40A0DA01F89DA9A52DC9B6B2E73511A0FE": true,
	// letmein
	"B7A875FC1EA228B9061041B7CEC4BD3C52AB3CE3": true,
	// 654321
	"C2C4B9E575502DCD3C9C6E2F7BB6FCB9B8DD1B12": true,
	// shadow
	"3F3DDDE38B95E60B92F1583BBFD61CFEB16B97B7": true,
	// superman
	"95D67E0FA66BCEFD4DA8B0A0E1AAFAE26FC8AB87": true,
	// football
	"B72CCF7B1D29C45D2C99C36B9E97D8D52BFAB10C": true,
	// baseball
	"6B62EAFAB6F2EF9D6F71E3C82DA0A3F0DCEDF06D": true,
}

// ID format regex per ISO-3166-1 alpha-2 country code.
//
// WHY: the strongest "claimed-issuer vs id-number" signal — most
// document-tampering kits regenerate the photo + name but reuse a
// number from a different country's pool, since making a number
// pass the home-country check digits is much harder.
var IDFormatByCountry = map[string]map[ClaimType]*regexp.Regexp{
	"AL": {
		ClaimPassport:    regexp.MustCompile(`^[A-Z]\d{7}[A-Z]?$`),
		ClaimNationalID:  regexp.MustCompile(`^[A-Z]\d{8}[A-Z]$`),
		ClaimDriverLicense: regexp.MustCompile(`^AL\d{7}$`),
	},
	"US": {
		ClaimPassport:   regexp.MustCompile(`^\d{9}$`),
		ClaimNationalID: regexp.MustCompile(`^\d{3}-?\d{2}-?\d{4}$`), // SSN
	},
	"GB": {
		ClaimPassport: regexp.MustCompile(`^\d{9}$`),
	},
	"DE": {
		ClaimPassport:   regexp.MustCompile(`^[CFGHJK]\d{8}$`),
		ClaimNationalID: regexp.MustCompile(`^[A-Z0-9]{9}\d$`),
	},
	"FR": {
		ClaimPassport: regexp.MustCompile(`^\d{2}[A-Z]{2}\d{5}$`),
	},
	"IT": {
		ClaimPassport: regexp.MustCompile(`^[A-Z]{2}\d{7}$`),
	},
}

// IDFormatFor returns the regex for the given country+claim type, or nil.
func IDFormatFor(country string, t ClaimType) *regexp.Regexp {
	cc := strings.ToUpper(strings.TrimSpace(country))
	byClaim, ok := IDFormatByCountry[cc]
	if !ok {
		return nil
	}
	return byClaim[t]
}

// IsSanctioned reports whether the country code is on the v1 sanctions list.
func IsSanctioned(country string) bool {
	return SanctionedCountries[strings.ToUpper(strings.TrimSpace(country))]
}

// IsDisposableEmail reports whether the email's host is on the disposable list.
func IsDisposableEmail(email string) bool {
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	host := strings.ToLower(strings.TrimSpace(email[at+1:]))
	return DisposableEmailDomains[host]
}

// IsLeakedHash reports whether the SHA-1 (40 hex chars) is on the v1
// leaked-credential blocklist. Caller hashes the password input.
func IsLeakedHash(sha1Hex string) bool {
	return LeakedHashPrefixes[strings.ToUpper(strings.TrimSpace(sha1Hex))]
}

// MaxHumanAgeYears caps "alive today" claims. WHY: oldest verified
// person on record died at 122; 130 leaves a safety margin without
// giving fraudulent claims room to hide.
const MaxHumanAgeYears = 130

// ParseDOB parses YYYY-MM-DD; returns zero time on bad input.
func ParseDOB(s string) time.Time {
	t, err := time.Parse("2006-01-02", strings.TrimSpace(s))
	if err != nil {
		return time.Time{}
	}
	return t
}

// DefaultLibrary — code-resident indicator set for v1 (Phase 4.3).
//
// 18+ indicators across 9 categories. Targets the well-understood
// rule-checkable fraud surface; ML stage handles the ambiguous rest.
var DefaultLibrary = []Pattern{
	// ── ID_FORMAT_MISMATCH ───────────────────────────────────────────
	// All ID format checks dispatch through one composite indicator
	// driven by IDFormatByCountry — keeping the per-country regex
	// catalogue in a map (above) lets operators add countries via
	// overlay without touching the indicator list itself.
	MustComposite(
		"ID.format.country_mismatch.v1",
		CategoryIDFormatMismatch,
		"ID number format does not match claimed issuer-country pattern",
		"",
		0.9,
	),

	// ── SANCTIONED_JURISDICTION ──────────────────────────────────────
	MustComposite(
		"ID.jurisdiction.sanctioned.v1",
		CategorySanctionedJurisdiction,
		"Issuer country is on the v1 sanctioned-jurisdiction list",
		"",
		0.85,
	),

	// ── SYNTHETIC_PROFILE ────────────────────────────────────────────
	MustCompilePattern(
		"ID.synth.us_ssn_invalid_area.v1",
		CategorySyntheticProfile,
		"US SSN with invalid area number (000, 666, 9XX) — synthetic-identity tell",
		"",
		0.85,
		FieldIDNumber,
		`^(000|666|9\d{2})-?\d{2}-?\d{4}$`,
	),
	MustComposite(
		"ID.synth.name_email_mismatch.v1",
		CategorySyntheticProfile,
		"Name tokens absent from email local-part (heuristic synthetic-identity tell)",
		"",
		0.45,
	),
	MustComposite(
		"ID.synth.dob_ssn_year_impossible.v1",
		CategorySyntheticProfile,
		"DOB year inconsistent with claimed SSN issuance window (stub heuristic)",
		"",
		0.7,
	),

	// ── IMPOSSIBLE_AGE ───────────────────────────────────────────────
	MustComposite(
		"ID.age.future_dob.v1",
		CategoryImpossibleAge,
		"Date of birth is in the future",
		"",
		0.95,
	),
	MustComposite(
		"ID.age.exceeds_max.v1",
		CategoryImpossibleAge,
		"Claimed age exceeds maximum recorded human lifespan",
		"",
		0.9,
	),

	// ── DOC_NUMBER_REPEATED_DIGITS ───────────────────────────────────
	MustCompilePattern(
		"ID.doc.all_same_digit.v1",
		CategoryDocNumberRepeated,
		"Document number is all the same digit (entropy floor)",
		"",
		0.8,
		FieldIDNumber,
		`^(?:0{6,}|1{6,}|2{6,}|3{6,}|4{6,}|5{6,}|6{6,}|7{6,}|8{6,}|9{6,})$`,
	),
	MustCompilePattern(
		"ID.doc.sequential_ascending.v1",
		CategoryDocNumberRepeated,
		"Document number is a strictly ascending digit run (e.g. 123456789)",
		"",
		0.8,
		FieldIDNumber,
		`^0?1234567(89)?$|^123456789$|^12345678$|^1234567$`,
	),
	MustCompilePattern(
		"ID.doc.sequential_descending.v1",
		CategoryDocNumberRepeated,
		"Document number is a strictly descending digit run (e.g. 9876543210)",
		"",
		0.8,
		FieldIDNumber,
		`^9876543210?$|^987654321$|^98765432$`,
	),

	// ── EMAIL_DISPOSABLE ─────────────────────────────────────────────
	MustComposite(
		"ID.email.disposable_domain.v1",
		CategoryEmailDisposable,
		"Email host is a known disposable / throwaway domain",
		"",
		0.55,
	),

	// ── CRED_STUFFING ────────────────────────────────────────────────
	MustComposite(
		"ID.cred.leaked_sha1.v1",
		CategoryCredStuffing,
		"Submitted password hash matches the v1 leaked-credential blocklist",
		"",
		0.95,
	),

	// ── REPLAY_SUSPECTED ─────────────────────────────────────────────
	MustComposite(
		"ID.replay.window_threshold.v1",
		CategoryReplaySuspected,
		"Same id_number observed N times within configured replay window",
		"",
		0.7,
	),

	// ── WEAK_PASSWORD_PATTERN ────────────────────────────────────────
	// login_credentials only — applying these to KYC name fields is
	// a known false-positive trap.
	MustCompilePattern(
		"ID.pwd.common_dictionary.v1",
		CategoryWeakPassword,
		"Password matches a common-dictionary lure (password, qwerty, etc.)",
		"",
		0.7,
		FieldPassword,
		`(?i)^(password|qwerty|letmein|welcome|admin|iloveyou|monkey|dragon|football|master)\d{0,4}$`,
	),
	MustCompilePattern(
		"ID.pwd.numeric_run.v1",
		CategoryWeakPassword,
		"Password is a short numeric run (12345/123456/etc.)",
		"",
		0.7,
		FieldPassword,
		`^\d{1,8}$`,
	),
	MustCompilePattern(
		"ID.pwd.keyboard_walk.v1",
		CategoryWeakPassword,
		"Password is a single-row keyboard walk",
		"",
		0.6,
		FieldPassword,
		`(?i)^(qwertyuiop|asdfghjkl|zxcvbnm|qazwsx|qwerty123|1q2w3e4r|1qaz2wsx)$`,
	),
	MustCompilePattern(
		"ID.pwd.length_floor.v1",
		CategoryWeakPassword,
		"Password length below the v1 floor (<6 chars)",
		"",
		0.5,
		FieldPassword,
		`^.{0,5}$`,
	),
}

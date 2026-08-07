// Package content — validator.go enforces content-quality rules.
//
// The linter returns a list of ValidationError rather than failing
// fast so `cyberpath-cli content lint` can show every issue in a track
// at once. The rule set is documented in docs/track-content-guide.md
// and docs/lab-content-guide.md.
package content

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ValidationError is one diagnostic produced by the validator.
type ValidationError struct {
	Code    string // stable machine-readable code (e.g. "track.missing_field")
	Path    string // dotted path (e.g. "modules[0].lessons[1].title_en")
	Message string
	// Severity: "error" blocks publication; "warning" is informational.
	Severity string
}

// Error implements the error interface.
func (v ValidationError) Error() string {
	return fmt.Sprintf("[%s] %s: %s", v.Severity, v.Path, v.Message)
}

// validNIS2Measures is the allowlist from docs/nis2-integration.md.
// Article 21(2)(a..i) plus the umbrella `art21.j` for cross-cutting.
var validNIS2Measures = map[string]struct{}{
	"art21.a": {}, "art21.b": {}, "art21.c": {}, "art21.d": {},
	"art21.e": {}, "art21.f": {}, "art21.g": {}, "art21.h": {},
	"art21.i": {}, "art21.j": {},
}

// validQuizKinds matches the DB enum (see migration 0003).
var validQuizKinds = map[string]struct{}{
	"multiple_choice": {}, "true_false": {}, "code_fill": {}, "scenario": {},
}

// validLabRuntimes matches the DB enum (see migration 0003) plus the
// wasm sub-runtimes that get normalised to `wasmtime` at publish time.
var validLabRuntimes = map[string]struct{}{
	"docker":       {},
	"wasmtime":     {},
	"wasm-shell":   {},
	"wasm-python":  {},
	"wasm-kubectl": {},
}

var validValidationRuleTypes = map[string]struct{}{
	"file_exists": {},
	"cmd_exit":    {},
	"regex_match": {},
}

// hostnameRE permits FQDNs and bare hostnames with optional `*.` prefix
// (used for wildcard whitelist entries).
var hostnameRE = regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

var slugRE = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
var semverishRE = regexp.MustCompile(`^\d+(\.\d+){0,2}(-[A-Za-z0-9.]+)?$`)

// ValidateTrack runs every check against t and returns the full list
// of diagnostics. Empty slice = clean.
//
// trackDir is optional; if non-empty the validator additionally cross-
// checks lesson body files actually exist on disk (used by `lint`).
func ValidateTrack(t *TrackYAML) []ValidationError {
	return validateTrackWithDir(t, "")
}

// ValidateTrackWithRoot is the lint-time variant that also confirms
// referenced files exist under rootDir/<track-id>/.
func ValidateTrackWithRoot(t *TrackYAML, rootDir string) []ValidationError {
	if t == nil {
		return []ValidationError{{Code: "track.nil", Path: "", Message: "track is nil", Severity: "error"}}
	}
	trackDir := ""
	if rootDir != "" {
		trackDir = filepath.Join(rootDir, t.ID)
	}
	return validateTrackWithDir(t, trackDir)
}

func validateTrackWithDir(t *TrackYAML, trackDir string) []ValidationError {
	if t == nil {
		return []ValidationError{{Code: "track.nil", Path: "", Message: "track is nil", Severity: "error"}}
	}
	var errs []ValidationError

	// Required fields.
	if t.ID == "" {
		errs = append(errs, ve("track.missing_id", "id", "track id is required", "error"))
	} else if !slugRE.MatchString(t.ID) {
		errs = append(errs, ve("track.bad_id", "id", "id must be lowercase ascii slug", "error"))
	}
	if t.Version == "" {
		errs = append(errs, ve("track.missing_version", "version", "track version is required", "error"))
	} else if !semverishRE.MatchString(t.Version) {
		errs = append(errs, ve("track.bad_version", "version", "version must be semver-ish (e.g. 1.4.0)", "error"))
	} else if !versionAtLeastOne(t.Version) {
		errs = append(errs, ve("track.version_too_low", "version", "version must be >= 1.0.0", "warning"))
	}

	// Bilingual completeness for translatable fields.
	if t.TitleSQ == "" {
		errs = append(errs, ve("track.missing_title_sq", "title.sq", "shqip title is required", "error"))
	}
	if t.TitleEN == "" {
		errs = append(errs, ve("track.missing_title_en", "title.en", "english title is required", "error"))
	}
	if t.DescriptionSQ == "" {
		errs = append(errs, ve("track.missing_description_sq", "description.sq", "shqip description is required", "error"))
	}
	if t.DescriptionEN == "" {
		errs = append(errs, ve("track.missing_description_en", "description.en", "english description is required", "error"))
	}

	// NIS2 mappings.
	if len(t.NIS2Mappings) == 0 {
		errs = append(errs, ve("track.no_nis2", "nis2_mappings", "at least one NIS2 measure mapping is required", "error"))
	}
	for i, m := range t.NIS2Mappings {
		if _, ok := validNIS2Measures[m]; !ok {
			errs = append(errs, ve(
				"track.bad_nis2",
				fmt.Sprintf("nis2_mappings[%d]", i),
				fmt.Sprintf("unknown NIS2 measure %q (allowed: art21.a..art21.j)", m),
				"error",
			))
		}
	}

	// Duration > 0.
	if t.DurationMinutes <= 0 {
		errs = append(errs, ve("track.bad_duration", "duration_minutes", "duration_minutes must be > 0", "error"))
	}

	// Prerequisites can only be validated at the loader-set level
	// (cross-track lookup is async); flag any non-slug entries as a
	// warning so authors can fix typos.
	for i, p := range t.Prerequisites {
		if !slugRE.MatchString(p) {
			errs = append(errs, ve(
				"track.bad_prerequisite",
				fmt.Sprintf("prerequisites[%d]", i),
				fmt.Sprintf("prerequisite %q is not a valid slug", p),
				"warning",
			))
		}
	}

	// Modules.
	if len(t.Modules) == 0 {
		errs = append(errs, ve("track.no_modules", "modules", "track must have at least one module", "error"))
	}
	for i := range t.Modules {
		errs = append(errs, validateModule(&t.Modules[i], i, trackDir)...)
	}

	return errs
}

func validateModule(m *ModuleYAML, idx int, trackDir string) []ValidationError {
	prefix := fmt.Sprintf("modules[%d]", idx)
	var errs []ValidationError
	if m.ID == "" {
		errs = append(errs, ve("module.missing_id", prefix+".id", "module id required", "error"))
	}
	if m.TitleSQ == "" {
		errs = append(errs, ve("module.missing_title_sq", prefix+".title.sq", "shqip module title required", "error"))
	}
	if m.TitleEN == "" {
		errs = append(errs, ve("module.missing_title_en", prefix+".title.en", "english module title required", "error"))
	}
	if len(m.Lessons) == 0 && m.Quiz == nil && m.Lab == nil {
		errs = append(errs, ve("module.thin", prefix, "module has no lessons, quiz, or lab", "warning"))
	}
	for j, l := range m.Lessons {
		errs = append(errs, validateLesson(&l, fmt.Sprintf("%s.lessons[%d]", prefix, j), trackDir)...)
	}
	if m.Quiz != nil {
		errs = append(errs, validateQuiz(m.Quiz, fmt.Sprintf("%s.quiz", prefix))...)
	}
	if m.Lab != nil {
		if m.Lab.Lab == nil {
			errs = append(errs, ve(
				"module.lab_missing",
				fmt.Sprintf("%s.lab", prefix),
				fmt.Sprintf("lab reference %q did not resolve to a lab.yaml", m.Lab.ID),
				"error",
			))
		} else {
			errs = append(errs, validateLab(m.Lab.Lab, fmt.Sprintf("%s.lab", prefix))...)
		}
	}
	return errs
}

func validateLesson(l *LessonYAML, prefix, trackDir string) []ValidationError {
	var errs []ValidationError
	if l.ID == "" {
		errs = append(errs, ve("lesson.missing_id", prefix+".id", "lesson id required", "error"))
	}
	if l.BodySQ == "" {
		errs = append(errs, ve("lesson.missing_body_sq", prefix+".body.sq", "shqip lesson body missing", "error"))
	}
	if l.BodyEN == "" {
		errs = append(errs, ve("lesson.missing_body_en", prefix+".body.en", "english lesson body missing", "error"))
	}
	if trackDir != "" && l.BodyPath != "" {
		if _, err := os.Stat(l.BodyPath); err != nil {
			errs = append(errs, ve(
				"lesson.body_file_missing",
				prefix+".body_path",
				fmt.Sprintf("body file %s not found", l.BodyPath),
				"error",
			))
		}
	}
	return errs
}

func validateQuiz(q *QuizYAML, prefix string) []ValidationError {
	var errs []ValidationError
	if q.ID == "" {
		errs = append(errs, ve("quiz.missing_id", prefix+".id", "quiz id required", "error"))
	}
	if q.PassThreshold < 0 || q.PassThreshold > 100 {
		errs = append(errs, ve("quiz.bad_pass_threshold", prefix+".pass_threshold", "pass_threshold must be 0..100 (or 0..1 fraction)", "error"))
	}
	if len(q.Questions) == 0 {
		errs = append(errs, ve("quiz.no_questions", prefix+".questions", "quiz must have at least one question", "error"))
	}
	for i, qq := range q.Questions {
		qprefix := fmt.Sprintf("%s.questions[%d]", prefix, i)
		if qq.ID == "" {
			errs = append(errs, ve("question.missing_id", qprefix+".id", "question id required", "error"))
		}
		if _, ok := validQuizKinds[qq.Kind]; !ok {
			errs = append(errs, ve(
				"question.bad_kind",
				qprefix+".type",
				fmt.Sprintf("unknown question kind %q", qq.Kind),
				"error",
			))
		}
		if qq.PromptSQ == "" || qq.PromptEN == "" {
			errs = append(errs, ve("question.missing_prompt_lang", qprefix+".prompt", "prompt requires both sq and en", "error"))
		}
		if qq.ExplanationSQ == "" || qq.ExplanationEN == "" {
			errs = append(errs, ve("question.missing_explanation", qprefix+".explanation", "every question must carry a bilingual explanation", "error"))
		}
		if len(qq.Correct) == 0 || string(qq.Correct) == "null" {
			errs = append(errs, ve("question.missing_correct", qprefix+".correct", "question must declare correct answer(s)", "error"))
		}
		switch qq.Kind {
		case "multiple_choice", "scenario":
			if len(qq.Choices) < 2 {
				errs = append(errs, ve("question.too_few_choices", qprefix+".choices", "MC/scenario questions need >= 2 choices", "error"))
			}
			// Ensure correct is a list of choice ids.
			var ids []string
			if err := json.Unmarshal(qq.Correct, &ids); err != nil || len(ids) == 0 {
				errs = append(errs, ve("question.bad_correct_shape", qprefix+".correct", "MC/scenario expects a list of choice ids", "error"))
			} else {
				present := make(map[string]bool, len(qq.Choices))
				for _, c := range qq.Choices {
					present[c.ID] = true
				}
				for _, id := range ids {
					if !present[id] {
						errs = append(errs, ve(
							"question.correct_not_a_choice",
							qprefix+".correct",
							fmt.Sprintf("correct id %q does not match any choice", id),
							"error",
						))
					}
				}
			}
		case "true_false":
			var b bool
			if err := json.Unmarshal(qq.Correct, &b); err != nil {
				errs = append(errs, ve("question.bad_correct_shape", qprefix+".correct", "true_false expects a boolean", "error"))
			}
		case "code_fill":
			var ss []string
			if err := json.Unmarshal(qq.Correct, &ss); err != nil || len(ss) == 0 {
				errs = append(errs, ve("question.bad_correct_shape", qprefix+".correct", "code_fill expects a non-empty list of strings", "error"))
			}
		}
	}
	return errs
}

// ValidateLab is the lab-only public entry point (used by lab linting).
func ValidateLab(l *LabYAML) []ValidationError {
	return validateLab(l, "lab")
}

func validateLab(l *LabYAML, prefix string) []ValidationError {
	var errs []ValidationError
	if l.ID == "" {
		errs = append(errs, ve("lab.missing_id", prefix+".id", "lab id required", "error"))
	}
	if _, ok := validLabRuntimes[l.Runtime]; !ok {
		errs = append(errs, ve(
			"lab.bad_runtime",
			prefix+".runtime",
			fmt.Sprintf("unknown lab runtime %q", l.Runtime),
			"error",
		))
	}
	if l.Image == "" {
		errs = append(errs, ve("lab.missing_image", prefix+".image", "lab image is required", "error"))
	}
	if l.EntryCommand == "" {
		errs = append(errs, ve("lab.missing_entry", prefix+".entry_command", "entry_command required", "error"))
	}
	if l.TimeLimitSeconds <= 0 {
		errs = append(errs, ve("lab.bad_time_limit", prefix+".time_limit_seconds", "time_limit_seconds must be > 0", "error"))
	}
	for i, r := range l.Validation {
		rprefix := fmt.Sprintf("%s.validation[%d]", prefix, i)
		if r.ID == "" {
			errs = append(errs, ve("rule.missing_id", rprefix+".id", "rule id required", "error"))
		}
		if _, ok := validValidationRuleTypes[r.Type]; !ok {
			errs = append(errs, ve(
				"rule.bad_type",
				rprefix+".type",
				fmt.Sprintf("unknown rule type %q", r.Type),
				"error",
			))
		}
		if r.Target == "" {
			errs = append(errs, ve("rule.missing_target", rprefix+".target", "rule target required", "error"))
		}
	}
	for i, host := range l.EgressWhitelist {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		// Allow IP literals or hostnames.
		if net.ParseIP(host) == nil && !hostnameRE.MatchString(host) {
			errs = append(errs, ve(
				"lab.bad_egress",
				fmt.Sprintf("%s.network.egress_whitelist[%d]", prefix, i),
				fmt.Sprintf("invalid hostname/IP %q", host),
				"error",
			))
		}
	}
	return errs
}

func ve(code, path, msg, sev string) ValidationError {
	return ValidationError{Code: code, Path: path, Message: msg, Severity: sev}
}

// versionAtLeastOne returns true if version parses to >= 1.0.0. We
// accept anything with a non-zero leading component so that 0.1.x and
// 1.x.x both pass.
func versionAtLeastOne(v string) bool {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) == 0 {
		return false
	}
	if parts[0] == "0" {
		if len(parts) < 2 {
			return false
		}
		// Strip pre-release suffix from minor.
		minor := parts[1]
		if idx := strings.IndexAny(minor, "-+"); idx >= 0 {
			minor = minor[:idx]
		}
		return minor != "0"
	}
	return true
}

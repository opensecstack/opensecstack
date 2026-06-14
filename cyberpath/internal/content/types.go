// Package content materialises track / module / lesson / quiz / lab
// YAML content from disk into the runtime + content_versions tables.
//
// Layout on disk (see docs/architecture.md, docs/track-content-guide.md):
//
//	content/<track-id>/track.yaml
//	content/<track-id>/lessons/<lesson-id>.{sq,en}.md
//	content/<track-id>/quizzes/<quiz-id>.yaml
//	content/<track-id>/labs/<lab-id>/lab.yaml
//
// Types in this file mirror the YAML schemas exactly. The struct shape
// is the contract between authors (writing YAML) and the platform
// (reading + hashing + storing).
package content

import "encoding/json"

// TrackYAML is the parsed representation of `track.yaml`.
//
// Bilingual fields carry both `sq` (canonical authoring language) and
// `en` (maintained translation). NIS2Mappings holds Article 21 measure
// IDs (e.g. "art21.g") — see docs/nis2-integration.md for the full
// allowlist; validator.go enforces it.
type TrackYAML struct {
	ID              string             `yaml:"id" json:"id"`
	Version         string             `yaml:"version" json:"version"`
	TitleSQ         string             `yaml:"-" json:"title_sq"`
	TitleEN         string             `yaml:"-" json:"title_en"`
	Title           BilingualText      `yaml:"title" json:"-"`
	DescriptionSQ   string             `yaml:"-" json:"description_sq"`
	DescriptionEN   string             `yaml:"-" json:"description_en"`
	Description     BilingualText      `yaml:"description" json:"-"`
	Audience        []string           `yaml:"audience" json:"audience"`
	NIS2Mappings    []string           `yaml:"-" json:"nis2_mappings"`
	NIS2Raw         NIS2MappingsYAML   `yaml:"nis2_mappings" json:"-"`
	Prerequisites   []string           `yaml:"prerequisites" json:"prerequisites"`
	DurationMinutes int                `yaml:"duration_minutes" json:"duration_minutes"`
	LanguageSource  string             `yaml:"language_source" json:"language_source"`
	Modules         []ModuleYAML       `yaml:"modules" json:"modules"`
	Certification   CertificationSpec  `yaml:"certification" json:"certification"`
	ContentHash     string             `yaml:"content_hash" json:"content_hash"`
	Changelog       []ChangelogEntryYAML `yaml:"changelog" json:"changelog,omitempty"`
}

// BilingualText is the on-disk shape of `{ sq: "...", en: "..." }`.
type BilingualText struct {
	SQ string `yaml:"sq" json:"sq"`
	EN string `yaml:"en" json:"en"`
}

// NIS2MappingsYAML decodes the on-disk shape:
//
//	nis2_mappings:
//	  primary: art21.g
//	  secondary: [art21.i]
//
// validator.go flattens these into TrackYAML.NIS2Mappings.
type NIS2MappingsYAML struct {
	Primary   string   `yaml:"primary"`
	Secondary []string `yaml:"secondary"`
}

// ChangelogEntryYAML is one row from `track.yaml.changelog`.
type ChangelogEntryYAML struct {
	Version  string   `yaml:"version" json:"version"`
	Date     string   `yaml:"date" json:"date"`
	Breaking bool     `yaml:"breaking" json:"breaking"`
	Changes  []string `yaml:"changes" json:"changes"`
}

// ModuleYAML is one entry inside `track.yaml.modules`.
//
// Lesson slugs are resolved by the loader against `lessons/<slug>.{sq,en}.md`
// and the resulting body markdown is folded into LessonYAML.BodyMarkdown.
// Quiz / Lab are referenced by slug; loader.LoadTrack resolves them.
type ModuleYAML struct {
	ID         string       `yaml:"id" json:"id"`
	Order      int          `yaml:"order" json:"order"`
	TitleSQ    string       `yaml:"-" json:"title_sq"`
	TitleEN    string       `yaml:"-" json:"title_en"`
	Title      BilingualText `yaml:"title" json:"-"`
	LessonRefs []string     `yaml:"lessons" json:"-"`
	Lessons    []LessonYAML `yaml:"-" json:"lessons"`
	QuizRef    string       `yaml:"quiz" json:"-"`
	Quiz       *QuizYAML    `yaml:"-" json:"quiz,omitempty"`
	LabRef     string       `yaml:"lab" json:"-"`
	Lab        *LabRef      `yaml:"-" json:"lab,omitempty"`
}

// LessonYAML is the parsed lesson markdown frontmatter + body.
//
// Lessons live as paired markdown files (`<id>.sq.md`, `<id>.en.md`) and
// share a frontmatter shape. The loader populates BodySQ / BodyEN from
// disk; BodyPath retains the on-disk path for diagnostics.
type LessonYAML struct {
	ID               string `yaml:"id" json:"id"`
	Order            int    `yaml:"order" json:"order"`
	TitleSQ          string `yaml:"-" json:"title_sq"`
	TitleEN          string `yaml:"-" json:"title_en"`
	BodyPath         string `yaml:"-" json:"body_path"`
	BodySQ           string `yaml:"-" json:"body_sq"`
	BodyEN           string `yaml:"-" json:"body_en"`
	VideoURL         string `yaml:"video" json:"video_url"`
	EstimatedMinutes int    `yaml:"duration_minutes" json:"estimated_minutes"`
}

// LessonFrontmatter is decoded from the YAML block at the top of
// `<id>.<lang>.md`. Internal to loader.go but exported so that callers
// can re-use the decoder.
type LessonFrontmatter struct {
	ID              string `yaml:"id"`
	Order           int    `yaml:"order"`
	DurationMinutes int    `yaml:"duration_minutes"`
	Title           string `yaml:"title"`
	Video           string `yaml:"video"`
	VideoCaption    string `yaml:"video_caption"`
}

// QuizYAML is the parsed `quizzes/<id>.yaml`.
type QuizYAML struct {
	ID               string         `yaml:"id" json:"id"`
	TitleSQ          string         `yaml:"-" json:"title_sq"`
	TitleEN          string         `yaml:"-" json:"title_en"`
	Title            BilingualText  `yaml:"title" json:"-"`
	Randomise        bool           `yaml:"randomise" json:"randomise"`
	RandomiseChoices bool           `yaml:"randomise_choices" json:"randomise_choices"`
	// PassThreshold accepts either an integer percentage (0..100) or a
	// fractional 0..1 form per docs/track-content-guide.md. Loader
	// normalises it to integer-percentage on the way in.
	PassThreshold    int            `yaml:"-" json:"pass_threshold"`
	PassThresholdRaw float64        `yaml:"pass_threshold" json:"-"`
	TimeLimitSeconds *int           `yaml:"time_limit_seconds" json:"time_limit_seconds,omitempty"`
	Questions        []QuestionYAML `yaml:"questions" json:"questions"`
}

// QuestionYAML is one entry inside `quiz.questions`. Correct's shape
// varies by Kind (list of choice ids, boolean, list of strings); we
// keep it as a json.RawMessage so canonical hashing can serialise it
// unchanged and validator.go can decode per-kind.
type QuestionYAML struct {
	ID            string          `yaml:"id" json:"id"`
	Kind          string          `yaml:"type" json:"kind"`
	PromptSQ      string          `yaml:"-" json:"prompt_sq"`
	PromptEN      string          `yaml:"-" json:"prompt_en"`
	Prompt        BilingualText   `yaml:"prompt" json:"-"`
	Choices       []Choice        `yaml:"choices" json:"choices,omitempty"`
	Correct       json.RawMessage `yaml:"-" json:"correct"`
	CorrectAny    interface{}     `yaml:"correct" json:"-"`
	Template      string          `yaml:"template" json:"template,omitempty"`
	ExplanationSQ string          `yaml:"-" json:"explanation_sq"`
	ExplanationEN string          `yaml:"-" json:"explanation_en"`
	Explanation   BilingualText   `yaml:"explanation" json:"-"`
	Points        int             `yaml:"points" json:"points"`
}

// Choice is one option inside a multiple-choice / scenario question.
type Choice struct {
	ID      string        `yaml:"id" json:"id"`
	TextSQ  string        `yaml:"-" json:"text_sq"`
	TextEN  string        `yaml:"-" json:"text_en"`
	Text    BilingualText `yaml:"text" json:"-"`
}

// CertificationSpec is the `track.yaml.certification` block.
type CertificationSpec struct {
	Offered             bool   `yaml:"offered" json:"offered"`
	Level               string `yaml:"level" json:"level"`
	ExpiresAfterMonths  int    `yaml:"expires_after_months" json:"expires_after_months"`
}

// LabRef is the in-track reference to a lab. The actual lab body lives
// at content/<track>/labs/<id>/lab.yaml and is loaded into LabYAML.
type LabRef struct {
	ID  string   `yaml:"id" json:"id"`
	Lab *LabYAML `yaml:"-" json:"lab,omitempty"`
}

// LabYAML is `labs/<id>/lab.yaml`. Schema in docs/lab-content-guide.md.
type LabYAML struct {
	ID               string           `yaml:"id" json:"id"`
	Version          string           `yaml:"version" json:"version"`
	Runtime          string           `yaml:"runtime" json:"runtime"`
	Image            string           `yaml:"image" json:"image"`
	EntryCommand     string           `yaml:"entry_command" json:"entry_command"`
	Assets           []Asset          `yaml:"assets" json:"assets"`
	Validation       []ValidationRule `yaml:"validation" json:"validation"`
	TimeLimitSeconds int              `yaml:"time_limit_seconds" json:"time_limit_seconds"`
	Network          NetworkSpec      `yaml:"network" json:"-"`
	EgressWhitelist  []string         `yaml:"-" json:"egress_whitelist"`
	SuccessCriteria  SuccessCriteria  `yaml:"success_criteria" json:"success_criteria"`
	Hints            []Hint           `yaml:"hints" json:"hints"`
	ContentHash      string           `yaml:"content_hash" json:"content_hash"`
}

// NetworkSpec mirrors the on-disk `network:` block.
type NetworkSpec struct {
	EgressWhitelist []string `yaml:"egress_whitelist"`
}

// SuccessCriteria is `lab.yaml.success_criteria`.
type SuccessCriteria struct {
	MinScore      int      `yaml:"min_score" json:"min_score"`
	RequiredRules []string `yaml:"required_rules" json:"required_rules"`
}

// Asset is one entry in `lab.yaml.assets`. Exactly one of Content
// (inline, "@./..." packed at build) or ContentURL (fetched at session
// start) is set.
type Asset struct {
	Path       string `yaml:"path" json:"path"`
	Content    string `yaml:"content" json:"content,omitempty"`
	ContentURL string `yaml:"url" json:"url,omitempty"`
	SHA256     string `yaml:"sha256" json:"sha256,omitempty"`
}

// ValidationRule is one entry in `lab.yaml.validation`.
type ValidationRule struct {
	ID         string        `yaml:"id" json:"id"`
	Type       string        `yaml:"type" json:"type"`
	Target     string        `yaml:"target" json:"target"`
	Expected   interface{}   `yaml:"expected" json:"expected,omitempty"`
	Weight     int           `yaml:"weight" json:"weight"`
	Diagnostic BilingualText `yaml:"diagnostic" json:"diagnostic"`
}

// Hint is one entry in `lab.yaml.hints`.
type Hint struct {
	Trigger string        `yaml:"trigger" json:"trigger"`
	TextSQ  string        `yaml:"-" json:"text_sq"`
	TextEN  string        `yaml:"-" json:"text_en"`
	Text    BilingualText `yaml:"text" json:"-"`
}

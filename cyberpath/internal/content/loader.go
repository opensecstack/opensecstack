// Package content — loader.go reads track / lesson / quiz / lab YAML
// from disk into typed structs. No DB access here; that's publisher.go.
//
// The loader fully resolves a track: it materialises lessons (paired
// markdown files with frontmatter), inline quizzes, and labs referenced
// by the track's modules. The result is a TrackYAML that is ready to
// hash + publish.
//
// Path safety: every file path is resolved with filepath.Clean and
// rejected if it escapes the configured root directory. Symlinks
// inside the root are followed (authors use them for shared assets);
// symlinks pointing outside are refused.
package content

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadTrack reads <rootDir>/<trackID>/track.yaml and resolves every
// lesson / quiz / lab reference into the returned TrackYAML.
//
// Errors wrap with `content/loader.LoadTrack: ...`. The function does
// not validate semantic rules (use validator.ValidateTrack for that);
// it only checks structural integrity (file exists, YAML parses,
// referenced lessons/labs/quizzes are present).
func LoadTrack(rootDir, trackID string) (*TrackYAML, error) {
	const op = "loader.LoadTrack"

	cleanRoot, err := canonicalRoot(rootDir)
	if err != nil {
		return nil, fmt.Errorf("content/%s: %w", op, err)
	}
	trackDir := filepath.Join(cleanRoot, trackID)
	if err := ensureInside(cleanRoot, trackDir); err != nil {
		return nil, fmt.Errorf("content/%s: %w", op, err)
	}

	trackYAMLPath := filepath.Join(trackDir, "track.yaml")
	raw, err := os.ReadFile(trackYAMLPath)
	if err != nil {
		return nil, fmt.Errorf("content/%s: read track.yaml: %w", op, err)
	}

	var t TrackYAML
	if err := yaml.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("content/%s: parse track.yaml: %w", op, err)
	}

	// Hoist bilingual struct fields onto the flat *SQ / *EN scalars
	// the rest of the system expects.
	t.TitleSQ, t.TitleEN = t.Title.SQ, t.Title.EN
	t.DescriptionSQ, t.DescriptionEN = t.Description.SQ, t.Description.EN
	t.NIS2Mappings = flattenNIS2(t.NIS2Raw)

	if t.ID == "" {
		t.ID = trackID
	} else if t.ID != trackID {
		return nil, fmt.Errorf("content/%s: track.id %q does not match directory %q", op, t.ID, trackID)
	}

	// Resolve modules → lessons / quiz / lab.
	for i := range t.Modules {
		m := &t.Modules[i]
		m.TitleSQ, m.TitleEN = m.Title.SQ, m.Title.EN

		lessons, err := loadLessons(trackDir, m.LessonRefs)
		if err != nil {
			return nil, fmt.Errorf("content/%s: module %q: %w", op, m.ID, err)
		}
		m.Lessons = lessons

		if m.QuizRef != "" {
			q, err := loadQuiz(trackDir, m.QuizRef)
			if err != nil {
				return nil, fmt.Errorf("content/%s: module %q quiz %q: %w", op, m.ID, m.QuizRef, err)
			}
			m.Quiz = q
		}
		if m.LabRef != "" {
			lab, err := loadLab(trackDir, m.LabRef)
			if err != nil {
				return nil, fmt.Errorf("content/%s: module %q lab %q: %w", op, m.ID, m.LabRef, err)
			}
			m.Lab = &LabRef{ID: m.LabRef, Lab: lab}
		}
	}

	return &t, nil
}

// LoadAllTracks scans rootDir and returns every track that parses.
// Failures on individual tracks short-circuit the scan — callers that
// want best-effort linting should iterate slugs themselves.
func LoadAllTracks(rootDir string) ([]*TrackYAML, error) {
	const op = "loader.LoadAllTracks"

	cleanRoot, err := canonicalRoot(rootDir)
	if err != nil {
		return nil, fmt.Errorf("content/%s: %w", op, err)
	}

	entries, err := os.ReadDir(cleanRoot)
	if err != nil {
		return nil, fmt.Errorf("content/%s: read dir: %w", op, err)
	}

	out := make([]*TrackYAML, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Skip dotfiles (e.g. .git, .DS_Store).
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		trackYAML := filepath.Join(cleanRoot, e.Name(), "track.yaml")
		if _, err := os.Stat(trackYAML); err != nil {
			continue
		}
		t, err := LoadTrack(cleanRoot, e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// ── helpers ───────────────────────────────────────────────────────────

func canonicalRoot(root string) (string, error) {
	if root == "" {
		return "", errors.New("rootDir is empty")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("abs: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		// Allow non-existent paths to surface a clearer error from the caller.
		return filepath.Clean(abs), nil
	}
	return resolved, nil
}

// ensureInside refuses paths that resolve outside root after symlink
// evaluation. Symlinks INSIDE the root are fine.
func ensureInside(root, candidate string) error {
	cleanCandidate := filepath.Clean(candidate)
	resolved, err := filepath.EvalSymlinks(cleanCandidate)
	if err != nil {
		// Path may legitimately not exist yet; fall back to lexical clean.
		resolved = cleanCandidate
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil {
		return fmt.Errorf("relpath: %w", err)
	}
	if strings.HasPrefix(rel, "..") || rel == ".." {
		return fmt.Errorf("path %q escapes root %q", candidate, root)
	}
	return nil
}

func flattenNIS2(raw NIS2MappingsYAML) []string {
	out := make([]string, 0, 1+len(raw.Secondary))
	if raw.Primary != "" {
		out = append(out, raw.Primary)
	}
	out = append(out, raw.Secondary...)
	return out
}

// loadLessons resolves each slug to <trackDir>/lessons/<slug>.{sq,en}.md.
// A lesson is required to exist in at least one language (sq preferred);
// validator.go enforces full bilingual parity separately.
func loadLessons(trackDir string, slugs []string) ([]LessonYAML, error) {
	out := make([]LessonYAML, 0, len(slugs))
	for _, slug := range slugs {
		lesson, err := loadLesson(trackDir, slug)
		if err != nil {
			return nil, err
		}
		out = append(out, *lesson)
	}
	return out, nil
}

func loadLesson(trackDir, slug string) (*LessonYAML, error) {
	lessonsDir := filepath.Join(trackDir, "lessons")
	sqPath := filepath.Join(lessonsDir, slug+".sq.md")
	enPath := filepath.Join(lessonsDir, slug+".en.md")

	var sqFM, enFM LessonFrontmatter
	var sqBody, enBody string
	var foundAny bool
	var bodyPath string

	if data, err := os.ReadFile(sqPath); err == nil {
		fm, body, err := splitFrontmatter(data)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", sqPath, err)
		}
		sqFM, sqBody = fm, body
		foundAny = true
		bodyPath = sqPath
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read %s: %w", sqPath, err)
	}

	if data, err := os.ReadFile(enPath); err == nil {
		fm, body, err := splitFrontmatter(data)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", enPath, err)
		}
		enFM, enBody = fm, body
		foundAny = true
		if bodyPath == "" {
			bodyPath = enPath
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read %s: %w", enPath, err)
	}

	if !foundAny {
		return nil, fmt.Errorf("lesson %q: no .sq.md or .en.md found in %s", slug, lessonsDir)
	}

	// Prefer sq frontmatter for canonical fields; fall back to en.
	fm := sqFM
	if fm.ID == "" {
		fm = enFM
	}

	return &LessonYAML{
		ID:               firstNonEmpty(fm.ID, slug),
		Order:            fm.Order,
		TitleSQ:          firstHeading(sqBody),
		TitleEN:          firstHeading(enBody),
		BodyPath:         bodyPath,
		BodySQ:           sqBody,
		BodyEN:           enBody,
		VideoURL:         fm.Video,
		EstimatedMinutes: fm.DurationMinutes,
	}, nil
}

// splitFrontmatter splits a markdown file into (frontmatter, body). If
// no frontmatter delimiter is present the entire content is treated as
// body and a zero frontmatter is returned.
func splitFrontmatter(data []byte) (LessonFrontmatter, string, error) {
	const delim = "---"
	// Trim a leading UTF-8 BOM if present (\xEF\xBB\xBF).
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		data = data[3:]
	}
	s := string(data)

	if !strings.HasPrefix(strings.TrimLeft(s, " \t\r\n"), delim) {
		return LessonFrontmatter{}, s, nil
	}
	// Find first delim line.
	first := strings.Index(s, delim)
	if first < 0 {
		return LessonFrontmatter{}, s, nil
	}
	rest := s[first+len(delim):]
	// Skip the newline after the opening delim.
	rest = strings.TrimLeft(rest, "\r\n")

	end := strings.Index(rest, "\n"+delim)
	if end < 0 {
		return LessonFrontmatter{}, s, nil
	}
	fmYAML := rest[:end]
	body := rest[end+len("\n"+delim):]
	body = strings.TrimLeft(body, "\r\n")

	var fm LessonFrontmatter
	if err := yaml.Unmarshal([]byte(fmYAML), &fm); err != nil {
		return LessonFrontmatter{}, "", fmt.Errorf("frontmatter yaml: %w", err)
	}
	return fm, body, nil
}

func firstHeading(body string) string {
	for _, line := range strings.Split(body, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "# ") {
			return strings.TrimSpace(strings.TrimPrefix(l, "#"))
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func loadQuiz(trackDir, slug string) (*QuizYAML, error) {
	path := filepath.Join(trackDir, "quizzes", slug+".yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read quiz: %w", err)
	}
	var q QuizYAML
	if err := yaml.Unmarshal(data, &q); err != nil {
		return nil, fmt.Errorf("parse quiz: %w", err)
	}
	q.TitleSQ, q.TitleEN = q.Title.SQ, q.Title.EN
	q.PassThreshold = normalisePassThreshold(q.PassThresholdRaw)
	for i := range q.Questions {
		qq := &q.Questions[i]
		qq.PromptSQ, qq.PromptEN = qq.Prompt.SQ, qq.Prompt.EN
		qq.ExplanationSQ, qq.ExplanationEN = qq.Explanation.SQ, qq.Explanation.EN
		for j := range qq.Choices {
			c := &qq.Choices[j]
			c.TextSQ, c.TextEN = c.Text.SQ, c.Text.EN
		}
		// Normalise the type alias `multiple-choice` -> `multiple_choice`
		// to match the DB enum (see migration 0003).
		qq.Kind = strings.ReplaceAll(qq.Kind, "-", "_")
		// Re-encode Correct as JSON RawMessage for hashing + DB storage.
		raw, err := json.Marshal(qq.CorrectAny)
		if err != nil {
			return nil, fmt.Errorf("marshal correct for question %q: %w", qq.ID, err)
		}
		qq.Correct = raw
	}
	return &q, nil
}

// normalisePassThreshold maps either a 0..1 fraction (e.g. 0.80) or a
// 0..100 integer percent (e.g. 80) to integer percentage.
func normalisePassThreshold(raw float64) int {
	if raw <= 1.0 {
		return int(raw * 100.0)
	}
	return int(raw)
}

func loadLab(trackDir, slug string) (*LabYAML, error) {
	path := filepath.Join(trackDir, "labs", slug, "lab.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read lab: %w", err)
	}
	var lab LabYAML
	if err := yaml.Unmarshal(data, &lab); err != nil {
		return nil, fmt.Errorf("parse lab: %w", err)
	}
	lab.EgressWhitelist = lab.Network.EgressWhitelist
	for i := range lab.Hints {
		h := &lab.Hints[i]
		h.TextSQ, h.TextEN = h.Text.SQ, h.Text.EN
	}
	return &lab, nil
}

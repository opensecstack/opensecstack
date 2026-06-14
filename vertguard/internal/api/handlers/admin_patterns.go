package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"

	"github.com/opensecstack/vertguard/internal/audit"
	"github.com/opensecstack/vertguard/internal/phishing"
	"github.com/opensecstack/vertguard/internal/prompt"
)

// AdminPatternsHandler hot-reloads the prompt + phishing libraries.
//
// The reload composes the always-on code-resident DefaultLibrary with
// optional YAML overlays at PromptOverlay / PhishingOverlay paths.
// Patterns are compiled fully before the swap so a malformed overlay
// fails the request without disturbing the running scanners.
type AdminPatternsHandler struct {
	PromptScanner   *prompt.Scanner
	PhishingScanner *phishing.Scanner
	PromptOverlay   string
	PhishingOverlay string
	Sink            audit.Sink
	Logger          *zerolog.Logger
	Metrics         AdminMetrics
}

// NewAdminPatternsHandler is a convenience constructor.
func NewAdminPatternsHandler(
	pp *prompt.Scanner,
	ph *phishing.Scanner,
	promptOverlay, phishingOverlay string,
	sink audit.Sink,
	logger *zerolog.Logger,
	m AdminMetrics,
) *AdminPatternsHandler {
	return &AdminPatternsHandler{
		PromptScanner:   pp,
		PhishingScanner: ph,
		PromptOverlay:   promptOverlay,
		PhishingOverlay: phishingOverlay,
		Sink:            sink,
		Logger:          logger,
		Metrics:         m,
	}
}

// patternYAML mirrors the on-disk overlay schema. The file is a list of
// these documents. `regex` is RE2; bad regex aborts the reload.
type patternYAML struct {
	ID             string  `yaml:"id"`
	Category       string  `yaml:"category"`
	Description    string  `yaml:"description"`
	AtlasTechnique string  `yaml:"atlas_technique"`
	BaseScore      float64 `yaml:"base_score"`
	Regex          string  `yaml:"regex"`
}

// Reload handles POST /api/v1/admin/patterns/reload.
func (h *AdminPatternsHandler) Reload(w http.ResponseWriter, r *http.Request) {
	if h == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "patterns_unavailable",
			"patterns handler not configured")
		return
	}
	start := time.Now()
	actor, role := callerIdentity(r)

	// Compile both libraries up-front; if either overlay is bad we
	// surface 400 without touching the running scanners.
	var newPrompt []prompt.Pattern
	if h.PromptScanner != nil {
		merged, err := buildPromptLibrary(h.PromptOverlay)
		if err != nil {
			h.failReload(r, actor, role, "prompt", err)
			writeJSONError(w, http.StatusBadRequest, "patterns_overlay_invalid", err.Error())
			return
		}
		newPrompt = merged
	}

	var newPhishing []phishing.Pattern
	if h.PhishingScanner != nil {
		merged, err := buildPhishingLibrary(h.PhishingOverlay)
		if err != nil {
			h.failReload(r, actor, role, "phishing", err)
			writeJSONError(w, http.StatusBadRequest, "patterns_overlay_invalid", err.Error())
			return
		}
		newPhishing = merged
	}

	// Atomic swap — in-flight Scans observe their pre-swap snapshot.
	if h.PromptScanner != nil {
		h.PromptScanner.SetPatterns(newPrompt)
	}
	if h.PhishingScanner != nil {
		h.PhishingScanner.SetPatterns(newPhishing)
	}

	durationMs := float64(time.Since(start).Microseconds()) / 1000.0
	body := map[string]any{
		"prompt_count":   len(newPrompt),
		"phishing_count": len(newPhishing),
		"duration_ms":    durationMs,
	}
	h.recordReload(r, actor, role, http.StatusOK, audit.OutcomeSuccess, body)
	if h.Metrics != nil {
		h.Metrics.IncAdminSync("patterns", "ok")
	}
	if h.Logger != nil {
		h.Logger.Info().
			Str("actor", actor).
			Int("prompt_count", len(newPrompt)).
			Int("phishing_count", len(newPhishing)).
			Float64("duration_ms", durationMs).
			Msg("admin patterns reload ok")
	}
	writeJSON(w, http.StatusOK, body)
}

func (h *AdminPatternsHandler) failReload(r *http.Request, actor, role, lib string, err error) {
	if h.Metrics != nil {
		h.Metrics.IncAdminSync("patterns", "fail")
	}
	if h.Logger != nil {
		h.Logger.Warn().Err(err).Str("library", lib).Str("actor", actor).
			Msg("admin patterns reload failed")
	}
	h.recordReload(r, actor, role, http.StatusBadRequest, audit.OutcomeError, map[string]any{
		"library": lib,
		"error":   err.Error(),
	})
}

func (h *AdminPatternsHandler) recordReload(r *http.Request, actor, role string, status int, outcome string, meta map[string]any) {
	if h == nil || h.Sink == nil {
		return
	}
	metaJSON, _ := json.Marshal(meta)
	ev := audit.Event{
		ID:         uuid.New(),
		Timestamp:  time.Now().UTC(),
		Actor:      actor,
		Role:       role,
		Action:     "ADMIN_PATTERNS_RELOAD",
		Outcome:    outcome,
		StatusCode: status,
		RemoteIP:   audit.ParseRemoteIP(r.RemoteAddr),
		Metadata:   metaJSON,
	}
	_ = h.Sink.Record(r.Context(), ev)
}

// buildPromptLibrary returns DefaultLibrary plus any overlay patterns.
// An empty overlay path is treated as "no overlay" — the default is
// returned alone. A missing file at a non-empty path is an error so
// operators notice config drift.
func buildPromptLibrary(overlayPath string) ([]prompt.Pattern, error) {
	out := make([]prompt.Pattern, 0, len(prompt.DefaultLibrary))
	out = append(out, prompt.DefaultLibrary...)
	if overlayPath == "" {
		return out, nil
	}
	docs, err := readOverlay(overlayPath)
	if err != nil {
		return nil, err
	}
	for i, d := range docs {
		p, err := compilePromptDoc(d)
		if err != nil {
			return nil, fmt.Errorf("prompt overlay #%d (%s): %w", i, d.ID, err)
		}
		out = append(out, p)
	}
	return out, nil
}

func buildPhishingLibrary(overlayPath string) ([]phishing.Pattern, error) {
	out := make([]phishing.Pattern, 0, len(phishing.DefaultLibrary))
	out = append(out, phishing.DefaultLibrary...)
	if overlayPath == "" {
		return out, nil
	}
	docs, err := readOverlay(overlayPath)
	if err != nil {
		return nil, err
	}
	for i, d := range docs {
		p, err := compilePhishingDoc(d)
		if err != nil {
			return nil, fmt.Errorf("phishing overlay #%d (%s): %w", i, d.ID, err)
		}
		out = append(out, p)
	}
	return out, nil
}

func readOverlay(path string) ([]patternYAML, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read overlay %s: %w", path, err)
	}
	var docs []patternYAML
	if err := yaml.Unmarshal(body, &docs); err != nil {
		return nil, fmt.Errorf("parse overlay %s: %w", path, err)
	}
	return docs, nil
}

func compilePromptDoc(d patternYAML) (prompt.Pattern, error) {
	if d.ID == "" || d.Regex == "" {
		return prompt.Pattern{}, fmt.Errorf("id and regex are required")
	}
	if _, err := regexp.Compile(d.Regex); err != nil {
		return prompt.Pattern{}, fmt.Errorf("bad regex: %w", err)
	}
	cat := prompt.Category(d.Category)
	if cat == "" {
		cat = prompt.CategoryCustom
	}
	// MustCompilePattern panics on bad regex; we already validated above.
	return prompt.MustCompilePattern(d.ID, cat, d.Description, d.AtlasTechnique, d.BaseScore, d.Regex), nil
}

func compilePhishingDoc(d patternYAML) (phishing.Pattern, error) {
	if d.ID == "" || d.Regex == "" {
		return phishing.Pattern{}, fmt.Errorf("id and regex are required")
	}
	if _, err := regexp.Compile(d.Regex); err != nil {
		return phishing.Pattern{}, fmt.Errorf("bad regex: %w", err)
	}
	cat := phishing.Category(d.Category)
	return phishing.MustCompilePattern(d.ID, cat, d.Description, d.AtlasTechnique, d.BaseScore, d.Regex), nil
}

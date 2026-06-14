package content

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateTrack_HappyPath(t *testing.T) {
	root, _ := filepath.Abs("testdata")
	tr, err := LoadTrack(root, "sample-track")
	if err != nil {
		t.Fatal(err)
	}
	diags := ValidateTrack(tr)
	for _, d := range diags {
		if d.Severity == "error" {
			t.Errorf("unexpected error: %s", d.Error())
		}
	}
}

func TestValidateTrack_MissingTitle(t *testing.T) {
	tr := minimalValidTrack()
	tr.TitleSQ = ""
	diags := ValidateTrack(tr)
	if !hasCode(diags, "track.missing_title_sq") {
		t.Errorf("expected track.missing_title_sq, got %+v", diags)
	}
}

func TestValidateTrack_BadNIS2(t *testing.T) {
	tr := minimalValidTrack()
	tr.NIS2Mappings = []string{"art21.zz"}
	diags := ValidateTrack(tr)
	if !hasCode(diags, "track.bad_nis2") {
		t.Errorf("expected track.bad_nis2, got %+v", diags)
	}
}

func TestValidateTrack_BadDuration(t *testing.T) {
	tr := minimalValidTrack()
	tr.DurationMinutes = 0
	diags := ValidateTrack(tr)
	if !hasCode(diags, "track.bad_duration") {
		t.Errorf("expected track.bad_duration, got %+v", diags)
	}
}

func TestValidateTrack_NoModules(t *testing.T) {
	tr := minimalValidTrack()
	tr.Modules = nil
	diags := ValidateTrack(tr)
	if !hasCode(diags, "track.no_modules") {
		t.Errorf("expected track.no_modules, got %+v", diags)
	}
}

func TestValidateQuiz_MCMissingChoices(t *testing.T) {
	q := &QuizYAML{
		ID:            "q",
		PassThreshold: 80,
		Questions: []QuestionYAML{{
			ID: "q1", Kind: "multiple_choice",
			PromptSQ: "p", PromptEN: "p",
			ExplanationSQ: "e", ExplanationEN: "e",
			Correct: json.RawMessage(`["a"]`),
			Choices: []Choice{{ID: "a"}}, // only 1 choice
		}},
	}
	diags := validateQuiz(q, "quiz")
	if !hasCode(diags, "question.too_few_choices") {
		t.Errorf("expected question.too_few_choices, got %+v", diags)
	}
}

func TestValidateQuiz_MissingExplanation(t *testing.T) {
	q := &QuizYAML{
		ID:            "q",
		PassThreshold: 80,
		Questions: []QuestionYAML{{
			ID: "q1", Kind: "true_false",
			PromptSQ: "p", PromptEN: "p",
			Correct: json.RawMessage(`true`),
		}},
	}
	diags := validateQuiz(q, "quiz")
	if !hasCode(diags, "question.missing_explanation") {
		t.Errorf("expected question.missing_explanation, got %+v", diags)
	}
}

func TestValidateLab_BadRuntime(t *testing.T) {
	lab := &LabYAML{
		ID: "x", Runtime: "vm", Image: "img",
		EntryCommand: "/bin/sh", TimeLimitSeconds: 600,
	}
	diags := ValidateLab(lab)
	if !hasCode(diags, "lab.bad_runtime") {
		t.Errorf("expected lab.bad_runtime, got %+v", diags)
	}
}

func TestValidateLab_BadEgressHost(t *testing.T) {
	lab := &LabYAML{
		ID: "x", Runtime: "wasmtime", Image: "img",
		EntryCommand: "/bin/sh", TimeLimitSeconds: 600,
		EgressWhitelist: []string{"http://bad host"},
	}
	diags := ValidateLab(lab)
	if !hasCode(diags, "lab.bad_egress") {
		t.Errorf("expected lab.bad_egress, got %+v", diags)
	}
}

func TestValidateLab_GoodEgressHost(t *testing.T) {
	lab := &LabYAML{
		ID: "x", Runtime: "wasmtime", Image: "img",
		EntryCommand: "/bin/sh", TimeLimitSeconds: 600,
		EgressWhitelist: []string{"api.example.com", "*.cdn.example.com", "10.0.0.1"},
	}
	diags := ValidateLab(lab)
	if hasCode(diags, "lab.bad_egress") {
		for _, d := range diags {
			if d.Code == "lab.bad_egress" {
				t.Errorf("unexpected lab.bad_egress: %s", d.Error())
			}
		}
	}
}

func TestVersionAtLeastOne(t *testing.T) {
	cases := map[string]bool{
		"1.0.0":  true,
		"0.0.1":  false,
		"2.3.4":  true,
		"0.10.0": true,
	}
	for in, want := range cases {
		if got := versionAtLeastOne(in); got != want {
			t.Errorf("versionAtLeastOne(%q) = %v want %v", in, got, want)
		}
	}
}

// ── helpers ───────────────────────────────────────────────────────────

func minimalValidTrack() *TrackYAML {
	return &TrackYAML{
		ID:              "sample",
		Version:         "1.0.0",
		TitleSQ:         "T",
		TitleEN:         "T",
		DescriptionSQ:   "D",
		DescriptionEN:   "D",
		NIS2Mappings:    []string{"art21.g"},
		DurationMinutes: 60,
		Modules: []ModuleYAML{{
			ID:      "m1",
			TitleSQ: "M",
			TitleEN: "M",
			Lessons: []LessonYAML{{ID: "l1", BodySQ: "x", BodyEN: "x"}},
		}},
	}
}

func hasCode(diags []ValidationError, code string) bool {
	for _, d := range diags {
		if d.Code == code {
			return true
		}
	}
	return false
}

func TestValidationError_Error(t *testing.T) {
	e := ve("x", "p", "m", "error")
	if !strings.Contains(e.Error(), "[error]") {
		t.Errorf("Error() format: %s", e.Error())
	}
}

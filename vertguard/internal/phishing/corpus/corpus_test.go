package corpus

import (
	"path/filepath"
	"testing"

	"github.com/opensecstack/vertguard/internal/phishing"
)

const corpusPath = "corpus.jsonl"

func TestLoad_AllValid(t *testing.T) {
	samples, err := Load(corpusPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(samples) < 100 {
		t.Fatalf("samples = %d, want >= 100", len(samples))
	}
	seen := map[string]bool{}
	for _, s := range samples {
		if seen[s.ID] {
			t.Errorf("duplicate id %q", s.ID)
		}
		seen[s.ID] = true
	}
}

func TestEvaluate_BaselineF1(t *testing.T) {
	abs, _ := filepath.Abs(corpusPath)
	samples, err := Load(abs)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	scanner := phishing.NewScanner(phishing.DefaultLibrary, 0.30, 0.70, 0)
	rep := Evaluate(samples, scanner)
	t.Log("\n" + rep.String())

	// Phase 4.2 baseline: regex-only scanner. ML stage in Phase 4.2.1.
	const baselineMacroF1 = 0.20
	if rep.MacroF1 < baselineMacroF1 {
		t.Errorf("Macro-F1 = %.3f regressed below baseline %.2f", rep.MacroF1, baselineMacroF1)
	}
	// BLOCKED precision should remain high — false positives on benign
	// emails are particularly painful for phishing classification.
	if rep.Precision["BLOCKED"] < 0.70 {
		t.Errorf("BLOCKED precision = %.3f, want >= 0.70", rep.Precision["BLOCKED"])
	}
}

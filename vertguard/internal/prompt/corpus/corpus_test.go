package corpus

import (
	"path/filepath"
	"testing"

	"github.com/opensecstack/vertguard/internal/prompt"
)

const corpusPath = "corpus.jsonl"

func TestLoad_AllValid(t *testing.T) {
	samples, err := Load(corpusPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Post-public-ingest floor: 885 hand+synth + 200 JBB + 939 DNA +
	// 1992 HH-RLHF ≈ 4016. Drift detection — drops below 3500 indicate
	// accidental corpus deletion in a PR.
	if len(samples) < 3500 {
		t.Fatalf("samples = %d, want >= 3500 (post-ingest floor)", len(samples))
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
	scanner := prompt.NewScanner(prompt.DefaultLibrary, 0.30, 0.70, 0)
	rep := Evaluate(samples, scanner)
	t.Log("\n" + rep.String())

	// Phase 4.1 baseline: regex-only scanner against the full 4016-sample
	// corpus (885 synth + 3131 public ingests). Real targets land with
	// the ML layer in Phase 4.2 (target Macro-F1 >= 0.80, BLOCKED
	// recall >= 0.90). See TUNING.md for the gap analysis.
	// Post-ingest (4016 samples) measured baseline:
	//   Macro-F1=0.093  BLOCKED-precision=0.994  BLOCKED-recall=0.073
	// The collapse vs. the 885-sample baseline (F1=0.291) is expected:
	// regex-only catches a fixed slice of patterns; adding diverse public
	// data reveals the true coverage gap that the ML layer must close.
	// Gate values are set just under the measurement so a regex-library
	// regression trips the test. Real targets ride the ML layer.
	const (
		baselineMacroF1       = 0.08
		baselineBlockedRecall = 0.06
	)
	if rep.MacroF1 < baselineMacroF1 {
		t.Errorf("Macro-F1 = %.3f regressed below baseline %.2f", rep.MacroF1, baselineMacroF1)
	}
	if rep.Recall["BLOCKED"] < baselineBlockedRecall {
		t.Errorf("BLOCKED recall = %.3f regressed below baseline %.2f", rep.Recall["BLOCKED"], baselineBlockedRecall)
	}
	if rep.Precision["BLOCKED"] < 0.95 {
		t.Errorf("BLOCKED precision = %.3f, want >= 0.95 (false-positive guard)", rep.Precision["BLOCKED"])
	}
}

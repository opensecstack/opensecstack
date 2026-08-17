// Package corpus loads labelled prompt samples and evaluates the
// scanner's precision/recall against them. Used to tune scorer
// thresholds and category boosts.
package corpus

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/opensecstack/vertguard/internal/prompt"
)

// Sample is one labelled corpus entry.
type Sample struct {
	ID       string   `json:"id"`
	Text     string   `json:"text"`
	Expected string   `json:"expected"` // CLEAN | SUSPICIOUS | BLOCKED
	Context  string   `json:"context"`
	Source   string   `json:"source"`
	Tags     []string `json:"tags,omitempty"`
	Notes    string   `json:"notes,omitempty"`
}

// Misclassified pairs an expected vs actual verdict for a sample.
type Misclassified struct {
	ID       string
	Expected string
	Actual   string
	Score    float64
	Patterns []string
	Snippet  string
}

// Report summarises corpus evaluation.
type Report struct {
	Total         int
	ByExpected    map[string]int
	Confusion     map[string]map[string]int // expected -> actual -> count
	Precision     map[string]float64
	Recall        map[string]float64
	F1            map[string]float64
	MacroF1       float64
	Misclassified []Misclassified
}

// Load reads a JSONL file. Blank lines + lines starting with "#" are
// ignored to keep the corpus easy to annotate.
func Load(path string) ([]Sample, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parse(f)
}

func parse(r io.Reader) ([]Sample, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	var out []Sample
	line := 0
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		var s Sample
		if err := json.Unmarshal([]byte(raw), &s); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		if s.ID == "" || s.Text == "" || s.Expected == "" {
			return nil, fmt.Errorf("line %d: id/text/expected all required", line)
		}
		switch s.Expected {
		case "CLEAN", "SUSPICIOUS", "BLOCKED":
		default:
			return nil, fmt.Errorf("line %d: invalid expected %q", line, s.Expected)
		}
		out = append(out, s)
	}
	return out, scanner.Err()
}

// Evaluate runs each sample through scanner and tallies precision/recall.
func Evaluate(samples []Sample, scanner *prompt.Scanner) Report {
	verdicts := []string{"CLEAN", "SUSPICIOUS", "BLOCKED"}
	rep := Report{
		ByExpected: map[string]int{},
		Confusion:  map[string]map[string]int{},
		Precision:  map[string]float64{},
		Recall:     map[string]float64{},
		F1:         map[string]float64{},
	}
	for _, v := range verdicts {
		rep.Confusion[v] = map[string]int{}
	}

	for _, s := range samples {
		rep.Total++
		rep.ByExpected[s.Expected]++

		ctx := s.Context
		if ctx == "" {
			ctx = "default"
		}
		result, err := scanner.Scan(s.Text, ctx)
		if err != nil {
			rep.Misclassified = append(rep.Misclassified, Misclassified{
				ID: s.ID, Expected: s.Expected, Actual: "ERROR", Snippet: snippet(s.Text),
			})
			continue
		}
		actual := string(result.Classification)
		rep.Confusion[s.Expected][actual]++
		if actual != s.Expected {
			pids := make([]string, 0, len(result.Matches))
			for _, m := range result.Matches {
				pids = append(pids, m.PatternID)
			}
			rep.Misclassified = append(rep.Misclassified, Misclassified{
				ID: s.ID, Expected: s.Expected, Actual: actual,
				Score: result.Confidence, Patterns: pids, Snippet: snippet(s.Text),
			})
		}
	}

	var macroSum float64
	var macroN float64
	for _, v := range verdicts {
		tp := rep.Confusion[v][v]
		fn := 0
		fp := 0
		for _, other := range verdicts {
			if other == v {
				continue
			}
			fn += rep.Confusion[v][other]
			fp += rep.Confusion[other][v]
		}
		var prec, rec, f1 float64
		if tp+fp > 0 {
			prec = float64(tp) / float64(tp+fp)
		}
		if tp+fn > 0 {
			rec = float64(tp) / float64(tp+fn)
		}
		if prec+rec > 0 {
			f1 = 2 * prec * rec / (prec + rec)
		}
		rep.Precision[v] = prec
		rep.Recall[v] = rec
		rep.F1[v] = f1
		if rep.ByExpected[v] > 0 {
			macroSum += f1
			macroN++
		}
	}
	if macroN > 0 {
		rep.MacroF1 = macroSum / macroN
	}

	sort.Slice(rep.Misclassified, func(i, j int) bool {
		return rep.Misclassified[i].ID < rep.Misclassified[j].ID
	})
	return rep
}

func snippet(text string) string {
	if len(text) > 80 {
		return text[:77] + "..."
	}
	return text
}

// String returns a short human-readable summary.
func (r Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Corpus: %d samples (CLEAN=%d, SUSPICIOUS=%d, BLOCKED=%d)\n",
		r.Total, r.ByExpected["CLEAN"], r.ByExpected["SUSPICIOUS"], r.ByExpected["BLOCKED"])
	fmt.Fprintf(&b, "Macro-F1: %.3f\n", r.MacroF1)
	for _, v := range []string{"CLEAN", "SUSPICIOUS", "BLOCKED"} {
		fmt.Fprintf(&b, "  %-11s P=%.3f R=%.3f F1=%.3f\n", v, r.Precision[v], r.Recall[v], r.F1[v])
	}
	fmt.Fprintf(&b, "Misclassified: %d\n", len(r.Misclassified))
	return b.String()
}

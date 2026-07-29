package csaf

import "testing"

func TestCompareVersions_NumericOrdering(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1", "2", -1},
		{"2", "1", 1},
		{"3", "3", 0},
		{"10", "2", 1}, // numeric, not lexical
		{"2", "10", -1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareVersions_NonNumericFallback(t *testing.T) {
	if got := compareVersions("rev-a", "rev-a"); got != 0 {
		t.Errorf("identical non-numeric strings should compare equal, got %d", got)
	}
	if got := compareVersions("rev-a", "rev-b"); got != -1 {
		t.Errorf("differing non-numeric strings should not compare equal, got %d", got)
	}
}

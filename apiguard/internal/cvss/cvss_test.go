package cvss

import (
	"math"
	"testing"
)

func TestKnownVectors(t *testing.T) {
	tests := []struct {
		vector   string
		wantScore float64
		wantSev  string
	}{
		// NIST NVD reference values
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1, "Critical"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "High"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, "High"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "None"},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N", 6.5, "Medium"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", 5.3, "Medium"},
		{"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", 3.1, "Low"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"},
		// Scope Changed example
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", 8.6, "High"},
		// PR:H Scope Changed
		{"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 9.1, "Critical"},
	}

	for _, tt := range tests {
		t.Run(tt.vector, func(t *testing.T) {
			got, err := Score(tt.vector)
			if err != nil {
				t.Fatalf("Score(%q) error: %v", tt.vector, err)
			}
			if math.Abs(got-tt.wantScore) > 0.05 {
				t.Errorf("Score(%q) = %.1f, want %.1f", tt.vector, got, tt.wantScore)
			}
			if sev := Severity(got); sev != tt.wantSev {
				t.Errorf("Severity(%.1f) = %q, want %q", got, sev, tt.wantSev)
			}
		})
	}
}

func TestRoundup(t *testing.T) {
	cases := []struct{ in, want float64 }{
		{9.05, 9.1},
		{4.0, 4.0},
		{3.14, 3.2},
		{7.499, 7.5},
		{0.0, 0.0},
	}
	for _, c := range cases {
		if got := roundup(c.in); got != c.want {
			t.Errorf("roundup(%.3f) = %.1f, want %.1f", c.in, got, c.want)
		}
	}
}

func TestInvalidVectors(t *testing.T) {
	bad := []string{
		"",
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
		"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
		"CVSS:3.1/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", // missing AV
	}
	for _, v := range bad {
		if _, err := Score(v); err == nil {
			t.Errorf("Score(%q) expected error, got nil", v)
		}
	}
}

func TestMustScorePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustScore with bad vector should panic")
		}
	}()
	MustScore("not-a-vector")
}

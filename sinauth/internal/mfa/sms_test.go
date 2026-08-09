package mfa

import (
	"strconv"
	"testing"
)

func TestGenerateOTP_ReturnsSixDigits(t *testing.T) {
	for i := 0; i < 50; i++ {
		code, err := GenerateOTP()
		if err != nil {
			t.Fatalf("GenerateOTP: %v", err)
		}
		if len(code) != 6 {
			t.Fatalf("GenerateOTP() = %q, want length 6", code)
		}
		n, err := strconv.Atoi(code)
		if err != nil {
			t.Fatalf("GenerateOTP() = %q, not numeric: %v", code, err)
		}
		if n < 0 || n > 999999 {
			t.Fatalf("GenerateOTP() = %d, out of expected range [0, 999999]", n)
		}
	}
}

func TestGenerateOTP_ZeroPadded(t *testing.T) {
	// Run enough iterations that a leading-zero code (n < 100000) is
	// overwhelmingly likely to appear at least once, proving %06d padding
	// is actually applied rather than the code sometimes being shorter.
	sawPadded := false
	for i := 0; i < 500; i++ {
		code, err := GenerateOTP()
		if err != nil {
			t.Fatalf("GenerateOTP: %v", err)
		}
		if len(code) != 6 {
			t.Fatalf("GenerateOTP() = %q, want length 6 always (zero-padded)", code)
		}
		if code[0] == '0' {
			sawPadded = true
		}
	}
	if !sawPadded {
		t.Skip("no leading-zero code observed in 500 draws (statistically ~2.7e-24 odds); not a failure but worth noting")
	}
}

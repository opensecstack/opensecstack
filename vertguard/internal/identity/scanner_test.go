package identity

import (
	"context"
	"strings"
	"testing"
	"time"
)

func newTestScanner(t *testing.T) *Scanner {
	t.Helper()
	return NewScanner(DefaultLibrary, 0.30, 0.70, 64*1024, 10*time.Minute, 5)
}

func TestScan_CleanKYC(t *testing.T) {
	s := newTestScanner(t)
	res, err := s.Scan(context.Background(), ClaimRequest{
		ClaimType: ClaimNationalID,
		Context:   ContextKYC,
		Fields: map[string]string{
			"id_number":      "I12345678X",
			"issuer_country": "AL",
			"dob":            "1990-05-12",
			"name":           "Albi Hoxha",
			"email":          "albi.hoxha@example.com",
		},
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.Classification != ClassificationClean {
		t.Fatalf("classification = %s, want CLEAN (matches=%d)", res.Classification, len(res.Matches))
	}
}

func TestScan_SanctionedJurisdictionBlocks(t *testing.T) {
	s := newTestScanner(t)
	res, _ := s.Scan(context.Background(), ClaimRequest{
		ClaimType: ClaimPassport,
		Context:   ContextKYC,
		Fields: map[string]string{
			"id_number":      "AB1234567",
			"issuer_country": "KP",
		},
	})
	if res.Classification == ClassificationClean {
		t.Fatalf("classification = CLEAN, expected SUSPICIOUS or BLOCKED")
	}
}

func TestScan_FutureDOB(t *testing.T) {
	s := newTestScanner(t)
	future := time.Now().AddDate(1, 0, 0).Format("2006-01-02")
	res, _ := s.Scan(context.Background(), ClaimRequest{
		ClaimType: ClaimNationalID,
		Context:   ContextKYC,
		Fields:    map[string]string{"dob": future, "id_number": "I12345678X", "issuer_country": "AL"},
	})
	hit := false
	for _, m := range res.Matches {
		if m.Category == CategoryImpossibleAge {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("expected IMPOSSIBLE_AGE match, got %+v", res.Matches)
	}
}

func TestScan_ExceedsMaxAge(t *testing.T) {
	s := newTestScanner(t)
	old := time.Now().AddDate(-200, 0, 0).Format("2006-01-02")
	res, _ := s.Scan(context.Background(), ClaimRequest{
		ClaimType: ClaimNationalID,
		Context:   ContextKYC,
		Fields:    map[string]string{"dob": old, "id_number": "I12345678X", "issuer_country": "AL"},
	})
	hit := false
	for _, m := range res.Matches {
		if m.Category == CategoryImpossibleAge {
			hit = true
		}
	}
	if !hit {
		t.Fatal("expected IMPOSSIBLE_AGE match for 200-year-old DOB")
	}
}

func TestScan_DisposableEmail(t *testing.T) {
	s := newTestScanner(t)
	res, _ := s.Scan(context.Background(), ClaimRequest{
		ClaimType: ClaimPassport,
		Context:   ContextKYC,
		Fields:    map[string]string{"email": "throwaway@mailinator.com", "name": "x"},
	})
	hit := false
	for _, m := range res.Matches {
		if m.Category == CategoryEmailDisposable {
			hit = true
		}
	}
	if !hit {
		t.Fatal("expected EMAIL_DISPOSABLE match")
	}
}

func TestScan_IDFormatMismatch(t *testing.T) {
	s := newTestScanner(t)
	res, _ := s.Scan(context.Background(), ClaimRequest{
		ClaimType: ClaimNationalID,
		Context:   ContextKYC,
		Fields: map[string]string{
			"id_number":      "999999999", // US format
			"issuer_country": "AL",        // Albanian issuer
		},
	})
	hit := false
	for _, m := range res.Matches {
		if m.Category == CategoryIDFormatMismatch {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("expected ID_FORMAT_MISMATCH match, got %+v", res.Matches)
	}
}

func TestScan_ReplayThreshold(t *testing.T) {
	s := NewScanner(DefaultLibrary, 0.30, 0.70, 64*1024, 1*time.Hour, 3)
	claim := ClaimRequest{
		ClaimType: ClaimPassport,
		Context:   ContextKYC,
		Fields:    map[string]string{"id_number": "REPLAYTEST123"},
	}
	for i := 0; i < 2; i++ {
		_, _ = s.Scan(context.Background(), claim)
	}
	res, _ := s.Scan(context.Background(), claim)
	hit := false
	for _, m := range res.Matches {
		if m.Category == CategoryReplaySuspected {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("expected REPLAY_SUSPECTED on 3rd hit, got %+v", res.Matches)
	}
}

func TestScan_OversizedClaim(t *testing.T) {
	s := NewScanner(DefaultLibrary, 0.30, 0.70, 100, 10*time.Minute, 5)
	huge := strings.Repeat("a", 5000)
	_, err := s.Scan(context.Background(), ClaimRequest{
		ClaimType: ClaimPassport,
		Context:   ContextKYC,
		Fields:    map[string]string{"id_number": huge},
	})
	if err == nil {
		t.Fatal("expected InputTooLargeError")
	}
}

func TestScan_LeakedPassword(t *testing.T) {
	s := newTestScanner(t)
	res, _ := s.Scan(context.Background(), ClaimRequest{
		ClaimType: ClaimLoginCreds,
		Context:   ContextLogin,
		Fields:    map[string]string{"password": "password"},
	})
	if res.Classification == ClassificationClean {
		// Some indicator should fire (LeakedHash or WeakPassword).
		t.Fatalf("classification = CLEAN; expected at least one match for password='password' (matches=%+v)", res.Matches)
	}
}

func TestScan_ClaimHashIsStable(t *testing.T) {
	s := newTestScanner(t)
	c := ClaimRequest{
		ClaimType: ClaimPassport,
		Context:   ContextKYC,
		Fields:    map[string]string{"id_number": "STABLE123", "name": "x"},
	}
	r1, _ := s.Scan(context.Background(), c)
	// Reorder field-map insertion (Go map iteration order is randomised
	// already; canonicalise sorts).
	c2 := ClaimRequest{
		ClaimType: ClaimPassport,
		Context:   ContextKYC,
		Fields:    map[string]string{"name": "x", "id_number": "STABLE123"},
	}
	r2, _ := s.Scan(context.Background(), c2)
	if r1.ClaimHash != r2.ClaimHash {
		t.Fatalf("hash mismatch despite identical claims: %s != %s", r1.ClaimHash, r2.ClaimHash)
	}
}

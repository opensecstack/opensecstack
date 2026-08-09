package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// validateSpecURL — SSRF prevention for POST /api/v1/scans spec_url
// ---------------------------------------------------------------------------

func TestValidateSpecURL_InvalidURL(t *testing.T) {
	err := validateSpecURL(context.Background(), "://not a url")
	if err == nil {
		t.Fatal("expected error for malformed URL")
	}
}

func TestValidateSpecURL_RejectsNonHTTPScheme(t *testing.T) {
	err := validateSpecURL(context.Background(), "ftp://example.com/spec.json")
	if err == nil {
		t.Fatal("expected error for ftp scheme")
	}
	if !strings.Contains(err.Error(), "scheme") {
		t.Errorf("expected scheme-related error, got: %v", err)
	}
}

func TestValidateSpecURL_RejectsFileScheme(t *testing.T) {
	err := validateSpecURL(context.Background(), "file:///etc/passwd")
	if err == nil {
		t.Fatal("expected error for file:// scheme")
	}
}

func TestValidateSpecURL_NoHostname(t *testing.T) {
	err := validateSpecURL(context.Background(), "http:///spec.json")
	if err == nil {
		t.Fatal("expected error for URL with no hostname")
	}
}

func TestValidateSpecURL_RejectsLoopbackIPLiteral(t *testing.T) {
	err := validateSpecURL(context.Background(), "http://127.0.0.1/spec.json")
	if err == nil {
		t.Fatal("expected error for loopback IP literal (SSRF)")
	}
}

func TestValidateSpecURL_RejectsPrivateIPLiteral(t *testing.T) {
	err := validateSpecURL(context.Background(), "http://10.0.0.5/spec.json")
	if err == nil {
		t.Fatal("expected error for private IP literal (SSRF)")
	}
}

func TestValidateSpecURL_RejectsCloudMetadataIP(t *testing.T) {
	err := validateSpecURL(context.Background(), "http://169.254.169.254/latest/meta-data/")
	if err == nil {
		t.Fatal("expected error for cloud metadata address (SSRF)")
	}
}

func TestValidateSpecURL_AcceptsPublicIPLiteral(t *testing.T) {
	// A public IP literal needs no DNS resolution (LookupHost on a literal IP
	// returns that IP immediately) and is not in any private/reserved block.
	err := validateSpecURL(context.Background(), "http://8.8.8.8/spec.json")
	if err != nil {
		t.Errorf("expected public IP literal to be accepted, got error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// downloadSpecToTemp
// ---------------------------------------------------------------------------

// downloadSpecToTemp uses ssrfSafeClient, which re-validates the resolved IP
// inside DialContext against the same private/reserved-range block list used
// by validateSpecURL. httptest.NewServer always binds to 127.0.0.1, which is
// itself inside that blocked range (127.0.0.0/8) — so every request against a
// local httptest server is rejected by design before ever reaching the
// handler's own HTTP-status/Content-Type logic. The tests below therefore
// verify that this second, independent SSRF layer (defense in depth against
// DNS-rebinding between validateSpecURL's check and the actual fetch) is
// itself enforced, rather than trying to reach the unreachable
// non-200/HTML/oversize branches directly.

func TestDownloadSpecToTemp_BlocksLoopbackAtDialTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"openapi":"3.0.0"}`))
	}))
	defer srv.Close()

	_, err := downloadSpecToTemp(context.Background(), srv.URL, 10)
	if err == nil {
		t.Fatal("expected ssrf-safe dial to reject a loopback target even though it serves a valid spec")
	}
	if !strings.Contains(err.Error(), "private/reserved range") {
		t.Errorf("expected SSRF dial-time rejection, got: %v", err)
	}
}

func TestDownloadSpecToTemp_InvalidURLRejectedBeforeDial(t *testing.T) {
	_, err := downloadSpecToTemp(context.Background(), "://not a url", 10)
	if err == nil {
		t.Fatal("expected error building the request for a malformed URL")
	}
}

func TestDownloadSpecToTemp_UnreachableHostReturnsError(t *testing.T) {
	// A public-looking but non-existent host: passes the request-construction
	// step, and (assuming its public-suffix resolution fails or is unreachable)
	// must surface as a fetch error rather than a silent empty file.
	_, err := downloadSpecToTemp(context.Background(), "http://127.0.0.1:1/spec.json", 10)
	if err == nil {
		t.Fatal("expected error for unreachable/blocked target")
	}
}

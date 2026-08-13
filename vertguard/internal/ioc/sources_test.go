package ioc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestFileSource_Name(t *testing.T) {
	if got := (FileSource{}).Name(); got != "file" {
		t.Errorf("Name() = %q, want file", got)
	}
	if got := (FileSource{NameTag: "custom"}).Name(); got != "custom" {
		t.Errorf("Name() = %q, want custom", got)
	}
}

func TestFileSource_Fetch_MissingFile(t *testing.T) {
	f := FileSource{Path: filepath.Join(t.TempDir(), "does-not-exist.json")}
	_, err := f.Fetch(context.Background())
	if err == nil {
		t.Fatal("Fetch() error = nil, want error for missing file")
	}
}

func TestFileSource_Fetch_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := FileSource{Path: path}
	_, err := f.Fetch(context.Background())
	if err == nil {
		t.Fatal("Fetch() error = nil, want error for malformed JSON")
	}
}

func TestFileSource_Fetch_DefaultsConfidenceAndExpiry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "iocs.json")
	body := `[
		{"kind":"ip","value":" 1.2.3.4 "},
		{"kind":"domain","value":"evil.example","confidence":0.9,"expires_at":"2030-01-01T00:00:00Z"},
		{"kind":"domain","value":"bad-expiry.example","expires_at":"not-a-date"}
	]`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	f := FileSource{NameTag: "myfeed", Path: path}
	iocs, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if len(iocs) != 3 {
		t.Fatalf("len(iocs) = %d, want 3", len(iocs))
	}
	if iocs[0].Value != "1.2.3.4" {
		t.Errorf("iocs[0].Value = %q, want trimmed \"1.2.3.4\"", iocs[0].Value)
	}
	if iocs[0].Confidence != 0.5 {
		t.Errorf("iocs[0].Confidence = %v, want default 0.5", iocs[0].Confidence)
	}
	if iocs[0].Source != "myfeed" {
		t.Errorf("iocs[0].Source = %q, want myfeed", iocs[0].Source)
	}
	if iocs[1].Confidence != 0.9 {
		t.Errorf("iocs[1].Confidence = %v, want 0.9 (explicit value preserved)", iocs[1].Confidence)
	}
	if iocs[1].ExpiresAt == nil {
		t.Fatal("iocs[1].ExpiresAt = nil, want parsed RFC3339 time")
	}
	if iocs[2].ExpiresAt != nil {
		t.Error("iocs[2].ExpiresAt should be nil when expires_at fails to parse")
	}
}

func TestMISPSource_Name(t *testing.T) {
	if got := (MISPSource{}).Name(); got != "misp" {
		t.Errorf("Name() = %q, want misp", got)
	}
	if got := (MISPSource{NameTag: "custom"}).Name(); got != "custom" {
		t.Errorf("Name() = %q, want custom", got)
	}
}

func TestMISPSource_Fetch_EmptyURL(t *testing.T) {
	_, err := (MISPSource{}).Fetch(context.Background())
	if err == nil {
		t.Fatal("Fetch() error = nil, want error for empty URL")
	}
}

func TestMISPSource_Fetch_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("Authorization header = %q, want \"Bearer tok\"", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"response": [
				{"Attribute": [
					{"type":"ip-src","value":"1.2.3.4"},
					{"type":"domain","value":"evil.example"},
					{"type":"unknown-type","value":"skip-me"}
				]}
			]
		}`))
	}))
	defer srv.Close()

	m := MISPSource{URL: srv.URL, AuthHeader: "Bearer tok"}
	iocs, err := m.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if len(iocs) != 2 {
		t.Fatalf("len(iocs) = %d, want 2 (unknown type filtered out)", len(iocs))
	}
	if iocs[0].Kind != KindIP || iocs[0].Value != "1.2.3.4" {
		t.Errorf("iocs[0] = %+v, want kind=ip value=1.2.3.4", iocs[0])
	}
	if iocs[1].Kind != KindDomain {
		t.Errorf("iocs[1].Kind = %q, want domain", iocs[1].Kind)
	}
}

func TestMISPSource_Fetch_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := (MISPSource{URL: srv.URL}).Fetch(context.Background())
	if err == nil {
		t.Fatal("Fetch() error = nil, want error for HTTP 500")
	}
}

func TestMISPSource_Fetch_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	_, err := (MISPSource{URL: srv.URL}).Fetch(context.Background())
	if err == nil {
		t.Fatal("Fetch() error = nil, want error for malformed JSON")
	}
}

func TestMispTypeToKind(t *testing.T) {
	tests := []struct {
		in     string
		want   Kind
		wantOK bool
	}{
		{"ip-src", KindIP, true},
		{"IP-DST", KindIP, true},
		{"hostname", KindDomain, true},
		{"url", KindURL, true},
		{"sha256", KindHashSHA256, true},
		{"md5", KindHashMD5, true},
		{"filename", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, ok := mispTypeToKind(tt.in)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("mispTypeToKind(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestAbuseChSource_Name(t *testing.T) {
	if got := (AbuseChSource{}).Name(); got != "abuse_ch" {
		t.Errorf("Name() = %q, want abuse_ch", got)
	}
	if got := (AbuseChSource{NameTag: "custom"}).Name(); got != "custom" {
		t.Errorf("Name() = %q, want custom", got)
	}
}

func TestAbuseChSource_Fetch_HappyPath(t *testing.T) {
	urlSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("# comment\nhttp://evil1.example\n\nhttp://evil2.example\n"))
	}))
	defer urlSrv.Close()
	hashSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("deadbeef00000000000000000000000000000000000000000000000000\n"))
	}))
	defer hashSrv.Close()

	a := AbuseChSource{URL: urlSrv.URL, HashURL: hashSrv.URL}
	iocs, err := a.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if len(iocs) != 3 {
		t.Fatalf("len(iocs) = %d, want 3 (2 urls + 1 hash)", len(iocs))
	}
	urlCount, hashCount := 0, 0
	for _, i := range iocs {
		switch i.Kind {
		case KindURL:
			urlCount++
		case KindHashSHA256:
			hashCount++
		}
	}
	if urlCount != 2 || hashCount != 1 {
		t.Errorf("urlCount=%d hashCount=%d, want 2 and 1", urlCount, hashCount)
	}
}

func TestAbuseChSource_Fetch_BothEmptyReturnsEmpty(t *testing.T) {
	iocs, err := (AbuseChSource{}).Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if len(iocs) != 0 {
		t.Errorf("len(iocs) = %d, want 0", len(iocs))
	}
}

func TestAbuseChSource_Fetch_URLErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, err := (AbuseChSource{URL: srv.URL}).Fetch(context.Background())
	if err == nil {
		t.Fatal("Fetch() error = nil, want error when URL feed returns non-2xx")
	}
}

func TestAbuseChSource_Fetch_HashErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, err := (AbuseChSource{HashURL: srv.URL}).Fetch(context.Background())
	if err == nil {
		t.Fatal("Fetch() error = nil, want error when hash feed returns non-2xx")
	}
}

func TestMISPSource_Fetch_InvalidURLRequestError(t *testing.T) {
	// A control character in the URL makes http.NewRequestWithContext
	// fail before any network call is attempted.
	_, err := (MISPSource{URL: "http://exa\nmple.com"}).Fetch(context.Background())
	if err == nil {
		t.Fatal("Fetch() error = nil, want error from malformed request URL")
	}
}

func TestMISPSource_Fetch_ConnectionRefused(t *testing.T) {
	// Port 1 is reserved and nothing listens there — Do() fails with a
	// network-level (not HTTP-level) error.
	_, err := (MISPSource{URL: "http://127.0.0.1:1/misp"}).Fetch(context.Background())
	if err == nil {
		t.Fatal("Fetch() error = nil, want network error for unreachable host")
	}
}

func TestAbuseChSource_Fetch_InvalidURLRequestError(t *testing.T) {
	_, err := (AbuseChSource{URL: "http://exa\nmple.com"}).Fetch(context.Background())
	if err == nil {
		t.Fatal("Fetch() error = nil, want error from malformed request URL")
	}
}

func TestAbuseChSource_Fetch_HashURLInvalidRequestError(t *testing.T) {
	_, err := (AbuseChSource{HashURL: "http://exa\nmple.com"}).Fetch(context.Background())
	if err == nil {
		t.Fatal("Fetch() error = nil, want error from malformed hash request URL")
	}
}

func TestValidKind(t *testing.T) {
	tests := []struct {
		k    Kind
		want bool
	}{
		{KindIP, true},
		{KindCIDR, true},
		{KindDomain, true},
		{KindURL, true},
		{KindHashSHA256, true},
		{KindHashMD5, true},
		{Kind("bogus"), false},
		{Kind(""), false},
	}
	for _, tt := range tests {
		if got := ValidKind(tt.k); got != tt.want {
			t.Errorf("ValidKind(%q) = %v, want %v", tt.k, got, tt.want)
		}
	}
}

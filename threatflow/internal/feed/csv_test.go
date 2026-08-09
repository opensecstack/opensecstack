package feed

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCSV_Poll_AbuseUrlhaus(t *testing.T) {
	csvBody := `# urlhaus dump
# generated 2026-01-01
id,dateadded,url,url_status,threat,tags
1,2026-01-01,http://bad.example/a,online,malware_download,foo
2,2026-01-01,http://bad.example/b,online,phishing,bar
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(csvBody))
	}))
	defer srv.Close()

	p := NewCSV(Config{Name: "urlhaus", URL: srv.URL, ConfidenceBase: 60})
	payload, n, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n < 2 {
		t.Fatalf("want >=2 indicators, got %d", n)
	}

	var bundle struct {
		Objects []json.RawMessage `json:"objects"`
	}
	if err := json.Unmarshal(payload, &bundle); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(bundle.Objects) < 2 {
		t.Fatalf("objects = %d", len(bundle.Objects))
	}
	// Verify at least one indicator is a url type.
	found := false
	for _, o := range bundle.Objects {
		if strings.Contains(string(o), `[url:value =`) {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected url indicator pattern in bundle")
	}
}

func TestCSV_Poll_TypeValuePairs(t *testing.T) {
	csvBody := `ipv4,1.2.3.4
domain,evil.test
email,x@y.z
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(csvBody))
	}))
	defer srv.Close()

	p := NewCSV(Config{Name: "otx", URL: srv.URL, ConfidenceBase: 70})
	payload, n, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if n != 3 {
		t.Fatalf("want 3 indicators, got %d", n)
	}
	if !strings.Contains(string(payload), "ipv4-addr") {
		t.Error("missing ipv4-addr translation")
	}
	if !strings.Contains(string(payload), "domain-name") {
		t.Error("missing domain-name translation")
	}
}

func TestNormaliseType_KnownAliases(t *testing.T) {
	cases := map[string]string{
		"ipv4":            "ipv4-addr",
		"IPv4-Addr":       "ipv4-addr",
		"ip":              "ipv4-addr",
		"ipaddr":          "ipv4-addr",
		"ipv6":            "ipv6-addr",
		"ipv6-addr":       "ipv6-addr",
		"domain":          "domain-name",
		"Hostname":        "domain-name",
		"url":             "url",
		"URI":             "url",
		"email":           "email-addr",
		"email-addr":      "email-addr",
		"filehash-md5":    "file",
		"md5":             "file",
		"filehash-sha1":   "file",
		"sha1":            "file",
		"filehash-sha256": "file",
		"sha256":          "file",
		"cve":             "vulnerability",
		"  ipv4  ":        "ipv4-addr", // whitespace is trimmed
	}
	for in, want := range cases {
		if got := normaliseType(in); got != want {
			t.Errorf("normaliseType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormaliseType_UnknownReturnsEmpty(t *testing.T) {
	for _, in := range []string{"", "bogus-type", "yara", "cidr"} {
		if got := normaliseType(in); got != "" {
			t.Errorf("normaliseType(%q) = %q, want empty string", in, got)
		}
	}
}

func TestInferType_URL(t *testing.T) {
	if got := inferType("http://evil.example/a"); got != "url" {
		t.Errorf("inferType(url) = %q, want url", got)
	}
	if got := inferType("https://evil.example/a"); got != "url" {
		t.Errorf("inferType(https url) = %q, want url", got)
	}
}

func TestInferType_Email(t *testing.T) {
	if got := inferType("attacker@evil.example"); got != "email-addr" {
		t.Errorf("inferType(email) = %q, want email-addr", got)
	}
}

func TestInferType_IPv4(t *testing.T) {
	if got := inferType("198.51.100.42"); got != "ipv4-addr" {
		t.Errorf("inferType(ipv4) = %q, want ipv4-addr", got)
	}
}

func TestInferType_Domain(t *testing.T) {
	if got := inferType("evil.example"); got != "domain-name" {
		t.Errorf("inferType(domain) = %q, want domain-name", got)
	}
}

func TestInferType_UnknownFallback(t *testing.T) {
	if got := inferType("not-a-recognisable-indicator"); got != "x-unknown" {
		t.Errorf("inferType(garbage) = %q, want x-unknown", got)
	}
}

func TestLooksLikeIPv4_ValidAddresses(t *testing.T) {
	for _, v := range []string{"1.2.3.4", "198.51.100.42", "0.0.0.0", "255.255.255.255"} {
		if !looksLikeIPv4(v) {
			t.Errorf("looksLikeIPv4(%q) = false, want true", v)
		}
	}
}

func TestLooksLikeIPv4_RejectsNonIPv4Shapes(t *testing.T) {
	cases := []string{
		"",
		"evil.example", // domain, 2 dots-worth of parts != 4
		"1.2.3",        // only 3 octets
		"1.2.3.4.5",    // 5 octets
		"1.2.3.",       // trailing empty octet
		"1.2.3.4a",     // non-digit char in last octet
		"a.b.c.d",      // all alpha
		"1.2.3.1234",   // octet too long (>3 chars)
	}
	for _, v := range cases {
		if looksLikeIPv4(v) {
			t.Errorf("looksLikeIPv4(%q) = true, want false", v)
		}
	}
}

func TestRowLabel_ExtractsTrailingCategoryColumn(t *testing.T) {
	if got := rowLabel([]string{"ipv4", "1.2.3.4", "Botnet"}); got != "botnet" {
		t.Errorf("rowLabel = %q, want botnet (lowercased)", got)
	}
}

func TestRowLabel_EmptyForShortRow(t *testing.T) {
	if got := rowLabel([]string{"ipv4", "1.2.3.4"}); got != "" {
		t.Errorf("rowLabel = %q, want empty for row with <3 columns", got)
	}
}

func TestRowLabel_EmptyWhenLastColumnIsURL(t *testing.T) {
	// A trailing column containing "://" is treated as a value, not a label
	// (guards against misreading a 3-column url-type row as having a label).
	if got := rowLabel([]string{"note", "x", "http://evil.example"}); got != "" {
		t.Errorf("rowLabel = %q, want empty when trailing column looks like a URL", got)
	}
}

func TestEscapeSingleQuote(t *testing.T) {
	if got := escapeSingleQuote(`o'malley`); got != `o\'malley` {
		t.Errorf("escapeSingleQuote = %q, want o\\'malley", got)
	}
	if got := escapeSingleQuote("no-quotes"); got != "no-quotes" {
		t.Errorf("escapeSingleQuote(no quotes) = %q", got)
	}
}

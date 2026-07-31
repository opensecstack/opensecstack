package checks

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func file(path, content string) ScannedFile {
	return ScannedFile{
		Path:    path,
		Content: []byte(content),
		Lines:   strings.Split(content, "\n"),
	}
}

func hasCheck(findings []Finding, checkID string) bool {
	for _, f := range findings {
		if f.CheckID == checkID {
			return true
		}
	}
	return false
}

func countCheck(findings []Finding, checkID string) int {
	n := 0
	for _, f := range findings {
		if f.CheckID == checkID {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// TDS-AUTH checks
// ---------------------------------------------------------------------------

func TestRunAuthChecks_AUTH001_HardcodedKey(t *testing.T) {
	src := `
package main

const api_key = "abcdefghijklmnopqrstuvwxyz"
`
	findings := RunAuthChecks([]ScannedFile{file("main.go", src)})
	if !hasCheck(findings, "TDS-AUTH-001") {
		t.Error("expected TDS-AUTH-001 for hardcoded api_key assignment")
	}
}

func TestRunAuthChecks_AUTH001_SecretLiteral(t *testing.T) {
	src := `secret = "supersecretvalue12345"`
	findings := RunAuthChecks([]ScannedFile{file("config.py", src)})
	if !hasCheck(findings, "TDS-AUTH-001") {
		t.Error("expected TDS-AUTH-001 for hardcoded secret")
	}
}

func TestRunAuthChecks_AUTH001_NoMatch(t *testing.T) {
	src := `apiKey := os.Getenv("API_KEY")`
	findings := RunAuthChecks([]ScannedFile{file("main.go", src)})
	if hasCheck(findings, "TDS-AUTH-001") {
		t.Error("should not flag env-var lookup as TDS-AUTH-001")
	}
}

func TestRunAuthChecks_AUTH002_JWTWithExpiry_NotFlagged(t *testing.T) {
	src := `
token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.fakeSignature"
if time.time() > exp:
    raise ValueError("expired")
`
	findings := RunAuthChecks([]ScannedFile{file("auth.py", src)})
	if hasCheck(findings, "TDS-AUTH-002") {
		t.Error("should not flag JWT when expiry check is present nearby")
	}
}

func TestRunAuthChecks_AUTH003_NoCredentials(t *testing.T) {
	src := `url = "https://internal.example.com/api"`
	findings := RunAuthChecks([]ScannedFile{file("client.py", src)})
	if hasCheck(findings, "TDS-AUTH-003") {
		t.Error("should not flag URL without credentials as TDS-AUTH-003")
	}
}

func TestRunAuthChecks_ReportsFilePath(t *testing.T) {
	src := `api_key = "verylongapikey12345678901234567890"`
	findings := RunAuthChecks([]ScannedFile{file("pkg/config.go", src)})
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	if findings[0].FilePath != "pkg/config.go" {
		t.Errorf("FilePath = %q, want %q", findings[0].FilePath, "pkg/config.go")
	}
}

func TestRunAuthChecks_EmptyFiles(t *testing.T) {
	findings := RunAuthChecks([]ScannedFile{})
	if len(findings) != 0 {
		t.Errorf("expected no findings on empty input, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// TDS-HDR checks
// ---------------------------------------------------------------------------

func TestRunHeaderChecks_HDR001_Present_NotFlagged(t *testing.T) {
	src := `
client := &http.Client{}
req.Header.Set("X-Request-ID", uuid.New().String())
resp, err := client.Do(req)
`
	findings := RunHeaderChecks([]ScannedFile{file("client.go", src)})
	if hasCheck(findings, "TDS-HDR-001") {
		t.Error("should not flag when X-Request-ID is set")
	}
}

func TestRunHeaderChecks_HDR002_Present_NotFlagged(t *testing.T) {
	src := `
client := &http.Client{}
req.Header.Set("User-Agent", "opensecstack-sdk/1.0")
`
	findings := RunHeaderChecks([]ScannedFile{file("client.go", src)})
	if hasCheck(findings, "TDS-HDR-002") {
		t.Error("should not flag when User-Agent is set")
	}
}

func TestRunHeaderChecks_NoHTTPClient_NoFindings(t *testing.T) {
	src := `func hello() { fmt.Println("hello") }`
	findings := RunHeaderChecks([]ScannedFile{file("main.go", src)})
	if len(findings) != 0 {
		t.Errorf("expected no findings for file without HTTP client, got %d", len(findings))
	}
}

func TestRunHeaderChecks_ReportsFirstClientLine(t *testing.T) {
	src := `package main

import "net/http"

func makeClient() *http.Client {
	return &http.Client{}
}
`
	findings := RunHeaderChecks([]ScannedFile{file("client.go", src)})
	for _, f := range findings {
		if f.Line == 0 {
			t.Errorf("finding %s has zero line number", f.CheckID)
		}
	}
}

// ---------------------------------------------------------------------------
// TDS-SECRET checks
// ---------------------------------------------------------------------------

func TestRunSecretChecks_SECRET001_CommentLineIgnored(t *testing.T) {
	src := `# password = "example_password_do_not_use"`
	findings := RunSecretChecks([]ScannedFile{file("docs.py", src)})
	if hasCheck(findings, "TDS-SECRET-001") {
		t.Error("should not flag commented-out secrets as TDS-SECRET-001")
	}
}

func TestRunSecretChecks_SECRET002_ECPrivateKey(t *testing.T) {
	src := `-----BEGIN EC PRIVATE KEY-----
...
-----END EC PRIVATE KEY-----`
	findings := RunSecretChecks([]ScannedFile{file("certs.go", src)})
	if !hasCheck(findings, "TDS-SECRET-002") {
		t.Error("expected TDS-SECRET-002 for EC private key")
	}
}

func TestRunSecretChecks_SECRET003_PasswordInConnString(t *testing.T) {
	src := `dsn := "postgres://user:password123@localhost:5432/db"`
	findings := RunSecretChecks([]ScannedFile{file("db.go", src)})
	if !hasCheck(findings, "TDS-SECRET-003") {
		t.Error("expected TDS-SECRET-003 for password in connection string")
	}
}

func TestRunSecretChecks_SECRET003_NoPassword_NotFlagged(t *testing.T) {
	src := `dsn := "postgres://localhost:5432/db"`
	findings := RunSecretChecks([]ScannedFile{file("db.go", src)})
	if hasCheck(findings, "TDS-SECRET-003") {
		t.Error("should not flag connection string without embedded password")
	}
}

func TestRunSecretChecks_MultipleIssues_AllReported(t *testing.T) {
	src := `password = "HardcodedPass1!"
dsn := "postgres://user:secretpass123@db:5432/app"`
	findings := RunSecretChecks([]ScannedFile{file("bad.go", src)})
	if countCheck(findings, "TDS-SECRET-001") == 0 {
		t.Error("expected TDS-SECRET-001")
	}
	if countCheck(findings, "TDS-SECRET-003") == 0 {
		t.Error("expected TDS-SECRET-003")
	}
}

// ---------------------------------------------------------------------------
// TDS-RETRY checks
// ---------------------------------------------------------------------------

func TestRunRetryChecks_RETRY001_NoRetry(t *testing.T) {
	src := `
func fetch(url string) {
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
}
`
	findings := RunRetryChecks([]ScannedFile{file("fetch.go", src)})
	if !hasCheck(findings, "TDS-RETRY-001") {
		t.Error("expected TDS-RETRY-001 for HTTP call without retry")
	}
}

func TestRunRetryChecks_RETRY001_WithRetryLoop_NotFlagged(t *testing.T) {
	src := `
func fetch(url string) {
	for attempt := 0; attempt < 3; attempt++ {
		resp, err := http.Get(url)
		if err == nil {
			return
		}
		time.Sleep(time.Second)
	}
}
`
	findings := RunRetryChecks([]ScannedFile{file("fetch.go", src)})
	if hasCheck(findings, "TDS-RETRY-001") {
		t.Error("should not flag HTTP call that is inside a retry loop")
	}
}

func TestRunRetryChecks_RETRY002_CommentIgnored(t *testing.T) {
	src := `// time.Sleep(baseDelay * 2) -- do not use this pattern`
	findings := RunRetryChecks([]ScannedFile{file("retry.go", src)})
	if hasCheck(findings, "TDS-RETRY-002") {
		t.Error("should not flag a commented-out sleep as TDS-RETRY-002")
	}
}

func TestRunRetryChecks_EmptyFile(t *testing.T) {
	findings := RunRetryChecks([]ScannedFile{file("empty.go", "")})
	if len(findings) != 0 {
		t.Errorf("expected no findings for empty file, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// TDS-TLS checks
// ---------------------------------------------------------------------------

func TestRunTLSChecks_TLS001_PythonVerifyFalse(t *testing.T) {
	src := `requests.get(url, verify=False)`
	findings := RunTLSChecks([]ScannedFile{file("client.py", src)})
	if !hasCheck(findings, "TDS-TLS-001") {
		t.Error("expected TDS-TLS-001 for verify=False")
	}
}

func TestRunTLSChecks_TLS001_CommentIgnored(t *testing.T) {
	src := `// InsecureSkipVerify: true  -- never do this`
	findings := RunTLSChecks([]ScannedFile{file("notes.go", src)})
	if hasCheck(findings, "TDS-TLS-001") {
		t.Error("should not flag commented InsecureSkipVerify")
	}
}

func TestRunTLSChecks_TLS002_HTTPBaseURL(t *testing.T) {
	src := `client := NewClient("http://api.example.com")`
	findings := RunTLSChecks([]ScannedFile{file("client.go", src)})
	if !hasCheck(findings, "TDS-TLS-002") {
		t.Error("expected TDS-TLS-002 for plain http:// base URL")
	}
}

func TestRunTLSChecks_TLS002_HTTPSNotFlagged(t *testing.T) {
	src := `client := NewClient("https://api.example.com")`
	findings := RunTLSChecks([]ScannedFile{file("client.go", src)})
	if hasCheck(findings, "TDS-TLS-002") {
		t.Error("should not flag https:// URL as TDS-TLS-002")
	}
}

func TestRunTLSChecks_TLS003_CheckHostnameFalse(t *testing.T) {
	src := `ssl_context.check_hostname = False`
	findings := RunTLSChecks([]ScannedFile{file("client.py", src)})
	if !hasCheck(findings, "TDS-TLS-003") {
		t.Error("expected TDS-TLS-003 for check_hostname=False")
	}
}

// ---------------------------------------------------------------------------
// SeverityRank ordering
// ---------------------------------------------------------------------------

func TestSeverityRank_Ordering(t *testing.T) {
	cases := []struct {
		severity string
		rank     int
	}{
		{"critical", 5},
		{"high", 4},
		{"medium", 3},
		{"low", 2},
		{"info", 1},
	}
	for _, tc := range cases {
		got := SeverityRank(tc.severity)
		if got != tc.rank {
			t.Errorf("SeverityRank(%q) = %d, want %d", tc.severity, got, tc.rank)
		}
	}
}

func TestSeverityRank_CriticalHigherThanHigh(t *testing.T) {
	if SeverityRank("critical") <= SeverityRank("high") {
		t.Error("critical should rank higher than high")
	}
}

func TestSeverityRank_Unknown_ReturnsZero(t *testing.T) {
	if SeverityRank("unknown") != 0 {
		t.Errorf("SeverityRank(\"unknown\") should be 0, got %d", SeverityRank("unknown"))
	}
}

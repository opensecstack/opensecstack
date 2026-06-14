package checks

import (
	"strings"
	"testing"
)

func makeFile(path, content string) ScannedFile {
	return ScannedFile{
		Path:    path,
		Content: []byte(content),
		Lines:   strings.Split(content, "\n"),
	}
}

func findingsByID(findings []Finding, checkID string) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.CheckID == checkID {
			out = append(out, f)
		}
	}
	return out
}

func TestRunAuthChecks_NoFindings_CleanFile(t *testing.T) {
	f := makeFile("main.go", `package main

func main() {
	key := os.Getenv("API_KEY")
	_ = key
}
`)
	findings := RunAuthChecks([]ScannedFile{f})
	if len(findings) != 0 {
		t.Errorf("expected no findings on clean file, got %d: %v", len(findings), findings)
	}
}

func TestRunAuthChecks_AUTH001_HardcodedAPIKey(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"api_key assignment", `api_key: "abcdefghijklmnopqrstu"`},
		{"api_secret assignment", `api_secret = "abcdefghijklmnopqrst"`},
		{"secret colon", `secret: "verylongsecretvalue12345"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := makeFile("config.go", tc.line)
			findings := RunAuthChecks([]ScannedFile{f})
			auth001 := findingsByID(findings, "TDS-AUTH-001")
			if len(auth001) == 0 {
				t.Errorf("expected TDS-AUTH-001 for %q, got none", tc.line)
			}
			if len(auth001) > 0 {
				if auth001[0].Severity != "critical" {
					t.Errorf("expected severity=critical, got %q", auth001[0].Severity)
				}
				if auth001[0].FilePath != "config.go" {
					t.Errorf("expected FilePath=config.go, got %q", auth001[0].FilePath)
				}
			}
		})
	}
}

func TestRunAuthChecks_AUTH001_ShortValue_NoFinding(t *testing.T) {
	// Values shorter than 20 chars should not trigger AUTH-001
	f := makeFile("test.go", `api_key: "short"`)
	findings := RunAuthChecks([]ScannedFile{f})
	if len(findingsByID(findings, "TDS-AUTH-001")) != 0 {
		t.Error("expected no TDS-AUTH-001 for short value")
	}
}

func TestRunAuthChecks_AUTH002_JWTWithoutExpiry(t *testing.T) {
	content := `token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature"`
	f := makeFile("auth.go", content)
	findings := RunAuthChecks([]ScannedFile{f})
	auth002 := findingsByID(findings, "TDS-AUTH-002")
	if len(auth002) == 0 {
		t.Error("expected TDS-AUTH-002 for JWT without expiry check")
	}
}

func TestRunAuthChecks_AUTH002_JWTWithExpiry_NoFinding(t *testing.T) {
	content := `token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature"
// check exp claim
if claims.ExpiresAt < time.Now().Unix() {
	return errors.New("token expired")
}`
	f := makeFile("auth.go", content)
	findings := RunAuthChecks([]ScannedFile{f})
	auth002 := findingsByID(findings, "TDS-AUTH-002")
	if len(auth002) != 0 {
		t.Error("expected no TDS-AUTH-002 when expiry hint is nearby")
	}
}

func TestRunAuthChecks_AUTH003_BasicAuthInURL(t *testing.T) {
	cases := []string{
		`url := "http://user:password@example.com/api"`,
		`endpoint = "https://admin:secret123@db.internal:5432"`,
	}
	for _, line := range cases {
		f := makeFile("client.go", line)
		findings := RunAuthChecks([]ScannedFile{f})
		auth003 := findingsByID(findings, "TDS-AUTH-003")
		if len(auth003) == 0 {
			t.Errorf("expected TDS-AUTH-003 for %q", line)
		}
	}
}

func TestRunAuthChecks_AUTH003_NoCredentials_NoFinding(t *testing.T) {
	f := makeFile("client.go", `url := "https://api.example.com/v1"`)
	findings := RunAuthChecks([]ScannedFile{f})
	if len(findingsByID(findings, "TDS-AUTH-003")) != 0 {
		t.Error("expected no TDS-AUTH-003 for URL without credentials")
	}
}

func TestRunAuthChecks_LineNumbers(t *testing.T) {
	content := "package main\n\napi_key: \"abcdefghijklmnopqrstu\"\n"
	f := makeFile("main.go", content)
	findings := RunAuthChecks([]ScannedFile{f})
	auth001 := findingsByID(findings, "TDS-AUTH-001")
	if len(auth001) == 0 {
		t.Fatal("expected TDS-AUTH-001 finding")
	}
	if auth001[0].Line != 3 {
		t.Errorf("expected Line=3, got %d", auth001[0].Line)
	}
}

func TestRunAuthChecks_MultipleFiles(t *testing.T) {
	files := []ScannedFile{
		makeFile("clean.go", `key := os.Getenv("API_KEY")`),
		makeFile("dirty.go", `api_key: "abcdefghijklmnopqrstu"`),
	}
	findings := RunAuthChecks(files)
	auth001 := findingsByID(findings, "TDS-AUTH-001")
	if len(auth001) != 1 {
		t.Errorf("expected 1 TDS-AUTH-001, got %d", len(auth001))
	}
	if auth001[0].FilePath != "dirty.go" {
		t.Errorf("expected finding in dirty.go, got %q", auth001[0].FilePath)
	}
}

func TestSeverityRank(t *testing.T) {
	cases := []struct {
		severity string
		want     int
	}{
		{"critical", 5},
		{"high", 4},
		{"medium", 3},
		{"low", 2},
		{"info", 1},
		{"unknown", 0},
		{"", 0},
	}
	for _, tc := range cases {
		if got := SeverityRank(tc.severity); got != tc.want {
			t.Errorf("SeverityRank(%q) = %d, want %d", tc.severity, got, tc.want)
		}
	}
}

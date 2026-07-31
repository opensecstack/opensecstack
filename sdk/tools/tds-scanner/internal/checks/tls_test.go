package checks

import (
	"testing"
)

func TestRunTLSChecks_CleanFile_NoFindings(t *testing.T) {
	content := `package main

import "net/http"

func main() {
	client := &http.Client{}
	resp, _ := client.Get("https://api.example.com/data")
	_ = resp
}
`
	f := makeFile("main.go", content)
	findings := RunTLSChecks([]ScannedFile{f})
	if len(findings) != 0 {
		t.Errorf("expected no findings for clean file, got %d: %v", len(findings), findings)
	}
}

func TestRunTLSChecks_TLS001_InsecureSkipVerify(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"Go InsecureSkipVerify", `TLSClientConfig: &tls.Config{InsecureSkipVerify: true}`},
		{"Python verify=False", `requests.get(url, verify=False)`},
		{"Rust danger_accept_invalid_certs", `danger_accept_invalid_certs = true`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := makeFile("client.go", tc.line)
			findings := RunTLSChecks([]ScannedFile{f})
			tls001 := findingsByID(findings, "TDS-TLS-001")
			if len(tls001) == 0 {
				t.Errorf("expected TDS-TLS-001 for %q, got none", tc.line)
			}
			if len(tls001) > 0 && tls001[0].Severity != "critical" {
				t.Errorf("expected severity=critical, got %q", tls001[0].Severity)
			}
		})
	}
}

func TestRunTLSChecks_TLS001_CommentLine_Skipped(t *testing.T) {
	cases := []string{
		`// InsecureSkipVerify: true`,
		`# verify=False`,
		`* InsecureSkipVerify: true — DO NOT USE`,
	}
	for _, line := range cases {
		t.Run(line, func(t *testing.T) {
			f := makeFile("doc.go", line)
			findings := RunTLSChecks([]ScannedFile{f})
			if len(findingsByID(findings, "TDS-TLS-001")) != 0 {
				t.Errorf("expected comment line %q to be skipped", line)
			}
		})
	}
}

func TestRunTLSChecks_TLS002_PlaintextHTTPURL(t *testing.T) {
	cases := []string{
		`baseURL := "http://api.internal.example.com"`,
		`endpoint = "http://localhost:8080/api"`,
	}
	for _, line := range cases {
		f := makeFile("client.go", line)
		findings := RunTLSChecks([]ScannedFile{f})
		tls002 := findingsByID(findings, "TDS-TLS-002")
		if len(tls002) == 0 {
			t.Errorf("expected TDS-TLS-002 for %q", line)
		}
		if len(tls002) > 0 && tls002[0].Severity != "high" {
			t.Errorf("expected severity=high, got %q", tls002[0].Severity)
		}
	}
}

func TestRunTLSChecks_TLS002_HTTPS_NoFinding(t *testing.T) {
	f := makeFile("client.go", `baseURL := "https://api.example.com"`)
	findings := RunTLSChecks([]ScannedFile{f})
	if len(findingsByID(findings, "TDS-TLS-002")) != 0 {
		t.Error("expected no TDS-TLS-002 for HTTPS URL")
	}
}

func TestRunTLSChecks_TLS003_SSLContextNone(t *testing.T) {
	cases := []string{
		`ctx.verify_mode = ssl.CERT_NONE`,
		`ssl_context.check_hostname = False`,
	}
	for _, line := range cases {
		f := makeFile("client.py", line)
		findings := RunTLSChecks([]ScannedFile{f})
		tls003 := findingsByID(findings, "TDS-TLS-003")
		if len(tls003) == 0 {
			t.Errorf("expected TDS-TLS-003 for %q", line)
		}
		if len(tls003) > 0 && tls003[0].Severity != "medium" {
			t.Errorf("expected severity=medium, got %q", tls003[0].Severity)
		}
	}
}

func TestRunTLSChecks_LineAndColumn(t *testing.T) {
	content := "package main\n\nclient := &tls.Config{InsecureSkipVerify: true}\n"
	f := makeFile("main.go", content)
	findings := RunTLSChecks([]ScannedFile{f})
	tls001 := findingsByID(findings, "TDS-TLS-001")
	if len(tls001) == 0 {
		t.Fatal("expected TDS-TLS-001")
	}
	if tls001[0].Line != 3 {
		t.Errorf("expected Line=3, got %d", tls001[0].Line)
	}
	if tls001[0].Column <= 0 {
		t.Errorf("expected positive Column, got %d", tls001[0].Column)
	}
}

func TestRunTLSChecks_SnippetTrimmed(t *testing.T) {
	content := "\t\t\tInsecureSkipVerify: true\n"
	f := makeFile("conf.go", content)
	findings := RunTLSChecks([]ScannedFile{f})
	tls001 := findingsByID(findings, "TDS-TLS-001")
	if len(tls001) == 0 {
		t.Fatal("expected TDS-TLS-001")
	}
	if tls001[0].Snippet != "InsecureSkipVerify: true" {
		t.Errorf("expected trimmed snippet, got %q", tls001[0].Snippet)
	}
}

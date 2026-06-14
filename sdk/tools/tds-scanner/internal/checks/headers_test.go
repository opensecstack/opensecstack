package checks

import (
	"testing"
)

func TestRunHeaderChecks_NoClient_NoFindings(t *testing.T) {
	// File with no HTTP client construction — should produce zero findings
	f := makeFile("util.go", `package util

func Add(a, b int) int { return a + b }
`)
	findings := RunHeaderChecks([]ScannedFile{f})
	if len(findings) != 0 {
		t.Errorf("expected no findings for file without HTTP client, got %d", len(findings))
	}
}

func TestRunHeaderChecks_HDR001_MissingXRequestID(t *testing.T) {
	content := `package main

import "net/http"

func main() {
	client := http.Client{}
	_ = client
}
`
	f := makeFile("client.go", content)
	findings := RunHeaderChecks([]ScannedFile{f})
	hdr001 := findingsByID(findings, "TDS-HDR-001")
	if len(hdr001) == 0 {
		t.Error("expected TDS-HDR-001 for HTTP client without X-Request-ID")
	}
	if len(hdr001) > 0 && hdr001[0].Severity != "medium" {
		t.Errorf("expected severity=medium, got %q", hdr001[0].Severity)
	}
}

func TestRunHeaderChecks_HDR001_XRequestIDPresent_NoFinding(t *testing.T) {
	content := `package main

import "net/http"

func call() {
	client := http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("X-Request-ID", uuid.New().String())
	client.Do(req)
}
`
	f := makeFile("client.go", content)
	findings := RunHeaderChecks([]ScannedFile{f})
	if len(findingsByID(findings, "TDS-HDR-001")) != 0 {
		t.Error("expected no TDS-HDR-001 when X-Request-ID is set")
	}
}

func TestRunHeaderChecks_HDR002_MissingUserAgent(t *testing.T) {
	content := `package main

import "net/http"

func main() {
	client := http.Client{}
	_ = client
}
`
	f := makeFile("client.go", content)
	findings := RunHeaderChecks([]ScannedFile{f})
	hdr002 := findingsByID(findings, "TDS-HDR-002")
	if len(hdr002) == 0 {
		t.Error("expected TDS-HDR-002 for HTTP client without User-Agent")
	}
	if len(hdr002) > 0 && hdr002[0].Severity != "low" {
		t.Errorf("expected severity=low, got %q", hdr002[0].Severity)
	}
}

func TestRunHeaderChecks_HDR002_UserAgentPresent_NoFinding(t *testing.T) {
	content := `package main

import "net/http"

func main() {
	client := http.Client{}
	req.Header.Set("User-Agent", "opensecstack-sdk/1.0")
	X-Request-ID: set
}
`
	f := makeFile("client.go", content)
	findings := RunHeaderChecks([]ScannedFile{f})
	if len(findingsByID(findings, "TDS-HDR-002")) != 0 {
		t.Error("expected no TDS-HDR-002 when User-Agent is set")
	}
}

func TestRunHeaderChecks_BothMissing_TwoFindings(t *testing.T) {
	content := `package main

import "net/http"

func main() {
	client := http.Client{}
	_ = client
}
`
	f := makeFile("client.go", content)
	findings := RunHeaderChecks([]ScannedFile{f})
	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings (HDR-001 and HDR-002), got %d", len(findings))
	}
}

func TestRunHeaderChecks_PythonRequestsClient(t *testing.T) {
	content := `import requests

def fetch():
    resp = requests.get("https://api.example.com/data")
    return resp.json()
`
	f := makeFile("client.py", content)
	findings := RunHeaderChecks([]ScannedFile{f})
	// Python requests.get triggers the client detection — should flag missing headers
	hdr001 := findingsByID(findings, "TDS-HDR-001")
	if len(hdr001) == 0 {
		t.Error("expected TDS-HDR-001 for Python requests.get without X-Request-ID")
	}
}

func TestRunHeaderChecks_ReportLineNumber(t *testing.T) {
	content := "package main\n\nimport \"net/http\"\n\nfunc f() {\n\tclient := http.Client{}\n}\n"
	f := makeFile("main.go", content)
	findings := RunHeaderChecks([]ScannedFile{f})
	hdr001 := findingsByID(findings, "TDS-HDR-001")
	if len(hdr001) == 0 {
		t.Fatal("expected TDS-HDR-001")
	}
	// Line should point to the client construction line (line 6)
	if hdr001[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}

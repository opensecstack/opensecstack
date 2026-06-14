package checks

import (
	"testing"
)

func TestRunRetryChecks_NoHTTPCalls_NoFindings(t *testing.T) {
	f := makeFile("util.go", `package util

func add(a, b int) int { return a + b }
`)
	findings := RunRetryChecks([]ScannedFile{f})
	if len(findings) != 0 {
		t.Errorf("expected no findings for file with no HTTP calls, got %d", len(findings))
	}
}

func TestRunRetryChecks_RETRY001_HTTPGetWithoutRetry(t *testing.T) {
	content := `package main

import "net/http"

func fetch(url string) {
	resp, err := http.Get(url)
	if err != nil { return }
	defer resp.Body.Close()
}
`
	f := makeFile("fetch.go", content)
	findings := RunRetryChecks([]ScannedFile{f})
	retry001 := findingsByID(findings, "TDS-RETRY-001")
	if len(retry001) == 0 {
		t.Error("expected TDS-RETRY-001 for http.Get without retry")
	}
	if len(retry001) > 0 && retry001[0].Severity != "medium" {
		t.Errorf("expected severity=medium, got %q", retry001[0].Severity)
	}
}

func TestRunRetryChecks_RETRY001_HTTPGetWithRetryLoop_NoFinding(t *testing.T) {
	content := `package main

import "net/http"

func fetch(url string) {
	for attempt := 0; attempt < 3; attempt++ {
		resp, err := http.Get(url)
		if err == nil {
			defer resp.Body.Close()
			return
		}
	}
}
`
	f := makeFile("fetch.go", content)
	findings := RunRetryChecks([]ScannedFile{f})
	if len(findingsByID(findings, "TDS-RETRY-001")) != 0 {
		t.Error("expected no TDS-RETRY-001 when retry loop is present")
	}
}

func TestRunRetryChecks_RETRY001_ClientDo(t *testing.T) {
	content := `package main

func call(client *http.Client, req *http.Request) {
	resp, err := client.Do(req)
	_ = resp
	_ = err
}
`
	f := makeFile("client.go", content)
	findings := RunRetryChecks([]ScannedFile{f})
	retry001 := findingsByID(findings, "TDS-RETRY-001")
	if len(retry001) == 0 {
		t.Error("expected TDS-RETRY-001 for client.Do without retry")
	}
}

func TestRunRetryChecks_RETRY001_BackoffHint_NoFinding(t *testing.T) {
	content := `package main

import "net/http"

func fetch(url string) {
	// using backoff library
	err := backoff.Retry(func() error {
		resp, err := http.Get(url)
		if err != nil { return err }
		defer resp.Body.Close()
		return nil
	}, backoff.NewExponentialBackOff())
	_ = err
}
`
	f := makeFile("fetch.go", content)
	findings := RunRetryChecks([]ScannedFile{f})
	if len(findingsByID(findings, "TDS-RETRY-001")) != 0 {
		t.Error("expected no TDS-RETRY-001 when backoff hint is present")
	}
}

func TestRunRetryChecks_RETRY002_FixedSleep(t *testing.T) {
	content := `package main

import "time"

func retryWithSleep(attempt int) {
	time.Sleep(500 * time.Millisecond * 2)
}
`
	f := makeFile("retry.go", content)
	findings := RunRetryChecks([]ScannedFile{f})
	retry002 := findingsByID(findings, "TDS-RETRY-002")
	if len(retry002) == 0 {
		t.Error("expected TDS-RETRY-002 for fixed sleep with integer multiplier")
	}
	if len(retry002) > 0 && retry002[0].Severity != "low" {
		t.Errorf("expected severity=low, got %q", retry002[0].Severity)
	}
}

func TestRunRetryChecks_CommentLines_Skipped(t *testing.T) {
	content := `package main

// resp, err := http.Get(url) — example, not real code
# http.Get(url)
`
	f := makeFile("example.go", content)
	findings := RunRetryChecks([]ScannedFile{f})
	if len(findingsByID(findings, "TDS-RETRY-001")) != 0 {
		t.Error("expected comment lines to be skipped")
	}
}

func TestRunRetryChecks_SnippetPopulated(t *testing.T) {
	content := `package main

import "net/http"

func f() { resp, _ := http.Post("url", "application/json", nil); _ = resp }
`
	f := makeFile("post.go", content)
	findings := RunRetryChecks([]ScannedFile{f})
	retry001 := findingsByID(findings, "TDS-RETRY-001")
	if len(retry001) == 0 {
		t.Fatal("expected TDS-RETRY-001")
	}
	if retry001[0].Snippet == "" {
		t.Error("expected non-empty Snippet in finding")
	}
}

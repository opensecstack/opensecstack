package checks

import (
	"testing"
)

func TestRunSecretChecks_CleanFile_NoFindings(t *testing.T) {
	content := `package main

import "os"

func getDB() string {
	return os.Getenv("DB_URL")
}
`
	f := makeFile("db.go", content)
	findings := RunSecretChecks([]ScannedFile{f})
	if len(findings) != 0 {
		t.Errorf("expected no findings for clean file, got %d: %v", len(findings), findings)
	}
}

func TestRunSecretChecks_SECRET001_HardcodedPassword(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"PASSWORD assignment", `PASSWORD = "supersecretpassword"`},
		{"password colon", `password: "mysecretvalue123"`},
		{"secret variable", `secret = "verylongsecret1234"`},
		{"token assignment", `token = "longtokenvalue12345"`},
		{"auth_key", `auth_key: "myauthkeyvalue12345"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := makeFile("config.go", tc.line)
			findings := RunSecretChecks([]ScannedFile{f})
			s001 := findingsByID(findings, "TDS-SECRET-001")
			if len(s001) == 0 {
				t.Errorf("expected TDS-SECRET-001 for %q, got none", tc.line)
			}
			if len(s001) > 0 && s001[0].Severity != "critical" {
				t.Errorf("expected severity=critical, got %q", s001[0].Severity)
			}
		})
	}
}

func TestRunSecretChecks_SECRET001_ShortValue_NoFinding(t *testing.T) {
	// Less than 8 characters — should not trigger
	f := makeFile("test.go", `password: "short"`)
	findings := RunSecretChecks([]ScannedFile{f})
	if len(findingsByID(findings, "TDS-SECRET-001")) != 0 {
		t.Error("expected no TDS-SECRET-001 for short value")
	}
}

func TestRunSecretChecks_SECRET001_CommentLine_Skipped(t *testing.T) {
	content := `// password: "thiswouldmatchbutisacomment"`
	f := makeFile("doc.go", content)
	findings := RunSecretChecks([]ScannedFile{f})
	if len(findingsByID(findings, "TDS-SECRET-001")) != 0 {
		t.Error("expected comment line to be skipped")
	}
}

func TestRunSecretChecks_SECRET002_PEMPrivateKey(t *testing.T) {
	cases := []string{
		`-----BEGIN RSA PRIVATE KEY-----`,
		`-----BEGIN EC PRIVATE KEY-----`,
		`-----BEGIN PRIVATE KEY-----`,
		`-----BEGIN OPENSSH PRIVATE KEY-----`,
	}
	for _, line := range cases {
		t.Run(line, func(t *testing.T) {
			f := makeFile("key.go", line)
			findings := RunSecretChecks([]ScannedFile{f})
			s002 := findingsByID(findings, "TDS-SECRET-002")
			if len(s002) == 0 {
				t.Errorf("expected TDS-SECRET-002 for %q", line)
			}
			if len(s002) > 0 && s002[0].Severity != "high" {
				t.Errorf("expected severity=high, got %q", s002[0].Severity)
			}
		})
	}
}

func TestRunSecretChecks_SECRET003_PasswordInConnectionString(t *testing.T) {
	cases := []string{
		`dsn := "postgres://user:supersecretpwd@localhost:5432/db"`,
		`url = "redis://admin:longpassword123@cache:6379"`,
		`amqp := "amqp://rabbit:secretpassword@mq:5672"`,
	}
	for _, line := range cases {
		t.Run(line, func(t *testing.T) {
			f := makeFile("db.go", line)
			findings := RunSecretChecks([]ScannedFile{f})
			s003 := findingsByID(findings, "TDS-SECRET-003")
			if len(s003) == 0 {
				t.Errorf("expected TDS-SECRET-003 for %q, got none", line)
			}
			if len(s003) > 0 && s003[0].Severity != "medium" {
				t.Errorf("expected severity=medium, got %q", s003[0].Severity)
			}
		})
	}
}

func TestRunSecretChecks_SECRET003_NoPassword_NoFinding(t *testing.T) {
	f := makeFile("db.go", `dsn := "postgres://localhost:5432/mydb"`)
	findings := RunSecretChecks([]ScannedFile{f})
	if len(findingsByID(findings, "TDS-SECRET-003")) != 0 {
		t.Error("expected no TDS-SECRET-003 for connection string without password")
	}
}

func TestRunSecretChecks_MultipleIssues_SameFile(t *testing.T) {
	content := `package main

password = "supersecretvalue"
-----BEGIN RSA PRIVATE KEY-----
dsn := "postgres://user:secretpassword@localhost/db"
`
	f := makeFile("bad.go", content)
	findings := RunSecretChecks([]ScannedFile{f})
	if len(findings) < 3 {
		t.Errorf("expected at least 3 findings (SECRET-001, 002, 003), got %d", len(findings))
	}
}

func TestRunSecretChecks_LineAndFilePath(t *testing.T) {
	content := "package main\n\nPASSWORD = \"supersecretpassword\"\n"
	f := makeFile("secrets.go", content)
	findings := RunSecretChecks([]ScannedFile{f})
	s001 := findingsByID(findings, "TDS-SECRET-001")
	if len(s001) == 0 {
		t.Fatal("expected TDS-SECRET-001")
	}
	if s001[0].Line != 3 {
		t.Errorf("expected Line=3, got %d", s001[0].Line)
	}
	if s001[0].FilePath != "secrets.go" {
		t.Errorf("expected FilePath=secrets.go, got %q", s001[0].FilePath)
	}
}

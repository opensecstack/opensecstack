# opensecstack Go SDK

Go client library for the opensecstack platform APIs — APIGuard and NIS2 Compass.

## Requirements

- Go 1.22+
- No external dependencies (uses only the standard library)

## Installation

```bash
go get github.com/opensecstack/sdk
```

## Usage

### Run a scan and retrieve findings

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/opensecstack/sdk/opensecstack"
)

func main() {
    client := opensecstack.NewAPIGuardClient(
        "https://apiguard.example.com",
        "sk-your-api-key-here",
    )

    ctx := context.Background()

    // Create a scan against a remote OpenAPI spec.
    scan, err := client.CreateScan(ctx, "https://api.example.com/openapi.yaml")
    if err != nil {
        log.Fatalf("create scan: %v", err)
    }
    fmt.Printf("Scan %s started (status: %s)\n", scan.ID, scan.Status)

    // Poll until the scan reaches a terminal state.
    for {
        scan, err = client.GetScan(ctx, scan.ID)
        if err != nil {
            log.Fatalf("get scan: %v", err)
        }
        if scan.Status == opensecstack.ScanStatusCompleted ||
            scan.Status == opensecstack.ScanStatusFailed {
            break
        }
        fmt.Printf("  ... status: %s\n", scan.Status)
        time.Sleep(5 * time.Second)
    }

    fmt.Printf("Scan finished: %s — %d findings\n", scan.Status, scan.TotalFindings)

    if scan.Status == opensecstack.ScanStatusFailed {
        fmt.Printf("Error: %s\n", scan.ErrorMessage)
        return
    }

    // Retrieve findings.
    findings, err := client.GetFindings(ctx, scan.ID)
    if err != nil {
        log.Fatalf("get findings: %v", err)
    }

    for _, f := range findings {
        fmt.Printf("[%s] %s  %s %s\n",
            f.Severity, f.Title, f.EndpointMethod, f.EndpointPath)
    }
}
```

### Full scan options (auth, modules, spec path)

```go
scan, err := client.CreateScanFull(ctx, opensecstack.CreateScanOptions{
    SpecURL:   "https://api.example.com/openapi.yaml",
    Target:    "https://api.example.com",
    Modules:   []string{"owasp-api1", "owasp-api2", "owasp-api3"},
    AuthType:  "bearer",
    AuthToken: "my-test-token",
})
```

### Audit log

```go
entries, err := client.GetAuditLog(ctx, 20)
if err != nil {
    log.Fatalf("audit log: %v", err)
}
for _, e := range entries {
    fmt.Printf("%s  %s  %s\n", e.CreatedAt.Format(time.RFC3339), e.Action, e.ActorID)
}
```

## NIS2 Compass

NIS2 Compass tracks organisational NIS2 Article 21 compliance through assessments and controls.
Authentication uses a direct `X-API-Key` header — no token exchange is needed.

### Run a full compliance workflow

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"

    "github.com/opensecstack/sdk/opensecstack"
)

func main() {
    ctx := context.Background()

    client := opensecstack.NewNIS2CompassClient("http://localhost:8090", "your-api-key")

    // Create an organisation.
    org, err := client.CreateOrganisation(ctx, opensecstack.CreateOrganisationRequest{
        Name: "Acme GmbH", Industry: "energy", Country: "DE", Size: "large",
    })
    if err != nil {
        log.Fatalf("create organisation: %v", err)
    }
    fmt.Printf("Organisation %s created\n", org.ID)

    // Create an assessment — 10 controls (a–j) are seeded automatically.
    assessment, err := client.CreateAssessment(ctx, org.ID, opensecstack.CreateAssessmentRequest{
        Title: "NIS2 2026 Q1 Assessment",
    })
    if err != nil {
        log.Fatalf("create assessment: %v", err)
    }
    fmt.Printf("Assessment %s created (status: %s)\n", assessment.ID, assessment.Status)

    // Transition the assessment to in_progress.
    assessment, err = client.PatchAssessment(ctx, assessment.ID, opensecstack.PatchAssessmentRequest{
        Status: "in_progress",
    })
    if err != nil {
        log.Fatalf("patch assessment: %v", err)
    }

    // Update a control finding.
    ctrl, err := client.PatchControl(ctx, assessment.ID, "a", opensecstack.PatchControlRequest{
        Status: "compliant", Notes: "ISO 27001 certified",
    })
    if err != nil {
        log.Fatalf("patch control: %v", err)
    }
    fmt.Printf("Control %s (%s) status: %s\n", ctrl.MeasureRef, ctrl.ArticleRef, ctrl.Status)

    // Generate a PDF compliance report.
    pdf, err := client.GenerateReport(ctx, assessment.ID)
    if err != nil {
        log.Fatalf("generate report: %v", err)
    }
    if err := os.WriteFile("report.pdf", pdf, 0644); err != nil {
        log.Fatalf("write report: %v", err)
    }
    fmt.Printf("Report written (%d bytes)\n", len(pdf))
}
```

### Audit log

```go
entries, err := client.GetAuditLog(ctx, 20)
if err != nil {
    log.Fatalf("audit log: %v", err)
}
for _, e := range entries {
    fmt.Printf("%s  [%s]  %s  %s\n",
        e.Timestamp.Format(time.RFC3339), e.RiskClass, e.Action, e.Actor)
}
```

## APIGuard types

| Type | Description |
|------|-------------|
| `Scan` | A scan record (id, status, target_url, finding counts, ...) |
| `Finding` | A single security finding (owasp_id, severity, endpoint, ...) |
| `AuditEntry` | An immutable CITADEL-chained audit log entry |
| `ScanStatus` | Enum: `pending`, `running`, `completed`, `failed`, `cancelled` |
| `FindingSeverity` | Enum: `critical`, `high`, `medium`, `low`, `info` |
| `FindingStatus` | Enum: `open`, `confirmed`, `false_positive`, `accepted`, `fixed` |

## NIS2 Compass types

| Type | Description |
|------|-------------|
| `Organisation` | A registered NIS2-subject organisation |
| `Assessment` | A NIS2 Article 21 compliance assessment with status lifecycle |
| `Control` | One of 10 Article 21(2) measure entries (a–j) within an assessment |
| `NIS2AuditEntry` | An immutable WORM-chained NIS2 audit log entry |
| `CreateOrganisationRequest` | Body for `POST /organisations` |
| `CreateAssessmentRequest` | Body for `POST /organisations/{id}/assessments` |
| `PatchAssessmentRequest` | Body for `PATCH /assessments/{id}` |
| `PatchControlRequest` | Body for `PATCH /assessments/{id}/controls/{measure_ref}` |

## Licence

Apache 2.0

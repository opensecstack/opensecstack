# opensecstack Go SDK

Go client library for the opensecstack platform APIs — currently APIGuard.

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

## Types

| Type | Description |
|------|-------------|
| `Scan` | A scan record (id, status, target_url, finding counts, ...) |
| `Finding` | A single security finding (owasp_id, severity, endpoint, ...) |
| `AuditEntry` | An immutable CITADEL-chained audit log entry |
| `ScanStatus` | Enum: `pending`, `running`, `completed`, `failed`, `cancelled` |
| `FindingSeverity` | Enum: `critical`, `high`, `medium`, `low`, `info` |
| `FindingStatus` | Enum: `open`, `confirmed`, `false_positive`, `accepted`, `fixed` |

## Licence

Apache 2.0

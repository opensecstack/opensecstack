# SDK Go Client

The Go SDK provides typed clients for APIGuard, NIS2 Compass, and CITADEL, plus shared types for the opensecstack integration contracts.

---

## Installation

```bash
go get github.com/opensecstack/sdk/go/opensecstack@latest
```

Requires Go 1.22+.  
No external dependencies — uses only the standard library.

---

## APIGuard Client

### Creating a client

```go
import "github.com/opensecstack/sdk/go/opensecstack"

client := opensecstack.NewAPIGuardClient(
    "https://apiguard.internal",
    "ag_key_...",
)
```

### Starting a scan

```go
// Simple — scan a remote OpenAPI spec URL.
scan, err := client.CreateScan(ctx, "https://api.example.com/openapi.json")
if err != nil {
    return err
}
fmt.Println("Scan ID:", scan.ID)

// Full options — auth, modules, spec path override.
scan, err = client.CreateScanFull(ctx, opensecstack.CreateScanOptions{
    SpecURL:   "https://api.example.com/openapi.json",
    Target:    "https://api.example.com",
    Modules:   []string{"owasp-api1", "owasp-api2", "owasp-api3"},
    AuthType:  "bearer",
    AuthToken: "my-test-token",
})
```

### Polling for results

The server starts scans asynchronously. Poll `GetScan` until the status reaches a terminal state:

```go
for {
    scan, err = client.GetScan(ctx, scan.ID)
    if err != nil {
        return err
    }
    if scan.Status == opensecstack.ScanStatusCompleted ||
        scan.Status == opensecstack.ScanStatusFailed {
        break
    }
    fmt.Printf("  ... status: %s\n", scan.Status)
    time.Sleep(5 * time.Second)
}

for _, finding := range findings {
    fmt.Printf("[%s] %s — %s %s\n",
        finding.Severity, finding.Title,
        finding.EndpointMethod, finding.EndpointPath)
}
```

### Getting scan results directly

```go
scan, err := client.GetScan(ctx, scanID)
```

### Listing recent scans

```go
scans, err := client.ListScans(ctx, opensecstack.ListScansOptions{
    Page:    1,
    PerPage: 20,
})
```

### Retrieving findings

```go
findings, err := client.GetFindings(ctx, scan.ID, opensecstack.GetFindingsOptions{
    Severity: "critical",
})
```

### Updating a finding triage status

```go
updated, err := client.PatchFinding(ctx, findingID, opensecstack.PatchFindingRequest{
    Status: "accepted",
})
```

### Uploading a spec file

```go
resp, err := client.UploadSpec(ctx, "/path/to/openapi.yaml")
fmt.Println("Stored at:", resp.SpecPath)
```

### Streaming a report

```go
f, _ := os.Create("report.sarif")
defer f.Close()
err = client.GetReportStream(ctx, scan.ID, "sarif", f)
```

### Audit log

```go
entries, err := client.GetAuditLog(ctx, 20, 1)
for _, e := range entries {
    fmt.Printf("%s  %s  %s\n", e.CreatedAt.Format(time.RFC3339), e.Action, e.ActorID)
}
```

---

## NIS2 Compass Client

### Creating a client

```go
client := opensecstack.NewNIS2CompassClient("https://nis2compass.internal", "nc_key_...")
```

### Managing organisations

```go
// Create
org, err := client.CreateOrganisation(ctx, opensecstack.CreateOrganisationRequest{
    Name:       "Acme Corp",
    Industry:   "finance",
    Country:    "AL",
    Size:       "large",
    EntityType: "essential",
})

// Get
org, err = client.GetOrganisation(ctx, orgID)

// List (paginated)
orgs, err := client.GetOrganisations(ctx, opensecstack.GetOrganisationsOptions{
    Page:    1,
    PerPage: 50,
})
```

### Managing assessments

```go
// Create — 10 NIS2 Article 21(2) controls (a–j) are seeded automatically.
assessment, err := client.CreateAssessment(ctx, org.ID, opensecstack.CreateAssessmentRequest{
    Title:            "Q1 2026 NIS2 Assessment",
    FrameworkVersion: "NIS2-2022/0383",
})

// Transition to in_progress
assessment, err = client.PatchAssessment(ctx, assessment.ID, opensecstack.PatchAssessmentRequest{
    Status: "in_progress",
})

// Get
assessment, err = client.GetAssessment(ctx, assessment.ID)
```

### Updating a control

Measure references are single letters `a` through `j`, matching Article 21(2)(a)–(j):

```go
ctrl, err := client.PatchControl(ctx, assessment.ID, "e", opensecstack.PatchControlRequest{
    Status: "compliant",
    Notes:  "APIGuard scan completed — zero critical findings",
})
fmt.Printf("Control %s (%s): %s\n", ctrl.MeasureRef, ctrl.ArticleRef, ctrl.Status)
```

### Artifacts

```go
// Upload
artifact, err := client.UploadArtifact(ctx, assessment.ID,
    "/path/to/evidence.pdf", "evidence", "", "APIGuard scan evidence")

// Download
err = client.DownloadArtifact(ctx, artifact.ID, "/tmp/downloaded.pdf")

// Delete
err = client.DeleteArtifact(ctx, artifact.ID)
```

### Generating a report

```go
pdf, err := client.GenerateReport(ctx, assessment.ID)
if err != nil {
    return err
}
os.WriteFile("report.pdf", pdf, 0644)
```

### Audit log

```go
entries, err := client.GetAuditLog(ctx, 20, 1)
for _, e := range entries {
    fmt.Printf("%s  [%s]  %s  %s\n",
        e.Timestamp.Format(time.RFC3339), e.RiskClass, e.Action, e.Actor)
}
```

---

## CITADEL Client

The CITADEL client delivers structured security events to the immutable WORM audit chain via HMAC-SHA256 signed HTTP POST.
`SendEvent` is non-blocking — it enqueues the event and returns immediately; a background goroutine handles delivery.

```go
citadel := opensecstack.NewCITADELClient(opensecstack.CITADELClientOptions{
    BaseURL:      "https://citadel.internal",
    SharedSecret: "hmac-secret",
})
defer citadel.Drain(context.Background()) // flush in-flight events on shutdown

// Dispatch an event (non-blocking)
citadel.SendEvent(ctx, opensecstack.SecurityEvent{
    EventType:    "apiguard.scan.completed",
    Source:       "apiguard",
    ActorID:      apiKeyID,
    ActorType:    "api_key",
    ResourceType: "scan",
    ResourceID:   scan.ID,
    Severity:     "info",
    Payload:      json.RawMessage(`{"total_findings":3}`),
})

// Query events
events, err := citadel.GetEvents(ctx, opensecstack.GetEventsOptions{
    Source:    "apiguard",
    EventType: "apiguard.scan.completed",
    Limit:     50,
})

// Verify the WORM chain integrity locally
err = citadel.VerifyChain(ctx, events)
```

---

## Error Handling

All clients return typed errors:

```go
scan, err := client.CreateScanFull(ctx, opensecstack.CreateScanOptions{
    SpecURL: "https://api.example.com/openapi.json",
})
if err != nil {
    var rateLimitErr *opensecstack.RateLimitError
    if errors.As(err, &rateLimitErr) {
        time.Sleep(rateLimitErr.RetryAfter)
        // retry
    }
    return err
}
```

Error types:

| Type | HTTP status | Meaning |
|------|------------|---------|
| `*opensecstack.AuthError` | 401 | Invalid API key |
| `*opensecstack.NotFoundError` | 404 | Resource not found |
| `*opensecstack.RateLimitError` | 429 | Rate limit hit; has `RetryAfter` field |
| `*opensecstack.ServerError` | 5xx | Server-side error |

---

## Complete Example: Scan and Update NIS2 Control

```go
apiguard := opensecstack.NewAPIGuardClient(apiguardURL, apiguardKey)
nis2    := opensecstack.NewNIS2CompassClient(nis2URL, nis2Key)

// Start scan
scan, err := apiguard.CreateScan(ctx, "https://api.example.com/openapi.json")
if err != nil {
    log.Fatal(err)
}

// Poll until complete
for {
    scan, err = apiguard.GetScan(ctx, scan.ID)
    if err != nil {
        log.Fatal(err)
    }
    if scan.Status == opensecstack.ScanStatusCompleted ||
        scan.Status == opensecstack.ScanStatusFailed {
        break
    }
    time.Sleep(5 * time.Second)
}

if scan.Status == opensecstack.ScanStatusFailed {
    log.Fatalf("scan failed: %s", scan.ErrorMessage)
}

// Upload the SARIF report as a NIS2 evidence artifact
buf := &bytes.Buffer{}
apiguard.GetReportStream(ctx, scan.ID, "sarif", buf)

tmp, _ := os.CreateTemp("", "apiguard-*.sarif")
tmp.Write(buf.Bytes())
tmp.Close()

artifact, err := nis2.UploadArtifact(ctx, assessmentID, tmp.Name(), "evidence", "", "APIGuard SARIF report")
if err != nil {
    log.Fatal(err)
}

// Mark control e as compliant
nis2.PatchControl(ctx, assessmentID, "e", opensecstack.PatchControlRequest{
    Status: "compliant",
    Notes:  fmt.Sprintf("APIGuard scan %s — %d critical findings", scan.ID, scan.CriticalCount),
})

fmt.Printf("Evidence artifact %s linked to control e\n", artifact.ID)
```

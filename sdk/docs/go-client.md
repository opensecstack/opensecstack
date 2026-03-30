# SDK Go Client

The Go SDK provides typed clients for APIGuard and NIS2Compass, plus shared types for the opensecstack integration contracts.

---

## Installation

```bash
go get github.com/opensecstack/sdk/go/opensecstack@latest
```

Requires Go 1.22+.

---

## APIGuard Client

### Creating a client

```go
import "github.com/opensecstack/sdk/go/opensecstack"

client := opensecstack.NewAPIGuardClient(
    "https://apiguard.internal",
    opensecstack.WithAPIKey("ag_key_..."),
    opensecstack.WithTimeout(30 * time.Second),
)
```

### Starting a scan

```go
scan, err := client.StartScan(ctx, &opensecstack.StartScanRequest{
    Target:   "https://api.example.com",
    SpecURL:  "https://api.example.com/openapi.json",
    Modules:  []string{"bola", "broken_auth", "injection"},
    Metadata: map[string]string{"project": "ABISSNET_TCL_001"},
})
if err != nil {
    return err
}
fmt.Println("Scan ID:", scan.ID)
```

### Polling for results

```go
result, err := client.WaitForScan(ctx, scan.ID, &opensecstack.WaitOptions{
    PollInterval: 5 * time.Second,
    Timeout:      10 * time.Minute,
})
if err != nil {
    return err
}

for _, finding := range result.Findings {
    fmt.Printf("[%s] %s — %s\n", finding.Severity, finding.OWASP, finding.Title)
}
```

### Getting scan results directly

```go
result, err := client.GetScan(ctx, scan.ID)
```

### Listing recent scans

```go
scans, err := client.ListScans(ctx, &opensecstack.ListScansOptions{
    Limit:  20,
    Status: opensecstack.ScanStatusCompleted,
})
```

---

## NIS2Compass Client

### Creating a client

```go
import "github.com/opensecstack/sdk/go/opensecstack"

client := opensecstack.NewNIS2CompassClient(
    "https://nis2compass.internal",
    opensecstack.WithAPIKey("nc_key_..."),
)
```

### Managing organisations

```go
// Create
org, err := client.CreateOrganisation(ctx, &opensecstack.CreateOrganisationRequest{
    Name:       "Acme Corp",
    Industry:   "finance",
    Country:    "AL",
    Size:       "large",
    EntityType: "essential",
})

// Get
org, err := client.GetOrganisation(ctx, orgID)

// List
orgs, err := client.ListOrganisations(ctx, nil)
```

### Managing assessments

```go
// Create
assessment, err := client.CreateAssessment(ctx, orgID, &opensecstack.CreateAssessmentRequest{
    Title:            "Q1 2026 NIS2 Assessment",
    FrameworkVersion: "NIS2-2022/0383",
})

// Get with controls
assessment, err := client.GetAssessment(ctx, orgID, assessmentID)
for _, control := range assessment.Controls {
    fmt.Printf("%s: %s\n", control.MeasureRef, control.Status)
}
```

### Updating a control

```go
updated, err := client.PatchControl(ctx, orgID, assessmentID, "art21_e", &opensecstack.PatchControlRequest{
    Status: "compliant",
    Notes:  "APIGuard scan completed — zero critical findings",
    EvidenceRefs: []string{"sha256:abc123..."},
})
```

---

## CITADEL Client

```go
import "github.com/opensecstack/sdk/go/opensecstack/citadel"

client := citadel.NewClient(
    "https://citadel.internal",
    keyID,
    secret,
)

// Check advisory before submitting
advisory, err := client.GetAdvisory(ctx, "ABISSNET_TCL_001", "deploy_change")
if advisory.HasCritical() {
    log.Warn("CITADEL advisory", "details", advisory.Advisories)
}

// Submit Kerkese
result, err := client.Evaluate(ctx, &citadel.Kerkese{
    Version:   "2.0",
    ProjectID: "ABISSNET_TCL_001",
    Action:    citadel.Action{Type: "deploy_change", Description: "Deploy v2.1.0"},
    Actor:     citadel.Principal{UserID: "alice@example.com", Role: "group_sig_operator"},
    Verifier:  citadel.Principal{UserID: "bob@example.com", Role: "group_sig_verifier"},
    Evidence:  citadel.Evidence{ChangeID: "CHG-001"},
})
if result.Outcome != citadel.OutcomeExecute {
    return fmt.Errorf("MARSHAL refused: %v", result.Reasons)
}
```

---

## Error Handling

All clients return typed errors:

```go
result, err := client.StartScan(ctx, req)
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

## Client Options

```go
opensecstack.NewAPIGuardClient(
    baseURL,
    opensecstack.WithAPIKey(key),
    opensecstack.WithTimeout(30 * time.Second),
    opensecstack.WithHTTPClient(customHTTPClient),
    opensecstack.WithUserAgent("myapp/1.0"),
    opensecstack.WithRetry(3, opensecstack.ExponentialBackoff),
)
```

---

## Complete Example: Scan and Update NIS2 Control

```go
apiguard := opensecstack.NewAPIGuardClient(apiguardURL, opensecstack.WithAPIKey(apiguardKey))
nis2 := opensecstack.NewNIS2CompassClient(nis2URL, opensecstack.WithAPIKey(nis2Key))

// Run scan
scan, _ := apiguard.StartScan(ctx, &opensecstack.StartScanRequest{Target: target})
result, _ := apiguard.WaitForScan(ctx, scan.ID, nil)

// Export evidence bundle
bundle, _ := apiguard.ExportNIS2Evidence(ctx, scan.ID)

// Upload evidence to NIS2Compass
artifact, _ := nis2.UploadArtifact(ctx, orgID, bundle)

// Mark control compliant
nis2.PatchControl(ctx, orgID, assessmentID, "art21_e", &opensecstack.PatchControlRequest{
    Status:       "compliant",
    Notes:        fmt.Sprintf("APIGuard scan %s — %d critical findings", scan.ID, result.Stats.Critical),
    EvidenceRefs: []string{artifact.Hash},
})
```

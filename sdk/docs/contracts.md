# Integration Contracts

The SDK defines typed contracts for data exchanged between opensecstack platforms. These contracts ensure that data produced by one platform (e.g. APIGuard) can be consumed by another (e.g. NIS2Compass) without custom transformation code.

---

## Contract Overview

| Contract | Producer | Consumer | Purpose |
|----------|---------|---------|---------|
| `ScanResult` | APIGuard | NIS2Compass, IRFlow, CITADEL | API security scan output |
| `IOCBundle` | ThreatFlow, APIGuard | IRFlow, NIS2Compass | Indicators of compromise |
| `IncidentRecord` | IRFlow | NIS2Compass, CITADEL | Security incident lifecycle |
| `ComplianceAssessment` | NIS2Compass | IRFlow, audit systems | NIS2 compliance state |
| `NIS2AuditEntry` | NIS2Compass | CITADEL WORM log | Audit trail entry |
| `AuditEntry` | Any platform | CITADEL WORM log | Generic audit event |

---

## ScanResult

Produced by APIGuard when a scan completes. Contains all findings and summary statistics.

```go
// Go
type ScanResult struct {
    ScanID      string     `json:"scan_id"`
    Target      string     `json:"target"`
    SpecHash    string     `json:"spec_hash"`
    StartedAt   time.Time  `json:"started_at"`
    CompletedAt time.Time  `json:"completed_at"`
    Status      string     `json:"status"`       // "completed" | "failed" | "cancelled"
    Findings    []Finding  `json:"findings"`
    Stats       ScanStats  `json:"stats"`
    Modules     []string   `json:"modules"`
}

type Finding struct {
    ID          string            `json:"id"`
    Severity    string            `json:"severity"`  // "critical" | "high" | "medium" | "low" | "info"
    OWASP       string            `json:"owasp"`     // "a1_bola" through "a10_unsafe_consumption"
    Title       string            `json:"title"`
    Description string            `json:"description"`
    Endpoint    string            `json:"endpoint"`
    Method      string            `json:"method"`
    Evidence    map[string]any    `json:"evidence"`
    CVSS        *CVSSScore        `json:"cvss,omitempty"`
    Remediation string            `json:"remediation"`
}

type ScanStats struct {
    Total    int `json:"total"`
    Critical int `json:"critical"`
    High     int `json:"high"`
    Medium   int `json:"medium"`
    Low      int `json:"low"`
    Info     int `json:"info"`
}
```

```python
# Python
@dataclass
class ScanResult:
    scan_id: str
    target: str
    spec_hash: str
    started_at: datetime
    completed_at: datetime
    status: str
    findings: list[Finding]
    stats: ScanStats
    modules: list[str]
```

---

## IOCBundle

Indicators of compromise, produced by ThreatFlow or APIGuard and consumed by IRFlow.

```go
type IOCBundle struct {
    BundleID    string    `json:"bundle_id"`
    Source      string    `json:"source"`
    Severity    string    `json:"severity"`
    CreatedAt   time.Time `json:"created_at"`
    IOCs        []IOC     `json:"iocs"`
    Context     string    `json:"context"`
    ScanRef     string    `json:"scan_ref,omitempty"`
}

type IOC struct {
    Type  string `json:"type"`   // "ip", "domain", "url", "hash", "cve"
    Value string `json:"value"`
    Confidence int `json:"confidence"` // 0–100
}
```

---

## IncidentRecord

Security incident lifecycle, produced by IRFlow.

```go
type IncidentRecord struct {
    IncidentID  string    `json:"incident_id"`
    Title       string    `json:"title"`
    Severity    string    `json:"severity"`   // "P1" | "P2" | "P3" | "P4"
    Status      string    `json:"status"`     // "open" | "investigating" | "contained" | "closed"
    ProjectID   string    `json:"project_id"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
    ClosedAt    *time.Time `json:"closed_at,omitempty"`
    RootCause   string    `json:"root_cause,omitempty"`
    WORMEntryID string    `json:"worm_entry_id,omitempty"`
}
```

---

## ComplianceAssessment

NIS2 compliance state, produced by NIS2Compass.

```go
type ComplianceAssessment struct {
    AssessmentID     string            `json:"assessment_id"`
    OrgID            string            `json:"org_id"`
    Title            string            `json:"title"`
    FrameworkVersion string            `json:"framework_version"`
    Status           string            `json:"status"`
    Controls         []ControlSummary  `json:"controls"`
    Stats            AssessmentStats   `json:"stats"`
    CreatedAt        time.Time         `json:"created_at"`
    UpdatedAt        time.Time         `json:"updated_at"`
}

type ControlSummary struct {
    MeasureRef string `json:"measure_ref"`
    Status     string `json:"status"`
    EvidenceCount int `json:"evidence_count"`
}
```

---

## AuditEntry / NIS2AuditEntry

Audit log entries for CITADEL WORM log emission.

```go
type AuditEntry struct {
    Source    string         `json:"source"`
    EventType string         `json:"event_type"`
    ProjectID string         `json:"project_id"`
    TsUTC     time.Time      `json:"ts_utc"`
    Payload   map[string]any `json:"payload"`
}

type NIS2AuditEntry struct {
    AuditEntry
    AssessmentID string `json:"assessment_id"`
    ControlRef   string `json:"control_ref"`
    Action       string `json:"action"`       // "control_updated", "evidence_uploaded", etc.
    ActorID      string `json:"actor_id"`
    ArtifactHash string `json:"artifact_hash,omitempty"`
}
```

---

## Using Contracts for Cross-Platform Integration

### APIGuard → NIS2Compass (via SDK)

```go
// 1. Get scan result from APIGuard
result, _ := apiguard.GetScan(ctx, scanID)

// 2. Export as NIS2 evidence bundle (ScanResult → NIS2Evidence)
bundle, _ := apiguard.ExportNIS2Evidence(ctx, scanID)

// 3. Upload to NIS2Compass — bundle satisfies the evidence contract
artifact, _ := nis2compass.UploadArtifact(ctx, orgID, bundle)

// 4. Patch the relevant NIS2 control
nis2compass.PatchControl(ctx, orgID, assessmentID, "art21_e", &PatchControlRequest{
    Status:       "compliant",
    EvidenceRefs: []string{artifact.Hash},
})
```

### APIGuard → CITADEL WORM log

```go
result, _ := apiguard.GetScan(ctx, scanID)

// Convert ScanResult to AuditEntry
entry := &opensecstack.AuditEntry{
    Source:    "apiguard",
    EventType: "scan_completed",
    ProjectID: "ABISSNET_TCL_001",
    TsUTC:     result.CompletedAt,
    Payload: map[string]any{
        "scan_id":          result.ScanID,
        "spec_hash":        result.SpecHash,
        "findings_summary": result.Stats,
    },
}

citadel.EmitWORM(ctx, entry)
```

---

## Contract Versioning

Contracts are versioned by the SDK package version. Breaking changes increment the minor version. See [migration.md](migration.md) for upgrade guidance between versions.

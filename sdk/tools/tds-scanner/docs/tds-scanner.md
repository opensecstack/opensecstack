# tds-scanner Documentation

tds-scanner measures and validates Time Dimension Segmentation (TDS) compliance for opensecstack platform deployments. It verifies that each operation falls within its expected latency tier.

---

## TDS Tiers

| Tier | Latency bound | Operations |
|------|--------------|-----------|
| Second hand | < 300ms | Real-time checks, per-request operations, status polls |
| Minute hand | 300ms – 30s | Report generation, standard scans (small specs), VIGIL_REALTIME (planned) |
| Hour hand | > 30s | Full large-spec scans, VIGIL_DEEP (planned), batch analytics |

Operations that exceed their tier boundary are flagged as TDS violations. A TDS violation does not mean the system is broken — it means an operation is taking longer than its contract allows.

---

## Installation

```bash
go install github.com/opensecstack/sdk/tools/tds-scanner@latest
```

Or build from source:

```bash
cd sdk/tools/tds-scanner
go build -o tds-scanner .
```

---

## Commands

### `tds-scanner scan`

Runs a TDS compliance scan against a platform deployment.

```bash
tds-scanner scan [flags]
```

Flags:

| Flag | Required | Default | Description |
|------|---------|---------|-------------|
| `--target` | Yes | — | Platform base URL |
| `--api-key` | Yes | — | API key for the platform |
| `--platform` | No | `apiguard` | Platform type: `apiguard`, `nis2compass`, `citadel` |
| `--iterations` | No | `5` | Number of times to run each operation (median is reported) |
| `--output` | No | `text` | Output format: `text`, `json`, `junit` |
| `--fail-on-violation` | No | `false` | Exit with code 1 if any TDS violation is found |
| `--timeout` | No | `300s` | Maximum total scan duration |

### `tds-scanner report`

Generates a detailed report from a previous scan's JSON output.

```bash
tds-scanner scan --output json > scan.json
tds-scanner report --input scan.json --format html > report.html
```

### `tds-scanner baseline`

Records a baseline of current operation latencies for comparison in future scans.

```bash
tds-scanner baseline --target https://apiguard.internal --api-key $KEY --save baseline.json
tds-scanner scan --target ... --compare-baseline baseline.json
```

---

## Operations Tested Per Platform

### APIGuard

| Operation | TDS tier | Test method |
|-----------|---------|------------|
| `GET /api/v1/health` | Second hand | Single request |
| `POST /api/v1/scans` (start) | Second hand | Submit minimal spec |
| `GET /api/v1/scans/{id}` | Second hand | Status poll |
| `GET /api/v1/scans/{id}/findings` | Second hand | Fetch result |
| Report generation (HTML) | Minute hand | Trigger report, wait |
| Report generation (PDF) | Minute hand | Trigger report, wait |
| Full scan — small spec (<50 endpoints) | Minute hand | End-to-end scan |
| Full scan — large spec (>200 endpoints) | Hour hand | End-to-end scan |

### NIS2Compass

| Operation | TDS tier | Test method |
|-----------|---------|------------|
| `GET /api/v1/health` | Second hand | Single request |
| `GET /api/v1/organisations` | Second hand | List request |
| `GET /api/v1/assessments/{id}` | Second hand | Fetch assessment |
| `PATCH /api/v1/controls/{id}` | Second hand | Update control |
| Evidence artifact upload | Minute hand | Upload test file |
| Audit log retrieval (full period) | Minute hand | Fetch all entries |

### CITADEL

| Operation | TDS tier | Test method |
|-----------|---------|------------|
| `GET /api/v1/vigil/status` (planned — VIGIL is design-stage, ships CITADEL v2.0) | Second hand | Single poll |
| `POST /api/v1/marshal/evaluate` (dry-run) | Second hand | Dry-run Kerkese |
| `GET /api/v1/augur/advisory` | Second hand | Advisory fetch |
| Chain anchor age check | Minute hand | Anchor status |
| `POST /api/v1/worm/verify` (7-day window) | Hour hand | Chain verify |
| VIGIL_DEEP (planned, on-demand) | Hour hand | Full audit scan |

---

## Output Formats

### Text (default)

Human-readable table with pass/fail per operation.

### JSON

```json
{
  "scan_id": "uuid",
  "ts_utc": "2026-03-30T14:00:00Z",
  "platform": "apiguard",
  "target": "https://apiguard.internal",
  "operations": [
    {
      "name": "scan_start",
      "tier": "second-hand",
      "tier_bound_ms": 300,
      "measured_ms": 87,
      "iterations": 5,
      "median_ms": 87,
      "p95_ms": 102,
      "status": "PASS"
    }
  ],
  "summary": {
    "total": 9,
    "pass": 9,
    "fail": 0,
    "tds_compliant": true
  }
}
```

### JUnit XML

Compatible with CI/CD systems (Jenkins, GitHub Actions, GitLab CI):

```xml
<testsuite name="tds-scanner" tests="9" failures="0">
  <testcase name="scan_start" classname="apiguard.second-hand" time="0.087"/>
  ...
</testsuite>
```

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: TDS compliance scan
  run: |
    tds-scanner scan \
      --target ${{ secrets.APIGUARD_URL }} \
      --api-key ${{ secrets.APIGUARD_KEY }} \
      --output junit \
      --fail-on-violation \
      > tds-results.xml

- name: Publish TDS results
  uses: mikepenz/action-junit-report@v4
  with:
    report_paths: tds-results.xml
```

### GitLab CI

```yaml
tds-scan:
  script:
    - tds-scanner scan --target $APIGUARD_URL --api-key $APIGUARD_KEY --output junit > tds-results.xml
  artifacts:
    reports:
      junit: tds-results.xml
```

---

## Interpreting Results

### TDS violation — second-hand operation exceeds 300ms

The operation is consistently slower than its tier bound. Common causes:
- Database query not using an index
- Network latency between tds-scanner and the platform (scan from inside the same network)
- Platform under load — run during off-peak or with `--iterations 1`

### TDS violation — minute-hand operation exceeds 30s

The operation has drifted into hour-hand territory. Common causes:
- Large spec / large dataset — expected for very large inputs
- Blocking I/O in report generation
- Missing async processing for report jobs

### All operations pass but with high p95

The median passes but p95 is close to the tier bound. Indicates occasional spikes. Monitor in production with Prometheus metrics.

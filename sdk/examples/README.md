# SDK Examples

Runnable examples showing common workflows for the opensecstack Go and Python SDKs.

```
examples/
├── go/
│   ├── scan_and_report/     Full APIGuard scan lifecycle (Go)
│   └── nis2_assessment/     NIS2 Compass assessment workflow (Go)
└── python/
    ├── scan_and_report.py   Full APIGuard scan lifecycle (Python)
    └── nis2_assessment.py   NIS2 Compass assessment workflow (Python)
```

---

## Prerequisites

### Go examples

- Go 1.22 or later
- The `github.com/opensecstack/sdk` module (already in `sdk/go/go.mod`)

### Python examples

- Python 3.10 or later
- The `opensecstack-sdk` package installed in the current environment:

  ```bash
  pip install -e sdk/python
  ```

---

## Environment variables

### APIGuard examples

| Variable | Required | Description |
|---|---|---|
| `APIGUARD_URL` | Yes | Base URL of your APIGuard instance, e.g. `https://apiguard.example.com` |
| `APIGUARD_API_KEY` | Yes | API key issued by the platform |
| `APIGUARD_SPEC_URL` | No | OpenAPI spec URL to scan (default: Petstore 3.0 demo) |
| `APIGUARD_TARGET` | No | Target base URL; derived from `APIGUARD_SPEC_URL` host when omitted |

### NIS2 Compass examples

| Variable | Required | Description |
|---|---|---|
| `NIS2_URL` | Yes | Base URL of your NIS2 Compass instance, e.g. `https://nis2.example.com` |
| `NIS2_API_KEY` | Yes | API key issued by the platform |
| `NIS2_ORG_NAME` | No | Organisation display name (default: `"Example Organisation"`) |
| `NIS2_ORG_COUNTRY` | No | ISO 3166-1 alpha-2 country code (default: `DE`) |

---

## Running the examples

### Go: APIGuard scan and report

```bash
export APIGUARD_URL=https://apiguard.example.com
export APIGUARD_API_KEY=your-api-key

go run ./sdk/examples/go/scan_and_report
```

What it does:
1. Creates an `APIGuardClient` with `MaxRetries: 3` and `RetryWaitBase: 500ms`.
2. Starts a scan against the configured spec URL.
3. Polls every 5 seconds until the scan reaches `completed` or `failed` (timeout: 10 minutes).
4. Streams the JSON report to `report-<scan-id>.json` without buffering in memory.
5. Fetches findings and prints a severity breakdown to stdout.

### Go: NIS2 Compass assessment

```bash
export NIS2_URL=https://nis2.example.com
export NIS2_API_KEY=your-api-key

go run ./sdk/examples/go/nis2_assessment
```

What it does:
1. Creates a `NIS2CompassClient` with retry options.
2. Registers a new organisation.
3. Creates a NIS2 assessment (the server auto-seeds Article 21(2) controls a–j).
4. Streams the SARIF report to `nis2-assessment-<id>.sarif`.

### Python: APIGuard scan and report

```bash
export APIGUARD_URL=https://apiguard.example.com
export APIGUARD_API_KEY=your-api-key

python sdk/examples/python/scan_and_report.py
```

What it does:
1. Creates an `APIGuardClient`.
2. Starts a scan against the configured spec URL.
3. Polls every 5 seconds until the scan completes (timeout: 10 minutes).
4. Streams the JSON report to `report-<scan-id>.json` using `stream_report()`.
5. Fetches findings and prints a severity summary via `collections.Counter`.

### Python: NIS2 Compass assessment

```bash
export NIS2_URL=https://nis2.example.com
export NIS2_API_KEY=your-api-key

python sdk/examples/python/nis2_assessment.py
```

What it does:
1. Creates a `NIS2CompassClient`.
2. Registers a new organisation.
3. Creates a NIS2 assessment under that organisation.
4. Streams the SARIF report to `nis2-assessment-<id>.sarif` using `stream_report()`.

---

## Output files

Each example writes one or more files to the current working directory:

| Example | Output file |
|---|---|
| Go/Python scan_and_report | `report-<scan-id>.json` |
| Go/Python nis2_assessment | `nis2-assessment-<assessment-id>.sarif` |

---

## Notes

- All examples read credentials exclusively from environment variables; no secrets are hard-coded.
- The Go examples are standalone `main` packages and do not require any additional `go.mod` setup beyond the SDK module.
- The Python NIS2 example creates real objects on the server. Pass the printed UUIDs to `delete_assessment()` / `delete_organisation()` to clean up test data afterwards.

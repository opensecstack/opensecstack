# tds-scanner

A CLI tool that analyses opensecstack platform integrations for Time Dimension Segmentation (TDS) compliance.

TDS is the principle that different types of operations should be bounded by latency tiers matching their urgency. tds-scanner measures actual operation latencies and reports whether they fall within the correct TDS tier.

See [docs/tds-scanner.md](docs/tds-scanner.md) for full documentation.

---

## Quick Start

```bash
# Install
go install github.com/opensecstack/sdk/tools/tds-scanner@latest

# Scan an APIGuard deployment
tds-scanner scan --target https://apiguard.internal --api-key $APIGUARD_KEY

# Scan a NIS2Compass deployment
tds-scanner scan --target https://nis2compass.internal --api-key $NIS2_KEY --platform nis2compass

# Scan CITADEL
tds-scanner scan --target https://citadel.internal --api-key $CITADEL_KEY --platform citadel
```

## Output Example

```
TDS Scan — apiguard @ https://apiguard.internal
──────────────────────────────────────────────
Operation                         Measured   Tier         Status
scan_start                        87ms       second-hand  PASS  (<300ms)
scan_status_poll                  12ms       second-hand  PASS
scan_result_fetch                 234ms      second-hand  PASS
spec_parse (Rust subprocess)      43ms       second-hand  PASS
db_write_finding                  18ms       second-hand  PASS
report_generate_html              1.2s       minute-hand  PASS  (300ms–30s)
report_generate_pdf               3.4s       minute-hand  PASS
full_scan_small_spec              8.1s       minute-hand  PASS
full_scan_large_spec              47s        hour-hand    PASS  (>30s)

TDS compliance: PASS (9/9 operations within tier bounds)
```

## License

Apache-2.0

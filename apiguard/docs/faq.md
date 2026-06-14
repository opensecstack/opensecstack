# APIGuard FAQ

---

**Does APIGuard modify data on the target API?**

APIGuard sends test requests to the target API. Some tests intentionally submit unexpected values (extra fields for mass assignment testing, malformed tokens for auth testing). APIGuard does not attempt to delete records or modify persistent state beyond what is required to confirm a vulnerability. Do not run APIGuard against a production database without read-only test accounts where possible.

---

**Can I scan a production API?**

Yes, with precautions. Use a test account with limited data scope. Set `scanner.rate_limit_rps` low enough to avoid triggering the API's own rate limiter. Review and disable `a6_business_flow` which tests sensitive business operations. Most teams run APIGuard against a staging environment that mirrors production.

---

**What happens to my auth tokens?**

Auth tokens are held in memory for the duration of the scan and then discarded. They are never written to the database, log files, or reports. The evidence block in findings redacts token values — they appear as `<token>` in stored evidence.

---

**My API has no OpenAPI spec. Can I still scan it?**

Partially. Options:
- Export a Postman collection — APIGuard can convert it to an IR
- Provide a HAR file captured from a browser session
- Use `a9_inventory` module alone to probe for undocumented endpoints

Full OWASP module coverage requires a schema. Without a schema, only the inventory and misconfiguration modules run meaningfully.

---

**What GraphQL support exists?**

GraphQL introspection schemas are supported by the Rust parser. APIGuard extracts queries, mutations, and field types into the IR. OWASP modules that apply to GraphQL (auth, BOLA via query field manipulation, rate limiting) run against GraphQL endpoints. Coverage is lower than for REST APIs — see [OWASP Coverage](owasp-coverage.md) for the GraphQL support matrix.

---

**What is the false positive rate?**

False positive rates vary by OWASP category. BOLA (A1) and auth (A2) tests have low false positive rates because they observe concrete access control failures. Mass assignment (A3) and misconfiguration (A8) tests are higher — some APIs intentionally accept extra fields. Use the triage workflow to mark false positives. Over time, use suppression rules to exclude known-good patterns. See [User Guide](user-guide.md) for the suppression syntax.

---

**Which OWASP API Security Top 10 version does APIGuard use?**

APIGuard targets the 2023 edition (API1:2023 through API10:2023). The 2019 edition IDs (API1 through API10) map directly in most cases. See [OWASP Coverage](owasp-coverage.md) for the full mapping between 2019 and 2023 categories.

---

**How do I integrate APIGuard results with GitHub Advanced Security?**

Use SARIF output and the GitHub code scanning upload action:

```yaml
- name: Run APIGuard
  run: |
    apiguard scan --spec ./openapi.yaml --target ${{ secrets.API_URL }} \
      --format sarif --output apiguard.sarif --fail-on NONE

- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: apiguard.sarif
```

Using `--fail-on NONE` lets the pipeline continue even with findings so the SARIF upload step always runs.

---

**What is the difference between the CLI and the dashboard?**

The CLI is for one-shot scans — run a scan, get a report, exit. Use it in CI/CD pipelines. The dashboard provides persistent scan history, finding trends over time, API inventory, and team management. The CLI can write results to the database for later viewing in the dashboard by setting `APIGUARD_DB_URL`.

---

**What permissions does APIGuard need on the target API?**

APIGuard needs the same permissions your API users have. For BOLA testing, provide two accounts — one to make the request and one whose data will be probed. For admin endpoint testing (A5), provide an admin token. Read-only accounts reduce the risk of test data pollution.

---

**Can I exclude specific endpoints from scanning?**

Yes. Use suppression rules in the config file:

```yaml
suppress:
  - endpoint: "/api/v1/internal/*"
    method: "*"
    reason: "Internal endpoints excluded from external scan scope"
```

You can also limit which modules run per endpoint using the `endpoint_overrides` block.

---

**How long does a scan take?**

Scan duration depends on the number of endpoints and the target API's response time. Reference benchmarks:

| API Size | Endpoints | Typical Duration |
|----------|-----------|-----------------|
| Small | < 20 | 30–90 seconds |
| Medium | 20–100 | 2–8 minutes |
| Large | 100–500 | 8–30 minutes |

The Rust parser processes even large specs in under 1 second. Scan time is dominated by HTTP round-trips to the target.

---

**Can I run APIGuard against multiple environments in parallel?**

Yes. Run multiple `apiguard scan` processes simultaneously — each is independent. If writing to the database, each scan creates its own `scan` record. Use tags or spec metadata to distinguish results from different environments.

---

**Does APIGuard support multi-environment scanning (dev/staging/prod) from the same config?**

Use environment variables to override the target URL and auth token per environment:

```bash
APIGUARD_TARGET=https://api.staging.example.com \
APIGUARD_AUTH_TOKEN=$STAGING_TOKEN \
apiguard scan --spec ./openapi.yaml
```

---

**Does APIGuard send my API schema or target URL to any external service?**

No. All scanning is local. APIGuard does not phone home. The only external communication is to your configured target API, your configured CITADEL/NIS2Compass/IRFlow endpoints, and optional OAST (Out-of-Band Application Security Testing) infrastructure you control.

---

**Where is the SBOM?**

The `SBOM.json` file in the repository root is updated with each release. It lists all Go and Rust dependencies with their versions and licences in CycloneDX format.

---

**What licence is APIGuard under?**

Apache 2.0. See [LICENSE](../LICENSE). The patent grant in Apache 2.0 protects users from patent claims by contributors. Commercial use is permitted without restriction.

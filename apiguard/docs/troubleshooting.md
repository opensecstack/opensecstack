# Troubleshooting

This guide covers common issues encountered when installing, configuring, and running APIGuard. Each section is organized as a problem-cause-solution table.

---

## Installation Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| `apiguard: command not found` after install | Binary not in `$PATH`, or install did not complete | Verify the install location (`which apiguard` or `where apiguard`). Add the install directory to your `PATH`. If installed via `go install`, ensure `$GOPATH/bin` is on your `PATH`. |
| Rust build fails with toolchain errors | Outdated Rust toolchain or missing components | Run `rustup update` to update to the latest stable toolchain. If the error mentions a specific component, install it with `rustup component add <component>`. |
| Rust build fails with linker errors | Missing C linker or build essentials | Install a C toolchain: `sudo apt install build-essential` (Debian/Ubuntu), `xcode-select --install` (macOS), or install Visual Studio Build Tools (Windows). |
| Go module errors during build | Stale or inconsistent module cache | Run `go mod tidy` in the project root to resolve dependency issues. If the problem persists, clear the module cache with `go clean -modcache` and retry. |

---

## Parser Errors

| Problem | Cause | Solution |
|---------|-------|----------|
| `invalid OpenAPI specification` | The spec file is malformed or does not conform to the OpenAPI standard | Validate your spec before scanning. Use `swagger-cli validate openapi.yaml` or `openapi-generator-cli validate -i openapi.yaml`. Fix all reported errors and re-run. |
| `circular $ref exceeds depth 10` | The spec contains circular `$ref` references that exceed the parser's maximum recursion depth | Refactor the spec to break circular references. Extract shared schemas into standalone definitions and reference them without creating loops. If the circularity is intentional, consider flattening the spec with `swagger-cli bundle openapi.yaml -o flat.yaml`. |
| `schema too large: exceeds max spec size` | The spec file exceeds the default maximum size limit | Increase the limit in your configuration: set `scanner.max_spec_size_mb` to a higher value (e.g., `scanner.max_spec_size_mb = 50`) in `apiguard.toml`, or pass `--max-spec-size-mb 50` on the command line. |
| `unsupported specification version` | The spec uses a version that APIGuard does not support | APIGuard supports OpenAPI 3.0.x, OpenAPI 3.1.x, and Swagger 2.0. Convert older specs to a supported version using `swagger2openapi` or the Swagger Editor. |

---

## Scan Errors

| Problem | Cause | Solution |
|---------|-------|----------|
| `target unreachable` or connection refused | The target URL is incorrect, the service is down, or a firewall is blocking the connection | Verify the target URL is correct and the service is running. Test connectivity with `curl <target-url>`. Check firewall rules and DNS resolution (`nslookup <hostname>`). |
| All requests return `401 Unauthorized` or `403 Forbidden` | Authentication is misconfigured or credentials are invalid | Verify your auth configuration. Check that `--auth-token` contains a valid, non-expired token. Confirm `--auth-type` matches what the target expects (e.g., `bearer`, `basic`, `api-key`). Test manually with `curl -H "Authorization: Bearer <token>" <target-url>`. |
| `scan timeout exceeded` | The target is slow to respond or the scan scope is too large | Increase the timeout with `--timeout 120` (seconds). Reduce parallelism with `--concurrency 5` to lower load on the target. Consider scanning a subset of endpoints. |
| `rate limited by target (HTTP 429)` | The scan is sending requests faster than the target allows | Reduce concurrency with `--concurrency 2`. Add request delays with `--request-delay 500` (milliseconds). Some targets publish rate limit headers; APIGuard will respect `Retry-After` when present. |
| SSL/TLS certificate errors | The target uses a self-signed or untrusted certificate | Use `--tls-skip-verify` to skip TLS verification for self-signed certificates. For custom CA certificates, use `--ca-cert /path/to/ca.pem`. Do not use `--tls-skip-verify` in production environments. |

---

## Auth Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| `JWT expired` errors mid-scan | The JWT token expires before the scan completes | APIGuard supports automatic token refresh. Ensure your auth configuration includes `refresh_token` or `token_url` for re-authentication. If using a static token, generate one with a longer lifetime (e.g., `--token-lifetime 3600`). |
| OAuth2 flow fails with `invalid_client` | The OAuth2 client credentials are incorrect or the token endpoint is wrong | Verify `client_id`, `client_secret`, and `token_url` in your auth configuration. Test the flow manually: `curl -X POST <token_url> -d "grant_type=client_credentials&client_id=<id>&client_secret=<secret>"`. |
| API key not sent with requests | The `--auth-header` flag is missing or incorrectly formatted | Specify the header name explicitly: `--auth-header "X-API-Key"` along with `--auth-token "<key-value>"`. Verify the header name matches what the target API expects (check the spec's `securitySchemes`). |

---

## Report Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| PDF generation fails | WeasyPrint or its system dependencies are not installed | Install WeasyPrint and its dependencies: `pip install weasyprint`. On Linux, install required system libraries: `sudo apt install libpango-1.0-0 libgdk-pixbuf2.0-0 libffi-dev libcairo2`. On macOS: `brew install pango libffi`. |
| SARIF upload rejected by GitHub | The SARIF file is malformed or exceeds GitHub's size limit | Validate the SARIF output with `sarif-tools validate report.sarif`. Ensure the file is under GitHub's 10 MB limit. If the file is too large, reduce findings by applying severity filters during the scan: `--min-severity medium`. |

---

## Database Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| `connection refused` when starting the server | PostgreSQL is not running or `APIGUARD_DB_URL` is incorrect | Verify PostgreSQL is running: `pg_isready` or `systemctl status postgresql`. Check the connection string in `APIGUARD_DB_URL` (format: `postgres://user:password@host:port/dbname`). Ensure the database exists and the user has access. |
| Migration fails with version mismatch | The database schema is out of sync with the application version | Run `make migrate` to apply pending migrations. If migrations are in a broken state, check the `schema_migrations` table for a `dirty` flag and resolve it manually. After fixing, run `make migrate` again. |

---

## Docker Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| `port already in use` on container start | Another process is bound to the same port | Identify the conflicting process: `lsof -i :<port>` (Linux/macOS) or `netstat -ano | findstr :<port>` (Windows). Either stop the conflicting process or change the port mapping in `.env` or `docker-compose.yml` (e.g., `APIGUARD_PORT=8081`). |
| `no space left on device` | Docker images, containers, or volumes have consumed available disk space | Run `docker system prune` to remove unused containers, networks, and images. For a more aggressive cleanup: `docker system prune -a --volumes`. Check available disk space with `df -h`. |
| Container exits immediately or won't start | Configuration error, missing environment variable, or dependency not ready | Check container logs: `docker compose logs apiguard`. Look for missing environment variables or connection errors. Ensure dependent services (PostgreSQL, Redis) are healthy: `docker compose ps`. Restart with `docker compose up -d`. |

---

## CI/CD Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| GitHub Action fails with unclear error | Misconfigured inputs or missing secrets | Verify the action inputs: `spec_path` must point to a valid spec file in the repository, `target_url` must be reachable from the runner. Ensure secrets (`APIGUARD_AUTH_TOKEN`, etc.) are configured in the repository settings under Settings > Secrets and variables > Actions. |
| Exit code 2 (unexpected failure) | APIGuard encountered a runtime error (not a findings result) | Exit code 2 indicates an operational error (invalid config, unreachable target, parse failure). Check the action logs for the specific error message and resolve accordingly. Exit code 1 indicates the scan succeeded but findings exceeded the configured threshold -- this is expected behavior. |
| Baseline comparison reports no diff | The baseline file path is wrong or the file format is incompatible | Verify the `--baseline` path is correct and accessible from the working directory. The baseline file must be a valid APIGuard JSON report generated by a previous scan. Regenerate it with `apiguard scan --format json -o baseline.json` if needed. |

---

## Debug Mode

When troubleshooting issues that are not covered above, enable detailed logging to gather more information.

### CLI Verbose Output

Add the `--verbose` flag to any `apiguard` command for detailed console output:

```bash
apiguard scan --spec openapi.yaml --target https://api.example.com --verbose
```

This prints request/response details, timing information, and internal decision-making to stderr.

### Server Debug Logging

Set the log level to `debug` for the APIGuard server:

```bash
export APIGUARD_LOG_LEVEL=debug
apiguard server
```

Or in `apiguard.toml`:

```toml
[logging]
level = "debug"
```

### Request/Response Logging

To capture full HTTP request and response bodies during a scan (useful for diagnosing auth or payload issues):

```bash
apiguard scan --spec openapi.yaml --target https://api.example.com --log-requests --log-dir ./scan-logs
```

This writes each request/response pair to a file in the specified directory. Review these files to verify headers, payloads, and response codes.

**Note:** Request logging may capture sensitive data (tokens, credentials, PII). Do not enable it in shared or production environments, and delete log files after debugging.

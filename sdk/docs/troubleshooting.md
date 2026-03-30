# SDK Troubleshooting Guide

Common issues encountered when integrating the opensecstack Python, Go, and Rust SDKs, with symptoms, root causes, and copy-paste solutions for each language.

---

## 1. Authentication Failures

### Symptom

```
AuthenticationError: Invalid API key — cannot obtain JWT
AuthenticationError: Invalid or missing credentials
```

Or a `401 Unauthorized` returned immediately on the first request.

### Cause

- The API key or client credentials (client_id / client_secret) are wrong, revoked, or belong to a different environment (e.g., staging key used against production).
- The `base_url` points to the wrong environment or includes an extra path prefix (e.g., `https://apiguard.internal/api/v1` instead of `https://apiguard.internal`).
- The token endpoint path is incorrect — the SDK always appends `/api/v1/auth/token`; if your deployment changes this path, override `base_url` accordingly.

### Solution

**Python**

```python
from opensecstack import APIGuardClient
from opensecstack.exceptions import AuthenticationError

try:
    # base_url must NOT include /api/v1
    client = APIGuardClient(
        base_url="https://apiguard.internal",   # correct
        api_key="ag_live_...",
    )
    client.list_scans()
except AuthenticationError as e:
    print(f"Auth failed: {e}")
    # Check: correct key? correct base_url? key not expired?
```

**Go**

```go
client, err := apiguard.NewClient(
    "https://apiguard.internal",  // no trailing /api/v1
    "ag_live_...",
)
if err != nil {
    log.Fatalf("auth error: %v", err)
}
```

**Rust**

```rust
let client = ApiGuardClient::builder()
    .base_url("https://apiguard.internal")
    .api_key("ag_live_...")
    .build()?;
```

---

## 2. Rate Limit Errors

### Symptom

```
RateLimitError: rate limited (retry_after=300)
```

Requests succeed for a while, then suddenly stop with HTTP 429.

### Cause

The server is enforcing a per-key request quota. The `Retry-After` header in the response tells you how many seconds to wait. The SDK auto-retries once if `Retry-After <= 60`; for longer waits it raises `RateLimitError` immediately so your process is not silently blocked.

### Solution

**Python**

```python
import time
from opensecstack.exceptions import RateLimitError

for attempt in range(3):
    try:
        result = client.list_scans()
        break
    except RateLimitError as e:
        if e.retry_after and e.retry_after <= 300:
            print(f"Rate limited — sleeping {e.retry_after}s")
            time.sleep(e.retry_after)
        else:
            raise  # retry_after too long; escalate
```

**Go**

```go
import "errors"

result, err := client.ListScans(ctx)
var rlErr *apiguard.RateLimitError
if errors.As(err, &rlErr) {
    time.Sleep(time.Duration(rlErr.RetryAfter) * time.Second)
    result, err = client.ListScans(ctx)
}
```

**Rust**

```rust
use opensecstack::Error;
use tokio::time::{sleep, Duration};

match client.list_scans().await {
    Err(Error::RateLimit { retry_after }) => {
        sleep(Duration::from_secs(retry_after)).await;
        client.list_scans().await?;
    }
    other => { other?; }
}
```

---

## 3. TLS Certificate Errors

### Symptom

```
httpx.ConnectError: [SSL: CERTIFICATE_VERIFY_FAILED]
requests.exceptions.SSLError: HTTPSConnectionPool ... certificate verify failed
```

Occurs when connecting to a local or staging server that uses a self-signed certificate.

### Cause

The SDK verifies TLS certificates by default (as required by security policy). Self-signed or internally-issued certificates are not trusted by the system CA store.

### Solution

> **Warning:** Disabling TLS verification removes protection against man-in-the-middle attacks. Use only in isolated development environments and never in production.

**Python (sync)**

```python
from opensecstack import APIGuardClient
import requests

client = APIGuardClient(base_url="https://dev.local", api_key="...")
client._session.verify = False  # dev only
```

**Python (async)**

```python
from opensecstack import AsyncAPIGuardClient

client = AsyncAPIGuardClient(
    base_url="https://dev.local",
    client_id="...",
    client_secret="...",
    verify_ssl=False,   # built-in parameter — dev only
)
```

**Go**

```go
import "crypto/tls"
import "net/http"

httpClient := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // dev only
    },
}
client, _ := apiguard.NewClientWithHTTP("https://dev.local", "...", httpClient)
```

**Rust**

```rust
let client = ApiGuardClient::builder()
    .base_url("https://dev.local")
    .api_key("...")
    .danger_accept_invalid_certs(true)  // dev only
    .build()?;
```

The proper fix for non-dev environments is to add the internal CA certificate to the system trust store, or to pass the CA bundle path to the SDK's TLS configuration.

---

## 4. Timeout Errors

### Symptom

```
httpx.ReadTimeout: timed out
requests.exceptions.ReadTimeout: HTTPSConnectionPool ... Read timed out
opensecstack::Error::Timeout
```

Often seen when downloading large PDF reports or waiting for a long-running scan to complete.

### Cause

The default per-request timeout is **30 seconds**. Large report downloads or slow scans exceed this budget.

### Solution

Increase the timeout at client construction time, or use a separate high-timeout client for report downloads.

**Python (sync)**

```python
from opensecstack import APIGuardClient

# 5-minute timeout for report downloads
report_client = APIGuardClient(
    base_url="https://apiguard.internal",
    api_key="...",
    timeout=300,
)
report = report_client.get_report(scan_id)
```

**Python (async)**

```python
from opensecstack import AsyncAPIGuardClient

async with AsyncAPIGuardClient(
    base_url="https://apiguard.internal",
    client_id="...",
    client_secret="...",
    timeout=300.0,
) as client:
    report = await client.get_report(scan_id)
```

**Go**

```go
client, _ := apiguard.NewClient(
    "https://apiguard.internal",
    "...",
    apiguard.WithTimeout(5*time.Minute),
)
```

**Rust**

```rust
let client = ApiGuardClient::builder()
    .base_url("https://apiguard.internal")
    .api_key("...")
    .timeout(Duration::from_secs(300))
    .build()?;
```

---

## 5. Streaming Errors

### Symptom

```
RuntimeError: response body already consumed
AttributeError: 'NoneType' object has no attribute 'read'
```

Or an empty/truncated file after `stream_report` / `GetReportStream`.

### Cause

- The destination file was opened in text mode (`"w"`) instead of binary mode (`"wb"`).
- The response object was consumed (`.json()` or `.text` called) before the stream was iterated.
- The context manager or streaming block was exited before all chunks were written.

### Solution

**Python (async)**

```python
import aiofiles
from opensecstack import AsyncNIS2CompassClient

async with AsyncNIS2CompassClient(base_url=..., client_id=..., client_secret=...) as client:
    async with aiofiles.open("report.pdf", "wb") as fh:   # binary mode is required
        await client.stream_report(
            assessment_id="...",
            format="pdf",
            dest=fh,
        )
```

**Go**

```go
f, err := os.Create("report.pdf")
if err != nil {
    return err
}
defer f.Close()

err = client.GetReportStream(ctx, assessmentID, "pdf", f)
```

**Rust**

```rust
use tokio::fs::File;
use tokio::io::BufWriter;

let file = File::create("report.pdf").await?;
let mut writer = BufWriter::new(file);
client.stream_report(assessment_id, "pdf", &mut writer).await?;
```

---

## 6. Token Refresh Race Conditions

### Symptom

Log lines like:

```
Token already refreshed by another thread; retrying request
```

Or sporadic 401 errors under concurrent load that resolve on retry.

### Cause

When multiple threads (or tasks) call the SDK simultaneously and the JWT is about to expire, they can each detect the token as stale and try to refresh concurrently. Without protection this causes redundant auth calls and can briefly set inconsistent token state.

### Solution

The SDK already handles this with a **double-checked locking** pattern: the first thread to acquire `_auth_lock` performs the refresh; any thread that acquires the lock afterwards sees the updated token and skips the refresh. The warning message is informational — it does not indicate a bug.

If you see this message frequently it means token lifetime is very short; increase it on the server or reduce request concurrency.

**Python — no extra code needed; the SDK handles this internally:**

```python
# Both of these run concurrently without double-refreshing
import asyncio
from opensecstack import AsyncAPIGuardClient

async def run():
    async with AsyncAPIGuardClient(base_url=..., client_id=..., client_secret=...) as client:
        results = await asyncio.gather(
            client.list_scans(),
            client.get_scan("scan-1"),
        )
```

**Go**

```go
// The Go client uses sync.Mutex internally; concurrent goroutines are safe.
var wg sync.WaitGroup
for i := 0; i < 10; i++ {
    wg.Add(1)
    go func() {
        defer wg.Done()
        _, _ = client.ListScans(ctx)
    }()
}
wg.Wait()
```

**Rust**

```rust
// The Rust client wraps token state in Arc<Mutex<...>>;
// cloning the Arc allows shared use across tasks.
let client = Arc::new(client);
let handles: Vec<_> = (0..10).map(|_| {
    let c = Arc::clone(&client);
    tokio::spawn(async move { c.list_scans().await })
}).collect();
for h in handles { h.await??; }
```

---

## 7. Webhook Signature Failures

### Symptom

```
WebhookSignatureError: HMAC mismatch — request may have been tampered with
```

Webhooks sent by APIGuard or NIS2 Compass are rejected by your handler.

### Cause

1. **Wrong secret** — the secret used to verify does not match what was registered on the platform.
2. **Body read twice** — many web frameworks (Flask, FastAPI, Express, Axum) consume the request body on the first read. If your middleware reads it before your webhook handler, the raw bytes passed to `verify_webhook_signature` are empty.
3. **Encoding mismatch** — the signature header is hex-encoded but your code base64-decodes it (or vice versa).
4. **Header name wrong** — the signature header is `X-OpenSecStack-Signature`, not `X-Hub-Signature-256`.

### Solution

**Python (FastAPI)**

```python
from fastapi import Request, HTTPException
from opensecstack.webhooks import verify_webhook_signature
from opensecstack.exceptions import WebhookSignatureError

WEBHOOK_SECRET = "wh_secret_..."

@app.post("/webhooks/apiguard")
async def handle_webhook(request: Request):
    raw_body = await request.body()   # read once, before any JSON parsing
    signature = request.headers.get("X-OpenSecStack-Signature", "")

    try:
        verify_webhook_signature(raw_body, signature, WEBHOOK_SECRET)
    except WebhookSignatureError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    payload = json.loads(raw_body)
    ...
```

**Go**

```go
func handleWebhook(w http.ResponseWriter, r *http.Request) {
    body, _ := io.ReadAll(r.Body)       // read once
    sig := r.Header.Get("X-OpenSecStack-Signature")

    if err := webhooks.VerifySignature(body, sig, webhookSecret); err != nil {
        http.Error(w, "invalid signature", http.StatusBadRequest)
        return
    }
    // parse body ...
}
```

**Rust (Axum)**

```rust
async fn handle_webhook(
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let sig = headers
        .get("x-opensecstack-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    if opensecstack::webhooks::verify_signature(&body, sig, WEBHOOK_SECRET).is_err() {
        return (StatusCode::BAD_REQUEST, "invalid signature").into_response();
    }
    // deserialize body ...
}
```

---

## 8. Connection Pooling

### Symptom

- High latency due to a new TCP/TLS handshake on every request.
- `ConnectionError: too many open files` under heavy concurrent load.
- Intermittent errors when reusing a client across threads.

### Cause

Each client instance owns an underlying connection pool (`requests.Session`, `net/http.Client`, or `reqwest::Client`). Creating a new SDK client per request throws away the pool and incurs full connection setup overhead. Sharing a single client across threads is safe as long as the SDK's internal lock guards token state (which it does).

### Solution

**Python — create once, share everywhere (thread-safe):**

```python
# module-level singleton
import functools
from opensecstack import APIGuardClient

@functools.lru_cache(maxsize=1)
def get_apiguard_client() -> APIGuardClient:
    return APIGuardClient(
        base_url=settings.APIGUARD_URL,
        api_key=settings.APIGUARD_KEY,
    )

# In request handlers:
client = get_apiguard_client()
result = client.list_scans()
```

**Python async — one client per event loop:**

```python
# In a FastAPI lifespan or startup handler:
from opensecstack import AsyncAPIGuardClient

_client: AsyncAPIGuardClient | None = None

async def startup():
    global _client
    _client = AsyncAPIGuardClient(
        base_url=settings.APIGUARD_URL,
        client_id=settings.CLIENT_ID,
        client_secret=settings.CLIENT_SECRET,
    )

async def shutdown():
    if _client:
        await _client._http.aclose()
```

**Go — pass the client in context or via dependency injection:**

```go
// Initialize once at startup, inject into handlers.
client, _ := apiguard.NewClient(url, key,
    apiguard.WithMaxIdleConns(50),
    apiguard.WithIdleConnTimeout(90*time.Second),
)
```

**Rust — wrap in `Arc` for multi-task sharing:**

```rust
// reqwest::Client internally uses an Arc; clone is cheap.
let client = Arc::new(
    ApiGuardClient::builder()
        .base_url(url)
        .api_key(key)
        .pool_max_idle_per_host(20)
        .build()?
);

// Share across Tokio tasks:
let c = Arc::clone(&client);
tokio::spawn(async move { c.list_scans().await });
```

> The async SDK clients (`AsyncAPIGuardClient`, `AsyncNIS2CompassClient`) are **not** `Send + Sync` by default in Python because they hold an asyncio Lock tied to a specific event loop. Use one client per event loop (e.g., one per Uvicorn worker process).

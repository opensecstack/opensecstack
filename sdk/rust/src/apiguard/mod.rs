pub mod types;
pub use types::*;

use crate::auth::{parse_jwt_exp, CachedToken, TokenCache};
use crate::error::{Error, Result};
use bytes::Bytes;
use reqwest::{multipart, Client, Method, Response};
use serde::{de::DeserializeOwned, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tracing::debug;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const REPORT_TIMEOUT: Duration = Duration::from_secs(120);
const DEFAULT_MAX_RETRIES: u32 = 2;
const DEFAULT_RETRY_BASE: Duration = Duration::from_millis(500);

/// Client for the APIGuard platform.
///
/// Provides a fully async, token-managed interface to the APIGuard REST API.
/// Authentication is handled automatically: the client exchanges the API key
/// for a JWT on the first request, caches it, and refreshes it proactively
/// before expiry (SDK-M5).
///
/// # Example
/// ```no_run
/// # #[tokio::main] async fn main() -> opensecstack::Result<()> {
/// use opensecstack::APIGuardClient;
///
/// let client = APIGuardClient::new("https://apiguard.example.com", "ak_live_…");
/// let scan = client.create_scan("https://api.example.com/openapi.json").await?;
/// println!("Scan started: {}", scan.id);
/// # Ok(()) }
/// ```
#[derive(Clone)]
pub struct APIGuardClient {
    pub(crate) base_url: String,
    pub(crate) api_key: String,
    pub(crate) http: Client,
    pub(crate) report_http: Client,
    pub(crate) token_cache: Arc<TokenCache>,
    pub(crate) max_retries: u32,
    pub(crate) retry_wait_base: Duration,
}

impl APIGuardClient {
    /// Creates a new client with default settings (30 s timeout, 2 retries).
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        let http = Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            // SDK-M4: prevent credential leakage through HTTP redirects.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build HTTP client");
        let report_http = Client::builder()
            .timeout(REPORT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build report HTTP client");
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_key: api_key.into(),
            http,
            report_http,
            token_cache: Arc::new(TokenCache::new(None)),
            max_retries: DEFAULT_MAX_RETRIES,
            retry_wait_base: DEFAULT_RETRY_BASE,
        }
    }

    /// Returns a builder for fully customised configuration.
    pub fn builder(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
    ) -> APIGuardClientBuilder {
        APIGuardClientBuilder::new(base_url, api_key)
    }

    // ---------- internal helpers ----------

    fn api_url(&self, path: &str) -> String {
        format!(
            "{}/api/v1/{}",
            self.base_url,
            path.trim_start_matches('/')
        )
    }

    // ---------- auth ----------

    async fn authenticate(&self) -> Result<String> {
        #[derive(Serialize)]
        struct TokenRequest<'a> {
            api_key: &'a str,
        }
        #[derive(serde::Deserialize)]
        struct TokenResponse {
            access_token: String,
            expires_in: Option<u64>,
        }

        let resp = self
            .http
            .post(self.api_url("auth/token"))
            .json(&TokenRequest {
                api_key: &self.api_key,
            })
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            return Err(Error::Auth(format!(
                "HTTP {status}: {}",
                body.get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
            )));
        }

        let token_resp: TokenResponse = resp.json().await?;
        let access_token = token_resp.access_token;

        // SDK-M5: parse the JWT exp claim for proactive refresh rather than
        // relying on a fixed TTL from the server.
        let expires_at = parse_jwt_exp(&access_token).unwrap_or_else(|| {
            use std::time::{SystemTime, UNIX_EPOCH};
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now + token_resp.expires_in.unwrap_or(3600)
        });

        *self.token_cache.lock().await = Some(CachedToken {
            access_token: access_token.clone(),
            expires_at,
        });

        Ok(access_token)
    }

    pub(crate) async fn ensure_authenticated(&self) -> Result<String> {
        // Fast path: cached token is still valid.
        if let Some(cached) = self.token_cache.lock().await.as_ref() {
            if cached.is_valid() {
                return Ok(cached.access_token.clone());
            }
        }
        // Slow path: exchange API key for a fresh JWT.
        self.authenticate().await
    }

    // ---------- request primitives ----------

    async fn do_request(
        &self,
        method: Method,
        url: &str,
        body: Option<serde_json::Value>,
        use_report_client: bool,
    ) -> Result<Response> {
        let token = self.ensure_authenticated().await?;
        let client = if use_report_client {
            &self.report_http
        } else {
            &self.http
        };

        let mut req = client.request(method.clone(), url).bearer_auth(&token);
        if let Some(ref b) = body {
            req = req.json(b);
        }
        let resp = req.send().await?;

        // On 401 during normal flow, re-authenticate once and retry.
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            debug!("received 401, re-authenticating");
            let new_token = self.authenticate().await?;
            let mut retry_req = client.request(method, url).bearer_auth(&new_token);
            if let Some(ref b) = body {
                retry_req = retry_req.json(b);
            }
            return Ok(retry_req.send().await?);
        }

        Ok(resp)
    }

    /// Wraps [`do_request`] with exponential-backoff retry on 5xx responses and
    /// network-level transport errors.  4xx responses (client errors) are
    /// returned immediately without retrying — the server has definitively
    /// rejected the request.
    ///
    /// The retry budget is controlled by `self.max_retries` and
    /// `self.retry_wait_base`; the wait doubles each attempt and is capped at
    /// 30 seconds.  When all attempts are exhausted the function returns
    /// `Error::MaxRetriesExceeded`.
    async fn do_request_with_retry(
        &self,
        method: Method,
        url: &str,
        body: Option<serde_json::Value>,
        use_report_client: bool,
    ) -> Result<Response> {
        let mut last_err: Option<Error> = None;
        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                let wait = self.retry_wait_base * 2u32.pow(attempt - 1);
                let wait = wait.min(Duration::from_secs(30));
                tokio::time::sleep(wait).await;
            }

            match self
                .do_request(method.clone(), url, body.clone(), use_report_client)
                .await
            {
                Ok(resp) if resp.status().as_u16() >= 500 => {
                    last_err = Some(Error::Api {
                        status: resp.status().as_u16(),
                        code: "SERVER_ERROR".to_string(),
                        message: format!(
                            "server error {} on attempt {}",
                            resp.status().as_u16(),
                            attempt + 1
                        ),
                    });
                    // continue to next retry attempt
                }
                Ok(resp) => return Ok(resp), // success or 4xx (don't retry 4xx)
                Err(e) => {
                    last_err = Some(e);
                    // continue to next retry attempt for transport errors
                }
            }
        }
        Err(Error::MaxRetriesExceeded {
            attempts: self.max_retries + 1,
            last_error: last_err
                .map(|e| e.to_string())
                .unwrap_or_default(),
        })
    }

    async fn check_response<T: DeserializeOwned>(resp: Response) -> Result<T> {
        let status = resp.status();

        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(Error::NotFound(resp.url().path().to_string()));
        }

        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let retry_after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(60);
            return Err(Error::RateLimit { retry_after });
        }

        if !status.is_success() {
            let s = status.as_u16();
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            let code = body
                .get("code")
                .and_then(|v| v.as_str())
                .unwrap_or("UNKNOWN")
                .to_string();
            let message = body
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("no message")
                .to_string();
            return Err(Error::Api {
                status: s,
                code,
                message,
            });
        }

        if status == reqwest::StatusCode::NO_CONTENT {
            return serde_json::from_value(serde_json::Value::Null).map_err(Error::Json);
        }

        Ok(resp.json::<T>().await?)
    }

    async fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
        query: Option<Vec<(&'static str, String)>>,
    ) -> Result<T> {
        // Build the URL with query parameters appended so do_request_with_retry
        // can use it as a plain string (reqwest query() cannot be applied after
        // the URL is serialised, so we fold the params in here).
        let base_url = self.api_url(path);
        let url = if let Some(ref q) = query {
            let mut url = reqwest::Url::parse(&base_url)
                .map_err(|e| Error::UnexpectedResponse(e.to_string()))?;
            url.query_pairs_mut().extend_pairs(q.iter().map(|(k, v)| (*k, v.as_str())));
            url.to_string()
        } else {
            base_url
        };

        let resp = self
            .do_request_with_retry(Method::GET, &url, None, false)
            .await?;
        Self::check_response(resp).await
    }

    async fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let resp = self
            .do_request_with_retry(
                Method::POST,
                &self.api_url(path),
                Some(serde_json::to_value(body)?),
                false,
            )
            .await?;
        Self::check_response(resp).await
    }

    async fn patch_json<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let resp = self
            .do_request_with_retry(
                Method::PATCH,
                &self.api_url(path),
                Some(serde_json::to_value(body)?),
                false,
            )
            .await?;
        Self::check_response(resp).await
    }

    async fn delete_no_content(&self, path: &str) -> Result<()> {
        let resp = self
            .do_request_with_retry(Method::DELETE, &self.api_url(path), None, false)
            .await?;
        let status = resp.status();
        if status.is_success() || status == reqwest::StatusCode::NO_CONTENT {
            return Ok(());
        }
        Err(Error::Api {
            status: status.as_u16(),
            code: "DELETE_FAILED".to_string(),
            message: "delete request failed".to_string(),
        })
    }

    // ---------- public API — scans ----------

    /// Start a scan from an OpenAPI spec URL.
    ///
    /// This is a convenience wrapper around [`create_scan_full`](Self::create_scan_full).
    pub async fn create_scan(&self, spec_url: &str) -> Result<Scan> {
        self.create_scan_full(CreateScanOptions {
            spec_url: Some(spec_url.to_string()),
            ..Default::default()
        })
        .await
    }

    /// Start a scan with full control over all options.
    pub async fn create_scan_full(&self, opts: CreateScanOptions) -> Result<Scan> {
        self.post_json("scans", &opts).await
    }

    /// Fetch a scan by its UUID string.
    pub async fn get_scan(&self, scan_id: &str) -> Result<Scan> {
        self.get_json(&format!("scans/{scan_id}"), None).await
    }

    /// List scans with optional pagination and status filters.
    pub async fn list_scans(&self, opts: Option<ListScansOptions>) -> Result<Vec<Scan>> {
        let mut q: Vec<(&'static str, String)> = vec![];
        if let Some(o) = opts {
            if let Some(p) = o.page {
                q.push(("page", p.to_string()));
            }
            if let Some(pp) = o.per_page {
                q.push(("per_page", pp.min(100).to_string()));
            }
        }
        self.get_json("scans", if q.is_empty() { None } else { Some(q) })
            .await
    }

    /// Delete a scan by its UUID string.
    pub async fn delete_scan(&self, scan_id: &str) -> Result<()> {
        self.delete_no_content(&format!("scans/{scan_id}")).await
    }

    // ---------- public API — findings ----------

    /// Get all findings for a scan, with optional filtering.
    ///
    /// Handles both plain-array and `{"data":[...]}` envelope response formats.
    pub async fn get_findings(
        &self,
        scan_id: &str,
        opts: Option<GetFindingsOptions>,
    ) -> Result<Vec<Finding>> {
        let mut q: Vec<(&str, String)> = vec![];
        if let Some(o) = opts {
            if let Some(sev) = o.severity {
                q.push(("severity", format!("{sev:?}").to_lowercase()));
            }
            if let Some(st) = o.status {
                q.push(("status", format!("{st:?}").to_lowercase()));
            }
            if let Some(p) = o.page {
                q.push(("page", p.to_string()));
            }
            if let Some(pp) = o.per_page {
                q.push(("per_page", pp.min(100).to_string()));
            }
        }

        let url = self.api_url(&format!("scans/{scan_id}/findings"));
        let token = self.ensure_authenticated().await?;

        let mut req = self.http.get(&url).bearer_auth(&token);
        if !q.is_empty() {
            req = req.query(&q);
        }
        let resp = req.send().await?;

        let status = resp.status();
        if !status.is_success() {
            return Self::check_response(resp).await;
        }

        // Handle both envelope {"data":[...]} and plain array responses.
        let value: serde_json::Value = resp.json().await?;
        if let Some(arr) = value.get("data") {
            Ok(serde_json::from_value(arr.clone())?)
        } else {
            Ok(serde_json::from_value(value)?)
        }
    }

    /// Get a single finding by its UUID string.
    pub async fn get_finding(&self, finding_id: &str) -> Result<Finding> {
        self.get_json(&format!("findings/{finding_id}"), None).await
    }

    /// Update a finding's triage status and optional note.
    pub async fn patch_finding(
        &self,
        finding_id: &str,
        req: PatchFindingRequest,
    ) -> Result<Finding> {
        self.patch_json(&format!("findings/{finding_id}"), &req)
            .await
    }

    // ---------- public API — reports ----------

    /// Download a report into memory. Prefer [`get_report_stream`](Self::get_report_stream)
    /// for large reports to avoid buffering the entire payload.
    pub async fn get_report(&self, scan_id: &str, format: &str) -> Result<Bytes> {
        let url = format!(
            "{}?format={format}",
            self.api_url(&format!("scans/{scan_id}/report"))
        );
        let token = self.ensure_authenticated().await?;
        let resp = self
            .report_http
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(Error::Api {
                status: resp.status().as_u16(),
                code: "REPORT_ERROR".to_string(),
                message: "failed to download report".to_string(),
            });
        }
        Ok(resp.bytes().await?)
    }

    /// Stream a report directly to an async writer (ideal for large files).
    pub async fn get_report_stream(
        &self,
        scan_id: &str,
        format: &str,
        writer: &mut (impl AsyncWrite + Unpin),
    ) -> Result<()> {
        use futures_util::StreamExt;

        let url = format!(
            "{}?format={format}",
            self.api_url(&format!("scans/{scan_id}/report"))
        );
        let token = self.ensure_authenticated().await?;
        let resp = self
            .report_http
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(Error::Api {
                status: resp.status().as_u16(),
                code: "REPORT_STREAM_ERROR".to_string(),
                message: "failed to stream report".to_string(),
            });
        }

        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            writer.write_all(&chunk?).await?;
        }
        writer.flush().await?;
        Ok(())
    }

    // ---------- public API — specs ----------

    /// Upload an OpenAPI spec file via multipart form upload.
    pub async fn upload_spec(&self, file_path: &str) -> Result<UploadSpecResponse> {
        let path = Path::new(file_path);
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("spec.yaml")
            .to_string();
        let contents = tokio::fs::read(path).await?;

        let part = multipart::Part::bytes(contents)
            .file_name(file_name)
            .mime_str("application/octet-stream")
            .map_err(|e| Error::UnexpectedResponse(e.to_string()))?;
        let form = multipart::Form::new().part("file", part);

        let token = self.ensure_authenticated().await?;
        let resp = self
            .http
            .post(self.api_url("specs/upload"))
            .bearer_auth(&token)
            .multipart(form)
            .send()
            .await?;

        Self::check_response(resp).await
    }

    // ---------- public API — audit ----------

    /// Retrieve the audit log with pagination.
    pub async fn get_audit_log(&self, limit: u32, page: u32) -> Result<Vec<AuditEntry>> {
        let q = vec![
            ("per_page", limit.to_string()),
            ("page", page.to_string()),
        ];
        self.get_json("audit", Some(q)).await
    }
}

// ---------- builder ----------

/// Builder for [`APIGuardClient`] with custom timeout and retry configuration.
///
/// # Example
/// ```no_run
/// use opensecstack::APIGuardClient;
/// use std::time::Duration;
///
/// let client = APIGuardClient::builder("https://apiguard.example.com", "ak_live_…")
///     .timeout(Duration::from_secs(60))
///     .max_retries(3)
///     .build();
/// ```
pub struct APIGuardClientBuilder {
    base_url: String,
    api_key: String,
    timeout: Duration,
    max_retries: u32,
    retry_wait_base: Duration,
    verify_ssl: bool,
}

impl APIGuardClientBuilder {
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            api_key: api_key.into(),
            timeout: DEFAULT_TIMEOUT,
            max_retries: DEFAULT_MAX_RETRIES,
            retry_wait_base: DEFAULT_RETRY_BASE,
            verify_ssl: true,
        }
    }

    /// Set the HTTP request timeout.
    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// Maximum number of retry attempts for transient failures.
    pub fn max_retries(mut self, n: u32) -> Self {
        self.max_retries = n;
        self
    }

    /// Base wait duration for exponential back-off between retries.
    pub fn retry_wait_base(mut self, d: Duration) -> Self {
        self.retry_wait_base = d;
        self
    }

    /// Accept invalid TLS certificates. **Do not use in production.**
    pub fn danger_accept_invalid_certs(mut self, v: bool) -> Self {
        self.verify_ssl = !v;
        self
    }

    /// Consume the builder and produce an [`APIGuardClient`].
    pub fn build(self) -> APIGuardClient {
        let http = Client::builder()
            .timeout(self.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(!self.verify_ssl)
            .build()
            .expect("failed to build HTTP client");
        let report_http = Client::builder()
            .timeout(REPORT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(!self.verify_ssl)
            .build()
            .expect("failed to build report HTTP client");

        APIGuardClient {
            base_url: self.base_url.trim_end_matches('/').to_string(),
            api_key: self.api_key,
            http,
            report_http,
            token_cache: Arc::new(TokenCache::new(None)),
            max_retries: self.max_retries,
            retry_wait_base: self.retry_wait_base,
        }
    }
}


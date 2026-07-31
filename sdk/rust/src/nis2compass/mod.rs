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

/// Client for the NIS2 Compass platform.
///
/// Provides a fully async, token-managed interface to the NIS2 Compass REST API.
/// Authentication is handled automatically via JWT token exchange and proactive
/// refresh (SDK-M5).
///
/// # Example
/// ```no_run
/// # #[tokio::main] async fn main() -> opensecstack::Result<()> {
/// use opensecstack::{NIS2CompassClient, CreateOrganisationRequest};
///
/// let client = NIS2CompassClient::new("https://nis2compass.example.com", "nk_live_…");
/// let org = client.create_organisation(CreateOrganisationRequest {
///     name: "Acme Corp".to_string(),
///     ..Default::default()
/// }).await?;
/// println!("Organisation created: {}", org.id);
/// # Ok(()) }
/// ```
#[derive(Clone)]
pub struct NIS2CompassClient {
    pub(crate) base_url: String,
    pub(crate) api_key: String,
    pub(crate) http: Client,
    pub(crate) report_http: Client,
    pub(crate) token_cache: Arc<TokenCache>,
    pub(crate) max_retries: u32,
    pub(crate) retry_wait_base: Duration,
}

impl NIS2CompassClient {
    /// Creates a new client with default settings (30 s timeout, 2 retries).
    ///
    /// # Panics
    ///
    /// Panics if the underlying `reqwest` HTTP client fails to build (this
    /// only happens if the TLS backend cannot be initialised).
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
    ) -> NIS2CompassClientBuilder {
        NIS2CompassClientBuilder::new(base_url, api_key)
    }

    // ---------- internal helpers ----------

    fn api_url(&self, path: &str) -> String {
        format!("{}/api/v1/{}", self.base_url, path.trim_start_matches('/'))
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

        // SDK-M5: parse the JWT exp claim for proactive refresh.
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
        if let Some(cached) = self.token_cache.lock().await.as_ref() {
            if cached.is_valid() {
                return Ok(cached.access_token.clone());
            }
        }
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
    /// network-level transport errors.  4xx responses are returned immediately
    /// without retrying — the server has definitively rejected the request.
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
                Err(Error::Transport(e)) => {
                    // Network-level error — worth retrying.
                    last_err = Some(Error::Transport(e));
                }
                Err(other) => {
                    // Auth errors, JSON errors, etc. are not transient — fail fast.
                    return Err(other);
                }
            }
        }
        Err(Error::MaxRetriesExceeded {
            attempts: self.max_retries + 1,
            last_error: last_err.map(|e| e.to_string()).unwrap_or_default(),
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
        // can use it as a plain string.
        let base_url = self.api_url(path);
        let url = if let Some(ref q) = query {
            let mut url = reqwest::Url::parse(&base_url)
                .map_err(|e| Error::UnexpectedResponse(e.to_string()))?;
            url.query_pairs_mut()
                .extend_pairs(q.iter().map(|(k, v)| (*k, v.as_str())));
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

    // ---------- public API — organisations ----------

    /// Create a new organisation.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the server returns a
    /// non-success response.
    pub async fn create_organisation(
        &self,
        req: CreateOrganisationRequest,
    ) -> Result<Organisation> {
        self.post_json("organisations", &req).await
    }

    /// Get an organisation by UUID string.
    ///
    /// # Errors
    ///
    /// Returns an error if the organisation does not exist or the request fails.
    pub async fn get_organisation(&self, id: &str) -> Result<Organisation> {
        self.get_json(&format!("organisations/{id}"), None).await
    }

    /// List organisations with optional pagination.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the server returns a
    /// non-success response.
    pub async fn list_organisations(
        &self,
        page: Option<u32>,
        per_page: Option<u32>,
    ) -> Result<Vec<Organisation>> {
        let mut q: Vec<(&'static str, String)> = vec![];
        if let Some(p) = page {
            q.push(("page", p.to_string()));
        }
        if let Some(pp) = per_page {
            q.push(("per_page", pp.min(100).to_string()));
        }
        self.get_json("organisations", if q.is_empty() { None } else { Some(q) })
            .await
    }

    /// Update organisation fields (partial update).
    ///
    /// # Errors
    ///
    /// Returns an error if the organisation does not exist or the request fails.
    pub async fn patch_organisation(
        &self,
        id: &str,
        req: PatchOrganisationRequest,
    ) -> Result<Organisation> {
        self.patch_json(&format!("organisations/{id}"), &req).await
    }

    /// Delete an organisation by UUID string.
    ///
    /// # Errors
    ///
    /// Returns an error if the organisation does not exist or the request fails.
    pub async fn delete_organisation(&self, id: &str) -> Result<()> {
        self.delete_no_content(&format!("organisations/{id}")).await
    }

    // ---------- public API — assessments ----------

    /// Create a new NIS2 assessment for an organisation.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the server returns a
    /// non-success response.
    pub async fn create_assessment(
        &self,
        org_id: &str,
        req: CreateAssessmentRequest,
    ) -> Result<Assessment> {
        self.post_json(&format!("organisations/{org_id}/assessments"), &req)
            .await
    }

    /// Get a single assessment by UUID string.
    ///
    /// # Errors
    ///
    /// Returns an error if the assessment does not exist or the request fails.
    pub async fn get_assessment(&self, id: &str) -> Result<Assessment> {
        self.get_json(&format!("assessments/{id}"), None).await
    }

    /// List assessments for an organisation, optionally filtered by status.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the server returns a
    /// non-success response.
    pub async fn list_assessments(
        &self,
        org_id: &str,
        status: Option<AssessmentStatus>,
    ) -> Result<Vec<Assessment>> {
        let mut q: Vec<(&'static str, String)> = vec![];
        if let Some(s) = status {
            let s_str = serde_json::to_value(&s)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default();
            q.push(("status", s_str));
        }
        self.get_json(
            &format!("organisations/{org_id}/assessments"),
            if q.is_empty() { None } else { Some(q) },
        )
        .await
    }

    /// Update assessment fields (partial update).
    ///
    /// # Errors
    ///
    /// Returns an error if the assessment does not exist or the request fails.
    pub async fn patch_assessment(
        &self,
        id: &str,
        req: PatchAssessmentRequest,
    ) -> Result<Assessment> {
        self.patch_json(&format!("assessments/{id}"), &req).await
    }

    /// Delete an assessment by UUID string.
    ///
    /// # Errors
    ///
    /// Returns an error if the assessment does not exist or the request fails.
    pub async fn delete_assessment(&self, id: &str) -> Result<()> {
        self.delete_no_content(&format!("assessments/{id}")).await
    }

    // ---------- public API — controls ----------

    /// Get all controls for an assessment.
    ///
    /// # Errors
    ///
    /// Returns an error if the assessment does not exist or the request fails.
    pub async fn get_controls(&self, assessment_id: &str) -> Result<Vec<Control>> {
        self.get_json(&format!("assessments/{assessment_id}/controls"), None)
            .await
    }

    /// Get a single control by its measure reference letter ('a' through 'j').
    ///
    /// # Errors
    ///
    /// Returns an error if the control does not exist or the request fails.
    pub async fn get_control(&self, assessment_id: &str, measure_ref: char) -> Result<Control> {
        self.get_json(
            &format!("assessments/{assessment_id}/controls/{measure_ref}"),
            None,
        )
        .await
    }

    /// Update a control's status, evidence, remediation or risk score.
    ///
    /// # Errors
    ///
    /// Returns an error if the control does not exist or the request fails.
    pub async fn patch_control(
        &self,
        assessment_id: &str,
        measure_ref: char,
        req: PatchControlRequest,
    ) -> Result<Control> {
        self.patch_json(
            &format!("assessments/{assessment_id}/controls/{measure_ref}"),
            &req,
        )
        .await
    }

    // ---------- public API — artifacts ----------

    /// List all artifacts for an assessment.
    ///
    /// # Errors
    ///
    /// Returns an error if the assessment does not exist or the request fails.
    pub async fn list_artifacts(&self, assessment_id: &str) -> Result<Vec<Artifact>> {
        self.get_json(&format!("assessments/{assessment_id}/artifacts"), None)
            .await
    }

    /// Upload an artifact file (multipart form) and associate it with an assessment.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or the upload request fails.
    pub async fn upload_artifact(
        &self,
        assessment_id: &str,
        file_path: &str,
        artifact_type: ArtifactType,
        control_id: Option<&str>,
        description: Option<&str>,
    ) -> Result<Artifact> {
        let path = Path::new(file_path);
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("artifact")
            .to_string();
        let contents = tokio::fs::read(path).await?;

        let artifact_type_str = serde_json::to_value(&artifact_type)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "other".to_string());

        let file_part = multipart::Part::bytes(contents)
            .file_name(file_name)
            .mime_str("application/octet-stream")
            .map_err(|e| Error::UnexpectedResponse(e.to_string()))?;

        let mut form = multipart::Form::new()
            .part("file", file_part)
            .text("artifact_type", artifact_type_str);

        if let Some(cid) = control_id {
            form = form.text("control_id", cid.to_string());
        }
        if let Some(desc) = description {
            form = form.text("description", desc.to_string());
        }

        let token = self.ensure_authenticated().await?;
        let resp = self
            .http
            .post(self.api_url(&format!("assessments/{assessment_id}/artifacts")))
            .bearer_auth(&token)
            .multipart(form)
            .send()
            .await?;

        Self::check_response(resp).await
    }

    /// Download an artifact to a local file path.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails, the server returns a
    /// non-success response, or writing the file fails.
    pub async fn download_artifact(&self, artifact_id: &str, dest_path: &str) -> Result<()> {
        use futures_util::StreamExt;

        let url = self.api_url(&format!("artifacts/{artifact_id}/download"));
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
                code: "DOWNLOAD_ERROR".to_string(),
                message: "failed to download artifact".to_string(),
            });
        }

        let mut file = tokio::fs::File::create(dest_path).await?;
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            file.write_all(&chunk?).await?;
        }
        file.flush().await?;
        Ok(())
    }

    /// Delete an artifact by UUID string.
    ///
    /// # Errors
    ///
    /// Returns an error if the artifact does not exist or the request fails.
    pub async fn delete_artifact(&self, artifact_id: &str) -> Result<()> {
        self.delete_no_content(&format!("artifacts/{artifact_id}"))
            .await
    }

    // ---------- public API — API keys ----------

    /// List all API keys for the current principal.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the server returns a
    /// non-success response.
    pub async fn list_api_keys(&self) -> Result<Vec<APIKey>> {
        self.get_json("api-keys", None).await
    }

    /// Create a new API key. The `plaintext_key` field in the response is
    /// only present at creation time and cannot be retrieved later.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the server returns a
    /// non-success response.
    pub async fn create_api_key(&self, req: CreateAPIKeyRequest) -> Result<APIKey> {
        self.post_json("api-keys", &req).await
    }

    /// Revoke (delete) an API key by UUID string.
    ///
    /// # Errors
    ///
    /// Returns an error if the key does not exist or the request fails.
    pub async fn revoke_api_key(&self, key_id: &str) -> Result<()> {
        self.delete_no_content(&format!("api-keys/{key_id}")).await
    }

    // ---------- public API — reports ----------

    /// Generate a PDF compliance report for an assessment, returned as bytes.
    ///
    /// Uses the extended 120-second timeout client.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the server returns a
    /// non-success response.
    pub async fn generate_report(&self, assessment_id: &str) -> Result<Bytes> {
        let url = format!(
            "{}?format=pdf",
            self.api_url(&format!("assessments/{assessment_id}/report"))
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
                message: "failed to generate report".to_string(),
            });
        }
        Ok(resp.bytes().await?)
    }

    /// Stream a compliance report to an async writer.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails, the server returns a
    /// non-success response, or writing to `writer` fails.
    pub async fn get_report_stream(
        &self,
        assessment_id: &str,
        format: &str,
        writer: &mut (impl AsyncWrite + Unpin),
    ) -> Result<()> {
        use futures_util::StreamExt;

        let url = format!(
            "{}?format={format}",
            self.api_url(&format!("assessments/{assessment_id}/report"))
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

    // ---------- public API — audit ----------

    /// Retrieve the NIS2 Compass audit log with pagination.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the server returns a
    /// non-success response.
    pub async fn get_audit_log(&self, limit: u32, page: u32) -> Result<Vec<NIS2AuditEntry>> {
        let q = vec![("per_page", limit.to_string()), ("page", page.to_string())];
        self.get_json("audit", Some(q)).await
    }

    // ---------- public API — health ----------

    /// Basic health check. Does **not** require authentication.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the server returns a
    /// non-success response.
    pub async fn get_health(&self) -> Result<HealthStatus> {
        let url = format!("{}/api/v1/health", self.base_url);
        let resp = self.http.get(&url).send().await?;
        Self::check_response(resp).await
    }

    /// Detailed health check (includes DB/Redis status). Requires authentication.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the server returns a
    /// non-success response.
    pub async fn get_health_detail(&self) -> Result<HealthStatus> {
        self.get_json("health/detail", None).await
    }

    /// Retrieve a single audit entry by UUID string.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry does not exist or the request fails.
    pub async fn get_audit_entry(&self, entry_id: &str) -> Result<NIS2AuditEntry> {
        self.get_json(&format!("audit/{entry_id}"), None).await
    }
}

// ---------- builder ----------

/// Builder for [`NIS2CompassClient`] with custom timeout and retry configuration.
///
/// # Example
/// ```no_run
/// use opensecstack::NIS2CompassClient;
/// use std::time::Duration;
///
/// let client = NIS2CompassClient::builder("https://nis2compass.example.com", "nk_live_…")
///     .timeout(Duration::from_secs(60))
///     .max_retries(3)
///     .build();
/// ```
pub struct NIS2CompassClientBuilder {
    base_url: String,
    api_key: String,
    timeout: Duration,
    max_retries: u32,
    retry_wait_base: Duration,
    verify_ssl: bool,
}

impl NIS2CompassClientBuilder {
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
    #[must_use]
    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// Maximum number of retry attempts for transient failures.
    #[must_use]
    pub fn max_retries(mut self, n: u32) -> Self {
        self.max_retries = n;
        self
    }

    /// Base wait duration for exponential back-off between retries.
    #[must_use]
    pub fn retry_wait_base(mut self, d: Duration) -> Self {
        self.retry_wait_base = d;
        self
    }

    /// Accept invalid TLS certificates. **Do not use in production.**
    #[must_use]
    pub fn danger_accept_invalid_certs(mut self, v: bool) -> Self {
        self.verify_ssl = !v;
        self
    }

    /// Consume the builder and produce a [`NIS2CompassClient`].
    ///
    /// # Panics
    ///
    /// Panics if the underlying `reqwest` HTTP client fails to build (this
    /// only happens if the TLS backend cannot be initialised).
    pub fn build(self) -> NIS2CompassClient {
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

        NIS2CompassClient {
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

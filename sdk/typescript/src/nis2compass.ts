import { HttpClient } from "./http.js";
import { parseJWTExp } from "./jwt.js";
import type {
  Organisation,
  CreateOrganisationRequest,
  PatchOrganisationRequest,
  GetOrganisationsOptions,
  Assessment,
  CreateAssessmentRequest,
  PatchAssessmentRequest,
  GetAssessmentsOptions,
  Control,
  PatchControlRequest,
  ListControlsOptions,
  Artifact,
  APIKey,
  CreateAPIKeyRequest,
  NIS2AuditEntry,
  HealthStatus,
} from "./types.js";

/** Number of seconds before token expiry at which we proactively refresh. */
const TOKEN_REFRESH_BUFFER_SECS = 30;

/** Fallback token lifetime (seconds) when the JWT exp claim cannot be parsed. */
const FALLBACK_TOKEN_LIFETIME_SECS = 5 * 60;

export interface NIS2CompassClientOptions {
  baseURL: string;
  apiKey: string;
  timeout?: number;
  maxRetries?: number;
  retryWaitBase?: number;
}

export class NIS2CompassClient {
  private readonly http: HttpClient;
  private readonly httpPublic: HttpClient;
  private readonly apiKey: string;
  private readonly baseURL: string;
  private readonly timeout: number;

  /** Cached JWT obtained from the auth/token endpoint. */
  private jwt: string | null = null;
  /** Token expiry as a Unix timestamp (seconds since epoch). */
  private tokenExpiry: number | null = null;
  /** Serialises concurrent authenticate() calls so only one HTTP round-trip fires. */
  private authPromise: Promise<void> | null = null;

  constructor(opts: NIS2CompassClientOptions) {
    this.apiKey = opts.apiKey;
    this.baseURL = opts.baseURL.replace(/\/+$/, "");
    this.timeout = opts.timeout ?? 30_000;
    this.http = new HttpClient({
      baseURL: opts.baseURL,
      timeout: opts.timeout,
      maxRetries: opts.maxRetries,
      retryWaitBase: opts.retryWaitBase,
      // No static Authorization header — we set it dynamically after auth.
    });
    this.httpPublic = new HttpClient({
      baseURL: opts.baseURL,
      timeout: opts.timeout,
      maxRetries: opts.maxRetries,
      retryWaitBase: opts.retryWaitBase,
    });
  }

  // ------------------------------------------------------------------
  // Auth helpers (matches Go/Python two-step JWT flow)
  // ------------------------------------------------------------------

  /**
   * Exchange the API key for a short-lived JWT and cache it.
   *
   * Uses a shared promise so concurrent calls coalesce into a single
   * HTTP request (analogous to Go's sync.Mutex / Python's threading.Lock).
   */
  private async authenticate(): Promise<void> {
    // Fast path: token is still valid.
    if (this.jwt && this.tokenExpiry != null) {
      const now = Math.floor(Date.now() / 1000);
      if (now + TOKEN_REFRESH_BUFFER_SECS < this.tokenExpiry) {
        return;
      }
    }

    // Coalesce concurrent callers behind one in-flight request.
    if (this.authPromise) {
      return this.authPromise;
    }

    this.authPromise = this.doAuthenticate();
    try {
      await this.authPromise;
    } finally {
      this.authPromise = null;
    }
  }

  private async doAuthenticate(): Promise<void> {
    const url = `${this.baseURL}/api/v1/auth/token`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const resp = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({ api_key: this.apiKey }),
        signal: controller.signal,
      });
      clearTimeout(timer);

      if (resp.status === 401) {
        throw new Error("Authentication failed: invalid API key");
      }
      if (!resp.ok) {
        const text = await resp.text();
        throw new Error(`Auth error HTTP ${resp.status}: ${text}`);
      }

      const data = (await resp.json()) as Record<string, unknown>;
      const token =
        (data.token as string) || (data.access_token as string) || "";
      if (!token) {
        throw new Error("No token in auth/token response");
      }

      const exp = parseJWTExp(token);
      this.jwt = token;
      this.tokenExpiry =
        exp ?? Math.floor(Date.now() / 1000) + FALLBACK_TOKEN_LIFETIME_SECS;
      this.http.setHeader("Authorization", `Bearer ${token}`);
    } catch (err) {
      clearTimeout(timer);
      throw err;
    }
  }

  /**
   * Ensure the token is still valid, refreshing proactively if it expires
   * within TOKEN_REFRESH_BUFFER_SECS. Called before every API request.
   */
  private async ensureAuthenticated(): Promise<void> {
    if (this.jwt && this.tokenExpiry != null) {
      const now = Math.floor(Date.now() / 1000);
      if (now + TOKEN_REFRESH_BUFFER_SECS >= this.tokenExpiry) {
        // Token is expiring soon — clear and re-authenticate.
        this.jwt = null;
        this.tokenExpiry = null;
      }
    }
    await this.authenticate();
  }

  /**
   * Execute an authenticated request with automatic re-auth on 401.
   */
  private async authenticatedRequest<T>(
    method: string,
    path: string,
    options?: {
      body?: unknown;
      params?: Record<string, string | number | undefined>;
      headers?: Record<string, string>;
      raw?: boolean;
    },
  ): Promise<T> {
    await this.ensureAuthenticated();

    try {
      return await this.http.request<T>(method, path, options);
    } catch (err: unknown) {
      // Reactive fallback: if the server returned 401 despite our
      // proactive check (e.g. token revoked server-side), re-auth once.
      if (
        err instanceof Error &&
        "statusCode" in err &&
        (err as { statusCode: number }).statusCode === 401
      ) {
        this.jwt = null;
        this.tokenExpiry = null;
        await this.authenticate();
        return this.http.request<T>(method, path, options);
      }
      throw err;
    }
  }

  // ─── Organisations ───

  async getOrganisations(
    opts?: GetOrganisationsOptions,
  ): Promise<Organisation[]> {
    return this.authenticatedRequest<Organisation[]>(
      "GET",
      "/api/v1/organisations",
      {
        params: {
          page: opts?.page,
          per_page: opts?.per_page,
        },
      },
    );
  }

  async createOrganisation(
    req: CreateOrganisationRequest,
  ): Promise<Organisation> {
    return this.authenticatedRequest<Organisation>(
      "POST",
      "/api/v1/organisations",
      { body: req },
    );
  }

  async getOrganisation(id: string): Promise<Organisation> {
    return this.authenticatedRequest<Organisation>(
      "GET",
      `/api/v1/organisations/${id}`,
    );
  }

  async patchOrganisation(
    id: string,
    req: PatchOrganisationRequest,
  ): Promise<Organisation> {
    return this.authenticatedRequest<Organisation>(
      "PATCH",
      `/api/v1/organisations/${id}`,
      { body: req },
    );
  }

  async deleteOrganisation(id: string): Promise<void> {
    return this.authenticatedRequest<void>(
      "DELETE",
      `/api/v1/organisations/${id}`,
    );
  }

  // ─── Assessments ───

  async getAssessments(
    orgID: string,
    opts?: GetAssessmentsOptions,
  ): Promise<Assessment[]> {
    return this.authenticatedRequest<Assessment[]>(
      "GET",
      `/api/v1/organisations/${orgID}/assessments`,
      {
        params: {
          status: opts?.status,
          page: opts?.page,
          per_page: opts?.per_page,
        },
      },
    );
  }

  async createAssessment(
    orgID: string,
    req: CreateAssessmentRequest,
  ): Promise<Assessment> {
    return this.authenticatedRequest<Assessment>(
      "POST",
      `/api/v1/organisations/${orgID}/assessments`,
      { body: req },
    );
  }

  async getAssessment(id: string): Promise<Assessment> {
    return this.authenticatedRequest<Assessment>(
      "GET",
      `/api/v1/assessments/${id}`,
    );
  }

  async patchAssessment(
    id: string,
    req: PatchAssessmentRequest,
  ): Promise<Assessment> {
    return this.authenticatedRequest<Assessment>(
      "PATCH",
      `/api/v1/assessments/${id}`,
      { body: req },
    );
  }

  async deleteAssessment(id: string): Promise<void> {
    return this.authenticatedRequest<void>(
      "DELETE",
      `/api/v1/assessments/${id}`,
    );
  }

  // ─── Controls ───

  /** List controls with optional filters (status, nist_category, measure_ref). */
  async listControls(
    assessmentID: string,
    opts?: ListControlsOptions,
  ): Promise<Control[]> {
    return this.authenticatedRequest<Control[]>(
      "GET",
      `/api/v1/assessments/${assessmentID}/controls`,
      {
        params: {
          status: opts?.status,
          nist_category: opts?.nist_category,
          measure_ref: opts?.measure_ref,
        },
      },
    );
  }

  /** Return all controls for an assessment without any filters. */
  async getControls(assessmentID: string): Promise<Control[]> {
    return this.authenticatedRequest<Control[]>(
      "GET",
      `/api/v1/assessments/${assessmentID}/controls`,
    );
  }

  async getControl(
    assessmentID: string,
    measureRef: string,
  ): Promise<Control> {
    return this.authenticatedRequest<Control>(
      "GET",
      `/api/v1/assessments/${assessmentID}/controls/${measureRef}`,
    );
  }

  async patchControl(
    assessmentID: string,
    measureRef: string,
    req: PatchControlRequest,
  ): Promise<Control> {
    return this.authenticatedRequest<Control>(
      "PATCH",
      `/api/v1/assessments/${assessmentID}/controls/${measureRef}`,
      { body: req },
    );
  }

  // ─── Artifacts ───

  /**
   * Upload an artifact from a file path (Node.js) or Blob (browser).
   *
   * In Node.js ≥ 20 pass a Blob created from `fs.readFileSync`:
   * ```ts
   * const blob = new Blob([fs.readFileSync(path)]);
   * await client.uploadArtifact(id, blob, "evidence", { description: "…" });
   * ```
   *
   * The method also accepts a File (which extends Blob) directly in
   * browser environments.
   */

  async listArtifacts(assessmentID: string): Promise<Artifact[]> {
    return this.authenticatedRequest<Artifact[]>(
      "GET",
      `/api/v1/assessments/${assessmentID}/artifacts`,
    );
  }

  async uploadArtifact(
    assessmentID: string,
    file: Blob | File,
    artifactType: string,
    opts?: { control_id?: string; description?: string; filename?: string },
  ): Promise<Artifact> {
    const formData = new FormData();
    // When a plain Blob is passed (Node.js), attach a filename so the
    // server can detect the file extension. File objects already carry a name.
    const name = (file as File).name ?? opts?.filename ?? "upload";
    formData.append("file", file, name);
    formData.append("artifact_type", artifactType);
    if (opts?.control_id) {
      formData.append("control_id", opts.control_id);
    }
    if (opts?.description) {
      formData.append("description", opts.description);
    }

    return this.authenticatedRequest<Artifact>(
      "POST",
      `/api/v1/assessments/${assessmentID}/artifacts`,
      { body: formData },
    );
  }

  async getArtifact(artifactID: string): Promise<Artifact> {
    return this.authenticatedRequest<Artifact>(
      "GET",
      `/api/v1/artifacts/${artifactID}`,
    );
  }

  async downloadArtifact(artifactID: string): Promise<ArrayBuffer> {
    const resp = await this.authenticatedRequest<Response>(
      "GET",
      `/api/v1/artifacts/${artifactID}/download`,
      { raw: true },
    );
    return resp.arrayBuffer();
  }

  async deleteArtifact(artifactID: string): Promise<void> {
    return this.authenticatedRequest<void>(
      "DELETE",
      `/api/v1/artifacts/${artifactID}`,
    );
  }

  // ─── API Keys ───

  async listAPIKeys(): Promise<APIKey[]> {
    return this.authenticatedRequest<APIKey[]>("GET", "/api/v1/api-keys");
  }

  async createAPIKey(req: CreateAPIKeyRequest): Promise<APIKey> {
    return this.authenticatedRequest<APIKey>("POST", "/api/v1/api-keys", {
      body: req,
    });
  }

  async revokeAPIKey(keyID: string): Promise<void> {
    return this.authenticatedRequest<void>(
      "DELETE",
      `/api/v1/api-keys/${keyID}`,
    );
  }

  // ─── Reports ───

  /**
   * Generate a PDF report for the given assessment.
   * Returns the full PDF as an ArrayBuffer. For large reports prefer
   * {@link getReportStream} which avoids buffering the entire body.
   */
  async generateReport(assessmentID: string): Promise<ArrayBuffer> {
    const resp = await this.authenticatedRequest<Response>(
      "POST",
      `/api/v1/assessments/${assessmentID}/report`,
      {
        headers: { Accept: "application/pdf" },
        raw: true,
      },
    );
    return resp.arrayBuffer();
  }

  /**
   * Stream a report in the requested format without buffering the full body.
   *
   * @param assessmentID - assessment UUID
   * @param format - "pdf" | "json" | "sarif" (default: "pdf")
   * @returns A `ReadableStream<Uint8Array>` that the caller can pipe to a
   *          file, HTTP response, or any writable sink.
   *
   * ```ts
   * import { Writable } from "node:stream";
   * const stream = await client.getReportStream(id, "pdf");
   * const file = fs.createWriteStream("report.pdf");
   * Readable.fromWeb(stream).pipe(file);
   * ```
   */
  async getReportStream(
    assessmentID: string,
    format: string = "pdf",
  ): Promise<ReadableStream<Uint8Array>> {
    const resp = await this.authenticatedRequest<Response>(
      "POST",
      `/api/v1/assessments/${assessmentID}/report`,
      {
        params: { format },
        raw: true,
      },
    );
    if (!resp.body) {
      throw new Error("Server returned no body for report stream");
    }
    return resp.body;
  }

  // ─── Audit ───

  async getAuditLog(
    limit?: number,
    page?: number,
  ): Promise<NIS2AuditEntry[]> {
    return this.authenticatedRequest<NIS2AuditEntry[]>(
      "GET",
      "/api/v1/audit",
      { params: { limit, page } },
    );
  }

  async getAuditEntry(entryID: string): Promise<NIS2AuditEntry> {
    return this.authenticatedRequest<NIS2AuditEntry>(
      "GET",
      `/api/v1/audit/${entryID}`,
    );
  }

  // ─── Health ───

  async getHealth(): Promise<HealthStatus> {
    return this.httpPublic.request<HealthStatus>("GET", "/health");
  }

  async getHealthDetail(): Promise<HealthStatus> {
    return this.authenticatedRequest<HealthStatus>("GET", "/health/detail");
  }
}

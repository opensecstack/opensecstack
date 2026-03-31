import { HttpClient } from "./http.js";
import { parseJWTExp } from "./jwt.js";
import type {
  Scan,
  Finding,
  AuditEntry,
  UploadSpecResponse,
  RefreshTokenResponse,
  CreateScanOptions,
  ListScansOptions,
  GetFindingsOptions,
  ListFindingsOptions,
  PatchFindingRequest,
} from "./types.js";

/** Number of seconds before token expiry at which we proactively refresh. */
const TOKEN_REFRESH_BUFFER_SECS = 30;

/** Fallback token lifetime (seconds) when the JWT exp claim cannot be parsed. */
const FALLBACK_TOKEN_LIFETIME_SECS = 5 * 60;

export interface APIGuardClientOptions {
  baseURL: string;
  apiKey: string;
  timeout?: number;
  maxRetries?: number;
  retryWaitBase?: number;
}

export class APIGuardClient {
  private readonly http: HttpClient;
  private readonly apiKey: string;
  private readonly baseURL: string;
  private readonly timeout: number;

  /** Cached JWT obtained from the auth/token endpoint. */
  private jwt: string | null = null;
  /** Token expiry as a Unix timestamp (seconds since epoch). */
  private tokenExpiry: number | null = null;
  /** Serialises concurrent authenticate() calls so only one HTTP round-trip fires. */
  private authPromise: Promise<void> | null = null;

  constructor(opts: APIGuardClientOptions) {
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
        (data.access_token as string) || (data.token as string) || "";
      if (!token) {
        throw new Error("No access_token in auth/token response");
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

  // ─── Scans ───

  async createScan(specURL: string): Promise<Scan> {
    return this.authenticatedRequest<Scan>("POST", "/api/v1/scans", {
      body: { spec_url: specURL },
    });
  }

  async createScanFull(opts: CreateScanOptions): Promise<Scan> {
    return this.authenticatedRequest<Scan>("POST", "/api/v1/scans", {
      body: opts,
    });
  }

  async getScan(scanID: string): Promise<Scan> {
    return this.authenticatedRequest<Scan>(
      "GET",
      `/api/v1/scans/${scanID}`,
    );
  }

  async listScans(opts?: ListScansOptions): Promise<Scan[]> {
    return this.authenticatedRequest<Scan[]>("GET", "/api/v1/scans", {
      params: {
        page: opts?.page,
        per_page: opts?.per_page,
      },
    });
  }

  async deleteScan(scanID: string): Promise<void> {
    return this.authenticatedRequest<void>(
      "DELETE",
      `/api/v1/scans/${scanID}`,
    );
  }

  // ─── Findings ───

  async getFindings(
    scanID: string,
    opts?: GetFindingsOptions,
  ): Promise<Finding[]> {
    return this.authenticatedRequest<Finding[]>(
      "GET",
      `/api/v1/scans/${scanID}/findings`,
      {
        params: {
          page: opts?.page,
          per_page: opts?.per_page,
          status: opts?.status,
          severity: opts?.severity,
        },
      },
    );
  }

  async listFindings(opts?: ListFindingsOptions): Promise<Finding[]> {
    return this.authenticatedRequest<Finding[]>("GET", "/api/v1/findings", {
      params: {
        page: opts?.page,
        per_page: opts?.per_page,
        scan_id: opts?.scan_id,
      },
    });
  }

  async getFinding(findingID: string): Promise<Finding> {
    return this.authenticatedRequest<Finding>(
      "GET",
      `/api/v1/findings/${findingID}`,
    );
  }

  async patchFinding(
    findingID: string,
    req: PatchFindingRequest,
  ): Promise<Finding> {
    return this.authenticatedRequest<Finding>(
      "PATCH",
      `/api/v1/findings/${findingID}`,
      { body: req },
    );
  }

  // ─── Reports ───

  async getReport(
    scanID: string,
    format: string = "json",
  ): Promise<ArrayBuffer> {
    const resp = await this.authenticatedRequest<Response>(
      "GET",
      `/api/v1/scans/${scanID}/report`,
      { params: { format }, raw: true },
    );
    return resp.arrayBuffer();
  }

  async getReportStream(
    scanID: string,
    format: string = "json",
  ): Promise<ReadableStream<Uint8Array>> {
    const resp = await this.authenticatedRequest<Response>(
      "GET",
      `/api/v1/scans/${scanID}/report`,
      { params: { format }, raw: true },
    );
    if (!resp.body) throw new Error("No response body");
    return resp.body;
  }

  // ─── Specs ───

  async uploadSpec(
    file: Blob | Buffer,
    filename: string,
  ): Promise<UploadSpecResponse> {
    // Note: uploadSpec needs multipart -- use FormData
    const formData = new FormData();
    formData.append(
      "file",
      file instanceof Blob ? file : new Blob([file]),
      filename,
    );
    return this.authenticatedRequest<UploadSpecResponse>(
      "POST",
      "/api/v1/specs",
      { body: formData },
    );
  }

  // ─── Audit ───

  async getAuditLog(
    limit: number = 50,
    page?: number,
  ): Promise<AuditEntry[]> {
    return this.authenticatedRequest<AuditEntry[]>("GET", "/api/v1/audit", {
      params: { limit, page },
    });
  }

  // ─── Auth ───

  /**
   * Exchange a refresh token for a new access token via
   * POST /api/v1/auth/refresh. Updates the cached JWT on success,
   * matching the Go SDK's RefreshToken behaviour.
   */
  async refreshToken(
    refreshToken: string,
  ): Promise<RefreshTokenResponse> {
    const result = await this.http.request<RefreshTokenResponse>(
      "POST",
      "/api/v1/auth/refresh",
      { body: { refresh_token: refreshToken } },
    );

    // Update cached token state, matching Go SDK behaviour.
    if (result.access_token) {
      const exp = parseJWTExp(result.access_token);
      this.jwt = result.access_token;
      this.tokenExpiry =
        exp ?? Math.floor(Date.now() / 1000) + FALLBACK_TOKEN_LIFETIME_SECS;
      this.http.setHeader("Authorization", `Bearer ${result.access_token}`);
    }

    return result;
  }
}

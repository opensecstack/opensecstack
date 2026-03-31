import { HttpClient } from "./http.js";
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

export interface APIGuardClientOptions {
  baseURL: string;
  apiKey: string;
  timeout?: number;
  maxRetries?: number;
  retryWaitBase?: number;
}

export class APIGuardClient {
  private readonly http: HttpClient;

  constructor(opts: APIGuardClientOptions) {
    this.http = new HttpClient({
      baseURL: opts.baseURL,
      timeout: opts.timeout,
      maxRetries: opts.maxRetries,
      retryWaitBase: opts.retryWaitBase,
      headers: { Authorization: `Bearer ${opts.apiKey}` },
    });
  }

  // ─── Scans ───

  async createScan(specURL: string): Promise<Scan> {
    return this.http.request<Scan>("POST", "/api/v1/scans", {
      body: { spec_url: specURL },
    });
  }

  async createScanFull(opts: CreateScanOptions): Promise<Scan> {
    return this.http.request<Scan>("POST", "/api/v1/scans", { body: opts });
  }

  async getScan(scanID: string): Promise<Scan> {
    return this.http.request<Scan>("GET", `/api/v1/scans/${scanID}`);
  }

  async listScans(opts?: ListScansOptions): Promise<Scan[]> {
    return this.http.request<Scan[]>("GET", "/api/v1/scans", {
      params: {
        page: opts?.page,
        per_page: opts?.per_page,
      },
    });
  }

  async deleteScan(scanID: string): Promise<void> {
    return this.http.request<void>("DELETE", `/api/v1/scans/${scanID}`);
  }

  // ─── Findings ───

  async getFindings(
    scanID: string,
    opts?: GetFindingsOptions,
  ): Promise<Finding[]> {
    return this.http.request<Finding[]>(
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
    return this.http.request<Finding[]>("GET", "/api/v1/findings", {
      params: {
        page: opts?.page,
        per_page: opts?.per_page,
        scan_id: opts?.scan_id,
      },
    });
  }

  async getFinding(findingID: string): Promise<Finding> {
    return this.http.request<Finding>(
      "GET",
      `/api/v1/findings/${findingID}`,
    );
  }

  async patchFinding(
    findingID: string,
    req: PatchFindingRequest,
  ): Promise<Finding> {
    return this.http.request<Finding>(
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
    const resp = await this.http.request<Response>(
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
    const resp = await this.http.request<Response>(
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
    return this.http.request<UploadSpecResponse>("POST", "/api/v1/specs", {
      body: formData,
    });
  }

  // ─── Audit ───

  async getAuditLog(
    limit: number = 50,
    page?: number,
  ): Promise<AuditEntry[]> {
    return this.http.request<AuditEntry[]>("GET", "/api/v1/audit", {
      params: { limit, page },
    });
  }

  // ─── Auth ───

  async refreshToken(
    refreshToken: string,
  ): Promise<RefreshTokenResponse> {
    return this.http.request<RefreshTokenResponse>(
      "POST",
      "/api/v1/auth/refresh",
      { body: { refresh_token: refreshToken } },
    );
  }
}

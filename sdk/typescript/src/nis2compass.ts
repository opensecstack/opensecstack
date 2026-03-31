import { HttpClient } from "./http.js";
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

  constructor(opts: NIS2CompassClientOptions) {
    this.http = new HttpClient({
      baseURL: opts.baseURL,
      timeout: opts.timeout,
      maxRetries: opts.maxRetries,
      retryWaitBase: opts.retryWaitBase,
      headers: { Authorization: `Bearer ${opts.apiKey}` },
    });
    this.httpPublic = new HttpClient({
      baseURL: opts.baseURL,
      timeout: opts.timeout,
      maxRetries: opts.maxRetries,
      retryWaitBase: opts.retryWaitBase,
    });
  }

  // ─── Organisations ───

  async getOrganisations(
    opts?: GetOrganisationsOptions,
  ): Promise<Organisation[]> {
    return this.http.request<Organisation[]>("GET", "/api/v1/organisations", {
      params: {
        page: opts?.page,
        per_page: opts?.per_page,
      },
    });
  }

  async createOrganisation(
    req: CreateOrganisationRequest,
  ): Promise<Organisation> {
    return this.http.request<Organisation>("POST", "/api/v1/organisations", {
      body: req,
    });
  }

  async getOrganisation(id: string): Promise<Organisation> {
    return this.http.request<Organisation>(
      "GET",
      `/api/v1/organisations/${id}`,
    );
  }

  async patchOrganisation(
    id: string,
    req: PatchOrganisationRequest,
  ): Promise<Organisation> {
    return this.http.request<Organisation>(
      "PATCH",
      `/api/v1/organisations/${id}`,
      { body: req },
    );
  }

  async deleteOrganisation(id: string): Promise<void> {
    return this.http.request<void>("DELETE", `/api/v1/organisations/${id}`);
  }

  // ─── Assessments ───

  async getAssessments(
    orgID: string,
    opts?: GetAssessmentsOptions,
  ): Promise<Assessment[]> {
    return this.http.request<Assessment[]>(
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
    return this.http.request<Assessment>(
      "POST",
      `/api/v1/organisations/${orgID}/assessments`,
      { body: req },
    );
  }

  async getAssessment(id: string): Promise<Assessment> {
    return this.http.request<Assessment>("GET", `/api/v1/assessments/${id}`);
  }

  async patchAssessment(
    id: string,
    req: PatchAssessmentRequest,
  ): Promise<Assessment> {
    return this.http.request<Assessment>(
      "PATCH",
      `/api/v1/assessments/${id}`,
      { body: req },
    );
  }

  async deleteAssessment(id: string): Promise<void> {
    return this.http.request<void>("DELETE", `/api/v1/assessments/${id}`);
  }

  // ─── Controls ───

  /** List controls with optional filters (status, nist_category, measure_ref). */
  async listControls(
    assessmentID: string,
    opts?: ListControlsOptions,
  ): Promise<Control[]> {
    return this.http.request<Control[]>(
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
    return this.http.request<Control[]>(
      "GET",
      `/api/v1/assessments/${assessmentID}/controls`,
    );
  }

  async getControl(
    assessmentID: string,
    measureRef: string,
  ): Promise<Control> {
    return this.http.request<Control>(
      "GET",
      `/api/v1/assessments/${assessmentID}/controls/${measureRef}`,
    );
  }

  async patchControl(
    assessmentID: string,
    measureRef: string,
    req: PatchControlRequest,
  ): Promise<Control> {
    return this.http.request<Control>(
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
    return this.http.request<Artifact[]>(
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

    return this.http.request<Artifact>(
      "POST",
      `/api/v1/assessments/${assessmentID}/artifacts`,
      { body: formData },
    );
  }

  async getArtifact(artifactID: string): Promise<Artifact> {
    return this.http.request<Artifact>(
      "GET",
      `/api/v1/artifacts/${artifactID}`,
    );
  }

  async downloadArtifact(artifactID: string): Promise<ArrayBuffer> {
    const resp = await this.http.request<Response>(
      "GET",
      `/api/v1/artifacts/${artifactID}/download`,
      { raw: true },
    );
    return resp.arrayBuffer();
  }

  async deleteArtifact(artifactID: string): Promise<void> {
    return this.http.request<void>(
      "DELETE",
      `/api/v1/artifacts/${artifactID}`,
    );
  }

  // ─── API Keys ───

  async listAPIKeys(): Promise<APIKey[]> {
    return this.http.request<APIKey[]>("GET", "/api/v1/api-keys");
  }

  async createAPIKey(req: CreateAPIKeyRequest): Promise<APIKey> {
    return this.http.request<APIKey>("POST", "/api/v1/api-keys", {
      body: req,
    });
  }

  async revokeAPIKey(keyID: string): Promise<void> {
    return this.http.request<void>("DELETE", `/api/v1/api-keys/${keyID}`);
  }

  // ─── Reports ───

  /**
   * Generate a PDF report for the given assessment.
   * Returns the full PDF as an ArrayBuffer. For large reports prefer
   * {@link getReportStream} which avoids buffering the entire body.
   */
  async generateReport(assessmentID: string): Promise<ArrayBuffer> {
    const resp = await this.http.request<Response>(
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
    const resp = await this.http.request<Response>(
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
    return this.http.request<NIS2AuditEntry[]>("GET", "/api/v1/audit", {
      params: { limit, page },
    });
  }

  async getAuditEntry(entryID: string): Promise<NIS2AuditEntry> {
    return this.http.request<NIS2AuditEntry>(
      "GET",
      `/api/v1/audit/${entryID}`,
    );
  }

  // ─── Health ───

  async getHealth(): Promise<HealthStatus> {
    return this.httpPublic.request<HealthStatus>("GET", "/health");
  }

  async getHealthDetail(): Promise<HealthStatus> {
    return this.http.request<HealthStatus>("GET", "/health/detail");
  }
}

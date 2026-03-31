import { createHmac, createHash } from "node:crypto";
import type {
  SecurityEvent,
  GetEventsOptions,
  Advisory,
  CreateAdvisoryRequest,
  PatchAdvisoryRequest,
  ListAdvisoriesOptions,
} from "./types.js";
import { OpenSecStackError, RateLimitError } from "./types.js";

export interface CITADELClientOptions {
  baseURL: string;
  keyID: string;
  sharedSecret: string;
  timeout?: number;
  maxRetries?: number;
  retryWaitBase?: number;
}

export class CITADELClient {
  private readonly baseURL: string;
  private readonly keyID: string;
  private readonly secret: string;
  private readonly timeout: number;
  private readonly maxRetries: number;
  private readonly retryWaitBase: number;
  private readonly disabled: boolean;
  private readonly pending = new Set<Promise<void>>();

  constructor(opts: CITADELClientOptions) {
    this.baseURL = opts.baseURL.replace(/\/+$/, "");
    this.keyID = opts.keyID;
    this.secret = opts.sharedSecret;
    this.timeout = opts.timeout ?? 30_000;
    this.maxRetries = opts.maxRetries ?? 3;
    this.retryWaitBase = opts.retryWaitBase ?? 500;
    this.disabled = !opts.baseURL;
  }

  // ─── HMAC Signing ───

  private sign(body: string): { key: string; ts: string; sig: string } {
    const ts = Math.floor(Date.now() / 1000).toString();
    const bodyHash = createHash("sha256").update(body).digest("hex");
    const message = `${this.keyID}:${ts}:${bodyHash}`;
    const sig =
      "hmac-sha256=" +
      createHmac("sha256", this.secret).update(message).digest("hex");
    return { key: this.keyID, ts, sig };
  }

  // ─── Internal request helper ───

  private async do<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    if (this.disabled) return undefined as T;

    const bodyStr = body !== undefined ? JSON.stringify(body) : "";
    const { key, ts, sig } = this.sign(bodyStr);

    const url = `${this.baseURL}${path}`;
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      if (attempt > 0) {
        await new Promise((r) =>
          setTimeout(r, this.retryWaitBase * Math.pow(2, attempt - 1)),
        );
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeout);

      try {
        const resp = await fetch(url, {
          method,
          headers: {
            "Content-Type": "application/json",
            "X-CITADEL-KEY": key,
            "X-CITADEL-TS": ts,
            "X-CITADEL-SIG": sig,
            "X-Request-ID": crypto.randomUUID(),
          },
          body: bodyStr || undefined,
          signal: controller.signal,
          redirect: "error",
        });
        clearTimeout(timer);

        if (resp.status === 429) {
          const retryAfter = parseInt(
            resp.headers.get("Retry-After") ?? "60",
            10,
          );
          if (attempt < this.maxRetries && retryAfter <= 60) {
            await new Promise((r) => setTimeout(r, retryAfter * 1000));
            continue;
          }
          throw new RateLimitError("Rate limited", retryAfter);
        }

        if (resp.status >= 500 && attempt < this.maxRetries) {
          lastError = new OpenSecStackError(
            `Server error: ${resp.status}`,
            resp.status,
          );
          continue;
        }

        if (resp.status === 204) return undefined as T;

        const data = (await resp.json()) as Record<string, unknown>;
        if (!resp.ok) {
          throw new OpenSecStackError(
            (data.error as string) ?? `HTTP ${resp.status}`,
            resp.status,
            data.code as string | undefined,
          );
        }
        return data as T;
      } catch (err) {
        clearTimeout(timer);
        if (err instanceof OpenSecStackError || err instanceof RateLimitError)
          throw err;
        lastError = err instanceof Error ? err : new Error(String(err));
        if (attempt >= this.maxRetries) break;
      }
    }
    throw lastError ?? new Error("Request failed");
  }

  // ─── Events ───

  async sendEvent(
    event: Omit<
      SecurityEvent,
      "id" | "chain_hash" | "prev_hash" | "timestamp"
    >,
  ): Promise<void> {
    const promise = this.do("POST", "/api/v1/events", event).then(() => {});
    this.pending.add(promise);
    promise.finally(() => this.pending.delete(promise));
    return promise;
  }

  async getEvents(opts?: GetEventsOptions): Promise<SecurityEvent[]> {
    const params = new URLSearchParams();
    if (opts?.source) params.set("source", opts.source);
    if (opts?.event_type) params.set("event_type", opts.event_type);
    if (opts?.since) params.set("since", opts.since);
    if (opts?.until) params.set("until", opts.until);
    if (opts?.limit) params.set("limit", String(opts.limit));
    if (opts?.page) params.set("page", String(opts.page));
    const qs = params.toString();
    return this.do<SecurityEvent[]>(
      "GET",
      `/api/v1/events${qs ? "?" + qs : ""}`,
    );
  }

  async getEvent(eventID: string): Promise<SecurityEvent> {
    return this.do<SecurityEvent>("GET", `/api/v1/events/${eventID}`);
  }

  // ─── Chain Verification ───

  verifyChain(events: SecurityEvent[]): void {
    if (events.length < 2) return;
    for (let i = 0; i < events.length - 1; i++) {
      const prev = events[i]!;
      const next = events[i + 1]!;

      // Verify prev_hash linkage.
      if (next.prev_hash !== prev.chain_hash) {
        throw new Error(
          `Chain broken at index ${i + 1}: expected prev_hash=${prev.chain_hash}, got ${next.prev_hash}`,
        );
      }

      // Recompute chain hash: SHA-256(prev.chain_hash + JSON(next.payload))
      const h = createHash("sha256");
      h.update(prev.chain_hash);
      h.update(JSON.stringify(next.payload));
      const computed = h.digest("hex");

      if (computed !== next.chain_hash) {
        throw new Error(
          `Chain hash mismatch at index ${i} -> ${i + 1}: ` +
            `expected chain_hash=${next.chain_hash}, computed ${computed} ` +
            `(event_ids: ${prev.id} -> ${next.id})`,
        );
      }
    }
  }

  // ─── Drain ───

  async drain(timeoutMs: number = 30_000): Promise<void> {
    if (this.pending.size === 0) return;
    const allDone = Promise.all(this.pending);
    const timeout = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("Drain timed out")), timeoutMs),
    );
    await Promise.race([allDone, timeout]);
  }

  // ─── AUGUR Advisories ───

  async createAdvisory(req: CreateAdvisoryRequest): Promise<Advisory> {
    return this.do<Advisory>("POST", "/api/v1/augur/advisories", req);
  }

  async listAdvisories(opts?: ListAdvisoriesOptions): Promise<Advisory[]> {
    const params = new URLSearchParams();
    if (opts?.page) params.set("page", String(opts.page));
    if (opts?.per_page) params.set("per_page", String(opts.per_page));
    if (opts?.status) params.set("status", opts.status);
    if (opts?.severity) params.set("severity", opts.severity);
    const qs = params.toString();
    return this.do<Advisory[]>(
      "GET",
      `/api/v1/augur/advisories${qs ? "?" + qs : ""}`,
    );
  }

  async getAdvisory(id: string): Promise<Advisory> {
    if (!id) throw new Error("Advisory ID must not be empty");
    return this.do<Advisory>("GET", `/api/v1/augur/advisories/${id}`);
  }

  async patchAdvisory(
    id: string,
    req: PatchAdvisoryRequest,
  ): Promise<Advisory> {
    if (!id) throw new Error("Advisory ID must not be empty");
    return this.do<Advisory>("PATCH", `/api/v1/augur/advisories/${id}`, req);
  }

  async deleteAdvisory(id: string): Promise<void> {
    if (!id) throw new Error("Advisory ID must not be empty");
    return this.do<void>("DELETE", `/api/v1/augur/advisories/${id}`);
  }

  async getActiveAdvisories(): Promise<Advisory[]> {
    return this.listAdvisories({ status: "published" });
  }
}

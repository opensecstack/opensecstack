import { OpenSecStackError, RateLimitError } from "./types.js";

export interface HttpClientOptions {
  baseURL: string;
  timeout?: number;
  maxRetries?: number;
  retryWaitBase?: number;
  headers?: Record<string, string>;
}

export class HttpClient {
  private readonly baseURL: string;
  private readonly timeout: number;
  private readonly maxRetries: number;
  private readonly retryWaitBase: number;
  private defaultHeaders: Record<string, string>;

  constructor(opts: HttpClientOptions) {
    this.baseURL = opts.baseURL.replace(/\/+$/, "");
    this.timeout = opts.timeout ?? 30_000;
    this.maxRetries = opts.maxRetries ?? 3;
    this.retryWaitBase = opts.retryWaitBase ?? 500;
    this.defaultHeaders = opts.headers ?? {};
  }

  /**
   * Update or add a default header. Used by clients to set the
   * Authorization header after obtaining/refreshing a JWT.
   */
  setHeader(key: string, value: string): void {
    this.defaultHeaders[key] = value;
  }

  /**
   * Return the current value of a default header, or undefined.
   */
  getHeader(key: string): string | undefined {
    return this.defaultHeaders[key];
  }

  async request<T>(
    method: string,
    path: string,
    options?: {
      body?: unknown;
      params?: Record<string, string | number | undefined>;
      headers?: Record<string, string>;
      raw?: boolean; // return raw Response instead of parsed JSON
    },
  ): Promise<T> {
    const url = new URL(this.baseURL + path);
    if (options?.params) {
      for (const [key, value] of Object.entries(options.params)) {
        if (value !== undefined && value !== "") {
          url.searchParams.set(key, String(value));
        }
      }
    }

    const headers: Record<string, string> = {
      ...this.defaultHeaders,
      ...options?.headers,
    };

    if (options?.body !== undefined && !(options.body instanceof FormData)) {
      headers["Content-Type"] = "application/json";
    }

    // Generate a request ID for tracing
    headers["X-Request-ID"] = crypto.randomUUID();

    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      if (attempt > 0) {
        const wait = this.retryWaitBase * Math.pow(2, attempt - 1);
        await new Promise((r) => setTimeout(r, wait));
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeout);

      try {
        const resp = await fetch(url.toString(), {
          method,
          headers,
          body: options?.body instanceof FormData
            ? options.body
            : options?.body !== undefined
              ? JSON.stringify(options.body)
              : undefined,
          signal: controller.signal,
          redirect: "error", // never follow redirects (prevent Bearer token leak)
        });

        clearTimeout(timer);

        // Rate limit
        if (resp.status === 429) {
          const retryAfter = parseInt(resp.headers.get("Retry-After") ?? "60", 10);
          if (attempt < this.maxRetries && retryAfter <= 60) {
            await new Promise((r) => setTimeout(r, retryAfter * 1000));
            continue;
          }
          throw new RateLimitError("Rate limited", retryAfter);
        }

        // Retry on 5xx
        if (resp.status >= 500 && attempt < this.maxRetries) {
          lastError = new OpenSecStackError(
            `Server error: ${resp.status}`,
            resp.status,
          );
          continue;
        }

        // Return raw response for streaming endpoints
        if (options?.raw) {
          return resp as unknown as T;
        }

        // 204 No Content
        if (resp.status === 204) {
          return undefined as T;
        }

        // Validate Content-Type for JSON responses
        const contentType = resp.headers.get("Content-Type") ?? "";
        if (!contentType.startsWith("application/json")) {
          if (resp.ok) {
            // For binary responses (PDF etc.), return the response
            return resp as unknown as T;
          }
          throw new OpenSecStackError(
            `Unexpected Content-Type: ${contentType}`,
            resp.status,
          );
        }

        const body = (await resp.json()) as Record<string, unknown>;

        if (!resp.ok) {
          const msg = (body.error ?? body.message ?? `HTTP ${resp.status}`) as string;
          throw new OpenSecStackError(msg, resp.status, body.code as string | undefined);
        }

        return body as T;
      } catch (err) {
        clearTimeout(timer);
        if (err instanceof OpenSecStackError || err instanceof RateLimitError) {
          throw err;
        }
        lastError = err instanceof Error ? err : new Error(String(err));
        if (attempt >= this.maxRetries) break;
      }
    }

    throw lastError ?? new Error("Request failed");
  }
}

import { createHmac, timingSafeEqual as nodeTimingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

// ─── Event Type Constants ────────────────────────────────────────────────────

export const EventAPIScanCompleted = "apiguard.scan.completed";
export const EventAPIScanFailed = "apiguard.scan.failed";
export const EventAPIFindingCritical = "apiguard.finding.critical";
export const EventNIS2ControlUpdated = "nis2compass.control.updated";
export const EventNIS2AssessmentCompleted = "nis2compass.assessment.completed";
export const EventCITADELHardStop = "citadel.hard_stop";
export const EventCITADELVigilRed = "citadel.vigil_red";
export const EventCITADELVigilAmber = "citadel.vigil_amber";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface WebhookEvent {
  id: string;
  event_type: string;
  source: string;
  timestamp: string;
  payload: Record<string, unknown>;
  signature?: string;
}

export type WebhookHandler = (event: WebhookEvent) => void | Promise<void>;

export class InvalidSignatureError extends Error {
  constructor(message = "invalid webhook signature") {
    super(message);
    this.name = "InvalidSignatureError";
  }
}

// ─── Signature Verification ──────────────────────────────────────────────────

/**
 * Compute HMAC-SHA256 of `body` using `secret` and return "sha256=<hex>".
 */
function computeHMAC(body: Buffer | Uint8Array, secret: string): string {
  const mac = createHmac("sha256", secret);
  mac.update(body);
  return "sha256=" + mac.digest("hex");
}

/**
 * Verify the HMAC-SHA256 signature of a webhook request body.
 *
 * Uses constant-time comparison to prevent timing attacks.
 * Throws {@link InvalidSignatureError} on mismatch.
 *
 * @param body      - Raw request body bytes.
 * @param signature - The signature header value (format: "sha256=<hex>").
 * @param secret    - The shared webhook secret.
 */
export function verifySignature(
  body: Buffer | Uint8Array,
  signature: string,
  secret: string,
): void {
  const expected = computeHMAC(body, secret);
  // Constant-length comparison: both strings are the same fixed format
  // ("sha256=" + 64 hex chars), so length leak is irrelevant.
  if (
    expected.length !== signature.length ||
    !timingSafeEqual(Buffer.from(expected), Buffer.from(signature))
  ) {
    throw new InvalidSignatureError();
  }
}

/**
 * Timing-safe comparison. Falls back to byte-by-byte OR if crypto import
 * is unavailable (should not happen in Node ≥ 18).
 */
function timingSafeEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  return nodeTimingSafeEqual(a, b);
}

// ─── Webhook Router ──────────────────────────────────────────────────────────

/**
 * Routes incoming webhook events to registered handlers after verifying the
 * HMAC-SHA256 signature.
 *
 * Works as both a standalone Node.js HTTP handler and with Express/Koa/Hono
 * when raw body bytes are available.
 *
 * @example
 * ```ts
 * import { WebhookRouter, EventAPIScanCompleted } from "@opensecstack/sdk/webhook";
 *
 * const router = new WebhookRouter("my-shared-secret");
 * router.on(EventAPIScanCompleted, (event) => {
 *   console.log("Scan done:", event.id);
 * });
 *
 * // Mount on a Node.js HTTP server:
 * http.createServer((req, res) => router.handleHttp(req, res));
 *
 * // Or call directly with raw body:
 * router.handle(rawBody, signatureHeader);
 * ```
 */
export class WebhookRouter {
  private readonly secret: string;
  private readonly handlers = new Map<string, WebhookHandler>();
  private catchAll: WebhookHandler | undefined;

  constructor(secret: string) {
    this.secret = secret;
  }

  /**
   * Register a handler for a specific event type.
   * Use `"*"` to register a catch-all handler for unmatched event types.
   * Returns `this` for method chaining.
   */
  on(eventType: string, handler: WebhookHandler): this {
    if (eventType === "*") {
      this.catchAll = handler;
    } else {
      this.handlers.set(eventType, handler);
    }
    return this;
  }

  /**
   * Verify signature, parse the event, and dispatch to the matching handler.
   *
   * @param body      - Raw request body bytes.
   * @param signature - The signature header value ("sha256=<hex>").
   * @returns The parsed event.
   * @throws {InvalidSignatureError} if signature verification fails.
   */
  async handle(
    body: Buffer | Uint8Array,
    signature: string,
  ): Promise<WebhookEvent> {
    verifySignature(body, signature, this.secret);

    const event: WebhookEvent = JSON.parse(
      Buffer.from(body).toString("utf-8"),
    );

    const handler = this.handlers.get(event.event_type) ?? this.catchAll;
    if (handler) {
      await handler(event);
    }

    return event;
  }

  /**
   * Node.js `http.IncomingMessage` / `http.ServerResponse` handler.
   *
   * Reads the raw body from the stream, verifies the signature from
   * `X-Citadel-Signature` or `X-APIGuard-Signature`, parses the event,
   * and dispatches to the registered handler.
   *
   * Response status codes:
   * - 200 — event processed (or no handler registered)
   * - 400 — missing or invalid signature
   * - 422 — body is not valid JSON
   * - 500 — handler threw an error
   */
  async handleHttp(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
    }
    const body = Buffer.concat(chunks);

    // Accept signature from either platform header.
    const sig =
      (req.headers["x-citadel-signature"] as string | undefined) ??
      (req.headers["x-apiguard-signature"] as string | undefined) ??
      "";

    try {
      verifySignature(body, sig, this.secret);
    } catch {
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("signature verification failed");
      return;
    }

    let event: WebhookEvent;
    try {
      event = JSON.parse(body.toString("utf-8"));
    } catch {
      res.writeHead(422, { "Content-Type": "text/plain" });
      res.end("failed to parse event JSON");
      return;
    }

    const handler = this.handlers.get(event.event_type) ?? this.catchAll;
    if (!handler) {
      res.writeHead(200);
      res.end();
      return;
    }

    try {
      await handler(event);
      res.writeHead(200);
      res.end();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.writeHead(500, { "Content-Type": "text/plain" });
      res.end(`handler error: ${msg}`);
    }
  }
}

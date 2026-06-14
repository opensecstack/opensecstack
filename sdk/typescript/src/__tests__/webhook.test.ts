import { describe, it, expect, vi } from "vitest";
import { createHmac } from "node:crypto";
import {
  WebhookRouter,
  verifySignature,
  InvalidSignatureError,
  EventAPIScanCompleted,
  EventAPIScanFailed,
  EventCITADELHardStop,
} from "../webhook.js";
import type { WebhookEvent } from "../webhook.js";

// ─── Helpers ────────────────────────────────────────────────────────────────

function sign(body: Buffer | string, secret: string): string {
  const mac = createHmac("sha256", secret);
  mac.update(typeof body === "string" ? Buffer.from(body) : body);
  return "sha256=" + mac.digest("hex");
}

function makeEventJSON(overrides?: Partial<WebhookEvent>): string {
  const event: WebhookEvent = {
    id: "evt-001",
    event_type: EventAPIScanCompleted,
    source: "apiguard",
    timestamp: "2026-03-31T12:00:00Z",
    payload: { scan_id: "scan-001", findings_count: 3 },
    ...overrides,
  };
  return JSON.stringify(event);
}

const SECRET = "test-webhook-secret";

// ─── verifySignature ────────────────────────────────────────────────────────

describe("verifySignature", () => {
  it("1. accepts a valid signature", () => {
    const body = Buffer.from("hello world");
    const sig = sign(body, SECRET);
    expect(() => verifySignature(body, sig, SECRET)).not.toThrow();
  });

  it("2. rejects an invalid signature", () => {
    const body = Buffer.from("hello world");
    expect(() =>
      verifySignature(body, "sha256=0000000000000000000000000000000000000000000000000000000000000000", SECRET),
    ).toThrow(InvalidSignatureError);
  });

  it("3. rejects a tampered body", () => {
    const body = Buffer.from("original");
    const sig = sign(body, SECRET);
    const tampered = Buffer.from("tampered");
    expect(() => verifySignature(tampered, sig, SECRET)).toThrow(
      InvalidSignatureError,
    );
  });

  it("4. rejects wrong secret", () => {
    const body = Buffer.from("test");
    const sig = sign(body, "correct-secret");
    expect(() => verifySignature(body, sig, "wrong-secret")).toThrow(
      InvalidSignatureError,
    );
  });

  it("5. rejects empty signature", () => {
    const body = Buffer.from("test");
    expect(() => verifySignature(body, "", SECRET)).toThrow(
      InvalidSignatureError,
    );
  });
});

// ─── WebhookRouter ──────────────────────────────────────────────────────────

describe("WebhookRouter", () => {
  it("6. dispatches to the correct handler", async () => {
    const handler = vi.fn();
    const router = new WebhookRouter(SECRET);
    router.on(EventAPIScanCompleted, handler);

    const body = Buffer.from(makeEventJSON());
    const sig = sign(body, SECRET);

    const event = await router.handle(body, sig);

    expect(handler).toHaveBeenCalledOnce();
    expect(handler).toHaveBeenCalledWith(
      expect.objectContaining({ event_type: EventAPIScanCompleted }),
    );
    expect(event.id).toBe("evt-001");
  });

  it("7. rejects bad signature with InvalidSignatureError", async () => {
    const router = new WebhookRouter(SECRET);
    router.on(EventAPIScanCompleted, vi.fn());

    const body = Buffer.from(makeEventJSON());

    await expect(router.handle(body, "sha256=bad")).rejects.toThrow(
      InvalidSignatureError,
    );
  });

  it("8. catch-all handler fires for unregistered event types", async () => {
    const catchAll = vi.fn();
    const router = new WebhookRouter(SECRET);
    router.on("*", catchAll);

    const body = Buffer.from(
      makeEventJSON({ event_type: "custom.unknown.event" }),
    );
    const sig = sign(body, SECRET);

    await router.handle(body, sig);

    expect(catchAll).toHaveBeenCalledOnce();
    expect(catchAll).toHaveBeenCalledWith(
      expect.objectContaining({ event_type: "custom.unknown.event" }),
    );
  });

  it("9. no handler registered — returns event without error", async () => {
    const router = new WebhookRouter(SECRET);
    const body = Buffer.from(makeEventJSON());
    const sig = sign(body, SECRET);

    const event = await router.handle(body, sig);
    expect(event.event_type).toBe(EventAPIScanCompleted);
  });

  it("10. handler error propagates", async () => {
    const router = new WebhookRouter(SECRET);
    router.on(EventAPIScanCompleted, () => {
      throw new Error("handler failed");
    });

    const body = Buffer.from(makeEventJSON());
    const sig = sign(body, SECRET);

    await expect(router.handle(body, sig)).rejects.toThrow("handler failed");
  });

  it("11. method chaining", () => {
    const router = new WebhookRouter(SECRET);
    const result = router
      .on(EventAPIScanCompleted, vi.fn())
      .on(EventAPIScanFailed, vi.fn())
      .on(EventCITADELHardStop, vi.fn());
    expect(result).toBe(router);
  });

  it("12. async handler is awaited", async () => {
    let resolved = false;
    const router = new WebhookRouter(SECRET);
    router.on(EventAPIScanCompleted, async () => {
      await new Promise((r) => setTimeout(r, 10));
      resolved = true;
    });

    const body = Buffer.from(makeEventJSON());
    const sig = sign(body, SECRET);

    await router.handle(body, sig);
    expect(resolved).toBe(true);
  });

  it("13. specific handler takes precedence over catch-all", async () => {
    const specific = vi.fn();
    const catchAll = vi.fn();
    const router = new WebhookRouter(SECRET);
    router.on(EventAPIScanCompleted, specific).on("*", catchAll);

    const body = Buffer.from(makeEventJSON());
    const sig = sign(body, SECRET);

    await router.handle(body, sig);

    expect(specific).toHaveBeenCalledOnce();
    expect(catchAll).not.toHaveBeenCalled();
  });

  it("14. event constants match Go/Python values", () => {
    expect(EventAPIScanCompleted).toBe("apiguard.scan.completed");
    expect(EventAPIScanFailed).toBe("apiguard.scan.failed");
    expect(EventCITADELHardStop).toBe("citadel.hard_stop");
  });
});

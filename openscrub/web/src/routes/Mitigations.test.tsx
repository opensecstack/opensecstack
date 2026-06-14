import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import "@/i18n";
import * as mitigationsApi from "@/api/mitigations";
import Mitigations from "./Mitigations";

function renderWithClient(client: QueryClient) {
  return render(
    <QueryClientProvider client={client}>
      <Mitigations />
    </QueryClientProvider>,
  );
}

describe("Mitigations route", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("renders rows from listMitigations", async () => {
    vi.spyOn(mitigationsApi, "listMitigations").mockResolvedValue({
      mitigations: [
        {
          id: "11111111-1111-1111-1111-111111111111",
          rule_id: "22222222-2222-2222-2222-222222222222",
          started_at: "2026-05-09T10:00:00Z",
          ended_at: null,
          packets_dropped: 4823,
          bytes_dropped: 2891204,
          src_ip: "198.51.100.7",
          emitted: true,
        },
      ],
      count: 1,
    });

    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    renderWithClient(client);

    expect(await screen.findByText("198.51.100.7")).toBeInTheDocument();
  });

  it("auto-refreshes every 5s", async () => {
    const spy = vi.spyOn(mitigationsApi, "listMitigations").mockResolvedValue({
      mitigations: [],
      count: 0,
    });

    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    renderWithClient(client);

    // Initial fetch.
    await waitFor(() => expect(spy).toHaveBeenCalledTimes(1));

    // Advance by 5s — refetchInterval should fire a second time.
    await vi.advanceTimersByTimeAsync(5_000);
    await waitFor(() => expect(spy).toHaveBeenCalledTimes(2));

    // …and again at 10s for good measure.
    await vi.advanceTimersByTimeAsync(5_000);
    await waitFor(() => expect(spy).toHaveBeenCalledTimes(3));
  });
});

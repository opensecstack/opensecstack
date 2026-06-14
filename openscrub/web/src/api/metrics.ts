import { apiClient } from "./client";

// MetricsSnapshot mirrors the JSON returned by GET /api/v1/metrics/snapshot
// on the Go control plane. The legacy /api/v1/metrics endpoint still serves
// Prometheus exposition text/plain for scrapers and is intentionally not used
// by the web UI.
export interface MetricsSnapshot {
  pps_passed: number;
  pps_dropped: number;
  pps_ratelimited: number;
  syn_cookies_sent: number;
  rules_active: number;
  rules_v4: number;
  rules_v6: number;
  rules_ratelimit: number;
  rules_syncookie: number;
  ioc_pull_last_at: string;
  ioc_pull_count: number;
  citadel_queue_depth: number;
  dataplane_attached: boolean;
  snapshot_at: string;
}

export async function fetchMetrics(): Promise<MetricsSnapshot> {
  const res = await apiClient.get<MetricsSnapshot>("/api/v1/metrics/snapshot");
  return res.data;
}

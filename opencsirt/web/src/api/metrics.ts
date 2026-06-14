import { apiClient } from "./client";

export interface MetricsSnapshot {
  incidents_by_status: Record<string, number>;
  advisories_by_state: Record<string, number>;
  outbox_pending: number;
  outbox_failed: number;
  citadel_queue_depth: number;
  iocs_last_ingested_at?: string;
  iocs_last_bundle_size: number;
  advisory_service_up: boolean;
  node: string;
  version: string;
  snapshot_at: string;
}

export async function fetchMetrics(): Promise<MetricsSnapshot> {
  const res = await apiClient.get<MetricsSnapshot>("/api/v1/metrics/snapshot");
  return res.data;
}

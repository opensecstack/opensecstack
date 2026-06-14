import { apiClient } from "./client";

export type TrustLevel = "verified" | "pending" | "failed" | "expired";

export interface Peer {
  id: string;
  name: string;
  country: string;
  registry: "first" | "tf-csirt" | "csirts-network" | "other";
  trust: TrustLevel;
  last_handshake_at: string | null;
  ed25519_fingerprint: string;
}

export interface PeerListResponse {
  peers: Peer[];
  count: number;
}

export async function listPeers(): Promise<PeerListResponse> {
  const res = await apiClient.get<PeerListResponse>("/api/v1/peers");
  return res.data;
}

export async function handshakePeer(id: string): Promise<Peer> {
  const res = await apiClient.post<Peer>(`/api/v1/peers/${id}/handshake`);
  return res.data;
}

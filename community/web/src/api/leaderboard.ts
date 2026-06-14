import { apiClient } from "./client";

export interface LeaderboardUser {
  id: string;
  username: string;
  display_name: string;
  avatar_url: string | null;
  bio: string;
}

export interface LeaderboardEntry {
  rank: number;
  user: LeaderboardUser;
  post_count: number;
  total_reactions: number;
  total_views: number;
  score: number;
}

export interface LeaderboardResponse {
  period: string;
  entries: LeaderboardEntry[];
}

export async function fetchLeaderboard(period: string): Promise<LeaderboardResponse> {
  const res = await apiClient.get<LeaderboardResponse>("/api/v1/leaderboard", {
    params: { period },
  });
  return res.data;
}

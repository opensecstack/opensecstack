import { z } from "zod";
import { apiClient } from "./client";

const Match = z.object({
  pattern_id: z.string(),
  category: z.string(),
  description: z.string(),
  atlas_technique: z.string().optional(),
  byte_range: z.tuple([z.number(), z.number()]),
  confidence: z.number(),
});

export const ScanResponseSchema = z.object({
  scan_id: z.string(),
  classification: z.enum(["CLEAN", "SUSPICIOUS", "BLOCKED"]),
  confidence: z.number(),
  matches: z.array(Match),
  duration_ms: z.number(),
  worm_entry_id: z.string().nullable().optional(),
});
export type ScanResponse = z.infer<typeof ScanResponseSchema>;

export async function scanPrompt(input: string, context = "default"): Promise<ScanResponse> {
  const res = await apiClient.post("/api/v1/prompt/scan", { input, context });
  return ScanResponseSchema.parse(res.data);
}

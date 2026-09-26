import { z } from "zod";
import { defineTool } from "../kit/index.mjs";
import { countTiers, gather, rankRow, sortRows } from "../priority.mjs";
import { counts, extractId, rankedRow, READ_ONLY } from "./schemas.mjs";

export const prioritizeVulns = defineTool({
  name: "prioritize_vulns",
  title: "Rank vulnerabilities by real-world risk",
  description: "Ranks up to 100 CVE or advisory ids (GHSA, PYSEC, GO, RUSTSEC) by risk of exploitation: act_now (in CISA KEV or exploited), high, medium, low. Each row gives why, KEV dates, ransomware use, EPSS, CVSS and CISA's SSVC decision. Fix first what comes first.",
  input: { ids: z.array(z.string().min(5).max(80)).min(1).max(100).describe("CVE or advisory ids") },
  output: { counts, results: z.array(rankedRow) },
  annotations: READ_ONLY,
  handler: async ({ ids }, ctx) => {
    const parsed = ids.map((raw) => ({ raw, id: extractId(raw) }));
    const gathered = await gather(ctx, parsed.map((p) => p.id).filter(Boolean));
    const rows = parsed.map(({ raw, id }) => (id ? rankRow(gathered.get(id)) : { id: raw, tier: "unknown", why: "not a CVE or advisory id" }));
    const unique = [...new Map(rows.map((r) => [r.id, r])).values()];
    return { counts: countTiers(unique), results: sortRows(unique) };
  },
});

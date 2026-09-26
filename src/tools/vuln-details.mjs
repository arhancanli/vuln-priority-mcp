import { z } from "zod";
import { clip, compact, defineTool, mapLimit, ToolError } from "../kit/index.mjs";
import { gather, osvSeverity, rankRow, round } from "../priority.mjs";
import { CVE_ID, osvVuln } from "../sources.mjs";
import { compareVersions } from "../versions.mjs";
import { extractId, READ_ONLY } from "./schemas.mjs";

const MAX_PACKAGES = 12;
const MAX_PRODUCTS = 10;
const MAX_REFS = 8;
// Reference tags worth an agent's attention first: the fix, then the vendor's word, then exploits.
const REF_ORDER = ["patch", "vendor-advisory", "mitigation", "exploit", "release-notes", "third-party-advisory"];
const refRank = (r) => Math.min(...(r.tags ?? []).map((t) => REF_ORDER.indexOf(t)).filter((i) => i >= 0), REF_ORDER.length);

/** Package-level facts from OSV advisories: every affected package with its fixed versions. */
function packagesFrom(advisories) {
  const byKey = new Map();
  for (const osv of advisories) {
    for (const a of osv.affected ?? []) {
      if (!a.package?.name) continue;
      const key = `${a.package.ecosystem}|${a.package.name}`;
      const entry = byKey.get(key) ?? { ecosystem: a.package.ecosystem, name: a.package.name, fixed: new Set(), unfixed: false };
      for (const r of a.ranges ?? []) {
        if (r.type === "GIT") continue;
        const fixed = r.events.map((e) => e.fixed).filter(Boolean);
        fixed.forEach((f) => entry.fixed.add(f));
        if (!fixed.length) entry.unfixed = true;
      }
      byKey.set(key, entry);
    }
  }
  return [...byKey.values()].map((p) => compact({ ecosystem: p.ecosystem, name: p.name, fixed_in: [...p.fixed].sort(compareVersions).slice(-6), no_fix_for_some: p.unfixed || undefined }));
}

export const vulnDetails = defineTool({
  name: "vuln_details",
  title: "One vulnerability in depth",
  description: "Everything about one CVE or advisory id: priority tier and why, description, CWE, CVSS vector, CISA SSVC, KEV entry (required action, due date, ransomware), EPSS, affected products and versions, affected packages with fixed versions, and the key references (patches first).",
  input: { id: z.string().min(5).max(80).describe("CVE or advisory id") },
  output: { id: z.string(), tier: z.string(), why: z.string() },
  annotations: READ_ONLY,
  handler: async ({ id: raw }, ctx) => {
    const id = extractId(raw);
    if (!id) throw new ToolError("bad_id", `"${raw}" is not a CVE id (CVE-2021-44228) or an advisory id (GHSA-..., PYSEC-..., GO-..., RUSTSEC-...).`);
    const g = (await gather(ctx, [id])).get(id);
    const row = rankRow(g);
    if (row.tier === "unknown" && !g.record && !g.osv) throw new ToolError("not_found", `No CVE record, KEV entry or advisory has the id ${id}.`);
    // Package advisories: the advisory itself, or those OSV lists for the CVE (GHSA, PYSEC, RUSTSEC...).
    const osvForCve = CVE_ID.test(id) ? await osvVuln(ctx, id) : null;
    const aliasIds = (osvForCve?.aliases ?? []).filter((a) => /^(GHSA|PYSEC|RUSTSEC|GO|GSD|RSEC|MAL)-/.test(a)).slice(0, 4);
    const advisories = [g.osv, ...(await mapLimit(aliasIds, 4, (a) => osvVuln(ctx, a)))].filter(Boolean);
    const rec = g.record;
    const cvss = rec?.cvss ?? osvSeverity(g.osv) ?? osvSeverity(osvForCve) ?? advisories.map(osvSeverity).find((x) => x?.score);
    // The ranking row's flat fields are replaced by the nested ones below.
    const { kev_added, kev_due, ransomware, epss_percentile, severity, ...lead } = row;
    return compact({
      ...lead,
      aliases: [...new Set([...(g.osv?.aliases ?? []), ...(osvForCve?.aliases ?? [])])].filter((a) => a !== id).slice(0, 10),
      published: rec?.published ?? g.osv?.published?.slice(0, 10),
      description: clip((rec?.description ?? g.osv?.details ?? g.osv?.summary ?? "").replace(/\s+/g, " ").trim(), 700),
      cwes: rec?.cwes?.length ? rec.cwes : g.osv?.database_specific?.cwe_ids,
      cvss: cvss && compact({ score: cvss.score, severity: cvss.severity, version: cvss.version, vector: cvss.vector, source: cvss.source }),
      ssvc: rec?.ssvc && compact({ ...rec.ssvc, source: "CISA Vulnrichment" }),
      // Stated either way: an absent field reads as "unknown", and agents then answer from memory.
      kev: !g.kev ? { listed: false } : compact({ listed: true, added: g.kev.dateAdded, due: g.kev.dueDate, action: clip(g.kev.requiredAction ?? "", 300), ransomware: g.kev.knownRansomwareCampaignUse, vendor: g.kev.vendorProject, product: g.kev.product }),
      epss: g.epss && { score: round(g.epss.epss), percentile: round(g.epss.percentile, 4), date: g.epss.date },
      affected_products: rec?.affected?.slice(0, MAX_PRODUCTS).map((a) => compact({ vendor: a.vendor, product: a.product, versions: a.versions.slice(0, 6) })),
      packages: packagesFrom(advisories).slice(0, MAX_PACKAGES),
      references: (rec?.references ?? g.osv?.references?.map((r) => ({ url: r.url, tags: [String(r.type ?? "").toLowerCase()] })) ?? [])
        .map((r, i) => ({ r, i }))
        .sort((a, b) => refRank(a.r) - refRank(b.r) || a.i - b.i)
        .slice(0, MAX_REFS)
        .map(({ r }) => compact({ url: r.url, tags: r.tags?.filter(Boolean) })),
    });
  },
});

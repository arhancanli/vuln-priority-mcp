// src/priority.mjs
//
// One ranking for any mix of CVE and advisory ids. The tiers follow what is known to predict
// harm, in this order: exploitation observed in the wild (CISA KEV, or CISA's SSVC "active"),
// then a high chance of exploitation soon (EPSS) or a public exploit that can be automated, then
// a moderate chance or a high CVSS score. CVSS alone measures how bad an exploit would be, not
// how likely one is, so it never raises a vulnerability above medium.
//   act_now  exploited in the wild
//   high     EPSS >= 0.1, or a public proof of concept that SSVC rates automatable
//   medium   EPSS >= 0.01, a public proof of concept, or CVSS >= 7
//   low      none of the above
//   unknown  no source has the id
import { mapLimit } from "./kit/index.mjs";
import { cvss3 } from "./cvss.mjs";
import { CVE_ID, cveOf, cveRecord, epssScores, kevCatalog, kevRow, normId, osvVuln } from "./sources.mjs";

export const TIERS = ["act_now", "high", "medium", "low", "unknown"];

export function tierOf(facts) {
  const { tier, why } = decide(facts);
  // Below act_now, say so: an absent KEV date reads as "unknown", and agents then answer from memory.
  return { tier, why: facts.kev ? why : `${why}; not in CISA KEV` };
}

function decide({ kev, ssvc, epss, cvss }) {
  if (kev) return { tier: "act_now", why: `in CISA KEV since ${kev.added}${kev.ransomware ? ", used by ransomware" : ""}` };
  if (ssvc?.exploitation === "active") return { tier: "act_now", why: "CISA SSVC: exploitation active" };
  if (epss?.epss >= 0.1) return { tier: "high", why: epssWhy(epss) };
  if (ssvc?.exploitation === "poc" && ssvc.automatable === "yes") return { tier: "high", why: "public exploit, automatable (CISA SSVC)" };
  if (epss?.epss >= 0.01) return { tier: "medium", why: epssWhy(epss) };
  if (ssvc?.exploitation === "poc") return { tier: "medium", why: "public proof of concept (CISA SSVC)" };
  if (cvss?.score >= 7) return { tier: "medium", why: `CVSS ${cvss.score}, no sign of exploitation` };
  return { tier: "low", why: epss ? `${epssWhy(epss)}, no sign of exploitation` : "no sign of exploitation" };
}

const epssWhy = (e) => `EPSS ${round(e.epss)}: ${e.epss >= 0.995 ? "over 99" : Number((e.epss * 100).toPrecision(2))}% chance of exploitation within 30 days`;

/** A short name from a description: its first sentence, or its first words. */
export function shortName(text, max = 110) {
  const t = String(text ?? "").replace(/\s+/g, " ").trim();
  const first = t.match(/^(.{20,}?[.!?])(?:\s|$)/)?.[1] ?? t;
  if (first.length <= max) return first.replace(/\.$/, "");
  return `${first.slice(0, max).replace(/\s+\S*$/, "")}...`;
}

export const round = (x, digits = 5) => Number(Number(x).toFixed(digits));

/** Severity for an OSV advisory without a CVE: its CVSS 3 vector, or the database's own label (GHSA). */
export function osvSeverity(osv) {
  const v3 = (osv?.severity ?? []).find((s) => s.type === "CVSS_V3");
  const computed = v3 && cvss3(v3.score);
  if (computed) return { ...computed, source: "osv" };
  const label = osv?.database_specific?.severity;
  return label ? { severity: String(label).toLowerCase().replace("moderate", "medium"), source: "osv" } : undefined;
}

const byTier = (a, b) => TIERS.indexOf(a.tier) - TIERS.indexOf(b.tier) || (b.epss ?? -1) - (a.epss ?? -1) || (b.cvss ?? -1) - (a.cvss ?? -1);

/**
 * Everything the ranking needs for each id, in one pass: advisory ids resolve to their CVE through
 * OSV, then KEV (cached catalog), EPSS (one request per 100) and CVE records run together.
 * `osvById` lets package_vulns hand over advisories it already has.
 * @returns {Promise<Map<string, object>>} by input id
 */
export async function gather(ctx, ids, { osvById = new Map(), records = true } = {}) {
  const clean = [...new Set(ids.map(normId))];
  const osv = new Map(osvById);
  await mapLimit(clean.filter((id) => !CVE_ID.test(id) && !osv.has(id)), 8, async (id) => osv.set(id, await osvVuln(ctx, id)));
  const cveFor = new Map(clean.map((id) => [id, CVE_ID.test(id) ? id : cveOf(osv.get(id))]));
  const cves = [...new Set([...cveFor.values()].filter(Boolean))];
  const [kev, epss, recs] = await Promise.all([
    kevCatalog(ctx),
    epssScores(ctx, cves),
    records ? mapLimit(cves, 12, async (c) => [c, await cveRecord(ctx, c)]).then((pairs) => new Map(pairs)) : new Map(),
  ]);
  return new Map(clean.map((id) => [id, { id, cve: cveFor.get(id), osv: osv.get(id), kev: kev.byCve.get(cveFor.get(id)), epss: epss.get(cveFor.get(id)), record: recs.get(cveFor.get(id)) }]));
}

/** The compact ranking row for one gathered id. */
export function rankRow(g) {
  const { id, cve, osv, record } = g;
  const kev = kevRow(g.kev) ?? (record?.kevAdded ? { added: record.kevAdded } : undefined);
  const cvss = record?.cvss ?? osvSeverity(osv);
  const ssvc = record?.ssvc;
  if (!record && !osv && !g.kev && !g.epss) return { id, tier: "unknown", why: CVE_ID.test(id) ? "no CVE record, KEV entry or EPSS score" : "no OSV advisory with this id" };
  if (record?.state === "REJECTED") return { id, tier: "unknown", why: "the CVE was rejected (not a vulnerability, or a duplicate)" };
  const { tier, why } = tierOf({ kev, ssvc, epss: g.epss, cvss });
  return {
    id,
    cve: cve !== id ? cve : undefined,
    tier,
    why,
    kev_added: kev?.added,
    kev_due: kev?.due,
    ransomware: kev?.ransomware,
    epss: g.epss ? round(g.epss.epss) : undefined,
    epss_percentile: g.epss ? round(g.epss.percentile, 4) : undefined,
    cvss: cvss?.score,
    severity: cvss?.severity,
    ssvc: ssvc ? [ssvc.exploitation, ssvc.automatable, ssvc.impact].map((x) => x ?? "?").join("/") : undefined,
    name: g.kev?.vulnerabilityName?.trim() ?? record?.title ?? osv?.summary ?? (record?.description ? shortName(record.description) : undefined),
  };
}

export const sortRows = (rows) => [...rows].sort(byTier);
export const countTiers = (rows) => Object.fromEntries(TIERS.map((t) => [t, rows.filter((r) => r.tier === t).length]).filter(([, n]) => n));

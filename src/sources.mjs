// src/sources.mjs
//
// The four sources, all without keys:
//   CISA KEV    the Known Exploited Vulnerabilities catalog: CVEs exploited in the wild, with the
//               date added, the federal due date, the required action and known ransomware use
//   FIRST EPSS  the probability that a CVE is exploited in the next 30 days, and its percentile
//   CVE record  the CVE Program's record (JSON 5): the CNA's description, CVSS, CWEs and affected
//               products, plus CISA's Vulnrichment (ADP) container with CVSS where the CNA gave
//               none and its SSVC decision points (exploitation, automatable, technical impact)
//   OSV         package advisories (GHSA, PYSEC, GO, RUSTSEC...) with affected and fixed versions
import { mapLimit } from "./kit/index.mjs";

const KEV_URLS = ["https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"];
const KEV_TTL_MS = 3 * 3_600_000;

export const CVE_ID = /^CVE-(\d{4})-(\d{4,})$/;
export const normId = (raw) => String(raw ?? "").trim().replace(/^cve-/i, "CVE-").replace(/^ghsa-/i, "GHSA-");

/** The KEV catalog as a Map by CVE id, kept for three hours; CISA's own feed first, its GitHub mirror if that fails. */
export async function kevCatalog(ctx) {
  const now = Date.now();
  if (ctx.kev && now - ctx.kev.at < KEV_TTL_MS) return ctx.kev.data;
  ctx.kevLoading ??= (async () => {
    let last;
    for (const url of KEV_URLS) {
      try {
        const { data } = await ctx.fetcher.getJson(url);
        const byCve = new Map((data?.vulnerabilities ?? []).map((v) => [v.cveID, v]));
        if (byCve.size) return { version: data.catalogVersion, released: data.dateReleased, byCve };
      } catch (err) {
        last = err;
      }
    }
    throw last ?? new Error("The CISA KEV catalog is empty.");
  })().finally(() => {
    ctx.kevLoading = undefined;
  });
  const data = await ctx.kevLoading;
  ctx.kev = { at: now, data };
  return data;
}

/** A KEV entry in the shape the tools return. */
export const kevRow = (k) => (k ? { added: k.dateAdded, due: k.dueDate, ransomware: k.knownRansomwareCampaignUse === "Known" || undefined } : undefined);

/** EPSS scores for up to any number of CVEs, 100 per request. Map by CVE id -> {epss, percentile, date}. */
export async function epssScores(ctx, cves) {
  const out = new Map();
  const ids = [...new Set(cves.filter((c) => CVE_ID.test(c)))];
  const chunks = [];
  for (let i = 0; i < ids.length; i += 100) chunks.push(ids.slice(i, i + 100));
  await mapLimit(chunks, 3, async (chunk) => {
    const { data } = await ctx.fetcher.getJson(`https://api.first.org/data/v1/epss?cve=${chunk.join(",")}&limit=100`);
    for (const d of data?.data ?? []) out.set(d.cve, { epss: Number(d.epss), percentile: Number(d.percentile), date: d.date });
  });
  return out;
}

/** The CVE record: the CVE Program's GitHub copy (fast, CDN-served), then its API for records too new for the copy. */
export async function cveRecord(ctx, cve) {
  const m = cve.match(CVE_ID);
  if (!m) return null;
  const [, year, num] = m;
  const bucket = `${Math.floor(Number(num) / 1000)}xxx`;
  const gh = await ctx.fetcher.getJson(`https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/${year}/${bucket}/${cve}.json`, { allowStatus: [404] });
  if (gh.status !== 404 && gh.data) return fromCveRecord(gh.data);
  const api = await ctx.fetcher.getJson(`https://cveawg.mitre.org/api/cve/${cve}`, { allowStatus: [404] });
  return api.status === 404 || !api.data?.cveMetadata ? null : fromCveRecord(api.data);
}

const METRIC_ORDER = ["cvssV3_1", "cvssV4_0", "cvssV3_0", "cvssV2_0"];

/** The first CVSS in preference order from a container's metrics, tagged with who gave it. */
function cvssFrom(metrics, source) {
  for (const key of METRIC_ORDER) {
    const m = (metrics ?? []).find((x) => x[key])?.[key];
    if (m && Number.isFinite(m.baseScore)) return { score: m.baseScore, severity: m.baseSeverity?.toLowerCase(), version: m.version ?? key.slice(5).replace("_", "."), vector: m.vectorString, source };
  }
  return undefined;
}

export function fromCveRecord(j) {
  const meta = j.cveMetadata ?? {};
  const cna = j.containers?.cna ?? {};
  const adp = j.containers?.adp ?? [];
  const cisa = adp.find((a) => a.providerMetadata?.shortName === "CISA-ADP");
  const other = (type) => (cisa?.metrics ?? []).map((m) => m.other).find((o) => o?.type === type)?.content;
  const ssvcOptions = Object.assign({}, ...(other("ssvc")?.options ?? []));
  const ssvc = other("ssvc")
    ? { exploitation: ssvcOptions.Exploitation?.toLowerCase(), automatable: ssvcOptions.Automatable?.toLowerCase(), impact: ssvcOptions["Technical Impact"]?.toLowerCase() }
    : undefined;
  const cwes = [...new Set([cna, ...adp].flatMap((c) => (c.problemTypes ?? []).flatMap((p) => (p.descriptions ?? []).map((d) => d.cweId)).filter(Boolean)))];
  return {
    cve: meta.cveId,
    state: meta.state,
    published: meta.datePublished?.slice(0, 10),
    updated: meta.dateUpdated?.slice(0, 10),
    assigner: meta.assignerShortName,
    title: cna.title,
    description: (cna.descriptions ?? []).find((d) => d.lang?.startsWith("en"))?.value ?? cna.descriptions?.[0]?.value ?? cna.rejectedReasons?.[0]?.value,
    cvss: cvssFrom(cna.metrics, "cna") ?? cvssFrom(cisa?.metrics, "cisa"),
    ssvc,
    kevAdded: other("kev")?.dateAdded,
    cwes,
    affected: (cna.affected ?? []).map((a) => ({ vendor: known(a.vendor), product: known(a.product ?? a.packageName), versions: (a.versions ?? []).map(versionText).filter(Boolean) })),
    // Older records tag references the MITRE way ("x_refsource_CONFIRM").
    references: (cna.references ?? []).map((r) => ({ url: r.url, tags: (r.tags ?? []).map((t) => t.replace(/^x_refsource_/i, "").toLowerCase()) })),
  };
}

const known = (s) => (s && !/^(n\/a|unknown|-)$/i.test(s.trim()) ? s : undefined);

function versionText(v) {
  if (v.status && v.status !== "affected") return v.lessThan || v.lessThanOrEqual ? undefined : `${v.version} (${v.status})`;
  if (v.lessThan) return v.version && v.version !== "0" && v.version !== v.lessThan ? `${v.version} to <${v.lessThan}` : `<${v.lessThan}`;
  if (v.lessThanOrEqual) return v.version && v.version !== "0" ? `${v.version} to ${v.lessThanOrEqual}` : `<=${v.lessThanOrEqual}`;
  return v.version;
}

/** One OSV advisory by id (GHSA-..., PYSEC-..., GO-..., CVE-...); null when OSV has none. */
export async function osvVuln(ctx, id) {
  const { status, data } = await ctx.fetcher.getJson(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, { allowStatus: [404] });
  return status === 404 ? null : data;
}

/** The OSV advisories affecting one package version (every page). */
export async function osvQuery(ctx, ecosystem, name, version) {
  const vulns = [];
  let token;
  for (let pageNo = 0; pageNo < 5; pageNo++) {
    const body = JSON.stringify({ package: { ecosystem, name }, version, ...(token ? { page_token: token } : {}) });
    const res = await ctx.fetcher.request("https://api.osv.dev/v1/query", { method: "POST", body, headers: { "content-type": "application/json" }, idempotent: true });
    if (!res.ok) throw new Error(`OSV answered ${res.status} for ${ecosystem} ${name}.`);
    const data = JSON.parse(res.text || "{}");
    vulns.push(...(data.vulns ?? []));
    token = data.next_page_token;
    if (!token) break;
  }
  return vulns;
}

/** The CVE an OSV advisory is about, from its id or aliases. */
export const cveOf = (osv) => [osv?.id, ...(osv?.aliases ?? [])].find((a) => CVE_ID.test(a ?? ""));

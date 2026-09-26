// src/versions.mjs
//
// Choosing the version that fixes an advisory for a given installed version. OSV already decides
// which advisories affect the version (the query does that per ecosystem); what is left is picking,
// among the advisory's "fixed" events, the smallest one above the installed version. The
// comparison below orders the versions of npm, PyPI, Go, Maven, crates.io, RubyGems, NuGet,
// Packagist and Hex well enough for that: numbers numerically, pre-releases (alpha, beta, rc, dev,
// snapshot...) before the release they lead to, post-releases after it.

const PRE = /^(?:dev|snapshot|a|alpha|b|beta|c|pre|preview|rc|cr|m|milestone|ea)$/i;
const POST = /^(?:post|p|patch|sp|r|rev)$/i;

function parts(v) {
  return String(v)
    .trim()
    .replace(/^v(?=\d)/i, "")
    .replace(/\+.*$/, "") // build metadata never orders versions
    .toLowerCase()
    .match(/\d+|[a-z]+/g) ?? [];
}

// Rank of a word part relative to "the release itself" (0): pre-releases below, post-releases above.
const wordRank = (w) => (PRE.test(w) ? -1 : POST.test(w) ? 1 : ["final", "ga", "release"].includes(w) ? 0 : -1);

export function compareVersions(a, b) {
  const x = parts(a);
  const y = parts(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const p = x[i];
    const q = y[i];
    if (p === q) continue;
    if (p === undefined) return /^\d/.test(q) ? (Number(q) === 0 ? 0 : -1) : -wordRank(q) || -1;
    if (q === undefined) return /^\d/.test(p) ? (Number(p) === 0 ? 0 : 1) : wordRank(p) || 1;
    const pn = /^\d/.test(p);
    const qn = /^\d/.test(q);
    if (pn && qn) {
      const d = Number(p) - Number(q);
      if (d) return Math.sign(d);
      continue;
    }
    if (pn !== qn) return pn ? 1 : -1; // "1.0.1" > "1.0.rc1": a number outranks a word at the same place
    const d = wordRank(p) - wordRank(q);
    if (d) return Math.sign(d);
    return p < q ? -1 : 1;
  }
  return 0;
}

const entriesFor = (osv, ecosystem, name) => {
  const key = (e, n) => `${String(e).toLowerCase()}|${String(n).toLowerCase()}`;
  return (osv.affected ?? []).filter((a) => a.package && key(a.package.ecosystem.split(":")[0], a.package.name) === key(ecosystem, name));
};

/** Whether an advisory's ranges (or explicit version list) for one package include a version. */
export function affects(osv, ecosystem, name, version) {
  for (const a of entriesFor(osv, ecosystem, name)) {
    if ((a.versions ?? []).includes(version)) return true;
    for (const r of a.ranges ?? []) {
      if (r.type === "GIT") continue;
      // Events in order: each "introduced" opens a range, the next "fixed" (exclusive) or
      // "last_affected" (inclusive) closes it.
      let open;
      for (const e of r.events) {
        if (e.introduced !== undefined) open = e.introduced === "0" ? "0" : e.introduced;
        else if (open !== undefined && (e.fixed !== undefined || e.last_affected !== undefined)) {
          const inRange = (open === "0" || compareVersions(version, open) >= 0) && (e.fixed !== undefined ? compareVersions(version, e.fixed) < 0 : compareVersions(version, e.last_affected) <= 0);
          if (inRange) return true;
          open = undefined;
        }
      }
      if (open !== undefined && (open === "0" || compareVersions(version, open) >= 0)) return true;
    }
  }
  return false;
}

/**
 * The smallest fixed version above `installed` among an OSV advisory's ranges for one package, and
 * whether any range for that package lacks a fix at all.
 */
export function fixFor(osv, ecosystem, name, installed) {
  const fixes = entriesFor(osv, ecosystem, name).flatMap((a) => (a.ranges ?? []).filter((r) => r.type !== "GIT").flatMap((r) => r.events.map((e) => e.fixed).filter(Boolean)));
  const above = fixes.filter((f) => compareVersions(f, installed) > 0).sort(compareVersions);
  return above[0];
}

/** The highest of several versions. */
export const highest = (versions) => versions.filter(Boolean).sort(compareVersions).at(-1);

/**
 * One upgrade that fixes every advisory: the highest of their fixes, then checked against every
 * advisory's ranges, stepping up to the next fix while one still covers it (a later branch can be
 * affected again). Undefined when some advisory has no fix above the installed version.
 */
export function upgradeFor(advisories, ecosystem, name, installed) {
  const fixes = advisories.map((osv) => fixFor(osv, ecosystem, name, installed));
  if (!fixes.length || fixes.some((f) => !f)) return undefined;
  let target = highest(fixes);
  for (let step = 0; step < 10; step++) {
    const still = advisories.find((osv) => affects(osv, ecosystem, name, target));
    if (!still) return target;
    target = fixFor(still, ecosystem, name, target);
    if (!target) return undefined;
  }
  return undefined;
}

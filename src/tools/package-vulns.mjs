import { z } from "zod";
import { compact, defineTool, mapLimit } from "../kit/index.mjs";
import { gather, rankRow, sortRows, TIERS } from "../priority.mjs";
import { osvQuery } from "../sources.mjs";
import { fixFor, highest, upgradeFor } from "../versions.mjs";
import { counts, READ_ONLY } from "./schemas.mjs";

// OSV's ecosystem names, by the names agents also use.
const ECOSYSTEMS = { npm: "npm", pypi: "PyPI", pip: "PyPI", python: "PyPI", go: "Go", golang: "Go", maven: "Maven", java: "Maven", cargo: "crates.io", "crates.io": "crates.io", rust: "crates.io", rubygems: "RubyGems", gem: "RubyGems", ruby: "RubyGems", nuget: "NuGet", packagist: "Packagist", composer: "Packagist", php: "Packagist", pub: "Pub", hex: "Hex", swift: "SwiftURL" };
const MAX_VULNS_SHOWN = 8;

export const packageVulns = defineTool({
  name: "package_vulns",
  title: "Rank a project's package vulnerabilities",
  description: "Checks up to 50 package versions (npm, PyPI, Go, Maven, crates.io, RubyGems, NuGet, Packagist, Pub, Hex) against OSV and ranks each package by its worst vulnerability (act_now, high, medium, low), with the smallest upgrade that fixes them all and each vulnerability's KEV, EPSS and CVSS.",
  input: {
    packages: z
      .array(z.object({ ecosystem: z.string().min(2).max(20), name: z.string().min(1).max(214), version: z.string().min(1).max(100) }))
      .min(1)
      .max(50),
  },
  output: { counts, results: z.array(z.looseObject({ package: z.string(), worst: z.string() })) },
  annotations: READ_ONLY,
  handler: async ({ packages }, ctx) => {
    const found = await mapLimit(packages, 8, async (p) => {
      const ecosystem = ECOSYSTEMS[p.ecosystem.toLowerCase()] ?? p.ecosystem;
      return { ...p, ecosystem, vulns: await osvQuery(ctx, ecosystem, p.name, p.version) };
    });
    const osvById = new Map(found.flatMap((p) => p.vulns.map((v) => [v.id, v])));
    const gathered = await gather(ctx, [...osvById.keys()], { osvById });
    const results = found.map((p) => {
      // OSV can list one CVE under several databases (a GHSA and a PYSEC advisory for the same
      // Django flaw): one row per CVE, the GitHub advisory first, the highest of their fixes.
      const groups = new Map();
      for (const v of p.vulns) {
        const r = { ...rankRow(gathered.get(v.id)), fixed: fixFor(v, p.ecosystem, p.name, p.version) ?? null };
        const key = r.cve ?? r.id;
        const prev = groups.get(key);
        if (!prev) groups.set(key, r);
        else {
          const [keep, drop] = prev.id.startsWith("GHSA-") || !r.id.startsWith("GHSA-") ? [prev, r] : [r, prev];
          groups.set(key, { ...keep, also: [...(prev.also ?? []), drop.id], fixed: prev.fixed && r.fixed ? highest([prev.fixed, r.fixed]) : null });
        }
      }
      const rows = sortRows([...groups.values()]);
      const unfixed = rows.filter((r) => r.fixed === null).length;
      return compact({
        package: `${p.ecosystem}:${p.name}@${p.version}`,
        worst: rows[0]?.tier ?? "none",
        vulns: rows.length,
        upgrade_to: rows.length ? upgradeFor(p.vulns, p.ecosystem, p.name, p.version) : undefined,
        no_fix_yet: unfixed || undefined,
        top: rows.slice(0, MAX_VULNS_SHOWN).map(({ id, also, cve, tier, why, epss, cvss, severity, kev_added, fixed, name }) => compact({ id, also, cve, tier, why, epss, cvss, severity, kev_added, fixed: fixed ?? "none", name })),
        note: rows.length > MAX_VULNS_SHOWN ? `${rows.length - MAX_VULNS_SHOWN} lower-ranked not shown; prioritize_vulns takes their ids.` : undefined,
      });
    });
    const order = [...TIERS, "none"];
    results.sort((a, b) => order.indexOf(a.worst) - order.indexOf(b.worst) || (b.vulns ?? 0) - (a.vulns ?? 0));
    return { counts: Object.fromEntries(order.map((t) => [t, results.filter((r) => r.worst === t).length]).filter(([, n]) => n)), results };
  },
});

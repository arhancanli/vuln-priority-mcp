#!/usr/bin/env node
// vuln-priority: Ranks CVEs and package vulnerabilities by real-world risk: CISA's Known Exploited Vulnerabilities catalog, FIRST EPSS exploit probability, CVSS, and CISA's SSVC decisions from the CVE record, with the fixed version for each package. No key.
//
// Tools live in src/tools/, one file each. The kit in src/kit/ is a copy of the factory kit
// (a drift test keeps it identical); it holds the network guard, the result wrapper and the
// stdio and HTTP entry points.
import { readFileSync } from "node:fs";
import { createFetcher, createServer, isMain, start, TtlCache } from "./kit/index.mjs";
import { packageVulns } from "./tools/package-vulns.mjs";
import { prioritizeVulns } from "./tools/prioritize-vulns.mjs";
import { recentExploited } from "./tools/recent-exploited.mjs";
import { vulnDetails } from "./tools/vuln-details.mjs";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

export const SERVER_NAME = pkg.name;
export const SERVER_VERSION = pkg.version;
export const TOOLS = [prioritizeVulns, packageVulns, vulnDetails, recentExploited];

export const INSTRUCTIONS = "Use prioritize_vulns for a list of CVE or GHSA ids, package_vulns for package versions from a manifest or lockfile, vuln_details for one vulnerability in depth, and recent_exploited for what attackers started exploiting lately. Tiers: act_now (exploited in the wild), high, medium, low; each result says why.";

export function createContext({ fetchImpl, now } = {}) {
  return {
    now,
    fetcher: createFetcher({
      allowHosts: pkg.factory.allowHosts,
      userAgent: `${SERVER_NAME}/${SERVER_VERSION} (+${pkg.homepage})`,
      // EPSS is published daily and KEV a few times a week; CVE records and advisories change rarely.
      cache: new TtlCache({ ttlMs: 30 * 60_000, maxEntries: 2000 }),
      limits: [
        { host: "api.osv.dev", perSecond: 20, concurrency: 8 },
        { host: "api.first.org", perSecond: 5, concurrency: 3 },
        { host: "cveawg.mitre.org", perSecond: 5, concurrency: 4 },
      ],
      timeoutMs: 25_000,
      attemptTimeoutMs: 10_000,
      fetchImpl,
    }),
  };
}

export function buildServer(ctx = createContext()) {
  return createServer({ name: SERVER_NAME, version: SERVER_VERSION, instructions: INSTRUCTIONS, tools: TOOLS, ctx });
}

if (isMain(import.meta.url)) start(() => buildServer(), SERVER_NAME);

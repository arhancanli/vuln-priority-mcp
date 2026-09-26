// Weekly canary (.github/workflows/canary.yml): the tools against the live sources. Asserts only
// facts that should not change (past KEV dates, fixed versions of old advisories).
import assert from "node:assert/strict";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { buildServer } from "../src/server.mjs";

const client = new Client({ name: "canary", version: "0" });
const [a, b] = InMemoryTransport.createLinkedPair();
await Promise.all([buildServer().connect(a), client.connect(b)]);
await client.listTools();

test("live: KEV, EPSS, CVE records and OSV still answer as before", { timeout: 90_000 }, async () => {
  const p = await client.callTool({ name: "prioritize_vulns", arguments: { ids: ["CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"] } });
  const log4shell = p.structuredContent.results.find((r) => r.id === "CVE-2021-44228");
  assert.deepEqual([log4shell.tier, log4shell.kev_added, log4shell.cvss], ["act_now", "2021-12-10", 10]);
  assert.ok(log4shell.epss > 0.5);
  assert.equal(p.structuredContent.results.find((r) => r.id.startsWith("GHSA")).cve, "CVE-2021-44228");
  const pkg = await client.callTool({ name: "package_vulns", arguments: { packages: [{ ecosystem: "maven", name: "org.apache.logging.log4j:log4j-core", version: "2.14.1" }] } });
  const top = pkg.structuredContent.results[0].top.find((t) => t.id === "GHSA-jfh8-c2jp-5v3q");
  assert.equal(top.fixed, "2.15.0");
  const recent = await client.callTool({ name: "recent_exploited", arguments: { days: 3650, vendor_or_product: "log4j" } });
  assert.ok(recent.structuredContent.results.some((r) => r.cve === "CVE-2021-44228"));
  await client.close();
});

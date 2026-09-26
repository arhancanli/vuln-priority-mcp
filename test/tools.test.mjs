// Golden tests: every tool over a real MCP client, replaying responses from CISA, FIRST, the CVE
// Program and OSV recorded by test/record.mjs, with the clock fixed at 2026-09-26. No test here
// touches the network.
import assert from "node:assert/strict";
import test from "node:test";
import { call, connect } from "./replay.mjs";
import { IDS, PACKAGES } from "./scenarios.mjs";

const TIER_ORDER = ["act_now", "high", "medium", "low", "unknown"];

test("prioritize_vulns: exploited first, then by exploit probability; each row says why", async () => {
  const client = await connect();
  const { res, data } = await call(client, "prioritize_vulns", { ids: IDS });
  assert.ok(!res.isError);
  const by = Object.fromEntries(data.results.map((r) => [r.id, r]));
  const log4shell = by["CVE-2021-44228"];
  assert.deepEqual([log4shell.tier, log4shell.kev_added, log4shell.kev_due, log4shell.ransomware, log4shell.cvss, log4shell.ssvc], ["act_now", "2021-12-10", "2021-12-24", true, 10, "active/yes/total"]);
  assert.match(log4shell.why, /CISA KEV since 2021-12-10, used by ransomware/);
  assert.equal(by["GHSA-jfh8-c2jp-5v3q"].cve, "CVE-2021-44228", "an advisory id resolves to its CVE");
  assert.equal(by["GHSA-jfh8-c2jp-5v3q"].tier, "act_now");
  assert.equal(by["CVE-2023-4863"].tier, "act_now");
  assert.equal(by["CVE-2023-4863"].cvss, 8.8, "CVSS from CISA's Vulnrichment when the CNA gave none");
  assert.equal(by["CVE-2024-3094"].tier, "high", "xz: EPSS above 0.1, not in KEV");
  assert.match(by["CVE-2024-3094"].why, /^EPSS 0\.\d+: \d+% chance of exploitation within 30 days; not in CISA KEV$/);
  assert.equal(by["CVE-2020-8203"].tier, "medium");
  assert.equal(by["CVE-2099-99999"].tier, "unknown");
  assert.equal(by["not an id"].why, "not a CVE or advisory id");
  const tiers = data.results.map((r) => TIER_ORDER.indexOf(r.tier));
  assert.deepEqual(tiers, [...tiers].sort((a, b) => a - b), "worst first");
  assert.deepEqual(data.counts, { act_now: 3, high: 1, medium: 2, unknown: 2 });
});

test("package_vulns: each package ranked by its worst vulnerability, one upgrade that fixes them all", async () => {
  const client = await connect();
  const { data } = await call(client, "package_vulns", { packages: PACKAGES });
  const by = Object.fromEntries(data.results.map((r) => [r.package.split("@")[0], r]));
  const log4j = by["Maven:org.apache.logging.log4j:log4j-core"];
  assert.equal(log4j.worst, "act_now");
  assert.equal(log4j.top[0].id, "GHSA-jfh8-c2jp-5v3q");
  assert.equal(log4j.top[0].fixed, "2.15.0", "the smallest fix above the installed version, per vulnerability");
  assert.equal(log4j.upgrade_to, "2.25.4");
  const django = by["PyPI:django"];
  assert.equal(new Set(django.top.map((t) => t.cve ?? t.id)).size, django.top.length, "one row per CVE though OSV lists GHSA and PYSEC advisories for each");
  assert.ok(django.top.every((t) => t.id.startsWith("GHSA-")), "the GitHub advisory is the one kept");
  assert.equal(django.upgrade_to, "5.2.17");
  const lodash = by["npm:lodash"];
  const merged = lodash.top.find((t) => t.also);
  assert.deepEqual([merged.id, merged.also, merged.fixed], ["GHSA-35jh-r3h4-6jhm", ["GHSA-r5fr-rjxr-66jc"], "4.18.0"], "advisories that alias each other merge, keeping the higher fix");
  assert.equal(lodash.upgrade_to, "4.18.0");
  assert.equal(by["npm:left-pad"].worst, "none");
  assert.deepEqual(data.results.map((r) => r.worst), ["act_now", "high", "high", "none"]);
});

test("vuln_details: SSVC, KEV action, EPSS, affected products and packages with fixed versions", async () => {
  const client = await connect();
  const { data } = await call(client, "vuln_details", { id: "CVE-2023-4863" });
  assert.equal(data.tier, "act_now");
  assert.deepEqual(data.ssvc, { exploitation: "active", automatable: "no", impact: "total", source: "CISA Vulnrichment" });
  assert.equal(data.cvss.vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  assert.deepEqual([data.kev.added, data.kev.due], ["2023-09-13", "2023-10-04"]);
  assert.ok(data.kev.action.startsWith("Apply mitigations per vendor instructions"));
  assert.deepEqual(data.cwes, ["CWE-787"]);
  assert.deepEqual(data.affected_products.find((a) => a.product === "libwebp").versions, ["<1.3.2"]);
  const electron = data.packages.find((p) => p.ecosystem === "npm" && p.name === "electron");
  assert.ok(electron.fixed_in.includes("25.8.1"), "fixed versions from the GHSA advisory OSV lists for the CVE");
  assert.equal(data.kev_added, undefined, "no flat duplicates of the nested fields");
  assert.equal(data.kev.listed, true);
});

test("vuln_details: absence from KEV is stated, not left out", async () => {
  const client = await connect();
  const { data } = await call(client, "vuln_details", { id: "CVE-2024-3094" });
  assert.deepEqual(data.kev, { listed: false });
  assert.equal(data.tier, "high");
  assert.match(data.why, /not in CISA KEV$/);
  assert.ok(!/\r|\n/.test(data.description), "whitespace normalised");
});

test("vuln_details: an advisory id works too; text that holds no id is a clear error", async () => {
  const client = await connect();
  const { data } = await call(client, "vuln_details", { id: "GHSA-jfh8-c2jp-5v3q" });
  assert.deepEqual([data.cve, data.tier, data.cvss.score], ["CVE-2021-44228", "act_now", 10]);
  assert.ok(data.packages.some((p) => p.name === "org.apache.logging.log4j:log4j-core" && p.fixed_in.includes("2.15.0")));
  const bad = await call(client, "vuln_details", { id: "log4shell please" });
  assert.equal(bad.res.isError, true);
  assert.equal(bad.data.error.code, "bad_id");
});

test("recent_exploited: newest first within the window; vendor and ransomware filters; empty is an answer", async () => {
  const client = await connect();
  const { data } = await call(client, "recent_exploited", { days: 30 });
  assert.equal(data.since, "2026-08-27");
  assert.equal(data.results.length, 25);
  assert.ok(data.total > 25 && data.note);
  const dates = data.results.map((r) => r.added);
  assert.deepEqual(dates, [...dates].sort().reverse());
  assert.ok(data.results.every((r) => r.added >= "2026-08-27" && r.vendor === r.vendor.trim()));
  const forti = await call(client, "recent_exploited", { days: 3650, vendor_or_product: "fortinet", ransomware_only: true, limit: 3 });
  assert.ok(forti.data.results.every((r) => r.vendor === "Fortinet" && r.ransomware === true));
  assert.equal(forti.data.results[0].cve, "CVE-2019-6693");
  const log4j = await call(client, "recent_exploited", { days: 3650, vendor_or_product: "log4j", limit: 5 });
  assert.ok(log4j.data.results.some((r) => r.cve === "CVE-2021-44228"), "a word finds the words it starts: log4j finds Log4j2");
  const none = await call(client, "recent_exploited", { days: 365, vendor_or_product: "fortinet", ransomware_only: true });
  assert.ok(!none.res.isError);
  assert.deepEqual(none.data.results, []);
});

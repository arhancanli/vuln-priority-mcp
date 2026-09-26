// The rules without the network: CVSS arithmetic, version order, fixes and upgrades, tiers, ids.
import assert from "node:assert/strict";
import test from "node:test";
import { cvss3, roundup } from "../src/cvss.mjs";
import { affects, compareVersions, fixFor, upgradeFor } from "../src/versions.mjs";
import { shortName, tierOf } from "../src/priority.mjs";
import { extractId } from "../src/tools/schemas.mjs";

test("CVSS 3: base scores match FIRST's calculator; Roundup has no floating-point artefacts", () => {
  assert.equal(cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H").score, 10);
  assert.equal(cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H").score, 8.8);
  assert.equal(cvss3("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H").score, 7.4);
  assert.equal(cvss3("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N").score, 5.5);
  assert.equal(cvss3("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N").score, 6.4);
  assert.equal(cvss3("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N").score, 0);
  assert.equal(cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H").severity, "critical", "temporal metrics are ignored");
  assert.equal(cvss3("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"), undefined);
  assert.equal(roundup(4.00001), 4.1);
  assert.equal(roundup(4.000001), 4, "the specification rounds to five decimals first");
  assert.equal(roundup(4.0), 4);
});

test("versions: numbers numerically, pre-releases before their release, post-releases after", () => {
  const sorted = ["1.10.0", "1.2.0", "1.2.0-rc.1", "1.2.0-beta.10", "1.2.0-beta.2", "v1.1", "1.2", "1.2.0.post1", "2.0.0a1"].sort(compareVersions);
  assert.deepEqual(sorted, ["v1.1", "1.2.0-beta.2", "1.2.0-beta.10", "1.2.0-rc.1", "1.2.0", "1.2", "1.2.0.post1", "1.10.0", "2.0.0a1"]);
  assert.equal(compareVersions("1.2", "1.2.0"), 0);
  assert.equal(compareVersions("2.0-SNAPSHOT", "2.0"), -1);
  assert.equal(compareVersions("1.0.post1", "1.0"), 1);
  assert.equal(compareVersions("0.0.0-20250406010349-76805d5a8860", "1.4.0"), -1);
});

const advisory = (events, name = "lib") => ({ affected: [{ package: { ecosystem: "npm", name }, ranges: [{ type: "SEMVER", events }] }] });

test("fixes: the smallest fix above the installed version, on its own branch", () => {
  const twoBranches = advisory([{ introduced: "0" }, { fixed: "2.3.4" }, { introduced: "3.0.0" }, { fixed: "3.1.2" }]);
  assert.equal(fixFor(twoBranches, "npm", "lib", "2.3.1"), "2.3.4");
  assert.equal(fixFor(twoBranches, "npm", "lib", "3.0.0"), "3.1.2");
  assert.equal(fixFor(twoBranches, "npm", "LIB", "3.2.0"), undefined);
  assert.ok(affects(twoBranches, "npm", "lib", "3.0.5"));
  assert.ok(!affects(twoBranches, "npm", "lib", "2.9.0"), "between branches");
  assert.ok(affects(advisory([{ introduced: "1.0.0" }, { last_affected: "1.4.0" }]), "npm", "lib", "1.4.0"), "last_affected is inclusive");
  assert.ok(affects(advisory([{ introduced: "5.0.0" }]), "npm", "lib", "9.9.9"), "no fix yet");
});

test("upgrades: one version that fixes every advisory, stepping past a branch that is affected again", () => {
  const a = advisory([{ introduced: "0" }, { fixed: "1.5.0" }]);
  const b = advisory([{ introduced: "0" }, { fixed: "1.3.0" }]);
  assert.equal(upgradeFor([a, b], "npm", "lib", "1.0.0"), "1.5.0");
  // A regression: 1.5.0 fixes a, but c covers 1.4.0 up to 1.6.0.
  const c = advisory([{ introduced: "0" }, { fixed: "1.2.0" }, { introduced: "1.4.0" }, { fixed: "1.6.0" }]);
  assert.equal(upgradeFor([a, b, c], "npm", "lib", "1.0.0"), "1.6.0");
  assert.equal(upgradeFor([a, advisory([{ introduced: "0" }])], "npm", "lib", "1.0.0"), undefined, "no single upgrade when one has no fix");
});

test("tiers: exploitation before probability before severity; CVSS alone never goes above medium", () => {
  assert.equal(tierOf({ kev: { added: "2024-01-01" } }).tier, "act_now");
  assert.equal(tierOf({ ssvc: { exploitation: "active" } }).tier, "act_now");
  assert.equal(tierOf({ epss: { epss: 0.1 } }).tier, "high");
  assert.equal(tierOf({ ssvc: { exploitation: "poc", automatable: "yes" } }).tier, "high");
  assert.equal(tierOf({ ssvc: { exploitation: "poc", automatable: "no" } }).tier, "medium");
  assert.equal(tierOf({ epss: { epss: 0.0099 }, cvss: { score: 10 } }).tier, "medium");
  assert.equal(tierOf({ epss: { epss: 0.0099 }, cvss: { score: 6.9 } }).tier, "low");
  assert.equal(tierOf({ epss: { epss: 0.99999 } }).why, "EPSS 0.99999: over 99% chance of exploitation within 30 days; not in CISA KEV");
  assert.equal(tierOf({ kev: { added: "2024-01-01", ransomware: true } }).why, "in CISA KEV since 2024-01-01, used by ransomware");
});

test("ids: found inside text, normalised; names: first sentence or first words", () => {
  assert.equal(extractId("CVE-2021-44228 (Log4Shell)"), "CVE-2021-44228");
  assert.equal(extractId("cve-2021-44228"), "CVE-2021-44228");
  assert.equal(extractId("see GHSA-JFH8-C2JP-5V3Q"), "GHSA-jfh8-c2jp-5v3q");
  assert.equal(extractId("pysec-2023-174"), "PYSEC-2023-174");
  assert.equal(extractId("GO-2024-2687"), "GO-2024-2687");
  assert.equal(extractId("log4shell"), undefined);
  assert.equal(shortName("Prototype pollution in lodash. More text follows here."), "Prototype pollution in lodash");
  assert.ok(shortName("x ".repeat(200)).endsWith("...") && shortName("x ".repeat(200)).length <= 113);
});

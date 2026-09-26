// The calls the golden tests replay and scripts/perf.mjs times. test/record.mjs runs them against
// the live sources and stores the responses, compressed, in test/fixtures.
export const NOW = Date.parse("2026-09-26T12:00:00Z");

export const IDS = ["CVE-2021-44228", "CVE-2023-4863", "CVE-2024-3094", "CVE-2020-8203", "GHSA-jfh8-c2jp-5v3q", "CVE-2019-10744", "CVE-2099-99999", "not an id"];
export const PACKAGES = [
  { ecosystem: "npm", name: "lodash", version: "4.17.15" },
  { ecosystem: "maven", name: "org.apache.logging.log4j:log4j-core", version: "2.14.1" },
  { ecosystem: "pypi", name: "django", version: "3.2.0" },
  { ecosystem: "npm", name: "left-pad", version: "1.3.0" },
];

export const SCENARIOS = [
  { label: "prioritize_vulns: 8 ids (KEV, EPSS-only, advisory alias, unknown, not an id)", tool: "prioritize_vulns", args: { ids: IDS }, example: true },
  { label: "package_vulns: 4 packages (npm, Maven, PyPI, one clean)", tool: "package_vulns", args: { packages: PACKAGES } },
  { label: "vuln_details: CVE-2023-4863 (libwebp)", tool: "vuln_details", args: { id: "CVE-2023-4863" } },
  { label: "vuln_details: CVE-2024-3094 (xz, not in KEV)", tool: "vuln_details", args: { id: "CVE-2024-3094" } },
  { label: "vuln_details: a GHSA advisory", tool: "vuln_details", args: { id: "GHSA-jfh8-c2jp-5v3q" } },
  { label: "recent_exploited: last 30 days", tool: "recent_exploited", args: { days: 30 } },
  { label: "recent_exploited: Fortinet, ransomware only, 10 years", tool: "recent_exploited", args: { days: 3650, vendor_or_product: "fortinet", ransomware_only: true, limit: 3 } },
  { label: "recent_exploited: log4j, 10 years", tool: "recent_exploited", args: { days: 3650, vendor_or_product: "log4j", limit: 5 } },
  { label: "vuln_details: not an id", tool: "vuln_details", args: { id: "log4shell please" }, expectError: true },
];

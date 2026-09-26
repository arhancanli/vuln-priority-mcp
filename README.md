# Vuln Priority

<!-- badges:start -->
[![CI](https://github.com/arhancanli/vuln-priority-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/arhancanli/vuln-priority-mcp/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/vuln-priority-mcp)](https://www.npmjs.com/package/vuln-priority-mcp)
[![downloads](https://img.shields.io/npm/dw/vuln-priority-mcp)](https://www.npmjs.com/package/vuln-priority-mcp)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/arhancanli/vuln-priority-mcp/badge)](https://scorecard.dev/viewer/?uri=github.com/arhancanli/vuln-priority-mcp)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
<!-- badges:end -->

Which vulnerability do I fix first? A scanner hands an agent dozens of CVEs, sorted by CVSS, and
CVSS says how bad an exploit would be, not whether anyone is exploiting it. Vuln Priority ranks
vulnerabilities by the evidence that predicts harm:

| Tier | Rule |
| --- | --- |
| `act_now` | Exploited in the wild: in CISA's Known Exploited Vulnerabilities catalog, or CISA's SSVC rates exploitation "active" |
| `high` | EPSS of 0.1 or more (a 10% or greater chance of exploitation in the next 30 days), or a public exploit that SSVC rates automatable |
| `medium` | EPSS of 0.01 or more, a public proof of concept, or CVSS 7 or higher |
| `low` | None of the above |

Every row says why it landed in its tier, with the KEV dates (and whether ransomware groups use
it), the EPSS score and percentile, the CVSS score and CISA's SSVC decision points. Give it CVE ids,
GitHub, PyPI, Go or RustSec advisory ids, or package versions straight from a lockfile: for each
package it returns the worst vulnerability, and the one upgrade that fixes all of them, checked
against every advisory's affected ranges (a later branch can be affected again).

No account or key needed. Built and maintained by [Arhan Canli](https://github.com/arhancanli).

## Install

<!-- install:start -->
[![Install in Cursor](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/en/install-mcp?name=vuln-priority&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsInZ1bG4tcHJpb3JpdHktbWNwIl19)
[![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_Server-0098FF?style=flat-square&logo=visualstudiocode&logoColor=white)](https://insiders.vscode.dev/redirect/mcp/install?name=vuln-priority&config=%7B%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22vuln-priority-mcp%22%5D%7D)
[![Install in Goose](https://block.github.io/goose/img/extension-install-dark.svg)](https://block.github.io/goose/extension?cmd=npx&arg=-y&arg=vuln-priority-mcp&id=vuln-priority&name=Vuln%20Priority&description=Ranks%20CVEs%20and%20package%20vulnerabilities%20by%20real-world%20risk%3A%20CISA's%20Known%20Exploited%20Vulnerabilities%20catalog%2C%20FIRST%20EPSS%20exploit%20probability%2C%20CVSS%2C%20and%20CISA's%20SSVC%20decisions%20from%20the%20CVE%20record%2C%20with%20the%20fixed%20version%20for%20each%20package.%20No%20key.)

Needs Node.js 20 or newer. No account or key.

**Claude Code**

```sh
claude mcp add vuln-priority -- npx -y vuln-priority-mcp
```

**Claude Desktop**: download `vuln-priority-mcp-<version>.mcpb` from the [latest release](https://github.com/arhancanli/vuln-priority-mcp/releases/latest) and open it. The bundle is signed; verify it with `gh attestation verify <file> --repo arhancanli/vuln-priority-mcp`.

**Any other client** (Windsurf, Zed, Cline, Continue and others), in its MCP config file:

```json
{
  "mcpServers": {
    "vuln-priority": {
      "command": "npx",
      "args": [
        "-y",
        "vuln-priority-mcp"
      ]
    }
  }
}
```

**Docker**

```sh
docker build -t vuln-priority-mcp https://github.com/arhancanli/vuln-priority-mcp.git && docker run -i --rm vuln-priority-mcp
```

**Hosted (Streamable HTTP)**: `node src/server.mjs --http` serves stateless MCP at `POST /mcp` (port from `PORT`, default 3000).
<!-- install:end -->

## Example

<!-- example:start -->
An agent calls `prioritize_vulns` with:

```json
{
  "ids": [
    "CVE-2021-44228",
    "CVE-2023-4863",
    "CVE-2024-3094",
    "CVE-2020-8203",
    "GHSA-jfh8-c2jp-5v3q",
    "CVE-2019-10744",
    "CVE-2099-99999",
    "not an id"
  ]
}
```

and gets back (recorded from the live server on 2026-09-26):

```json
{
  "counts": {
    "act_now": 3,
    "high": 1,
    "medium": 2,
    "unknown": 2
  },
  "results": [
    {
      "id": "CVE-2021-44228",
      "tier": "act_now",
      "why": "in CISA KEV since 2021-12-10, used by ransomware",
      "kev_added": "2021-12-10",
      "kev_due": "2021-12-24",
      "ransomware": true,
      "epss": 0.99999,
      "epss_percentile": 1,
      "cvss": 10,
      "severity": "critical",
      "ssvc": "active/yes/total",
      "name": "Apache Log4j2 Remote Code Execution Vulnerability"
    },
    {
      "id": "GHSA-jfh8-c2jp-5v3q",
      "cve": "CVE-2021-44228",
      "tier": "act_now",
      "why": "in CISA KEV since 2021-12-10, used by ransomware",
      "kev_added": "2021-12-10",
      "kev_due": "2021-12-24",
      "ransomware": true,
      "epss": 0.99999,
      "epss_percentile": 1,
      "cvss": 10,
      "severity": "critical",
      "ssvc": "active/yes/total",
      "name": "Apache Log4j2 Remote Code Execution Vulnerability"
    },
    {
      "id": "CVE-2023-4863",
      "tier": "act_now",
      "why": "in CISA KEV since 2023-09-13",
      "kev_added": "2023-09-13",
      "kev_due": "2023-10-04",
      "epss": 0.99979,
      "epss_percentile": 0.9998,
      "cvss": 8.8,
      "severity": "high",
      "ssvc": "active/no/total",
      "name": "Google Chromium WebP Heap-Based Buffer Overflow Vulnerability"
    },
    {
      "id": "CVE-2024-3094",
      "tier": "high",
      "why": "EPSS 0.85974: 86% chance of exploitation within 30 days; not in CISA KEV",
      "epss": 0.85974,
      "epss_percentile": 0.9972,
      "cvss": 10,
      "severity": "critical",
      "ssvc": "none/yes/total",
      "name": "Xz: malicious code in distributed source"
... (29 more lines)
```
<!-- example:end -->

## Tools

<!-- tools:start -->
| Tool | What it does |
| --- | --- |
| `package_vulns` | Checks up to 50 package versions (npm, PyPI, Go, Maven, crates.io, RubyGems, NuGet, Packagist, Pub, Hex) against OSV and ranks each package by its worst vulnerability (act_now, high, medium, low), with the smallest upgrade that fixes them all and each vulnerability's KEV, EPSS and CVSS. |
| `prioritize_vulns` | Ranks up to 100 CVE or advisory ids (GHSA, PYSEC, GO, RUSTSEC) by risk of exploitation: act_now (in CISA KEV or exploited), high, medium, low. Each row gives why, KEV dates, ransomware use, EPSS, CVSS and CISA's SSVC decision. Fix first what comes first. |
| `recent_exploited` | What CISA added to its Known Exploited Vulnerabilities catalog in the last N days, newest first, optionally only for a vendor or product (fortinet, chrome, exchange) or only ransomware-linked. Each row: CVE, vendor, product, name, date added, federal due date, EPSS. |
| `vuln_details` | Everything about one CVE or advisory id: priority tier and why, description, CWE, CVSS vector, CISA SSVC, KEV entry (required action, due date, ransomware), EPSS, affected products and versions, affected packages with fixed versions, and the key references (patches first). |
<!-- tools:end -->

## How it behaves

- Read-only: no tool changes anything outside this process. Package names and versions go to OSV,
  CVE ids to FIRST and the CVE Program; nothing about your project is sent anywhere else.
- Network: HTTPS only, to the hosts listed in `package.json` under `factory.allowHosts`, with a
  deadline, a size cap and bounded retries. Nothing else is contacted, and nothing is logged
  except unexpected failures (to stderr, without your inputs).
- The KEV catalog is kept for three hours, other answers for 30 minutes. CVE records come from the
  CVE Program's GitHub copy (about 0.2 s each), and from its API for records too new for the copy.
- When OSV lists one CVE under several databases (a GHSA and a PYSEC advisory for the same Django
  flaw), it is one row, the GitHub advisory first, with the other ids under `also`.
- Results are compact JSON with a matching output schema, worst first. Lists say how many items
  were left out.

## Data sources

- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  (public domain), with its [GitHub mirror](https://github.com/cisagov/kev-data) as a fallback.
- [FIRST EPSS](https://www.first.org/epss/), the Exploit Prediction Scoring System, updated daily.
- [CVE records](https://github.com/CVEProject/cvelistV5) from the CVE Program, including CISA's
  [Vulnrichment](https://github.com/cisagov/vulnrichment) container (CVSS where the reporting
  organisation gave none, and SSVC decision points).
- [OSV](https://osv.dev), the open source vulnerability database (GitHub Advisories, PyPA, Go,
  RustSec and more), for package versions and fixes.

Tiers are a starting point for your own policy: CISA's SSVC guidance and FIRST's EPSS guidance
describe how to set thresholds for your environment.

## Benchmark

<!-- bench:start -->
Measured 2026-09-26 with gpt-5.4-mini, 12 fixed tasks graded by fixed checks (`bench/tasks.json`, raw results in `bench/results/`).

| Server | Correct | Input tokens | Output tokens | Tool calls | Median time |
| --- | --- | --- | --- | --- | --- |
| This server | 12/12 | 25253 | 530 | 12 | 3.0 s |
| mukul975/cve-mcp-server, the most-starred vulnerability server (28 tools) | 7/12 | 130333 | 1174 | 34 | 3.4 s |
<!-- bench:end -->

The same tasks against [cve-mcp](https://www.npmjs.com/package/cve-mcp) (41 tools), in a separate run: 10/12 correct with 222,717 input tokens, against 12/12 and 25,253 for this server (`bench/results/2026-09-26-gpt-5.4-mini-cve-mcp.json`).
mukul975/cve-mcp-server ran from its repository at commit `d666bac` with the MCP Python SDK pinned
below 2: its default install fails on SDK 2, where FastMCP was renamed.

## Performance

<!-- perf:start -->
Measured 2026-09-26 from Dubai, home connection against the live upstream, Node 24.19.0 (`bench/perf.json`, `scripts/perf.mjs` in the factory).

| Call | First call | Repeat | Result size |
| --- | --- | --- | --- |
| prioritize_vulns: 8 ids (KEV, EPSS-only, advisory alias, unknown, not an id) | 2684 ms | 0.5 ms | 1,933 chars |
| package_vulns: 4 packages (npm, Maven, PyPI, one clean) | 2863 ms | 3 ms | 6,102 chars |
| vuln_details: CVE-2023-4863 (libwebp) | 2213 ms | 0.5 ms | 2,829 chars |
| vuln_details: CVE-2024-3094 (xz, not in KEV) | 2081 ms | 0.4 ms | 1,876 chars |
| vuln_details: a GHSA advisory | 1386 ms | 0.4 ms | 3,429 chars |
| recent_exploited: last 30 days | 635 ms | 0.3 ms | 5,196 chars |
| recent_exploited: Fortinet, ransomware only, 10 years | 647 ms | 0.5 ms | 795 chars |
| recent_exploited: log4j, 10 years | 587 ms | 1.3 ms | 475 chars |

First call: a fresh server process, including the TLS connection and the upstream's own time. Repeat: the same call again, answered from the in-process cache, so it shows this server's own overhead.

Tool definitions the model reads on every turn (name, description, input schema): 2,298 characters, against 12,864 for mukul975/cve-mcp-server, the most-starred vulnerability server (28 tools). The full tool list, with the output schemas and annotations clients use to validate results, is 4,019 characters (16,964 for the alternative).
<!-- perf:end -->

## More MCP servers by Arhan Canli

<!-- family:start -->
- [Citation Check](https://github.com/arhancanli/citation-check-mcp): Verifies citations: finds fabricated or mismatched references and retractions, returns clean BibTeX.
- [Drug Label](https://github.com/arhancanli/drug-label-mcp): FDA drug label answers with section citations, RxNorm name resolution, recalls and shortages.
- [End of Life](https://github.com/arhancanli/end-of-life-mcp): Is this version still supported? EOL dates, latest patch and upgrade target for 470+ products.
- [Internet Standards](https://github.com/arhancanli/internet-standards-mcp): RFC sections, status, obsoleted-by chains, errata and IANA registries for coding agents.
- [Package Truth](https://github.com/arhancanli/package-truth-mcp): Checks packages exist before install: version, deprecation, vulnerabilities, licence. 7 ecosystems.
- [Recall Check](https://github.com/arhancanli/recall-check-mcp): One recall check across CPSC, FDA and NHTSA: match by name, model number, UPC or VIN.
- [Satellite Imagery](https://github.com/arhancanli/satellite-imagery-mcp): Find the clearest Sentinel-2, Landsat, Sentinel-1 or NAIP scene for any place, with band links.
- [World Time](https://github.com/arhancanli/world-time-mcp): Time anywhere, DST-safe conversions, holidays for 200+ countries, business days and meeting slots.
- [The whole collection](https://github.com/arhancanli/mcp-factory#servers)
<!-- family:end -->

## License

MIT, Copyright (c) 2026 Arhan Canli.

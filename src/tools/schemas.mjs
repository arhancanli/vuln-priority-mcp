import { z } from "zod";

export const READ_ONLY = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true };
export const rankedRow = z.looseObject({ id: z.string(), tier: z.string(), why: z.string() });
export const counts = z.record(z.string(), z.number());

/** A CVE or advisory id inside whatever an agent passes ("CVE-2021-44228 (Log4Shell)", "ghsa-jfh8-..."). */
const ID_IN_TEXT = /\b(CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|[A-Z][A-Z0-9]*-\d{4}-[A-Za-z0-9-]+|GO-\d{4}-\d+)\b/i;
export function extractId(raw) {
  const m = String(raw).match(ID_IN_TEXT);
  if (!m) return undefined;
  const id = m[1];
  return /^(cve|ghsa)-/i.test(id) ? id.replace(/^cve-/i, "CVE-").replace(/^ghsa-(.*)$/i, (_, rest) => `GHSA-${rest.toLowerCase()}`) : id.toUpperCase();
}

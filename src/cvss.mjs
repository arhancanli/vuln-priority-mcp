// src/cvss.mjs
//
// CVSS 3.0/3.1 base score from a vector string, by the FIRST specification (section 7.1 and the
// Roundup of appendix A). OSV advisories carry vectors, not scores; CVE records carry both.
// CVSS 4.0 scores need FIRST's macro-vector tables and are taken from the record, never computed.
const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
};
const PR = { U: { N: 0.85, L: 0.62, H: 0.27 }, C: { N: 0.85, L: 0.68, H: 0.5 } };

/** Round up to one decimal, as the specification defines it (free of floating-point artefacts). */
export function roundup(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

export const severityOf = (score) => (score === 0 ? "none" : score < 4 ? "low" : score < 7 ? "medium" : score < 9 ? "high" : "critical");

/** @returns {{score: number, severity: string, version: string, vector: string} | undefined} */
export function cvss3(vector) {
  const m = String(vector ?? "").match(/^CVSS:(3\.[01])\/(.+)$/);
  if (!m) return undefined;
  const v = Object.fromEntries(m[2].split("/").map((p) => p.split(":")));
  const { AV, AC, PR: pr, UI, S, C, I, A } = v;
  if (!W.AV[AV] || !W.AC[AC] || !PR.U[pr] || !W.UI[UI] || !["U", "C"].includes(S) || [C, I, A].some((x) => W.CIA[x] === undefined)) return undefined;
  const iss = 1 - (1 - W.CIA[C]) * (1 - W.CIA[I]) * (1 - W.CIA[A]);
  const impact = S === "U" ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
  const exploitability = 8.22 * W.AV[AV] * W.AC[AC] * PR[S][pr] * W.UI[UI];
  const score = impact <= 0 ? 0 : S === "U" ? roundup(Math.min(impact + exploitability, 10)) : roundup(Math.min(1.08 * (impact + exploitability), 10));
  return { score, severity: severityOf(score), version: m[1], vector };
}

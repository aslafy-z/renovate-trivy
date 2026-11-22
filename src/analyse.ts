/** Turn scans into per-image counts and per-update CVE diffs. */
import {
  GATE, SEVERITIES,
  type Analysis, type Cve, type Diff, type RepoTargets, type Scan, type Severity, type Vuln,
} from "./types.ts";

export const sevRank = (s: Severity) => SEVERITIES.indexOf(s);

/**
 * Collapse per-package findings into one entry per CVE. One CVE often hits
 * several packages built from the same source (perl, perl-base, libperl...);
 * counting it once keeps totals and diffs honest.
 */
export function byCve(vulns: Vuln[]): Map<string, Cve> {
  const out = new Map<string, Cve>();
  for (const v of vulns) {
    let e = out.get(v.id);
    if (!e) out.set(v.id, (e = { ...v, pkgs: [] }));
    else if (sevRank(v.severity) < sevRank(e.severity)) e.severity = v.severity;
    if (!e.pkgs.includes(v.pkg)) e.pkgs.push(v.pkg);
    if (v.fixed && !e.fixed) e.fixed = v.fixed;
  }
  return out;
}

export function counts(vulns: Vuln[]): Record<Severity, number> {
  const c = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const v of byCve(vulns).values()) c[v.severity]++;
  return c;
}

export const gateCves = (vulns: Vuln[]) => [...byCve(vulns).values()].filter((v) => GATE.includes(v.severity));

export function diff(oldVulns: Vuln[], newVulns: Vuln[]): Diff {
  const a = byCve(oldVulns);
  const b = byCve(newVulns);
  const fixed = [...a.values()].filter((v) => !b.has(v.id));
  const introduced = [...b.values()].filter((v) => !a.has(v.id));
  const gate = (l: Cve[]) => l.filter((v) => GATE.includes(v.severity)).length;
  return { fixed, introduced, fixedGate: gate(fixed), introducedGate: gate(introduced) };
}

export function analyse(targets: RepoTargets, scans: Map<string, Scan>): Analysis {
  const out: Analysis = {
    repository: targets.repository, images: [], updates: [], errors: [], skipped: [], branchUpdates: targets.branchUpdates,
  };
  const error = (ref: string, scan: Scan | undefined) => {
    const msg = scan && !scan.ok ? scan.error : "not scanned";
    if (!out.errors.some((e) => e.ref === ref)) out.errors.push({ ref, error: msg });
  };
  for (const image of targets.images) {
    if (image.skipped) {
      out.skipped.push(image.ref);
      continue;
    }
    const cur = scans.get(image.ref);
    if (!cur?.ok) {
      error(image.ref, cur);
      continue;
    }
    out.images.push({
      ...image,
      scan: cur,
      counts: counts(cur.vulns),
      fixableGate: gateCves(cur.vulns).filter((v) => v.fixed).length,
    });
    for (const upd of image.updates) {
      const next = scans.get(upd.ref);
      if (!next?.ok) {
        error(upd.ref, next);
        continue;
      }
      out.updates.push({
        ...upd,
        from: image.ref,
        fromName: image.name,
        currentValue: image.currentValue,
        currentDigest: image.currentDigest,
        fromCounts: counts(cur.vulns),
        toCounts: counts(next.vulns),
        diff: diff(cur.vulns, next.vulns),
      });
    }
  }
  return out;
}

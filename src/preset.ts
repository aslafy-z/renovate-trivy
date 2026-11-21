/**
 * Generate Renovate package rules from the analysis. This is the only channel
 * back to Renovate: it reads the preset on its next run and does the rest
 * itself (opens the PR, labels it, writes the note in the PR body).
 */
import { DIGEST_RE, versionOf } from "./refs.ts";
import { sevRank } from "./analyse.ts";
import type { AnalysedUpdate, Analysis, BranchUpdate, Cve } from "./types.ts";

export interface PresetOptions {
  label: string;
  prPriority: number;
  /** Release fixing updates (and the rest of their branch) from the schedule. */
  release: boolean;
  /** Web URL of the repo's report, linked from PR notes. */
  reportUrl?: string;
}

export type PackageRule = Record<string, unknown>;

/** Exact-match pattern for Renovate's regex-or-glob matchers. */
export function exact(value: string): string {
  return `/^${value.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")}$/`;
}

/**
 * Text from image metadata (CVE ids, package names) ends up in a Handlebars
 * template rendered into a PR body: neutralise braces, table pipes and
 * Markdown link syntax.
 */
const text = (s: string) =>
  s.replace(/[{}]/g, (c) => `&#${c.charCodeAt(0)};`).replace(/[|[\]()<>`]/g, "").replace(/\s+/g, " ");
const link = (label: string, url: string) =>
  /^https:\/\/[\w.-]+\/[\w./?=&%#~+-]*$/.test(url) ? `[${text(label)}](${url})` : text(label);

function matcher(repository: string, u: Pick<BranchUpdate, "datasource" | "name" | "currentValue" | "newValue" | "newDigest">): PackageRule | undefined {
  if (!u.newValue && !u.newDigest) return undefined;
  if (u.newDigest && !DIGEST_RE.test(u.newDigest)) return undefined;
  return {
    matchRepositories: [repository],
    matchDatasources: [u.datasource],
    matchPackageNames: [u.name],
    ...(u.currentValue ? { matchCurrentValue: exact(u.currentValue) } : {}),
    ...(u.newValue ? { matchNewValue: exact(u.newValue) } : {}),
    ...(u.newDigest ? { matchJsonata: [`newDigest = "${u.newDigest}"`] } : {}),
  };
}

/** Identity of a rule's match part: the same update yields the same key across runs. */
export function matchKey(rule: PackageRule): string {
  return JSON.stringify([rule.matchDatasources, rule.matchPackageNames, rule.matchCurrentValue, rule.matchNewValue, rule.matchJsonata]);
}

function cveList(cves: Cve[], max = 5): string {
  const sorted = [...cves].sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || a.id.localeCompare(b.id));
  // Advisory ids are plain tokens (CVE-…, GHSA-…); anything else is dropped.
  const shown = sorted.slice(0, max).map((c) => link(c.id.replace(/[^\w.-]/g, ""), c.url));
  return shown.join(", ") + (sorted.length > max ? ` and ${sorted.length - max} more` : "");
}

const split = (cves: Cve[]) => ({
  critical: cves.filter((c) => c.severity === "CRITICAL").length,
  high: cves.filter((c) => c.severity === "HIGH").length,
});

export function note(u: AnalysedUpdate, reportUrl?: string): string {
  const gate = (l: Cve[]) => l.filter((c) => c.severity === "CRITICAL" || c.severity === "HIGH");
  const fixed = gate(u.diff.fixed);
  const introduced = gate(u.diff.introduced);
  const parts: string[] = [];
  if (fixed.length) {
    const n = split(fixed);
    parts.push(`fixes **${n.critical} critical** and **${n.high} high** CVEs (${cveList(fixed)})`);
  }
  if (introduced.length) {
    const n = split(introduced);
    parts.push(`${fixed.length ? "" : "⚠️ "}introduces **${n.critical} critical** and **${n.high} high** CVEs (${cveList(introduced)})`);
  }
  const after = `${u.toCounts.CRITICAL} critical / ${u.toCounts.HIGH} high remain`;
  const report = reportUrl ? ` · ${link("full report", reportUrl)}` : "";
  const name = (s: string) => `\`${text(s)}\``;
  return `🛡️ **Trivy**: ${name(u.fromName)} ${name(versionOf(u.from))} → ${name(versionOf(u.ref))} ${parts.join("; ")}. ${after}${report}`;
}

export function rulesFor(analysis: Analysis, opts: PresetOptions): PackageRule[] {
  const rules: PackageRule[] = [];
  const seen = new Set<string>();
  const fixingBranches = new Set<string>();
  for (const u of analysis.updates) {
    // A replacement renames the package; matching it reliably is not worth it.
    if (u.name !== u.fromName) continue;
    const match = matcher(analysis.repository, { datasource: "docker", name: u.fromName, currentValue: u.currentValue, newValue: u.newValue, newDigest: u.newDigest });
    if (!match) continue;
    const fixes = u.diff.fixedGate > 0;
    const worsens = u.diff.introducedGate > 0;
    if (!fixes && !worsens) continue;
    if (fixes && u.branchName) fixingBranches.add(u.branchName);
    const what = `${u.fromName} ${versionOf(u.from)} -> ${versionOf(u.ref)}`;
    rules.push({
      description: fixes
        ? `renovate-trivy: ${what} fixes ${u.diff.fixedGate} critical/high CVEs`
        : `renovate-trivy: ${what} introduces ${u.diff.introducedGate} critical/high CVEs`,
      ...match,
      ...(fixes && opts.release ? { schedule: ["at any time"], prPriority: opts.prPriority } : {}),
      ...(fixes ? { addLabels: [opts.label] } : {}),
      prBodyNotes: [note(u, opts.reportUrl)],
    });
    if (fixes) seen.add(matchKey(match));
  }
  if (opts.release) {
    // Renovate takes a branch's schedule and priority from whichever update
    // sorts first in it, so every member of a fixing update's branch is
    // released with it, whatever its datasource and whether or not it was scanned.
    for (const b of analysis.branchUpdates) {
      if (!fixingBranches.has(b.branchName)) continue;
      const match = matcher(analysis.repository, b);
      if (!match || seen.has(matchKey(match))) continue;
      seen.add(matchKey(match));
      rules.push({
        description: `renovate-trivy: ${b.name} shares a branch with a security fix`,
        ...match,
        schedule: ["at any time"],
        prPriority: opts.prPriority,
      });
    }
  }
  return rules;
}

/**
 * Rules of the previous run for updates that could not be scanned this time:
 * one registry hiccup should not drop a label and re-schedule a PR.
 */
export function carryForward(previous: PackageRule[], analysis: Analysis, targets: { images: { name: string; currentValue?: string; ref: string; updates: { ref: string; newValue?: string; newDigest?: string }[] }[] }): PackageRule[] {
  const failed = new Set(analysis.errors.map((e) => e.ref));
  const keys = new Set<string>();
  for (const image of targets.images) {
    for (const u of image.updates) {
      if (!failed.has(image.ref) && !failed.has(u.ref)) continue;
      const m = matcher(analysis.repository, { datasource: "docker", name: image.name, currentValue: image.currentValue, newValue: u.newValue, newDigest: u.newDigest });
      if (m) keys.add(matchKey(m));
    }
  }
  return previous.filter((r) => keys.has(matchKey(r)));
}

/** The preset Renovate extends: every repository's rules, each scoped by matchRepositories. */
export function buildPreset(fragments: PackageRule[][], reportUrlTemplate?: string): Record<string, unknown> {
  return {
    $schema: "https://docs.renovatebot.com/renovate-schema.json",
    description: ["Generated by renovate-trivy: container image CVE findings. Do not edit, it is overwritten."],
    ...(reportUrlTemplate
      ? { dependencyDashboardHeader: `🛡️ Container image CVEs (Trivy): [report for this repository](${reportUrlTemplate})` }
      : {}),
    packageRules: fragments.flat(),
  };
}

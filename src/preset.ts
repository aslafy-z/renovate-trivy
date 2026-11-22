/**
 * Generate Renovate package rules from the analysis. This is the only channel
 * back to Renovate: it reads the preset on its next run and does the rest
 * itself (opens the PR, labels it, writes the note in the PR body).
 */
import { DIGEST_RE, versionOf } from "./refs.ts";
import { sevRank } from "./analyse.ts";
import type { AnalysedUpdate, Analysis, BranchUpdate, Cve, Image } from "./types.ts";

export interface PresetOptions {
  label: string;
  prPriority: number;
  /** Release fixing updates (and the rest of their branch) from the schedule. */
  release: boolean;
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

type Matchable = Pick<BranchUpdate, "datasource" | "name" | "currentValue" | "currentDigest" | "newValue" | "newDigest">;

/**
 * Match one exact update. Without `repository` the rule holds for every
 * repository extending the preset: what an image update fixes does not depend
 * on who deploys it.
 */
function matcher(u: Matchable, repository?: string): PackageRule | undefined {
  if (!u.newValue && !u.newDigest) return undefined;
  if (u.newDigest && !DIGEST_RE.test(u.newDigest)) return undefined;
  if (u.currentDigest && !DIGEST_RE.test(u.currentDigest)) return undefined;
  const digests = [
    ...(u.currentDigest ? [`currentDigest = "${u.currentDigest}"`] : []),
    ...(u.newDigest ? [`newDigest = "${u.newDigest}"`] : []),
  ];
  return {
    ...(repository ? { matchRepositories: [repository] } : {}),
    matchDatasources: [u.datasource],
    matchPackageNames: [u.name],
    ...(u.currentValue ? { matchCurrentValue: exact(u.currentValue) } : {}),
    ...(u.newValue ? { matchNewValue: exact(u.newValue) } : {}),
    ...(digests.length ? { matchJsonata: [digests.join(" and ")] } : {}),
  };
}

/** Identity of a rule's match part: the same update yields the same key across runs and repositories. */
export function matchKey(rule: PackageRule): string {
  return JSON.stringify([rule.matchDatasources, rule.matchPackageNames, rule.matchCurrentValue, rule.matchNewValue, rule.matchJsonata]);
}

function cveList(cves: Cve[], max = 3): string {
  const sorted = [...cves].sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || a.id.localeCompare(b.id));
  // Advisory ids are plain tokens (CVE-…, GHSA-…); anything else is dropped.
  const shown = sorted.slice(0, max).map((c) => link(c.id.replace(/[^\w.-]/g, ""), c.url));
  return shown.join(", ") + (sorted.length > max ? ` and ${sorted.length - max} more` : "");
}

const split = (cves: Cve[]) => ({
  critical: cves.filter((c) => c.severity === "CRITICAL").length,
  high: cves.filter((c) => c.severity === "HIGH").length,
});

export function note(u: AnalysedUpdate): string {
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
  const name = (s: string) => `\`${text(s)}\``;
  return `🛡️ **Trivy**: ${name(u.fromName)} ${name(versionOf(u.from))} → ${name(versionOf(u.ref))} ${parts.join("; ")}. ${u.toCounts.CRITICAL} critical / ${u.toCounts.HIGH} high remain`;
}

const asMatchable = (u: AnalysedUpdate): Matchable => ({
  datasource: "docker", name: u.fromName, currentValue: u.currentValue, currentDigest: u.currentDigest, newValue: u.newValue, newDigest: u.newDigest,
});

/**
 * One repository's rules. Image rules carry no repository: they are merged
 * with every other repository's in the shared preset. Only "this update
 * shares a branch with a fix" depends on the repository's own grouping.
 */
export function rulesFor(analysis: Analysis, opts: PresetOptions): PackageRule[] {
  const rules: PackageRule[] = [];
  const seen = new Set<string>();
  const fixingBranches = new Set<string>();
  for (const u of analysis.updates) {
    // A replacement renames the package; matching it reliably is not worth it.
    if (u.name !== u.fromName) continue;
    const match = matcher(asMatchable(u));
    if (!match || seen.has(matchKey(match))) continue;
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
      prBodyNotes: [note(u)],
    });
    seen.add(matchKey(match));
  }
  const released = new Set(rules.filter((r) => r.schedule).map(matchKey));
  if (opts.release) {
    // Renovate takes a branch's schedule and priority from whichever update
    // sorts first in it, so every member of a fixing update's branch is
    // released with it, whatever its datasource and whether or not it was scanned.
    for (const b of analysis.branchUpdates) {
      if (!fixingBranches.has(b.branchName)) continue;
      const match = matcher(b, analysis.repository);
      if (!match || released.has(matchKey(match))) continue;
      released.add(matchKey(match));
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
export function carryForward(previous: PackageRule[], analysis: Analysis, targets: { images: Image[] }): PackageRule[] {
  const failed = new Set(analysis.errors.map((e) => e.ref));
  const keys = new Set<string>();
  for (const image of targets.images) {
    for (const u of image.updates) {
      if (!failed.has(image.ref) && !failed.has(u.ref)) continue;
      const m = matcher({ datasource: "docker", name: image.name, currentValue: image.currentValue, currentDigest: image.currentDigest, newValue: u.newValue, newDigest: u.newDigest });
      if (m) keys.add(matchKey(m));
    }
  }
  return previous.filter((r) => !r.matchRepositories && keys.has(matchKey(r)));
}

export interface AssembleOptions {
  /** File view of the data branch, e.g. https://github.com/o/data/blob/data */
  webUrl?: string;
  /** Total size of the per-repository summaries embedded in the dashboard footer. */
  summaryBudget?: number;
  /**
   * Appended to the dashboard footer on every repository. A preset's footer
   * replaces the one Renovate would otherwise use, such as the hosted app's
   * "run again" checkbox: this is where to put it back.
   */
  dashboardFooter?: string;
  /** Rules beyond this size move to shard files the preset extends. */
  shardBytes?: number;
}

const size = (v: unknown) => Buffer.byteLength(typeof v === "string" ? v : JSON.stringify(v));

/** Merge every repository's rules: identical image rules collapse, branch rules pool their repositories. */
export function mergeRules(fragments: Map<string, PackageRule[]>): PackageRule[] {
  const merged = new Map<string, PackageRule>();
  for (const [, rules] of [...fragments].sort(([a], [b]) => a.localeCompare(b))) {
    for (const rule of rules) {
      const { matchRepositories, ...rest } = rule;
      const scoped = Array.isArray(matchRepositories);
      const key = `${scoped}${matchKey(rule)}`;
      const existing = merged.get(key);
      if (!existing) merged.set(key, scoped ? { ...rule, matchRepositories: [...(matchRepositories as string[])] } : rest);
      else if (scoped) {
        const repos = existing.matchRepositories as string[];
        for (const r of matchRepositories as string[]) if (!repos.includes(r)) repos.push(r);
      }
    }
  }
  return [...merged.values()];
}

/**
 * The files Renovate reads: the preset every repository extends and, once the
 * rules outgrow one file, the shards it extends in turn.
 */
export function buildPreset(fragments: Map<string, PackageRule[]>, summaries: Map<string, string>, o: AssembleOptions = {}): Record<string, unknown> {
  const reportUrl = o.webUrl ? `${o.webUrl}/repos/{{{repository}}}/report.md` : undefined;
  // Renovate fills in the repository, so one rule links each repository to its own report.
  const rules = mergeRules(fragments).map((r) =>
    reportUrl && Array.isArray(r.prBodyNotes) ? { ...r, prBodyNotes: r.prBodyNotes.map((n) => `${n} · [full report](${reportUrl})`) } : r,
  );

  // The dashboard footer is one template for everybody (the footer, so that
  // Renovate's own content comes first): each repository's summary sits in a
  // block only it renders. Smallest first, within a budget;
  // the others get a link while that still fits.
  const when = (repo: string, body: string) => `{{#if (equals (lowercase repository) "${repo.toLowerCase()}")}}${body}{{/if}}`;
  let budget = o.summaryBudget ?? 200_000;
  const blocks: string[] = [];
  for (const [repo, md] of [...summaries].sort((a, b) => size(a[1]) - size(b[1]) || a[0].localeCompare(b[0]))) {
    const full = when(repo, md);
    const link = when(repo, o.webUrl ? `🛡️ [Container image vulnerability report](${o.webUrl}/repos/${repo}/report.md)` : "");
    const block = size(full) <= budget ? full : o.webUrl && size(link) <= budget ? link : "";
    budget -= size(block);
    blocks.push(block);
  }

  const body = blocks.join("");
  const footer = body && o.dashboardFooter ? `${body}\n\n${o.dashboardFooter}` : body;

  const shardBytes = o.shardBytes ?? 400_000;
  const shards: PackageRule[][] = [[]];
  let current = 0;
  for (const rule of rules) {
    if (current && current + size(rule) > shardBytes) {
      shards.push([]);
      current = 0;
    }
    shards.at(-1)!.push(rule);
    current += size(rule);
  }
  const name = (i: number) => `shards/${String(i).padStart(3, "0")}`;
  const preset = {
    $schema: "https://docs.renovatebot.com/renovate-schema.json",
    description: ["Generated by renovate-trivy: container image CVE findings. Do not edit, it is overwritten."],
    ...(shards.length > 1 ? { extends: shards.map((_, i) => `./${name(i)}`) } : {}),
    ...(footer ? { dependencyDashboardFooter: footer } : {}),
    packageRules: shards.length > 1 ? [] : shards[0],
  };
  const files: Record<string, unknown> = { "renovate-trivy.json": preset };
  if (shards.length > 1) shards.forEach((packageRules, i) => (files[`${name(i)}.json`] = { packageRules }));
  return files;
}

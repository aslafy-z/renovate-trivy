import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { gzipSync } from "node:zlib";
import { analyse, counts, diff } from "../src/analyse.ts";
import { buildPreset, carryForward, exact, mergeRules, note, rulesFor, type PackageRule } from "../src/preset.ts";
import { applyDelta, assemble, validateRules } from "../src/publish.ts";
import { parseRef, versionOf } from "../src/refs.ts";
import { renderReport, renderSummary } from "../src/report.ts";
import { SbomStore, describesDigest, isFresh, sbomKey, sbomPath } from "../src/store.ts";
import { targetsFromReport } from "../src/targets.ts";
import { parseTrivyJson } from "../src/trivy.ts";
import type { Scan, Severity, Vuln } from "../src/types.ts";

const report = JSON.parse(readFileSync(new URL("./fixtures/renovate-report.json", import.meta.url), "utf8"));
const vuln = (id: string, severity: Severity, pkg = "openssl", fixed = "1.1"): Vuln => ({
  id, pkg, installed: "1.0", fixed, severity, title: `${id} title`, url: `https://example.test/${id}`,
});
const ok = (vulns: Vuln[]): Scan => ({ ok: true, os: "alpine 3.24", eosl: false, cached: false, vulns });
const meta = { scannedAt: "2026-01-01T00:00:00Z", platform: "linux/amd64", trivyVersion: "0.76.2", dbUpdatedAt: "2026-01-01T00:00:00Z" };
const opts = { label: "security", prPriority: 10, release: true };
const names = (rules: PackageRule[]) => rules.map((r) => (r.matchPackageNames as string[])[0]);

test("parseRef applies Docker Hub defaults", () => {
  assert.deepEqual(parseRef("nginx"), { registry: "docker.io", repository: "library/nginx", tag: "latest", digest: undefined });
  assert.deepEqual(parseRef("valkey/valkey:9-alpine"), { registry: "docker.io", repository: "valkey/valkey", tag: "9-alpine", digest: undefined });
  assert.deepEqual(parseRef("localhost:5000/a/b@sha256:abc"), { registry: "localhost:5000", repository: "a/b", tag: undefined, digest: "sha256:abc" });
  assert.equal(versionOf("ghcr.io/o/i:v1@sha256:0123456789abcdef"), "v1@0123456789ab");
});

test("targets: images, updates and their branches come from the Renovate report", () => {
  const [repo] = targetsFromReport(report, { localRepository: "o/r" });
  assert.equal(repo.repository, "o/r");
  const prowlarr = repo.images.find((i) => i.ref === "lscr.io/linuxserver/prowlarr:2.7.0")!;
  assert.deepEqual(prowlarr.updates.map((u) => [u.ref, u.branchName]), [["lscr.io/linuxserver/prowlarr:3.0.2", "renovate/lsio-arr"]]);
  assert.match(repo.images.find((i) => i.currentDigest)!.updates[0].ref, /^docker\.io\/valkey\/valkey:9\.2-alpine@sha256:/);
  assert.deepEqual(repo.images.find((i) => i.ref === "nginx:1-alpine")!.updates, []);
  assert.equal(targetsFromReport(report, { skipRegistries: ["lscr.io"] })[0].images.find((i) => i.name.startsWith("lscr.io/"))!.skipped, true);
});

test("a CVE on several packages counts once, at its worst severity", () => {
  const vulns = [vuln("CVE-1", "HIGH", "perl"), vuln("CVE-1", "CRITICAL", "perl-base"), vuln("CVE-2", "LOW")];
  assert.deepEqual(counts(vulns), { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 1, UNKNOWN: 0 });
  const d = diff(vulns, [vuln("CVE-2", "LOW"), vuln("CVE-3", "HIGH")]);
  assert.deepEqual([d.fixed.map((c) => c.id), d.introduced.map((c) => c.id), d.fixedGate, d.introducedGate], [["CVE-1"], ["CVE-3"], 1, 1]);
});

function demo(repository = "o/r") {
  const [targets] = targetsFromReport(report, { localRepository: repository });
  const scans = new Map<string, Scan>();
  for (const i of targets.images) {
    scans.set(i.ref, ok([vuln("CVE-OLD", "CRITICAL"), vuln("CVE-KEPT", "MEDIUM")]));
    for (const u of i.updates) scans.set(u.ref, ok([vuln("CVE-KEPT", "MEDIUM")]));
  }
  // kener's update fixes nothing; argocd's could not be scanned.
  scans.set("rajnandan1/kener:v4.2.2", scans.get("rajnandan1/kener:4.2.1")!);
  scans.set("quay.io/argoproj/argocd:v3.6.2", { ok: false, error: "boom" });
  return { targets, analysis: analyse(targets, scans) };
}

test("image rules are repository-free; only branch releases are scoped", () => {
  const { analysis } = demo();
  const rules = rulesFor(analysis, opts);
  const prowlarr = rules.find((r) => names([r])[0] === "lscr.io/linuxserver/prowlarr")!;
  assert.equal(prowlarr.matchRepositories, undefined);
  assert.deepEqual([prowlarr.matchCurrentValue, prowlarr.matchNewValue, prowlarr.schedule, prowlarr.addLabels], ["/^2\\.7\\.0$/", "/^3\\.0\\.2$/", ["at any time"], ["security"]]);
  assert.match((prowlarr.prBodyNotes as string[])[0], /fixes \*\*1 critical\*\* and \*\*0 high\*\* CVEs.*CVE-OLD/);
  // A digest-pinned image is matched on both digests: the fix count is relative to the old one.
  assert.match((rules.find((r) => r.matchJsonata)!.matchJsonata as string[])[0], /^currentDigest = "sha256:[0-9a-f]{64}" and newDigest = "sha256:[0-9a-f]{64}"$/);
  // kener fixes nothing but shares a group branch with updates that do.
  const kener = rules.find((r) => names([r])[0] === "rajnandan1/kener")!;
  assert.deepEqual([kener.matchRepositories, kener.schedule, kener.prPriority, kener.addLabels, kener.prBodyNotes], [["o/r"], ["at any time"], 10, undefined, undefined]);
  assert.ok(!names(rules).includes("quay.io/argoproj/argocd"));
  assert.deepEqual(analysis.errors, [{ ref: "quay.io/argoproj/argocd:v3.6.2", error: "boom" }]);
  assert.equal(validateRules(rules, "o/r").length, rules.length);
  assert.ok(rulesFor(analysis, { ...opts, release: false }).every((r) => r.schedule === undefined));
});

test("a branch mate that is not an image is released too", () => {
  const { analysis } = demo();
  const branch = analysis.updates.find((u) => u.diff.fixedGate > 0 && u.branchName)!.branchName!;
  analysis.branchUpdates.push({ datasource: "github-releases", name: "aaa/tool", currentValue: "1.0.0", newValue: "1.0.1", branchName: branch });
  const tool = rulesFor(analysis, opts).find((r) => names([r])[0] === "aaa/tool")!;
  assert.deepEqual([tool.matchDatasources, tool.matchRepositories, tool.schedule], [["github-releases"], ["o/r"], ["at any time"]]);
});

test("a regression gets a warning note only", () => {
  const { analysis } = demo();
  const u = analysis.updates.find((x) => x.fromName === "rajnandan1/kener")!;
  u.diff = diff([], [vuln("CVE-NEW", "HIGH")]);
  const kener = rulesFor(analysis, { ...opts, release: false }).find((r) => names([r])[0] === "rajnandan1/kener")!;
  assert.equal(kener.addLabels, undefined);
  assert.match((kener.prBodyNotes as string[])[0], /⚠️ introduces \*\*0 critical\*\* and \*\*1 high\*\*/);
});

test("notes cannot inject handlebars, tables or links", () => {
  const { analysis } = demo();
  const u = analysis.updates.find((x) => x.diff.fixedGate > 0)!;
  u.diff.fixed[0].id = "CVE-{{{evil}}}|x](https://evil.test)";
  u.diff.fixed[0].url = "https://ok.test/a) [click](https://evil.test";
  const n = note(u);
  assert.doesNotMatch(n, /[{}|]/);
  assert.doesNotMatch(n, /https:\/\/evil|\]\(/);
  assert.equal(exact("v1.2+a/b"), "/^v1\\.2\\+a\\/b$/");
});

test("a failed scan keeps the previous run's rule for that update", () => {
  const { analysis, targets } = demo();
  const previous = [
    { matchDatasources: ["docker"], matchPackageNames: ["quay.io/argoproj/argocd"], matchCurrentValue: "/^v3\\.6\\.1$/", matchNewValue: "/^v3\\.6\\.2$/", addLabels: ["security"] },
    { matchDatasources: ["docker"], matchPackageNames: ["lscr.io/linuxserver/prowlarr"], matchCurrentValue: "/^2\\.7\\.0$/", matchNewValue: "/^3\\.0\\.2$/" },
  ];
  assert.deepEqual(names(carryForward(previous, analysis, targets)), ["quay.io/argoproj/argocd"]);
});

test("the preset size follows distinct image updates, not repositories", () => {
  const fragments = new Map<string, PackageRule[]>();
  for (const repo of ["o/a", "o/b", "o/c"]) fragments.set(repo, rulesFor(demo(repo).analysis, opts));
  const one = mergeRules(new Map([["o/a", fragments.get("o/a")!]]));
  const merged = mergeRules(fragments);
  assert.equal(merged.length, one.length);
  const kener = merged.find((r) => names([r])[0] === "rajnandan1/kener")!;
  assert.deepEqual(kener.matchRepositories, ["o/a", "o/b", "o/c"]);
  const files = buildPreset(fragments, new Map(), { webUrl: "https://h/o/data/blob/data" }) as any;
  assert.deepEqual(Object.keys(files), ["renovate-trivy.json"]);
  const noted = files["renovate-trivy.json"].packageRules.find((r: PackageRule) => r.prBodyNotes);
  assert.match(noted.prBodyNotes[0], / · \[full report\]\(https:\/\/h\/o\/data\/blob\/data\/repos\/\{\{\{repository\}\}\}\/report\.md\)$/);
});

test("rules beyond one file move to shards the preset extends", () => {
  const rules = Array.from({ length: 30 }, (_, i) => ({ matchDatasources: ["docker"], matchPackageNames: [`img${i}`], matchNewValue: "/^1$/", addLabels: ["security"] }));
  const files = buildPreset(new Map([["o/a", rules]]), new Map(), { shardBytes: 1000 }) as any;
  const main = files["renovate-trivy.json"];
  assert.deepEqual(main.packageRules, []);
  assert.ok(main.extends.length > 1 && main.extends[0] === "./shards/000");
  const total = main.extends.reduce((n: number, e: string) => n + files[`${e.slice(2)}.json`].packageRules.length, 0);
  assert.equal(total, 30);
  for (const f of Object.keys(files)) assert.ok(JSON.stringify(files[f]).length < 1500, f);
});

test("dashboard summaries are embedded within a budget, then degrade to links", () => {
  const summaries = new Map([["o/small", "S".repeat(100)], ["o/big", "B".repeat(5000)], ["o/huge", "H".repeat(9000)]]);
  const header = (buildPreset(new Map(), summaries, { webUrl: "https://h/d", summaryBudget: 5400 }) as any)["renovate-trivy.json"].dependencyDashboardFooter as string;
  assert.match(header, /\{\{#if \(equals \(lowercase repository\) "o\/small"\)\}\}S{100}\{\{\/if\}\}/);
  assert.match(header, /B{5000}/);
  const withFooter = (buildPreset(new Map(), summaries, { dashboardFooter: "KEEP ME" }) as any)["renovate-trivy.json"].dependencyDashboardFooter as string;
  assert.ok(withFooter.endsWith("{{/if}}\n\nKEEP ME"));
  assert.doesNotMatch(header, /HHH/);
  assert.match(header, /"o\/huge"\)\}\}🛡️ \[Container image vulnerability report\]\(https:\/\/h\/d\/repos\/o\/huge\/report\.md\)/);
});

test("validateRules rejects anything renovate-trivy would not generate", () => {
  const base = { matchDatasources: ["docker"], matchPackageNames: ["x"], matchNewValue: "/^1$/" };
  assert.equal(validateRules([base, { ...base, matchRepositories: ["o/r"], schedule: ["at any time"] }], "o/r").length, 2);
  for (const bad of [
    { ...base, automerge: true },
    { ...base, registryUrls: ["https://evil.test"] },
    { ...base, matchRepositories: ["other/repo"], schedule: ["at any time"] },
    { ...base, matchRepositories: ["o/r"], addLabels: ["security"] },
    { ...base, schedule: ["* * * * *"] },
    { ...base, prBodyNotes: ["{{{lookup}}}"] },
    { ...base, matchJsonata: ["$eval('x')"] },
    { matchDatasources: ["docker"], matchPackageNames: ["x"] },
    { matchDatasources: ["docker"], matchPackageNames: ["x"], matchJsonata: [`currentDigest = "sha256:${"a".repeat(64)}"`] },
  ]) assert.throws(() => validateRules([bad], "o/r"), /rules\.json\[0\]/, JSON.stringify(bad));
});

const digest = `sha256:${"a".repeat(64)}`;
const key = sbomKey(digest, "linux/amd64");
const sbom = (d = digest) => JSON.stringify({ bomFormat: "CycloneDX", metadata: { component: { properties: [{ name: "aquasecurity:trivy:RepoDigest", value: `x/y@${d}` }] } } });

test("an SBOM is only archived and reused under the digest it names", () => {
  assert.equal(key, `sha256-${"a".repeat(64)}.linux-amd64`);
  assert.equal(sbomPath(key), `sboms/aa/${key}.cdx.json.gz`);
  assert.equal(describesDigest(sbom(), key), true);
  assert.equal(describesDigest(sbom(`sha256:${"b".repeat(64)}`), key), false);
  assert.equal(describesDigest("not json", key), false);
  const dir = mkdtempSync(join(tmpdir(), "rt-store-"));
  const store = new SbomStore(join(dir, "out"), 30);
  writeFileSync(join(dir, "ok.json"), sbom());
  writeFileSync(join(dir, "other.json"), sbom(`sha256:${"b".repeat(64)}`));
  const m = { ref: "x", trivyVersion: "0.76.2", createdAt: new Date().toISOString() };
  assert.equal(store.save(key, join(dir, "other.json"), m), false);
  assert.equal(store.has(key, "0.76.2"), false);
  assert.equal(store.save(key, join(dir, "ok.json"), m), true);
  assert.equal(store.restore(key, "0.76.9", join(dir, "back.json")), true);
  assert.equal(readFileSync(join(dir, "back.json"), "utf8"), sbom());
  assert.equal(store.restore(key, "0.77.0", join(dir, "back.json")), false);
  const t0 = Date.parse("2026-01-01T00:00:00Z");
  const old = { ref: "x", trivyVersion: "0.76.2", createdAt: "2026-01-01T00:00:00Z" };
  assert.deepEqual([isFresh(old, "0.76.2", 30, t0 + 86_400_000), isFresh(old, "0.76.2", 30, t0 + 31 * 86_400_000), isFresh({ ...old, createdAt: "2999-01-01T00:00:00Z" }, "0.76.2", 30, t0)], [true, false, false]);
});

function delta(repos: { repository: string; ok: boolean }[], sboms: Record<string, string> = {}) {
  const d = mkdtempSync(join(tmpdir(), "rt-delta-"));
  for (const { repository, ok: fine } of repos) {
    if (!fine) continue;
    mkdirSync(join(d, "repos", repository), { recursive: true });
    writeFileSync(join(d, "repos", repository, "rules.json"), JSON.stringify({ packageRules: [{ matchDatasources: ["docker"], matchPackageNames: ["x"], matchNewValue: "/^1$/", addLabels: ["security"] }] }));
    writeFileSync(join(d, "repos", repository, "state.json"), JSON.stringify({ scannedAt: "t", sboms: { "x:1": key, bad: "../../etc" }, extra: 1 }));
    writeFileSync(join(d, "repos", repository, "report.md"), "# report");
    writeFileSync(join(d, "repos", repository, "summary.md"), "summary");
  }
  const index: Record<string, unknown> = {};
  for (const [k, content] of Object.entries(sboms)) {
    mkdirSync(dirname(join(d, sbomPath(k))), { recursive: true });
    writeFileSync(join(d, sbomPath(k)), gzipSync(content));
    index[k] = { ref: "x:1", trivyVersion: "0.76.2", createdAt: "2999-01-01T00:00:00Z" };
  }
  writeFileSync(join(d, "run.json"), JSON.stringify({ repositories: repos, sboms: index }));
  return d;
}

test("applyDelta validates, dates SBOMs itself and ignores everything else", () => {
  const root = mkdtempSync(join(tmpdir(), "rt-root-"));
  const d = delta([{ repository: "o/a", ok: true }, { repository: "o/b", ok: true }], { [key]: sbom() });
  mkdirSync(join(d, ".git"));
  writeFileSync(join(d, ".git", "config"), "[core]\n\tfsmonitor = evil");
  mkdirSync(join(d, "repos/victim/x"), { recursive: true });
  writeFileSync(join(d, "repos/victim/x/rules.json"), "{}");
  const now = Date.parse("2026-06-01T00:00:00Z");
  assert.deepEqual(applyDelta(d, root, now), { repositories: 2, sboms: [sbomPath(key)] });
  assert.equal(existsSync(join(root, ".git")), false);
  assert.equal(existsSync(join(root, "repos", "victim")), false);
  assert.deepEqual(JSON.parse(readFileSync(join(root, "repos/o/a/state.json"), "utf8")).sboms, { "x:1": key });
  assert.equal(JSON.parse(readFileSync(join(root, "sbom-index.json"), "utf8"))[key].createdAt, "2026-06-01T00:00:00.000Z");

  // An SBOM that names another image never enters the shared archive.
  assert.throws(() => applyDelta(delta([{ repository: "o/a", ok: true }], { [key]: sbom(`sha256:${"b".repeat(64)}`) }), root), /does not describe/);
  assert.throws(() => applyDelta(delta([{ repository: "../x", ok: true }]), root), /unsupported repository/);

  // A failed lookup keeps the previous entry; a repository off the list loses it.
  applyDelta(delta([{ repository: "o/a", ok: false }]), root, now);
  assert.equal(existsSync(join(root, "repos/o/a/report.md")), true);
  assert.equal(existsSync(join(root, "repos/o/b")), false);
});

test("assemble writes the preset and prunes SBOMs nobody references", () => {
  const root = mkdtempSync(join(tmpdir(), "rt-data-"));
  const stale = sbomKey(`sha256:${"c".repeat(64)}`, "linux/amd64");
  applyDelta(delta([{ repository: "o/a", ok: true }, { repository: "g/sub/b", ok: true }], { [key]: sbom(), [stale]: sbom(`sha256:${"c".repeat(64)}`) }), root);
  const res = assemble(root, { webUrl: "https://host/o/data/blob/data" });
  assert.deepEqual([res.repos, res.pruned], [["g/sub/b", "o/a"], [sbomPath(stale)]]);
  assert.equal(existsSync(join(root, sbomPath(stale))), false);
  assert.equal(existsSync(join(root, sbomPath(key))), true);
  assert.deepEqual(Object.keys(JSON.parse(readFileSync(join(root, "sbom-index.json"), "utf8"))), [key]);
  const preset = JSON.parse(readFileSync(join(root, "renovate-trivy.json"), "utf8"));
  // Two repositories, one identical image rule.
  assert.equal(preset.packageRules.length, 1);
  assert.match(preset.dependencyDashboardFooter, /"g\/sub\/b"\)\}\}summary\{\{\/if\}\}/);
});

test("report and summary render totals, fixing updates and failures", () => {
  const { analysis } = demo();
  const md = renderReport(analysis, meta);
  assert.match(md, /`lscr.io\/linuxserver\/prowlarr` \| `2\.7\.0` → `3\.0\.2` \| 1 \/ 0 → 0 \/ 0 \| 1 \| 0 \|/);
  assert.match(md, /## Not scanned\n\n- `quay.io\/argoproj\/argocd:v3\.6\.2`: boom/);
  const summary = renderSummary(analysis, meta, { reportUrl: "https://h/report.md", prUrl: (b) => `https://h/o/r/pull/${b}` });
  assert.match(summary, /in 9 images\. \[Full report\]\(https:\/\/h\/report\.md\)/);
  assert.match(summary, / - \[`linuxserver\/prowlarr` 2\.7\.0 → 3\.0\.2\]\(https:\/\/h\/o\/r\/pull\/renovate\/lsio-arr\): fixes 1 critical/);
  assert.doesNotMatch(summary, /^\|/m);
  assert.doesNotMatch(summary, /[{}]/);
});

test("parseTrivyJson dedupes and normalises severities", () => {
  const r = parseTrivyJson({
    Metadata: { OS: { Family: "debian", Name: "12", EOSL: true } },
    Results: [{ Vulnerabilities: [
      { VulnerabilityID: "CVE-1", PkgName: "a", InstalledVersion: "1", Severity: "high" },
      { VulnerabilityID: "CVE-1", PkgName: "a", InstalledVersion: "1", Severity: "high" },
      { VulnerabilityID: "CVE-2", PkgName: "b", InstalledVersion: "1", Severity: "weird" },
    ] }],
  });
  assert.deepEqual([r.os, r.eosl, r.vulns.map((v) => v.severity)], ["debian 12", true, ["HIGH", "UNKNOWN"]]);
});

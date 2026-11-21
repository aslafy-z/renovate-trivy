import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { analyse, counts, diff } from "../src/analyse.ts";
import { exact, note, rulesFor } from "../src/preset.ts";
import { assemble, PRESET_FILE } from "../src/publish.ts";
import { parseRef, versionOf } from "../src/refs.ts";
import { renderReport } from "../src/report.ts";
import { SbomStore, sbomKey } from "../src/store.ts";
import { targetsFromReport } from "../src/targets.ts";
import { parseTrivyJson } from "../src/trivy.ts";
import type { Scan, Severity, Vuln } from "../src/types.ts";

const report = JSON.parse(readFileSync(new URL("./fixtures/renovate-report.json", import.meta.url), "utf8"));
const vuln = (id: string, severity: Severity, pkg = "openssl", fixed = "1.1"): Vuln => ({
  id, pkg, installed: "1.0", fixed, severity, title: `${id} title`, url: `https://example.test/${id}`,
});
const ok = (vulns: Vuln[]): Scan => ({ ok: true, os: "alpine 3.24", eosl: false, cached: false, vulns });

test("parseRef applies Docker Hub defaults", () => {
  assert.deepEqual(parseRef("nginx"), { registry: "docker.io", repository: "library/nginx", tag: "latest", digest: undefined });
  assert.deepEqual(parseRef("valkey/valkey:9-alpine"), { registry: "docker.io", repository: "valkey/valkey", tag: "9-alpine", digest: undefined });
  assert.deepEqual(parseRef("localhost:5000/a/b@sha256:abc"), { registry: "localhost:5000", repository: "a/b", tag: undefined, digest: "sha256:abc" });
  assert.equal(parseRef("ghcr.io/o/i:v1@sha256:abc").tag, "v1");
  assert.equal(versionOf("ghcr.io/o/i:v1@sha256:0123456789abcdef"), "v1@0123456789ab");
});

test("targets: images, updates and their branches come from the Renovate report", () => {
  const [repo] = targetsFromReport(report, { localRepository: "o/r" });
  assert.equal(repo.repository, "o/r");
  const prowlarr = repo.images.find((i) => i.ref === "lscr.io/linuxserver/prowlarr:2.7.0")!;
  assert.deepEqual(prowlarr.updates.map((u) => [u.ref, u.branchName]), [["lscr.io/linuxserver/prowlarr:3.0.2", "renovate/lsio-arr"]]);
  const pinned = repo.images.find((i) => i.currentDigest)!;
  assert.match(pinned.updates[0].ref, /^docker\.io\/valkey\/valkey:9\.2-alpine@sha256:/);
  // An image with no proposed update is still scanned.
  assert.deepEqual(repo.images.find((i) => i.ref === "nginx:1-alpine")!.updates, []);
});

test("targets: excluded registries are kept but marked", () => {
  const [repo] = targetsFromReport(report, { skipRegistries: ["lscr.io"] });
  assert.equal(repo.images.find((i) => i.name.startsWith("lscr.io/"))!.skipped, true);
});

test("a CVE on several packages counts once, at its worst severity", () => {
  const vulns = [vuln("CVE-1", "HIGH", "perl"), vuln("CVE-1", "CRITICAL", "perl-base"), vuln("CVE-2", "LOW")];
  assert.deepEqual(counts(vulns), { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 1, UNKNOWN: 0 });
  const d = diff(vulns, [vuln("CVE-2", "LOW"), vuln("CVE-3", "HIGH")]);
  assert.deepEqual([d.fixed.map((c) => c.id), d.introduced.map((c) => c.id), d.fixedGate, d.introducedGate], [["CVE-1"], ["CVE-3"], 1, 1]);
});

test("exact() escapes regex and slash characters", () => {
  assert.equal(exact("v1.2+a/b"), "/^v1\\.2\\+a\\/b$/");
});

function demo() {
  const [targets] = targetsFromReport(report, { localRepository: "o/r" });
  const scans = new Map<string, Scan>();
  for (const i of targets.images) {
    scans.set(i.ref, ok([vuln("CVE-OLD", "CRITICAL"), vuln("CVE-KEPT", "MEDIUM")]));
    for (const u of i.updates) scans.set(u.ref, ok([vuln("CVE-KEPT", "MEDIUM")]));
  }
  // kener's update fixes nothing; argocd's could not be scanned.
  scans.set("rajnandan1/kener:v4.2.2", scans.get("rajnandan1/kener:4.2.1")!);
  scans.set("quay.io/argoproj/argocd:v3.6.2", { ok: false, error: "boom" });
  return analyse(targets, scans);
}

test("rules: only fixing updates are released, labelled and annotated", () => {
  const a = demo();
  const rules = rulesFor(a, { label: "security", prPriority: 10, release: true, reportUrl: "https://d/report.md" });
  const of = (name: string) => rules.filter((r) => (r.matchPackageNames as string[])[0] === name);
  const [prowlarr] = of("lscr.io/linuxserver/prowlarr");
  assert.deepEqual(prowlarr.matchRepositories, ["o/r"]);
  assert.equal(prowlarr.matchCurrentValue, "/^2\\.7\\.0$/");
  assert.equal(prowlarr.matchNewValue, "/^3\\.0\\.2$/");
  assert.deepEqual(prowlarr.schedule, ["at any time"]);
  assert.deepEqual(prowlarr.addLabels, ["security"]);
  assert.match((prowlarr.prBodyNotes as string[])[0], /fixes \*\*1 critical\*\* and \*\*0 high\*\* CVEs.*CVE-OLD.*full report/);
  const digest = rules.find((r) => r.matchJsonata)!;
  assert.match((digest.matchJsonata as string[])[0], /^newDigest = "sha256:[0-9a-f]{64}"$/);
  // kener fixes nothing but sits in a group branch with updates that do.
  assert.deepEqual(of("rajnandan1/kener").map((r) => [r.schedule, r.addLabels, r.prBodyNotes]), [[["at any time"], undefined, undefined]]);
  assert.deepEqual(of("quay.io/argoproj/argocd"), []);
  assert.deepEqual(a.errors, [{ ref: "quay.io/argoproj/argocd:v3.6.2", error: "boom" }]);
});

test("rules: --no-release keeps the schedule; a regression gets a warning only", () => {
  const a = demo();
  const u = a.updates.find((x) => x.fromName === "rajnandan1/kener")!;
  u.diff = diff([], [vuln("CVE-NEW", "HIGH")]);
  const rules = rulesFor(a, { label: "security", prPriority: 10, release: false });
  assert.ok(rules.every((r) => r.schedule === undefined));
  const kener = rules.find((r) => (r.matchPackageNames as string[])[0] === "rajnandan1/kener")!;
  assert.equal(kener.addLabels, undefined);
  assert.match((kener.prBodyNotes as string[])[0], /⚠️ introduces \*\*0 critical\*\* and \*\*1 high\*\*/);
});

test("rules: the rest of a fixing update's branch is released with it", () => {
  const a = demo();
  const rules = rulesFor(a, { label: "security", prPriority: 10, release: true });
  // valkey 9.1.3 -> 9.2.0 fixes CVE-OLD too here; make it neutral so only its branch mate fixes.
  const neutral = a.updates.find((x) => x.from === "valkey/valkey:9.1.3-alpine")!;
  neutral.diff = diff([], []);
  const again = rulesFor(a, { label: "security", prPriority: 10, release: true });
  const mate = again.find((r) => (r.matchPackageNames as string[])[0] === "valkey/valkey")!;
  assert.deepEqual([mate.schedule, mate.addLabels, mate.prBodyNotes], [["at any time"], undefined, undefined]);
  assert.ok(rules.length >= again.length);
});

test("notes cannot inject handlebars or break tables", () => {
  const a = demo();
  const u = a.updates[0];
  u.diff.fixed[0].id = "CVE-{{evil}}|x";
  assert.doesNotMatch(note(u), /\{\{|[^\\]\|/);
});

test("report renders totals, fixing updates and failures", () => {
  const md = renderReport(demo(), { scannedAt: "2026-01-01T00:00:00Z", platform: "linux/amd64", trivyVersion: "0.76.2", dbUpdatedAt: "2026-01-01T00:00:00Z" });
  assert.match(md, /# Container image CVEs: o\/r/);
  assert.match(md, /`lscr.io\/linuxserver\/prowlarr` \| `2\.7\.0` → `3\.0\.2` \| 1 \/ 0 → 0 \/ 0 \| 1 \| 0 \|/);
  assert.match(md, /## Not scanned\n\n- `quay.io\/argoproj\/argocd:v3\.6\.2`: boom/);
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

test("SBOM store: reuse, then regenerate on age or a new Trivy minor", () => {
  const dir = mkdtempSync(join(tmpdir(), "rt-store-"));
  const src = join(dir, "in.json");
  writeFileSync(src, '{"bomFormat":"CycloneDX"}');
  const key = sbomKey("sha256:abc", "linux/amd64");
  assert.equal(key, "sha256-abc.linux-amd64");
  new SbomStore(undefined, join(dir, "archive"), 30).save(key, src, {
    ref: "x", digest: "sha256:abc", platform: "linux/amd64", trivyVersion: "0.76.2", createdAt: "2026-01-01T00:00:00Z",
  });
  const store = new SbomStore(join(dir, "archive"), join(dir, "out"), 30);
  const dest = join(dir, "restored.json");
  const day = 86_400_000;
  const t0 = Date.parse("2026-01-01T00:00:00Z");
  assert.equal(store.restore(key, "0.76.9", dest, t0 + day), true);
  assert.equal(readFileSync(dest, "utf8"), '{"bomFormat":"CycloneDX"}');
  assert.equal(store.restore(key, "0.77.0", dest, t0 + day), false);
  assert.equal(store.restore(key, "0.76.2", dest, t0 + 31 * day), false);
  assert.equal(store.restore("sha256-nope.linux-amd64", "0.76.2", dest, t0), false);
});

test("assemble merges every repository's rules and prunes unreferenced SBOMs", () => {
  const root = mkdtempSync(join(tmpdir(), "rt-data-"));
  for (const [repo, key] of [["o/a", "k1"], ["g/sub/b", "k2"]]) {
    mkdirSync(join(root, "repos", repo), { recursive: true });
    writeFileSync(join(root, "repos", repo, "rules.json"), JSON.stringify({ packageRules: [{ matchRepositories: [repo] }] }));
    writeFileSync(join(root, "repos", repo, "state.json"), JSON.stringify({ sboms: [key] }));
  }
  mkdirSync(join(root, "sboms"));
  for (const k of ["k1", "k2", "stale"]) for (const ext of ["cdx.json.gz", "meta.json"]) writeFileSync(join(root, "sboms", `${k}.${ext}`), "x");
  const res = assemble(root, "https://host/o/data/blob/main");
  assert.deepEqual([res.repos.sort(), res.pruned], [["g/sub/b", "o/a"], 2]);
  assert.equal(existsSync(join(root, "sboms", "stale.meta.json")), false);
  assert.equal(existsSync(join(root, "sboms", "k2.cdx.json.gz")), true);
  const preset = JSON.parse(readFileSync(join(root, PRESET_FILE), "utf8"));
  assert.equal(preset.packageRules.length, 2);
  assert.match(preset.dependencyDashboardHeader, /blob\/main\/repos\/\{\{\{repository\}\}\}\/report\.md/);
});

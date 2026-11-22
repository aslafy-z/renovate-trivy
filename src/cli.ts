#!/usr/bin/env node
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { analyse } from "./analyse.ts";
import { cloneData, makeGit, makeGitBlob } from "./git.ts";
import { carryForward, matchKey, rulesFor, type PackageRule } from "./preset.ts";
import { REPOSITORY_RE, publish, type RunManifest } from "./publish.ts";
import { lookup } from "./renovate.ts";
import { renderReport, renderSummary } from "./report.ts";
import { scanAll } from "./scan.ts";
import { SbomStore } from "./store.ts";
import { targetsFromReport } from "./targets.ts";
import { downloadDbs, trivyVersion, type TrivyOptions } from "./trivy.ts";
import type { RepoTargets, ScanMeta } from "./types.ts";

// renovate: datasource=npm depName=renovate
const DEFAULT_RENOVATE_VERSION = "44.257.9";

const HELP = `renovate-trivy: container image CVEs, fed back into Renovate through a preset

One central run serves any number of repositories:

  renovate-trivy lookup   what does Renovate track and propose in each repository?  -> targets.json
  renovate-trivy scan     Trivy on every distinct image, through the SBOM archive   -> delta/
  renovate-trivy publish  validate the delta and push it to the data branch

lookup options:
  --repositories <list>     space- or comma-separated owner/name list to clone and look up
  --git-base <url>          where they are cloned from (default: $GITHUB_SERVER_URL or https://github.com)
  --repo-dir <dir>          or: one existing checkout, with --repository <owner/name>
  --out <file>              default: .renovate-trivy/targets.json
  --skip-registry <host>    do not scan images from this registry (repeatable)
  --concurrency <n>         parallel lookups (default: 3)
  --renovate-version <v>    Renovate npm version (default: ${DEFAULT_RENOVATE_VERSION})
  --renovate-bin <path>     use this Renovate binary instead of npx
  token: $RENOVATE_TRIVY_READ_TOKEN, sent to git as a basic-auth header (private repositories)

scan options:
  --targets <file>          default: .renovate-trivy/targets.json
  --out <dir>               default: .renovate-trivy/delta
  --data-remote <url>       git URL of the data repository, to reuse archived SBOMs
  --data-branch <name>      default: data
  --web-url <url>           file view of the data branch, e.g. https://github.com/o/data/blob/data
  --platform <os/arch>      image platform to scan (default: linux/amd64)
  --label <name>            label for PRs that fix critical/high CVEs (default: security)
  --pr-priority <n>         prPriority for those PRs (default: 10)
  --no-release              keep fixing updates on each repository's schedule
  --no-dashboard-report     do not put CVE summaries in Dependency Dashboards
  --sbom-max-age <days>     regenerate SBOMs older than this (default: 30)
  --concurrency <n>         parallel scans (default: 4)
  --trivy <path>            trivy binary (default: trivy)

publish options:
  --delta <dir>             default: .renovate-trivy/delta
  --remote <url>            git URL of the data repository (required)
  --branch <name>           default: data
  --web-url <url>           as above
  --dashboard-footer <md>   appended to the dashboard footer, which the preset replaces
                            (e.g. the hosted app's "run again" checkbox)
  token: $RENOVATE_TRIVY_DATA_TOKEN, sent to git as a basic-auth header
`;

const log = (msg: string) => console.error(msg);
const tmp = (name: string) => mkdtempSync(join(process.env.RUNNER_TEMP ?? tmpdir(), `renovate-trivy-${name}-`));

interface Targets {
  repositories: ({ ok: true } & RepoTargets | { ok: false; repository: string; error: string })[];
}

async function pool<T>(items: T[], size: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  await Promise.all(Array.from({ length: Math.max(1, Math.min(size, items.length)) }, async () => {
    while (next < items.length) await fn(items[next++]);
  }));
}

async function doLookup(v: Record<string, any>): Promise<string> {
  const out = resolve(v.out ?? ".renovate-trivy/targets.json");
  const work = tmp("lookup");
  const renovate = { version: v["renovate-version"] ?? DEFAULT_RENOVATE_VERSION, bin: v["renovate-bin"], cacheDir: join(work, "cache") };
  const jobs: { repository: string; dir?: string }[] = [];
  if (v.repositories) {
    for (const r of String(v.repositories).split(/[\s,]+/).filter(Boolean)) jobs.push({ repository: r });
  } else {
    const repository = v.repository ?? process.env.GITHUB_REPOSITORY ?? process.env.CI_PROJECT_PATH;
    if (!repository) throw new Error("--repositories, or --repository with --repo-dir, is required");
    jobs.push({ repository, dir: resolve(v["repo-dir"] ?? ".") });
  }
  for (const j of jobs) if (!REPOSITORY_RE.test(j.repository)) throw new Error(`unsupported repository name: ${j.repository}`);
  const base = String(v["git-base"] ?? process.env.GITHUB_SERVER_URL ?? "https://github.com").replace(/\/$/, "");
  const git = makeGit({ token: process.env.RENOVATE_TRIVY_READ_TOKEN });
  const targets: Targets = { repositories: [] };
  let n = 0;
  await pool(jobs, Number(v.concurrency ?? 3), async (job) => {
    const id = n++;
    try {
      let dir = job.dir;
      if (!dir) {
        dir = join(work, `repo-${id}`);
        mkdirSync(dir);
        git(dir, "clone", "-q", "--depth", "1", `${base}/${job.repository}.git`, ".");
      }
      const report = await lookup({ ...renovate, repoDir: dir, reportPath: join(work, `report-${id}.json`) });
      const [t] = targetsFromReport(report as any, { localRepository: job.repository, skipRegistries: v["skip-registry"] });
      targets.repositories.push({ ok: true, ...t, ...(job.dir ? {} : { url: `${base}/${job.repository}` }) });
      log(`${job.repository}: ${t.images.length} images, ${t.images.reduce((s, i) => s + i.updates.length, 0)} proposed updates`);
    } catch (err) {
      const stderr = (err as { stderr?: string }).stderr;
      const error = String(stderr ?? (err as Error).message).trim().split("\n").at(-1)!.slice(0, 300);
      targets.repositories.push({ ok: false, repository: job.repository, error });
      log(`${job.repository}: FAILED ${error}`);
    }
  });
  targets.repositories.sort((a, b) => a.repository.localeCompare(b.repository));
  mkdirSync(resolve(out, ".."), { recursive: true });
  writeFileSync(out, `${JSON.stringify(targets, null, 1)}\n`);
  if (!process.env.RENOVATE_TRIVY_KEEP_WORK) rmSync(work, { recursive: true, force: true });
  // Not fatal: publishing still (re)creates the preset, which is what a
  // repository extending a preset that does not exist yet is waiting for.
  if (!targets.repositories.some((r) => r.ok)) log("warning: no repository could be looked up");
  return out;
}

/** Where a branch's pull request lives, for the hosts whose URL scheme is known. */
function prLinker(repoUrl?: string): ((branch: string) => string | undefined) | undefined {
  if (!repoUrl) return undefined;
  const host = new URL(repoUrl).host;
  // GitHub redirects /pull/<branch> to that branch's pull request.
  if (host.includes("github")) return (b) => `${repoUrl}/pull/${b.split("/").map(encodeURIComponent).join("/")}`;
  if (host.includes("gitlab")) return (b) => `${repoUrl}/-/merge_requests?scope=all&state=opened&source_branch=${encodeURIComponent(b)}`;
  return undefined;
}

async function doScan(v: Record<string, any>, targetsFile?: string): Promise<string> {
  const targets = JSON.parse(readFileSync(resolve(targetsFile ?? v.targets ?? ".renovate-trivy/targets.json"), "utf8")) as Targets;
  const out = resolve(v.out ?? ".renovate-trivy/delta");
  const work = tmp("scan");
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });

  // Read side of the archive: a blobless clone, SBOMs fetched on demand.
  let dataDir: string | undefined;
  const auth = { token: process.env.RENOVATE_TRIVY_DATA_TOKEN };
  const git = makeGit(auth);
  if (v["data-remote"]) {
    dataDir = join(work, "data");
    mkdirSync(dataDir);
    if (!cloneData(git, v["data-remote"], v["data-branch"] ?? "data", dataDir)) {
      log("no existing data branch: scanning from scratch");
      dataDir = undefined;
    }
  }

  const trivy: TrivyOptions = { bin: v.trivy ?? "trivy", platform: v.platform ?? "linux/amd64", timeout: "30m" };
  await downloadDbs(trivy);
  const version = await trivyVersion(trivy);
  const meta: ScanMeta = { scannedAt: new Date().toISOString(), platform: trivy.platform, ...version };
  const store = new SbomStore(out, Number(v["sbom-max-age"] ?? 30), dataDir, git, makeGitBlob(auth));

  const ok = targets.repositories.filter((r) => r.ok);
  const refs = [...new Set(ok.flatMap((r) => r.images.filter((i) => !i.skipped).flatMap((i) => [i.ref, ...i.updates.map((u) => u.ref)])))];
  const { scans, keys } = await scanAll(refs, {
    trivy, trivyVersion: version.trivyVersion, store, workDir: join(work, "trivy"), concurrency: Number(v.concurrency ?? 4), log,
  });

  let failed = 0;
  for (const t of ok) {
    const analysis = analyse(t, scans);
    failed += analysis.errors.length;
    const rules = rulesFor(analysis, { label: v.label ?? "security", prPriority: Number(v["pr-priority"] ?? 10), release: !v["no-release"] });
    const sboms: Record<string, string> = {};
    for (const ref of t.images.flatMap((i) => [i.ref, ...i.updates.map((u) => u.ref)])) if (keys.has(ref)) sboms[ref] = keys.get(ref)!;
    // References that failed this time keep what the previous run knew about them.
    const previous = dataDir ? join(dataDir, "repos", t.repository) : undefined;
    if (previous && analysis.errors.length && existsSync(join(previous, "rules.json"))) {
      const have = new Set(rules.map(matchKey));
      const old = JSON.parse(readFileSync(join(previous, "rules.json"), "utf8")).packageRules as PackageRule[];
      rules.push(...carryForward(old, analysis, t).filter((r) => !have.has(matchKey(r))));
    }
    const dir = join(out, "repos", t.repository);
    mkdirSync(dir, { recursive: true });
    const reportUrl = v["web-url"] ? `${v["web-url"]}/repos/${t.repository}/report.md` : undefined;
    writeFileSync(join(dir, "rules.json"), `${JSON.stringify({ packageRules: rules }, null, 2)}\n`);
    writeFileSync(join(dir, "report.md"), renderReport(analysis, meta));
    if (!v["no-dashboard-report"]) writeFileSync(join(dir, "summary.md"), renderSummary(analysis, meta, { reportUrl, prUrl: prLinker(t.url) }));
    writeFileSync(join(dir, "state.json"), `${JSON.stringify({ ...meta, sboms }, null, 2)}\n`);
    log(`${t.repository}: ${analysis.updates.filter((u) => u.diff.fixedGate).length} updates fix critical/high CVEs, ${rules.length} rules, ${analysis.errors.length} references not scanned`);
  }
  const run: RunManifest = {
    repositories: targets.repositories.map((r) => ({ repository: r.repository, ok: r.ok })),
    sboms: store.additions(),
  };
  writeFileSync(join(out, "run.json"), `${JSON.stringify(run, null, 1)}\n`);
  rmSync(work, { recursive: true, force: true });
  if (process.env.GITHUB_STEP_SUMMARY) {
    const rows = targets.repositories.map((r) => `| ${r.repository} | ${r.ok ? `${r.images.length} images` : `lookup failed: ${r.error}`} |`);
    writeFileSync(process.env.GITHUB_STEP_SUMMARY, ["| Repository | |", "|---|---|", ...rows, "", `${refs.length} image references, ${Object.keys(run.sboms).length} new SBOMs, ${failed} failures`, ""].join("\n"), { flag: "a" });
  }
  log(`delta written to ${out}: ${Object.keys(run.sboms).length} new SBOMs${failed ? `, ${failed} references failed` : ""}`);
  return out;
}

async function doPublish(v: Record<string, any>, delta?: string): Promise<void> {
  if (!v.remote) throw new Error("--remote is required");
  await publish({
    delta: resolve(delta ?? v.delta ?? ".renovate-trivy/delta"),
    remote: v.remote,
    branch: v.branch ?? "data",
    webUrl: v["web-url"],
    dashboardFooter: v["dashboard-footer"],
    token: process.env.RENOVATE_TRIVY_DATA_TOKEN,
    log,
  });
}

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    help: { type: "boolean", short: "h" },
    repositories: { type: "string" }, "git-base": { type: "string" }, "repo-dir": { type: "string" }, repository: { type: "string" },
    out: { type: "string" }, targets: { type: "string" }, "data-remote": { type: "string" }, "data-branch": { type: "string" },
    "web-url": { type: "string" }, platform: { type: "string" }, "skip-registry": { type: "string", multiple: true },
    label: { type: "string" }, "pr-priority": { type: "string" }, "no-release": { type: "boolean" },
    "no-dashboard-report": { type: "boolean" }, "sbom-max-age": { type: "string" }, concurrency: { type: "string" },
    "renovate-version": { type: "string" }, "renovate-bin": { type: "string" }, trivy: { type: "string" },
    "dashboard-footer": { type: "string" }, delta: { type: "string" }, remote: { type: "string" }, branch: { type: "string" },
  },
});

try {
  const cmd = positionals[0];
  if (values.help || !cmd) console.log(HELP);
  else if (cmd === "lookup") await doLookup(values);
  else if (cmd === "scan") await doScan(values);
  else if (cmd === "publish") await doPublish(values);
  else throw new Error(`unknown command: ${cmd}\n\n${HELP}`);
} catch (err) {
  console.error(`renovate-trivy: ${(err as Error).message}`);
  process.exit(1);
}

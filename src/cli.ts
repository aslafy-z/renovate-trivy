#!/usr/bin/env node
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { analyse } from "./analyse.ts";
import { carryForward, matchKey, rulesFor, type PackageRule } from "./preset.ts";
import { publish } from "./publish.ts";
import { lookup } from "./renovate.ts";
import { renderReport, renderSummary } from "./report.ts";
import { scanAll } from "./scan.ts";
import { SbomStore } from "./store.ts";
import { targetsFromReport } from "./targets.ts";
import { downloadDbs, trivyVersion, type TrivyOptions } from "./trivy.ts";
import type { ScanMeta } from "./types.ts";

// renovate: datasource=npm depName=renovate
const DEFAULT_RENOVATE_VERSION = "44.257.9";

const HELP = `renovate-trivy: container image CVEs, fed back into Renovate through a preset

Usage:
  renovate-trivy scan     [options]   lookup with Renovate, scan with Trivy, write a delta
  renovate-trivy publish  [options]   push a delta to the data repository
  renovate-trivy run      [options]   scan, then publish

scan options:
  --repo-dir <dir>          checkout to scan (default: .)
  --repository <owner/name> its name (default: $GITHUB_REPOSITORY or $CI_PROJECT_PATH)
  --out <dir>               where to write the delta (default: .renovate-trivy/delta)
  --data-dir <dir>          checkout of the data repository, to reuse archived SBOMs
  --web-url <url>           file view of the data repository, e.g. https://github.com/o/data/blob/main
  --platform <os/arch>      image platform to scan (default: linux/amd64)
  --skip-registry <host>    do not scan images from this registry (repeatable)
  --label <name>            label for PRs that fix critical/high CVEs (default: security)
  --pr-priority <n>         prPriority for those PRs (default: 10)
  --no-release              keep fixing updates on the repository's schedule
  --no-dashboard-report     do not put the CVE summary in the Dependency Dashboard
  --sbom-max-age <days>     regenerate SBOMs older than this (default: 30)
  --concurrency <n>         parallel scans (default: 4)
  --renovate-version <v>    Renovate npm version for the lookup (default: ${DEFAULT_RENOVATE_VERSION})
  --renovate-bin <path>     use this Renovate binary instead of npx
  --renovate-report <file>  use an existing Renovate report instead of running the lookup
  --trivy <path>            trivy binary (default: trivy)

publish options:
  --delta <dir>             delta to publish (default: .renovate-trivy/delta)
  --repository <owner/name> the repository the delta is for; it can only write that entry
  --remote <url>            git URL of the data repository (required)
  --branch <name>           branch to publish to (default: main)
  --web-url <url>           as above; links reports from the Dependency Dashboard
  token: $RENOVATE_TRIVY_DATA_TOKEN, sent to an https remote as a basic-auth header
`;

const log = (msg: string) => console.error(msg);

async function scan(v: Record<string, any>): Promise<string> {
  const repoDir = resolve(v["repo-dir"] ?? ".");
  const out = resolve(v.out ?? ".renovate-trivy/delta");
  const work = mkdtempSync(join(process.env.RUNNER_TEMP ?? tmpdir(), "renovate-trivy-work-"));
  const repository = v.repository ?? process.env.GITHUB_REPOSITORY ?? process.env.CI_PROJECT_PATH;
  if (!repository) throw new Error("--repository is required (or GITHUB_REPOSITORY / CI_PROJECT_PATH)");
  rmSync(out, { recursive: true, force: true });

  const report = v["renovate-report"]
    ? JSON.parse(readFileSync(v["renovate-report"], "utf8"))
    : lookup({ repoDir, reportPath: join(work, "renovate-report.json"), version: v["renovate-version"] ?? DEFAULT_RENOVATE_VERSION, bin: v["renovate-bin"], log });
  const all = targetsFromReport(report, { localRepository: repository, skipRegistries: v["skip-registry"] });

  const trivy: TrivyOptions = { bin: v.trivy ?? "trivy", platform: v.platform ?? "linux/amd64", timeout: "30m" };
  await downloadDbs(trivy);
  const version = await trivyVersion(trivy);
  const meta: ScanMeta = { scannedAt: new Date().toISOString(), platform: trivy.platform, ...version };
  const dataSboms = v["data-dir"] ? join(resolve(v["data-dir"]), "sboms") : undefined;
  const store = new SbomStore(dataSboms && existsSync(dataSboms) ? dataSboms : undefined, join(out, "sboms"), Number(v["sbom-max-age"] ?? 30));

  let failed = 0;
  for (const targets of all) {
    const refs = [...new Set(targets.images.filter((i) => !i.skipped).flatMap((i) => [i.ref, ...i.updates.map((u) => u.ref)]))];
    log(`${targets.repository}: ${targets.images.length} images, ${refs.length} references to scan`);
    const { scans, keys } = await scanAll(refs, {
      trivy, trivyVersion: version.trivyVersion, store, workDir: work, concurrency: Number(v.concurrency ?? 4), log,
    });
    const analysis = analyse(targets, scans);
    failed += analysis.errors.length;
    const dir = join(out, "repos", targets.repository);
    mkdirSync(dir, { recursive: true });
    const reportUrl = v["web-url"] ? `${v["web-url"]}/repos/${targets.repository}/report.md` : undefined;
    const rules = rulesFor(analysis, {
      label: v.label ?? "security", prPriority: Number(v["pr-priority"] ?? 10), release: !v["no-release"], reportUrl,
    });
    // References that failed this time keep what the previous run knew about them.
    const sboms: Record<string, string> = Object.fromEntries(keys);
    const previous = v["data-dir"] ? join(resolve(v["data-dir"]), "repos", targets.repository) : undefined;
    if (previous && analysis.errors.length && existsSync(join(previous, "rules.json"))) {
      const have = new Set(rules.map(matchKey));
      const old = JSON.parse(readFileSync(join(previous, "rules.json"), "utf8")).packageRules as PackageRule[];
      rules.push(...carryForward(old, analysis, targets).filter((r) => !have.has(matchKey(r))));
      const oldSboms = JSON.parse(readFileSync(join(previous, "state.json"), "utf8")).sboms ?? {};
      for (const e of analysis.errors) if (typeof oldSboms[e.ref] === "string") sboms[e.ref] = oldSboms[e.ref];
    }
    writeFileSync(join(dir, "rules.json"), `${JSON.stringify({ packageRules: rules }, null, 2)}\n`);
    writeFileSync(join(dir, "report.md"), renderReport(analysis, meta));
    if (!v["no-dashboard-report"]) writeFileSync(join(dir, "summary.md"), renderSummary(analysis, meta, reportUrl));
    writeFileSync(join(dir, "state.json"), `${JSON.stringify({ ...meta, sboms }, null, 2)}\n`);
    const fixing = analysis.updates.filter((u) => u.diff.fixedGate).length;
    log(`${targets.repository}: ${fixing} updates fix critical/high CVEs, ${rules.length} rules, ${analysis.errors.length} references not scanned`);
    if (process.env.GITHUB_STEP_SUMMARY) writeFileSync(process.env.GITHUB_STEP_SUMMARY, renderReport(analysis, meta), { flag: "a" });
  }
  rmSync(work, { recursive: true, force: true });
  log(`delta written to ${out}${failed ? ` (${failed} references failed)` : ""}`);
  return out;
}

async function doPublish(v: Record<string, any>, delta?: string): Promise<void> {
  if (!v.remote) throw new Error("--remote is required");
  const repository = v.repository ?? process.env.GITHUB_REPOSITORY ?? process.env.CI_PROJECT_PATH;
  if (!repository) throw new Error("--repository is required (or GITHUB_REPOSITORY / CI_PROJECT_PATH)");
  await publish({
    repository,
    sbomMaxAgeDays: Number(v["sbom-max-age"] ?? 30),
    delta: resolve(delta ?? v.delta ?? ".renovate-trivy/delta"),
    remote: v.remote,
    branch: v.branch ?? "main",
    webUrl: v["web-url"],
    token: process.env.RENOVATE_TRIVY_DATA_TOKEN,
    log,
  });
}

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    help: { type: "boolean", short: "h" },
    "repo-dir": { type: "string" }, repository: { type: "string" }, out: { type: "string" },
    "data-dir": { type: "string" }, "web-url": { type: "string" }, platform: { type: "string" },
    "skip-registry": { type: "string", multiple: true }, label: { type: "string" },
    "pr-priority": { type: "string" }, "no-release": { type: "boolean" }, "no-dashboard-report": { type: "boolean" }, "sbom-max-age": { type: "string" },
    concurrency: { type: "string" }, "renovate-version": { type: "string" }, "renovate-bin": { type: "string" },
    "renovate-report": { type: "string" }, trivy: { type: "string" },
    delta: { type: "string" }, remote: { type: "string" }, branch: { type: "string" },
  },
});

try {
  const cmd = positionals[0];
  if (values.help || !cmd) console.log(HELP);
  else if (cmd === "scan") await scan(values);
  else if (cmd === "publish") await doPublish(values);
  else if (cmd === "run") await doPublish(values, await scan(values));
  else throw new Error(`unknown command: ${cmd}\n\n${HELP}`);
} catch (err) {
  console.error(`renovate-trivy: ${(err as Error).message}`);
  process.exit(1);
}

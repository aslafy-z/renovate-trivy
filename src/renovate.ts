/** Run Renovate read-only to learn what it tracks and what it would propose. */
import { execFile } from "node:child_process";
import { readFileSync, rmSync } from "node:fs";
import { promisify } from "node:util";

const exec = promisify(execFile);

export interface LookupOptions {
  repoDir: string;
  reportPath: string;
  /** npm version of Renovate to run through npx; ignored when `bin` is set. */
  version: string;
  bin?: string;
  cacheDir?: string;
}

/**
 * `--platform=local` reads a checkout and its Renovate config only; with
 * `--dry-run=lookup` it creates no branch and calls no repository API. All it
 * needs is the files, so it works for a repository on any git host.
 */
export async function lookup(o: LookupOptions): Promise<unknown> {
  const env: NodeJS.ProcessEnv = {
    LOG_LEVEL: "warn",
    ...process.env,
    RENOVATE_REPORT_TYPE: "file",
    RENOVATE_REPORT_PATH: o.reportPath,
    ...(o.cacheDir ? { RENOVATE_CACHE_DIR: o.cacheDir } : {}),
  };
  // Lets Renovate look up github-releases/tags and fetch github> presets without hitting anonymous rate limits.
  if (!env.RENOVATE_GITHUB_COM_TOKEN && !env.GITHUB_COM_TOKEN && env.GITHUB_TOKEN) env.RENOVATE_GITHUB_COM_TOKEN = env.GITHUB_TOKEN;
  // The token that reads the repositories is for git only.
  delete env.RENOVATE_TRIVY_READ_TOKEN;
  const [cmd, args] = o.bin ? [o.bin, []] : ["npx", ["--yes", `renovate@${o.version}`]];
  // Never read back a report this run did not write.
  rmSync(o.reportPath, { force: true });
  try {
    await exec(cmd, [...args, "--platform=local", "--dry-run=lookup"], { cwd: o.repoDir, env, maxBuffer: 64 * 1024 * 1024 });
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; message: string };
    const lines = `${e.stdout ?? ""}\n${e.stderr ?? ""}`.split("\n").filter((l) => l.trim());
    throw new Error(`renovate lookup failed: ${(lines.at(-1) ?? e.message).trim().slice(0, 300)}`);
  }
  const report = JSON.parse(readFileSync(o.reportPath, "utf8"));
  // Renovate exits 0 on a repository error (an unreachable preset, an invalid
  // config) and reports no dependency at all: that is a failure, not "no image".
  const problems = [...(report.problems ?? []), ...Object.values<any>(report.repositories ?? {}).flatMap((r) => r.problems ?? [])];
  const fatal = problems.find((p) => p.err || p.level >= 50);
  if (fatal) throw new Error(`renovate lookup failed: ${String(fatal.err?.validationError ?? fatal.err?.message ?? fatal.msg).slice(0, 300)}`);
  return report;
}

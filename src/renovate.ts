/** Run Renovate read-only to learn what it tracks and what it would propose. */
import { execFileSync } from "node:child_process";
import { readFileSync, rmSync } from "node:fs";

export interface LookupOptions {
  repoDir: string;
  reportPath: string;
  /** npm version of Renovate to run through npx; ignored when `bin` is set. */
  version: string;
  bin?: string;
  log: (msg: string) => void;
}

/**
 * `--platform=local` reads the checkout and its Renovate config only; with
 * `--dry-run=lookup` it creates no branch and calls no repository API.
 */
export function lookup(o: LookupOptions): unknown {
  const env: NodeJS.ProcessEnv = {
    LOG_LEVEL: "warn",
    ...process.env,
    RENOVATE_REPORT_TYPE: "file",
    RENOVATE_REPORT_PATH: o.reportPath,
  };
  // Lets Renovate look up github-releases/tags and fetch github> presets without hitting anonymous rate limits.
  if (!env.RENOVATE_GITHUB_COM_TOKEN && !env.GITHUB_COM_TOKEN && env.GITHUB_TOKEN) env.RENOVATE_GITHUB_COM_TOKEN = env.GITHUB_TOKEN;
  const [cmd, args] = o.bin ? [o.bin, []] : ["npx", ["--yes", `renovate@${o.version}`]];
  // Never read back a report this run did not write.
  rmSync(o.reportPath, { force: true });
  o.log(`renovate lookup (${o.bin ?? `renovate@${o.version}`})`);
  execFileSync(cmd, [...args, "--platform=local", "--dry-run=lookup"], { cwd: o.repoDir, env, stdio: ["ignore", "inherit", "inherit"] });
  return JSON.parse(readFileSync(o.reportPath, "utf8"));
}

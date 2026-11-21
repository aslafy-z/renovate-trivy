/**
 * Publish a scan's delta to the data repository: a single commit, replaced on
 * every run, holding the preset Renovate extends, each repository's rules
 * and report, and the SBOM archive.
 *
 * The delta comes from the scan job, which runs Renovate and Trivy on
 * repository-controlled input, so it is treated as untrusted: only known
 * files are read, their content is validated and re-serialised, and nothing
 * in it can reach beyond its own repository's entry.
 */
import { execFileSync } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { buildPreset, type PackageRule } from "./preset.ts";

export interface PublishOptions {
  delta: string;
  /** The repository this delta is for: the only entry it may write. */
  repository: string;
  remote: string;
  branch: string;
  /** Web URL of the data repository's file view, e.g. https://github.com/o/r/blob/main */
  webUrl?: string;
  /** Token for an https remote; passed to git through the environment, never the URL. */
  token?: string;
  sbomMaxAgeDays?: number;
  log: (msg: string) => void;
}

export const PRESET_FILE = "renovate-trivy.json";
const REPOSITORY_RE = /^[\w-][\w.-]*(\/[\w-][\w.-]*)+$/;
const SBOM_KEY_RE = /^sha256-[0-9a-f]{64}\.[a-z0-9]+-[a-z0-9]+(-[a-z0-9]+)?$/;
const VERSION_RE = /^\d+\.\d+\.\d+[\w.+-]*$/;
const MAX_RULES = 5000;

function readRegular(path: string, maxBytes: number): Buffer {
  const st = lstatSync(path);
  if (!st.isFile()) throw new Error(`${path}: not a regular file`);
  if (st.size > maxBytes) throw new Error(`${path}: larger than ${maxBytes} bytes`);
  return readFileSync(path);
}

const isStrings = (v: unknown, max = 50): v is string[] =>
  Array.isArray(v) && v.length <= max && v.every((s) => typeof s === "string" && s.length <= 5000 && !/[\r\n]/.test(s));
const isExact = (v: unknown) => typeof v === "string" && v.startsWith("/^") && v.endsWith("$/") && v.length <= 600;

/**
 * Accept only the rule shape renovate-trivy generates. A preset is
 * configuration Renovate trusts, shared by every repository extending it:
 * a delta must not be able to add `automerge`, registries, or rules for
 * another repository.
 */
export function validateRules(input: unknown, repository: string): PackageRule[] {
  if (!Array.isArray(input) || input.length > MAX_RULES) throw new Error("rules.json: packageRules must be an array");
  const checks: Record<string, (v: unknown) => boolean> = {
    description: (v) => typeof v === "string" && v.length <= 500,
    matchRepositories: (v) => isStrings(v) && v.length === 1 && v[0] === repository,
    matchDatasources: (v) => isStrings(v) && v.length === 1 && /^[\w.-]+$/.test(v[0]),
    matchPackageNames: (v) => isStrings(v) && v.length === 1,
    matchCurrentValue: isExact,
    matchNewValue: isExact,
    matchJsonata: (v) => isStrings(v) && v.length === 1 && /^newDigest = "sha256:[0-9a-f]{64}"$/.test(v[0]),
    schedule: (v) => isStrings(v) && v.length === 1 && v[0] === "at any time",
    addLabels: (v) => isStrings(v, 5) && v.every((s) => s.length <= 50),
    prPriority: (v) => Number.isInteger(v) && Math.abs(v as number) <= 100,
    prBodyNotes: (v) => isStrings(v, 5) && v.every((s) => !/[{}]/.test(s)),
  };
  return input.map((rule, i) => {
    if (typeof rule !== "object" || rule === null || Array.isArray(rule)) throw new Error(`rules.json[${i}]: not an object`);
    for (const required of ["matchRepositories", "matchDatasources", "matchPackageNames"]) {
      if (!(required in rule)) throw new Error(`rules.json[${i}]: ${required} is required`);
    }
    if (!("matchNewValue" in rule) && !("matchJsonata" in rule)) throw new Error(`rules.json[${i}]: must match an exact new version`);
    const out: PackageRule = {};
    for (const [key, value] of Object.entries(rule)) {
      if (!checks[key]?.(value)) throw new Error(`rules.json[${i}]: ${key} is not allowed or has an unexpected value`);
      out[key] = value;
    }
    return out;
  });
}

const minor = (v: string) => v.split(".").slice(0, 2).join(".");

/** Copy one repository's validated entry and its new SBOMs from the delta into the data tree. */
export function applyDelta(delta: string, root: string, repository: string, maxAgeDays = 30, now = Date.now()): { sboms: number } {
  if (!REPOSITORY_RE.test(repository) || repository.split("/").some((s) => s === ".." || s === ".")) {
    throw new Error(`unsupported repository name: ${repository}`);
  }
  const src = join(delta, "repos", repository);
  const dst = join(root, "repos", repository);
  const rules = validateRules(JSON.parse(readRegular(join(src, "rules.json"), 8 << 20).toString("utf8")).packageRules, repository);
  const stateIn = JSON.parse(readRegular(join(src, "state.json"), 8 << 20).toString("utf8"));
  const sboms: Record<string, string> = {};
  for (const [ref, key] of Object.entries(stateIn.sboms ?? {})) {
    if (typeof key === "string" && SBOM_KEY_RE.test(key) && ref.length <= 1000) sboms[ref] = key;
  }
  const str = (v: unknown) => (typeof v === "string" ? v.slice(0, 100) : "");
  const state = {
    scannedAt: str(stateIn.scannedAt), platform: str(stateIn.platform),
    trivyVersion: str(stateIn.trivyVersion), dbUpdatedAt: str(stateIn.dbUpdatedAt), sboms,
  };
  const report = readRegular(join(src, "report.md"), 4 << 20);

  mkdirSync(dst, { recursive: true });
  writeFileSync(join(dst, "rules.json"), `${JSON.stringify({ packageRules: rules }, null, 2)}\n`);
  writeFileSync(join(dst, "state.json"), `${JSON.stringify(state, null, 2)}\n`);
  writeFileSync(join(dst, "report.md"), report);
  // The summary becomes part of a Handlebars template in the shared preset.
  rmSync(join(dst, "summary.md"), { force: true });
  if (existsSync(join(src, "summary.md"))) {
    const summary = readRegular(join(src, "summary.md"), 20_000).toString("utf8");
    if (/[{}]/.test(summary)) throw new Error("summary.md: braces are not allowed");
    writeFileSync(join(dst, "summary.md"), summary);
  }

  let added = 0;
  const from = join(delta, "sboms");
  const to = join(root, "sboms");
  if (existsSync(from)) {
    mkdirSync(to, { recursive: true });
    for (const file of readdirSync(from)) {
      if (!file.endsWith(".cdx.json.gz")) continue;
      const key = file.slice(0, -".cdx.json.gz".length);
      if (!SBOM_KEY_RE.test(key)) throw new Error(`sboms/${file}: unexpected name`);
      const metaIn = JSON.parse(readRegular(join(from, `${key}.meta.json`), 1 << 16).toString("utf8"));
      const trivyVersion = String(metaIn.trivyVersion ?? "");
      if (!VERSION_RE.test(trivyVersion)) throw new Error(`sboms/${key}.meta.json: bad trivyVersion`);
      // An archived SBOM is shared by every repository using that image, so
      // it is only replaced when it would be regenerated anyway.
      const existing = join(to, `${key}.meta.json`);
      if (existsSync(existing)) {
        const old = JSON.parse(readFileSync(existing, "utf8"));
        const expired = now - Date.parse(old.createdAt) > maxAgeDays * 86_400_000;
        if (!expired && minor(String(old.trivyVersion)) === minor(trivyVersion)) continue;
      }
      writeFileSync(join(to, file), readRegular(join(from, file), 64 << 20));
      const [digest, platform] = [key.slice(0, 71).replace("-", ":"), key.slice(72)];
      // createdAt is set here: the delta does not get to decide how long its SBOM lives.
      const meta = { ref: String(metaIn.ref ?? "").slice(0, 1000), digest, platform, trivyVersion, createdAt: new Date(now).toISOString() };
      writeFileSync(existing, `${JSON.stringify(meta, null, 2)}\n`);
      added++;
    }
  }
  return { sboms: added };
}

function find(dir: string, name: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { recursive: true, encoding: "utf8" })
    .filter((f) => f === name || f.endsWith(`/${name}`))
    .map((f) => join(dir, f))
    .sort();
}

/** Rebuild everything derived from the per-repository entries. */
export function assemble(root: string, webUrl?: string): { repos: string[]; pruned: number } {
  const repos = find(join(root, "repos"), "rules.json");
  const fragments = repos.map((f) => (JSON.parse(readFileSync(f, "utf8")).packageRules ?? []) as PackageRule[]);
  const summaries = new Map<string, string>();
  for (const f of repos) {
    const summary = join(f, "..", "summary.md");
    const name = relative(join(root, "repos"), f).replace(/\/rules\.json$/, "");
    if (REPOSITORY_RE.test(name) && existsSync(summary)) summaries.set(name, readFileSync(summary, "utf8"));
  }
  const template = webUrl ? `${webUrl}/repos/{{{repository}}}/report.md` : undefined;
  writeFileSync(join(root, PRESET_FILE), `${JSON.stringify(buildPreset(fragments, template, summaries), null, 2)}\n`);

  // An SBOM no repository references any more is of an image nobody runs.
  const used = new Set<string>();
  for (const f of find(join(root, "repos"), "state.json")) {
    for (const k of Object.values(JSON.parse(readFileSync(f, "utf8")).sboms ?? {})) used.add(String(k));
  }
  let pruned = 0;
  const sboms = join(root, "sboms");
  if (existsSync(sboms)) {
    for (const f of readdirSync(sboms)) {
      const key = f.replace(/\.(cdx\.json\.gz|meta\.json)$/, "");
      if (!used.has(key)) {
        rmSync(join(sboms, f));
        pruned++;
      }
    }
  }
  const names = repos.map((f) => relative(join(root, "repos"), f).replace(/\/rules\.json$/, ""));
  writeFileSync(
    join(root, "README.md"),
    [
      "# renovate-trivy data",
      "",
      "Generated by [renovate-trivy](https://github.com/aslafy-z/renovate-trivy). This branch is a single commit,",
      "force-pushed on every run: do not edit it, and do not delete it while a Renovate config extends the preset.",
      "",
      `- \`${PRESET_FILE}\`: the Renovate preset.`,
      "- `repos/<repository>/report.md`: CVE report per repository.",
      "- `sboms/`: one CycloneDX SBOM per image digest, so images are pulled once.",
      "",
      "## Repositories",
      "",
      ...names.map((n) => `- [${n}](repos/${n}/report.md)`),
      "",
    ].join("\n"),
  );
  return { repos: names, pruned };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function publish(o: PublishOptions): Promise<void> {
  const env: NodeJS.ProcessEnv = { ...process.env, GIT_TERMINAL_PROMPT: "0" };
  if (o.token) {
    // http.extraHeader through the environment keeps the token out of argv,
    // .git/config and error messages.
    const basic = Buffer.from(`x-access-token:${o.token}`).toString("base64");
    env.GIT_CONFIG_COUNT = "1";
    env.GIT_CONFIG_KEY_0 = "http.extraHeader";
    env.GIT_CONFIG_VALUE_0 = `Authorization: Basic ${basic}`;
  }
  const git = (cwd: string, ...args: string[]) =>
    execFileSync("git", args, { cwd, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();

  let lastError: unknown;
  for (let attempt = 1; attempt <= 5; attempt++) {
    const dir = mkdtempSync(join(tmpdir(), "renovate-trivy-data-"));
    try {
      git(dir, "init", "-q");
      git(dir, "remote", "add", "origin", o.remote);
      let base = "";
      try {
        git(dir, "fetch", "-q", "--depth", "1", "origin", o.branch);
        base = git(dir, "rev-parse", "FETCH_HEAD");
        git(dir, "checkout", "-q", "FETCH_HEAD");
      } catch {
        o.log(`branch ${o.branch} does not exist yet: creating it`);
      }
      const { sboms } = applyDelta(o.delta, dir, o.repository, o.sbomMaxAgeDays);
      const { repos, pruned } = assemble(dir, o.webUrl);
      git(dir, "checkout", "-q", "--orphan", "publish");
      git(dir, "add", "-A");
      git(
        dir, "-c", "user.name=renovate-trivy", "-c", "user.email=renovate-trivy@users.noreply.github.com",
        "commit", "-q", "--allow-empty", "-m", `renovate-trivy: ${repos.length} repositories`,
      );
      // The lease makes a concurrent run's push fail instead of being
      // overwritten; the retry then re-applies this delta on top of it.
      git(dir, "push", "-q", `--force-with-lease=${o.branch}:${base}`, "origin", `HEAD:refs/heads/${o.branch}`);
      o.log(`published ${o.repository}: ${sboms} new SBOMs, ${pruned} stale files pruned, ${repos.length} repositories in the preset`);
      return;
    } catch (err) {
      lastError = err;
      const stderr = (err as { stderr?: string }).stderr;
      // A validation error will not get better by retrying.
      if (stderr === undefined) throw err;
      o.log(`publish attempt ${attempt} failed: ${stderr.trim().split("\n").at(-1)}`);
      await sleep(attempt * (2000 + Math.random() * 8000));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
  throw lastError;
}

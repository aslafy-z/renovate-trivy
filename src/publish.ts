/**
 * Publish a scan's delta to the data branch: a single commit, replaced on
 * every run, holding the preset Renovate extends, each repository's report
 * and the shared SBOM archive.
 *
 * The delta comes from jobs that run Renovate and Trivy on repository- and
 * registry-controlled input, so it is treated as untrusted: only known files
 * are read, their content is validated and re-serialised.
 */
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { gunzipSync } from "node:zlib";
import { cloneData, makeGit } from "./git.ts";
import { buildPreset, type AssembleOptions, type PackageRule } from "./preset.ts";
import { SBOM_INDEX, SBOM_KEY_RE, describesDigest, sbomPath, type SbomIndex } from "./store.ts";

export interface PublishOptions extends AssembleOptions {
  delta: string;
  remote: string;
  branch: string;
  token?: string;
  log: (msg: string) => void;
}

/** What a scan hands to publish, next to the files themselves. */
export interface RunManifest {
  /** Every repository of this run; entries of repositories not listed are removed. */
  repositories: { repository: string; ok: boolean }[];
  /** SBOMs generated this run. */
  sboms: SbomIndex;
}

export const REPOSITORY_RE = /^[\w-][\w.-]*(\/[\w-][\w.-]*)+$/;
const VERSION_RE = /^\d+\.\d+\.\d+[\w.+-]*$/;
const JSONATA_RE = /^(currentDigest = "sha256:[0-9a-f]{64}"|newDigest = "sha256:[0-9a-f]{64}"|currentDigest = "sha256:[0-9a-f]{64}" and newDigest = "sha256:[0-9a-f]{64}")$/;
const MAX_RULES = 20_000;

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
 * Accept only the rule shape renovate-trivy generates. The preset is
 * configuration Renovate trusts, on every repository extending it: nothing
 * coming out of a scan may add `automerge`, a registry, or a template.
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
    matchJsonata: (v) => isStrings(v) && v.length === 1 && JSONATA_RE.test(v[0]),
    schedule: (v) => isStrings(v) && v.length === 1 && v[0] === "at any time",
    addLabels: (v) => isStrings(v, 5) && v.every((s) => s.length <= 50),
    prPriority: (v) => Number.isInteger(v) && Math.abs(v as number) <= 100,
    prBodyNotes: (v) => isStrings(v, 5) && v.every((s) => !/[{}]/.test(s)),
  };
  return input.map((rule, i) => {
    if (typeof rule !== "object" || rule === null || Array.isArray(rule)) throw new Error(`rules.json[${i}]: not an object`);
    for (const required of ["matchDatasources", "matchPackageNames"]) {
      if (!(required in rule)) throw new Error(`rules.json[${i}]: ${required} is required`);
    }
    if (!("matchNewValue" in rule) && !/newDigest/.test(String((rule as PackageRule).matchJsonata))) {
      throw new Error(`rules.json[${i}]: must match an exact new version`);
    }
    // Labels and notes describe an image; only a schedule release may be repository-specific.
    if ("matchRepositories" in rule && ("addLabels" in rule || "prBodyNotes" in rule)) {
      throw new Error(`rules.json[${i}]: a repository-scoped rule can only release a schedule`);
    }
    const out: PackageRule = {};
    for (const [key, value] of Object.entries(rule)) {
      if (!checks[key]?.(value)) throw new Error(`rules.json[${i}]: ${key} is not allowed or has an unexpected value`);
      out[key] = value;
    }
    return out;
  });
}

const validRepo = (r: unknown): r is string => typeof r === "string" && REPOSITORY_RE.test(r) && !r.split("/").some((s) => s === ".." || s === ".");

function entries(root: string): string[] {
  const dir = join(root, "repos");
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { recursive: true, encoding: "utf8" })
    .filter((f) => f.endsWith("/rules.json"))
    .map((f) => f.slice(0, -"/rules.json".length))
    .sort();
}

/** Bring the validated content of a delta into the data tree. Returns the SBOM files written. */
export function applyDelta(delta: string, root: string, now = Date.now()): { repositories: number; sboms: string[] } {
  const run = JSON.parse(readRegular(join(delta, "run.json"), 16 << 20).toString("utf8")) as RunManifest;
  if (!Array.isArray(run.repositories)) throw new Error("run.json: repositories must be an array");
  const listed = new Set<string>();
  for (const r of run.repositories) {
    if (!validRepo(r.repository)) throw new Error(`unsupported repository name: ${String(r.repository)}`);
    listed.add(r.repository);
  }
  // A repository that left the scan list takes its rules and report with it.
  for (const repo of entries(root)) if (!listed.has(repo)) rmSync(join(root, "repos", repo), { recursive: true, force: true });

  let written = 0;
  for (const { repository, ok } of run.repositories) {
    // A repository whose lookup failed keeps what the previous run published.
    if (!ok) continue;
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
    rmSync(dst, { recursive: true, force: true });
    mkdirSync(dst, { recursive: true });
    writeFileSync(join(dst, "rules.json"), `${JSON.stringify({ packageRules: rules }, null, 2)}\n`);
    writeFileSync(join(dst, "state.json"), `${JSON.stringify(state, null, 2)}\n`);
    writeFileSync(join(dst, "report.md"), report);
    // The summary becomes part of a Handlebars template in the preset.
    if (existsSync(join(src, "summary.md"))) {
      const summary = readRegular(join(src, "summary.md"), 20_000).toString("utf8");
      if (/[{}]/.test(summary)) throw new Error(`${repository}/summary.md: braces are not allowed`);
      writeFileSync(join(dst, "summary.md"), summary);
    }
    written++;
  }

  const indexFile = join(root, SBOM_INDEX);
  const index: SbomIndex = existsSync(indexFile) ? JSON.parse(readFileSync(indexFile, "utf8")) : {};
  const added: string[] = [];
  for (const [key, meta] of Object.entries(run.sboms ?? {})) {
    if (!SBOM_KEY_RE.test(key)) throw new Error(`run.json: unexpected SBOM key ${key}`);
    const trivyVersion = String(meta?.trivyVersion ?? "");
    if (!VERSION_RE.test(trivyVersion)) throw new Error(`run.json: bad trivyVersion for ${key}`);
    const gz = readRegular(join(delta, sbomPath(key)), 64 << 20);
    // The archive is shared: an SBOM only enters it under the digest it names.
    if (!describesDigest(gunzipSync(gz, { maxOutputLength: 1 << 30 }).toString("utf8"), key)) {
      throw new Error(`${sbomPath(key)}: does not describe the image its name says`);
    }
    const file = join(root, sbomPath(key));
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, gz);
    // Dated here: a delta does not decide how long its SBOM lives.
    index[key] = { ref: String(meta.ref ?? "").slice(0, 1000), trivyVersion, createdAt: new Date(now).toISOString() };
    added.push(sbomPath(key));
  }
  writeIndex(indexFile, index);
  return { repositories: written, sboms: added };
}

function writeIndex(file: string, index: SbomIndex): void {
  const sorted = Object.fromEntries(Object.entries(index).sort(([a], [b]) => a.localeCompare(b)));
  writeFileSync(file, `${JSON.stringify(sorted, null, 1)}\n`);
}

/** Rebuild everything derived from the per-repository entries. Returns the SBOM files no repository uses any more. */
export function assemble(root: string, o: AssembleOptions = {}): { repos: string[]; pruned: string[] } {
  const repos = entries(root);
  const fragments = new Map<string, PackageRule[]>();
  const summaries = new Map<string, string>();
  const used = new Set<string>();
  for (const repo of repos) {
    const dir = join(root, "repos", repo);
    fragments.set(repo, JSON.parse(readFileSync(join(dir, "rules.json"), "utf8")).packageRules ?? []);
    if (existsSync(join(dir, "summary.md"))) summaries.set(repo, readFileSync(join(dir, "summary.md"), "utf8"));
    for (const k of Object.values(JSON.parse(readFileSync(join(dir, "state.json"), "utf8")).sboms ?? {})) used.add(String(k));
  }
  rmSync(join(root, "shards"), { recursive: true, force: true });
  for (const [file, content] of Object.entries(buildPreset(fragments, summaries, o))) {
    mkdirSync(dirname(join(root, file)), { recursive: true });
    writeFileSync(join(root, file), `${JSON.stringify(content, null, 2)}\n`);
  }

  // An SBOM no repository references any more is of an image nobody runs.
  const indexFile = join(root, SBOM_INDEX);
  const index: SbomIndex = existsSync(indexFile) ? JSON.parse(readFileSync(indexFile, "utf8")) : {};
  const pruned: string[] = [];
  for (const key of Object.keys(index)) {
    if (used.has(key)) continue;
    delete index[key];
    pruned.push(sbomPath(key));
    rmSync(join(root, sbomPath(key)), { force: true });
  }
  writeIndex(indexFile, index);

  writeFileSync(
    join(root, "README.md"),
    [
      "# renovate-trivy data",
      "",
      "Generated by [renovate-trivy](https://github.com/aslafy-z/renovate-trivy). This branch is a single commit,",
      "force-pushed on every run: do not edit it, and do not delete it while a Renovate config extends the preset.",
      "",
      "- `renovate-trivy.json`: the Renovate preset (and `shards/` once it outgrows one file).",
      "- `repos/<repository>/report.md`: CVE report per repository.",
      `- \`sboms/\`, \`${SBOM_INDEX}\`: one CycloneDX SBOM per image digest, shared by every repository.`,
      "",
      `## Repositories (${repos.length})`,
      "",
      ...repos.map((n) => `- [${n}](repos/${n}/report.md)`),
      "",
    ].join("\n"),
  );
  return { repos, pruned };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function publish(o: PublishOptions): Promise<void> {
  const git = makeGit({ token: o.token });
  let lastError: unknown;
  for (let attempt = 1; attempt <= 5; attempt++) {
    const dir = mkdtempSync(join(tmpdir(), "renovate-trivy-data-"));
    try {
      // SBOM blobs stay on the server: only the small files are downloaded,
      // and the new commit reuses the archived ones by id.
      const exists = cloneData(git, o.remote, o.branch, dir);
      const base = exists ? git(dir, "rev-parse", "HEAD") : "";
      if (!exists) o.log(`branch ${o.branch} does not exist yet: creating it`);
      const { repositories, sboms } = applyDelta(o.delta, dir);
      const { repos, pruned } = assemble(dir, o);
      git(dir, "checkout", "-q", "--orphan", "publish");
      git(dir, "add", "-A", "--sparse", ".");
      for (let i = 0; i < pruned.length; i += 500) {
        git(dir, "rm", "-q", "--cached", "--sparse", "--ignore-unmatch", "--", ...pruned.slice(i, i + 500));
      }
      git(
        dir, "-c", "user.name=renovate-trivy", "-c", "user.email=renovate-trivy@users.noreply.github.com",
        "commit", "-q", "--allow-empty", "-m", `renovate-trivy: ${repos.length} repositories`,
      );
      // The lease makes a concurrent run's push fail instead of being overwritten.
      git(dir, "push", "-q", `--force-with-lease=${o.branch}:${base}`, "origin", `HEAD:refs/heads/${o.branch}`);
      o.log(`published: ${repositories} repositories updated (${repos.length} in the preset), ${sboms.length} new SBOMs, ${pruned.length} pruned`);
      return;
    } catch (err) {
      lastError = err;
      const stderr = (err as { stderr?: string }).stderr;
      // A validation error will not get better by retrying.
      if (stderr === undefined) throw err;
      o.log(`publish attempt ${attempt} failed: ${String(stderr).trim().split("\n").at(-1)}`);
      await sleep(attempt * (2000 + Math.random() * 8000));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
  throw lastError;
}

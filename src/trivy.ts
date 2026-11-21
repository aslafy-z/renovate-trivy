/** Thin wrapper around the trivy binary. */
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { promisify } from "node:util";
import { SEVERITIES, type ScanMeta, type Severity, type Vuln } from "./types.ts";

const exec = promisify(execFile);

export interface TrivyOptions {
  bin: string;
  platform: string;
  timeout: string;
}

async function trivy(opts: TrivyOptions, args: string[]): Promise<void> {
  // Trivy sends GITHUB_TOKEN to ghcr.io; a repository-scoped CI token is
  // refused for other owners' packages, while anonymous pulls of public
  // images work. Registry logins (docker config) are kept.
  const env = { ...process.env };
  delete env.GITHUB_TOKEN;
  delete env.GH_TOKEN;
  try {
    await exec(opts.bin, args, { env, maxBuffer: 64 * 1024 * 1024 });
  } catch (err) {
    const e = err as { stderr?: string; message: string };
    const lines = (e.stderr || e.message).split("\n").filter((l) => l.trim());
    throw new Error((lines.at(-1) ?? "trivy failed").replace(/^\S+\s+FATAL\s+/, "").slice(0, 500));
  }
}

export async function downloadDbs(opts: TrivyOptions): Promise<void> {
  await trivy(opts, ["image", "--download-db-only", "--quiet"]);
  await trivy(opts, ["image", "--download-java-db-only", "--quiet"]);
}

/** Pull the image once and write its package inventory as a CycloneDX SBOM. */
export async function imageToSbom(opts: TrivyOptions, ref: string, out: string): Promise<void> {
  await trivy(opts, [
    "image", "--quiet", "--format", "cyclonedx", "--output", out, "--cache-backend", "memory",
    "--skip-db-update", "--skip-java-db-update", "--skip-check-update",
    "--image-src", "remote", "--platform", opts.platform, "--timeout", opts.timeout, "--", ref,
  ]);
}

export interface SbomResult {
  os: string;
  eosl: boolean;
  vulns: Vuln[];
}

/** Match an archived SBOM against the local vulnerability DB: no image access. */
export async function scanSbom(opts: TrivyOptions, sbom: string, out: string): Promise<SbomResult> {
  await trivy(opts, [
    "sbom", "--quiet", "--scanners", "vuln", "--format", "json", "--output", out, "--cache-backend", "memory",
    "--skip-db-update", "--skip-java-db-update", "--", sbom,
  ]);
  return parseTrivyJson(JSON.parse(readFileSync(out, "utf8")));
}

export function parseTrivyJson(data: any): SbomResult {
  const os = data?.Metadata?.OS ?? {};
  const seen = new Map<string, Vuln>();
  for (const result of data?.Results ?? []) {
    for (const v of result.Vulnerabilities ?? []) {
      const key = `${v.VulnerabilityID}\0${v.PkgName}\0${v.InstalledVersion}`;
      if (seen.has(key)) continue;
      const severity = String(v.Severity ?? "UNKNOWN").toUpperCase();
      seen.set(key, {
        id: v.VulnerabilityID,
        pkg: v.PkgName,
        installed: v.InstalledVersion ?? "",
        fixed: v.FixedVersion ?? "",
        severity: (SEVERITIES as readonly string[]).includes(severity) ? (severity as Severity) : "UNKNOWN",
        title: String(v.Title ?? "").trim(),
        url: v.PrimaryURL ?? "",
      });
    }
  }
  return { os: [os.Family, os.Name].filter(Boolean).join(" "), eosl: Boolean(os.EOSL), vulns: [...seen.values()] };
}

export async function trivyVersion(opts: TrivyOptions): Promise<Pick<ScanMeta, "trivyVersion" | "dbUpdatedAt">> {
  const { stdout } = await exec(opts.bin, ["version", "--format", "json"]);
  const v = JSON.parse(stdout);
  return { trivyVersion: v.Version ?? "", dbUpdatedAt: v.VulnerabilityDB?.UpdatedAt ?? "" };
}

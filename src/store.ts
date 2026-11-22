/**
 * SBOM archive: one gzipped CycloneDX file per image digest and platform, so
 * an image is pulled once and then only re-matched against fresh advisories.
 *
 * An SBOM is bound to its image three ways: the key is the image digest, the
 * image is pulled by that digest (the registry client verifies the content),
 * and the digest Trivy records inside the SBOM is checked against the key
 * both when archiving and when reusing.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { gunzipSync, gzipSync } from "node:zlib";
import type { Git, GitBlob } from "./git.ts";

export interface SbomMeta {
  ref: string;
  trivyVersion: string;
  createdAt: string;
}
export type SbomIndex = Record<string, SbomMeta>;

export const SBOM_INDEX = "sbom-index.json";
export const SBOM_KEY_RE = /^sha256-[0-9a-f]{64}\.[a-z0-9]+-[a-z0-9]+(-[a-z0-9]+)?$/;

export function sbomKey(digest: string, platform: string): string {
  return `${digest.replace(":", "-")}.${platform.replaceAll("/", "-")}`;
}
/** Fan out over 256 directories so no git tree gets huge. */
export const sbomPath = (key: string) => `sboms/${key.slice(7, 9)}/${key}.cdx.json.gz`;
const digestOf = (key: string) => key.slice(0, 71).replace("-", ":");

const minor = (v: string) => v.split(".").slice(0, 2).join(".");

export function isFresh(meta: SbomMeta | undefined, trivyVersion: string, maxAgeDays: number, now = Date.now()): boolean {
  if (!meta) return false;
  // A newer Trivy may detect more packages in the same image; an old SBOM never learns about them.
  if (minor(meta.trivyVersion) !== minor(trivyVersion)) return false;
  const age = now - Date.parse(meta.createdAt);
  return age >= -86_400_000 && age <= maxAgeDays * 86_400_000;
}

/** True when the SBOM says it describes the image the key names. */
export function describesDigest(sbomJson: string, key: string): boolean {
  try {
    const component = JSON.parse(sbomJson)?.metadata?.component;
    const digest = digestOf(key);
    return (component?.properties ?? []).some(
      (p: { name?: string; value?: string }) => p.name === "aquasecurity:trivy:RepoDigest" && String(p.value).endsWith(`@${digest}`),
    );
  } catch {
    return false;
  }
}

export class SbomStore {
  private index: SbomIndex = {};
  private added: SbomIndex = {};
  private dataDir: string | undefined;
  private git: Git | undefined;
  private blob: GitBlob | undefined;
  private outDir: string;
  private maxAgeDays: number;

  /** `dataDir` is a blobless checkout of the data branch (read); new SBOMs go to `outDir`. */
  constructor(outDir: string, maxAgeDays: number, dataDir?: string, git?: Git, blob?: GitBlob) {
    this.blob = blob;
    this.outDir = outDir;
    this.maxAgeDays = maxAgeDays;
    this.dataDir = dataDir;
    this.git = git;
    if (dataDir && existsSync(join(dataDir, SBOM_INDEX))) this.index = JSON.parse(readFileSync(join(dataDir, SBOM_INDEX), "utf8"));
  }

  has(key: string, trivyVersion: string): boolean {
    return isFresh(this.added[key] ?? this.index[key], trivyVersion, this.maxAgeDays);
  }

  /** Download the archived SBOMs for these keys in one request instead of one each. */
  prefetch(keys: string[], trivyVersion: string): void {
    if (!this.dataDir || !this.git) return;
    const paths = keys.filter((k) => isFresh(this.index[k], trivyVersion, this.maxAgeDays)).map(sbomPath);
    if (!paths.length) return;
    const oids: string[] = [];
    for (let i = 0; i < paths.length; i += 500) {
      const out = this.git(this.dataDir, "ls-tree", "HEAD", "--", ...paths.slice(i, i + 500));
      for (const line of out.split("\n")) if (line) oids.push(line.split(/\s+/)[2]);
    }
    try {
      for (let i = 0; i < oids.length; i += 500) this.git(this.dataDir, "fetch", "-q", "--no-tags", "--no-write-fetch-head", "origin", ...oids.slice(i, i + 500));
    } catch {
      // Not every server accepts object ids; each blob is then fetched on first read.
    }
  }

  /** Write a fresh, verified SBOM to `dest` (uncompressed); false when it must be regenerated. */
  restore(key: string, trivyVersion: string, dest: string): boolean {
    if (!this.has(key, trivyVersion)) return false;
    try {
      const gz = this.added[key]
        ? readFileSync(join(this.outDir, sbomPath(key)))
        : this.blob!(this.dataDir!, `HEAD:${sbomPath(key)}`);
      const json = gunzipSync(gz).toString("utf8");
      if (!describesDigest(json, key)) return false;
      writeFileSync(dest, json);
      return true;
    } catch {
      return false;
    }
  }

  /** Archive an SBOM; refused when it does not describe the image the key names. */
  save(key: string, sbomFile: string, meta: SbomMeta): boolean {
    const json = readFileSync(sbomFile, "utf8");
    if (!describesDigest(json, key)) return false;
    const file = join(this.outDir, sbomPath(key));
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, gzipSync(json, { level: 9 }));
    this.added[key] = meta;
    return true;
  }

  /** Index entries of the SBOMs written to `outDir` this run. */
  additions(): SbomIndex {
    return this.added;
  }
}


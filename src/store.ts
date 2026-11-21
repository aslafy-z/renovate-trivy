/**
 * SBOM archive: one gzipped CycloneDX file per image digest and platform, so
 * an image is pulled once and then only re-matched against fresh advisories.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { gunzipSync, gzipSync } from "node:zlib";

export interface SbomMeta {
  ref: string;
  digest: string;
  platform: string;
  trivyVersion: string;
  createdAt: string;
}

export function sbomKey(digest: string, platform: string): string {
  return `${digest.replace(":", "-")}.${platform.replace("/", "-")}`;
}

const minor = (v: string) => v.split(".").slice(0, 2).join(".");

export class SbomStore {
  private dir: string | undefined;
  private outDir: string;
  private maxAgeDays: number;

  /** `dir` is read (the existing archive); new SBOMs are written to `outDir`. */
  constructor(dir: string | undefined, outDir: string, maxAgeDays: number) {
    this.dir = dir;
    this.outDir = outDir;
    this.maxAgeDays = maxAgeDays;
    mkdirSync(outDir, { recursive: true });
  }

  private paths(root: string, key: string) {
    return { sbom: join(root, `${key}.cdx.json.gz`), meta: join(root, `${key}.meta.json`) };
  }

  /** Write a fresh, usable SBOM to `dest` (uncompressed); false when it must be regenerated. */
  restore(key: string, trivyVersion: string, dest: string, now = Date.now()): boolean {
    for (const root of [this.outDir, this.dir]) {
      if (!root) continue;
      const p = this.paths(root, key);
      if (!existsSync(p.sbom) || !existsSync(p.meta)) continue;
      const meta = JSON.parse(readFileSync(p.meta, "utf8")) as SbomMeta;
      // A newer Trivy may detect more packages in the same image; an old
      // SBOM never learns about them.
      if (minor(meta.trivyVersion) !== minor(trivyVersion)) continue;
      if (now - Date.parse(meta.createdAt) > this.maxAgeDays * 86_400_000) continue;
      writeFileSync(dest, gunzipSync(readFileSync(p.sbom)));
      return true;
    }
    return false;
  }

  save(key: string, sbomFile: string, meta: SbomMeta): void {
    const p = this.paths(this.outDir, key);
    writeFileSync(p.sbom, gzipSync(readFileSync(sbomFile), { level: 9 }));
    writeFileSync(p.meta, `${JSON.stringify(meta, null, 2)}\n`);
  }
}

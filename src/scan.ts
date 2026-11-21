/** Scan every image reference once, through the SBOM archive. */
import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { makeRef, parseRef } from "./refs.ts";
import { DOCKER_HUB_MIRROR, resolveDigest } from "./registry.ts";
import { SbomStore, sbomKey } from "./store.ts";
import { imageToSbom, scanSbom, type TrivyOptions } from "./trivy.ts";
import type { Scan } from "./types.ts";

export interface ScanOptions {
  trivy: TrivyOptions;
  trivyVersion: string;
  store: SbomStore;
  workDir: string;
  concurrency: number;
  log: (msg: string) => void;
  /** Injected in tests. */
  resolve?: (ref: string) => Promise<string>;
}

const rateLimited = (msg: string) => /TOOMANYREQUESTS|429 Too Many Requests/i.test(msg);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function scanOne(ref: string, n: number, o: ScanOptions): Promise<Scan & { key?: string }> {
  const sbom = join(o.workDir, `${n}.cdx.json`);
  const result = join(o.workDir, `${n}.json`);
  try {
    let digest: string | undefined;
    try {
      digest = await (o.resolve ?? resolveDigest)(ref);
    } catch {
      // Unknown digest: scan the tag directly, without the archive.
    }
    const key = digest ? sbomKey(digest, o.trivy.platform) : undefined;
    let cached = false;
    if (key && o.store.restore(key, o.trivyVersion, sbom)) cached = true;
    else {
      const { registry, repository } = parseRef(ref);
      // Pull by digest so the SBOM is of exactly what the key names.
      const target = digest ? makeRef(`${registry}/${repository}`, null, digest) : ref;
      try {
        await imageToSbom(o.trivy, target, sbom);
      } catch (err) {
        if (!rateLimited((err as Error).message)) throw err;
        if (registry === "docker.io") {
          // Same content under the same digest, on a separate quota.
          await imageToSbom(o.trivy, makeRef(`${DOCKER_HUB_MIRROR}/${repository}`, digest ? null : parseRef(ref).tag, digest), sbom);
        } else {
          await sleep(60_000);
          await imageToSbom(o.trivy, target, sbom);
        }
      }
      if (key && digest) {
        o.store.save(key, sbom, {
          ref, digest, platform: o.trivy.platform, trivyVersion: o.trivyVersion, createdAt: new Date().toISOString(),
        });
      }
    }
    const res = await scanSbom(o.trivy, sbom, result);
    return { ok: true, digest, cached, key, ...res };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  } finally {
    rmSync(sbom, { force: true });
    rmSync(result, { force: true });
  }
}

export async function scanAll(refs: string[], o: ScanOptions): Promise<{ scans: Map<string, Scan>; keys: Set<string> }> {
  mkdirSync(o.workDir, { recursive: true });
  const scans = new Map<string, Scan>();
  const keys = new Set<string>();
  let next = 0;
  let done = 0;
  const worker = async () => {
    while (next < refs.length) {
      const n = next++;
      const ref = refs[n];
      const t0 = Date.now();
      const res = await scanOne(ref, n, o);
      if (res.key) keys.add(res.key);
      scans.set(ref, res);
      const status = res.ok ? (res.cached ? "archived SBOM" : "pulled") : `ERROR ${res.error}`;
      o.log(`[${++done}/${refs.length}] ${ref} (${Math.round((Date.now() - t0) / 1000)}s) ${status}`);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, o.concurrency) }, worker));
  return { scans, keys };
}

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
}

const rateLimited = (msg: string) => /TOOMANYREQUESTS|429 Too Many Requests/i.test(msg);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function pool<T>(items: T[], size: number, fn: (item: T, n: number) => Promise<void>): Promise<void> {
  let next = 0;
  await Promise.all(Array.from({ length: Math.max(1, Math.min(size, items.length)) }, async () => {
    while (next < items.length) {
      const n = next++;
      await fn(items[n], n);
    }
  }));
}

async function scanOne(ref: string, digest: string | undefined, n: number, o: ScanOptions): Promise<Scan> {
  const sbom = join(o.workDir, `${n}.cdx.json`);
  const result = join(o.workDir, `${n}.json`);
  try {
    const key = digest ? sbomKey(digest, o.trivy.platform) : undefined;
    let cached = false;
    if (key && o.store.restore(key, o.trivyVersion, sbom)) cached = true;
    else {
      const { registry, repository, tag } = parseRef(ref);
      // Pull by digest so the SBOM is of exactly what the key names.
      const target = digest ? makeRef(`${registry}/${repository}`, null, digest) : ref;
      try {
        await imageToSbom(o.trivy, target, sbom);
      } catch (err) {
        if (!rateLimited((err as Error).message)) throw err;
        if (registry === "docker.io") {
          // Same content under the same digest, on a separate quota.
          await imageToSbom(o.trivy, makeRef(`${DOCKER_HUB_MIRROR}/${repository}`, digest ? null : tag, digest), sbom);
        } else {
          await sleep(60_000);
          await imageToSbom(o.trivy, target, sbom);
        }
      }
      if (key && !o.store.save(key, sbom, { ref, trivyVersion: o.trivyVersion, createdAt: new Date().toISOString() })) {
        o.log(`${ref}: the SBOM does not name ${digest}, not archived`);
      }
    }
    const res = await scanSbom(o.trivy, sbom, result);
    return { ok: true, digest, cached, ...res };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  } finally {
    rmSync(sbom, { force: true });
    rmSync(result, { force: true });
  }
}

export interface ScanResult {
  scans: Map<string, Scan>;
  /** Archive key of every reference whose digest is known. */
  keys: Map<string, string>;
}

export async function scanAll(refs: string[], o: ScanOptions, resolve: (ref: string) => Promise<string> = resolveDigest): Promise<ScanResult> {
  mkdirSync(o.workDir, { recursive: true });
  // 1. tag -> digest for everything: HEAD requests only.
  const digests = new Map<string, string>();
  await pool(refs, 8, async (ref) => {
    try {
      digests.set(ref, await resolve(ref));
    } catch {
      // Unknown digest: the tag is scanned directly, without the archive.
    }
  });
  const keys = new Map([...digests].map(([ref, d]) => [ref, sbomKey(d, o.trivy.platform)]));
  // 2. one request for every archived SBOM this run needs.
  const wanted = [...new Set(keys.values())];
  o.store.prefetch(wanted, o.trivyVersion);
  o.log(`${refs.length} references, ${wanted.length} distinct digests, ${wanted.filter((k) => o.store.has(k, o.trivyVersion)).length} already archived`);
  // 3. scan; references sharing a digest are scanned once.
  const scans = new Map<string, Scan>();
  const byKey = new Map<string, Promise<Scan>>();
  let done = 0;
  await pool(refs, o.concurrency, async (ref, n) => {
    const t0 = Date.now();
    const key = keys.get(ref);
    let job = key ? byKey.get(key) : undefined;
    if (!job) {
      job = scanOne(ref, digests.get(ref), n, o);
      if (key) byKey.set(key, job);
    }
    const res = await job;
    scans.set(ref, res);
    const status = res.ok ? (res.cached ? "archived SBOM" : "pulled") : `ERROR ${res.error}`;
    o.log(`[${++done}/${refs.length}] ${ref} (${Math.round((Date.now() - t0) / 1000)}s) ${status}`);
  });
  return { scans, keys };
}

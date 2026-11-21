/**
 * Resolve an image reference to the digest its tag points at, with a HEAD
 * request on the registry: nothing is pulled, and Docker Hub does not count
 * HEAD requests against its pull rate limit.
 */
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { parseRef } from "./refs.ts";

const ACCEPT = [
  "application/vnd.oci.image.index.v1+json",
  "application/vnd.docker.distribution.manifest.list.v2+json",
  "application/vnd.oci.image.manifest.v1+json",
  "application/vnd.docker.distribution.manifest.v2+json",
].join(", ");

function basicAuth(registry: string): string | undefined {
  try {
    const dir = process.env.DOCKER_CONFIG ?? join(homedir(), ".docker");
    const auths = JSON.parse(readFileSync(join(dir, "config.json"), "utf8")).auths ?? {};
    const keys = registry === "docker.io" ? ["https://index.docker.io/v1/", "docker.io", "index.docker.io"] : [registry, `https://${registry}`];
    for (const key of keys) if (auths[key]?.auth) return `Basic ${auths[key].auth}`;
  } catch {
    // No docker config: anonymous.
  }
  return undefined;
}

async function bearer(challenge: string, registry: string): Promise<string | undefined> {
  const params = Object.fromEntries([...challenge.matchAll(/(\w+)="([^"]*)"/g)].map((m) => [m[1], m[2]]));
  if (!params.realm) return undefined;
  const url = new URL(params.realm);
  if (params.service) url.searchParams.set("service", params.service);
  if (params.scope) url.searchParams.set("scope", params.scope);
  const auth = basicAuth(registry);
  const res = await fetch(url, { headers: auth ? { authorization: auth } : {}, signal: AbortSignal.timeout(30_000) });
  if (!res.ok) return undefined;
  const body = (await res.json()) as { token?: string; access_token?: string };
  return body.token ?? body.access_token;
}

/** Google's pull-through cache of Docker Hub: same digests, separate quota. */
export const DOCKER_HUB_MIRROR = "mirror.gcr.io";

async function head(host: string, registry: string, repository: string, reference: string): Promise<string> {
  const url = `https://${host}/v2/${repository}/manifests/${reference}`;
  const request = (authorization?: string) =>
    fetch(url, {
      method: "HEAD",
      headers: { accept: ACCEPT, ...(authorization ? { authorization } : {}) },
      signal: AbortSignal.timeout(30_000),
    });
  let res = await request(basicAuth(registry));
  if (res.status === 401) {
    const challenge = res.headers.get("www-authenticate") ?? "";
    if (/^bearer/i.test(challenge)) {
      const token = await bearer(challenge, registry);
      if (token) res = await request(`Bearer ${token}`);
    }
  }
  if (!res.ok) throw Object.assign(new Error(`HEAD ${url}: HTTP ${res.status}`), { status: res.status });
  const found = res.headers.get("docker-content-digest");
  if (!found) throw new Error(`HEAD ${url}: no Docker-Content-Digest header`);
  return found;
}

/**
 * Digest the reference resolves to (the index digest for multi-arch images).
 * Docker Hub does not count HEAD requests against the pull quota, but refuses
 * them once the quota is spent; the mirror answers for cached images then.
 */
export async function resolveDigest(ref: string): Promise<string> {
  const { registry, repository, tag, digest } = parseRef(ref);
  if (digest) return digest;
  if (registry !== "docker.io") return head(registry, registry, repository, tag!);
  try {
    return await head("registry-1.docker.io", registry, repository, tag!);
  } catch (err) {
    if ((err as { status?: number }).status !== 429) throw err;
    return head(DOCKER_HUB_MIRROR, DOCKER_HUB_MIRROR, repository, tag!);
  }
}

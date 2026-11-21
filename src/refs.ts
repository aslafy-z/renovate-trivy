/** Helpers for OCI image references. */

export function makeRef(name: string, tag?: string | null, digest?: string | null): string {
  return name + (tag ? `:${tag}` : "") + (digest ? `@${digest}` : "");
}

export interface ParsedRef {
  registry: string;
  repository: string;
  tag?: string;
  digest?: string;
}

/** Split a reference the way container runtimes do (docker.io and library/ defaults). */
export function parseRef(ref: string): ParsedRef {
  let rest = ref;
  let digest: string | undefined;
  const at = rest.indexOf("@");
  if (at >= 0) {
    digest = rest.slice(at + 1);
    rest = rest.slice(0, at);
  }
  let tag: string | undefined;
  const lastSlash = rest.lastIndexOf("/");
  const colon = rest.lastIndexOf(":");
  if (colon > lastSlash) {
    tag = rest.slice(colon + 1);
    rest = rest.slice(0, colon);
  }
  const first = rest.split("/", 1)[0];
  let registry = "docker.io";
  let repository = rest;
  if (rest.includes("/") && (first.includes(".") || first.includes(":") || first === "localhost")) {
    registry = first;
    repository = rest.slice(first.length + 1);
  }
  if (registry === "index.docker.io" || registry === "registry-1.docker.io") registry = "docker.io";
  if (registry === "docker.io" && !repository.includes("/")) repository = `library/${repository}`;
  if (!tag && !digest) tag = "latest";
  return { registry, repository, tag, digest };
}

export function registryOf(name: string): string {
  return parseRef(name).registry;
}

/** Short display form of the version part of a ref. */
export function versionOf(ref: string): string {
  const { tag, digest } = parseRef(ref);
  const short = digest ? `@${digest.replace(/^sha256:/, "").slice(0, 12)}` : "";
  return `${tag ?? ""}${short}`;
}

export function shortRef(ref: string): string {
  const at = ref.indexOf("@");
  if (at < 0) return ref;
  return `${ref.slice(0, at)}@${ref.slice(at + 1).replace(/^sha256:/, "").slice(0, 12)}`;
}

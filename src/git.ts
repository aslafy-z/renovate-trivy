/** Minimal git plumbing shared by the archive reader and the publisher. */
import { execFileSync } from "node:child_process";

export interface GitAuth {
  /** Sent to an https remote as a basic-auth header; never put in a URL, argv or .git/config. */
  token?: string;
}

export function gitEnv(auth: GitAuth = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, GIT_TERMINAL_PROMPT: "0" };
  if (auth.token) {
    env.GIT_CONFIG_COUNT = "1";
    env.GIT_CONFIG_KEY_0 = "http.extraHeader";
    env.GIT_CONFIG_VALUE_0 = `Authorization: Basic ${Buffer.from(`x-access-token:${auth.token}`).toString("base64")}`;
  }
  return env;
}

export type Git = (cwd: string, ...args: string[]) => string;
export type GitBlob = (cwd: string, spec: string) => Buffer;

/** Read one object, fetching it from the promisor remote when it is not local yet. */
export function makeGitBlob(auth: GitAuth = {}): GitBlob {
  const env = gitEnv(auth);
  return (cwd, spec) => execFileSync("git", ["cat-file", "blob", spec], { cwd, env, stdio: ["ignore", "pipe", "pipe"], maxBuffer: 256 * 1024 * 1024 });
}

export function makeGit(auth: GitAuth = {}): Git {
  const env = gitEnv(auth);
  return (cwd, ...args) =>
    execFileSync("git", ["-c", "push.negotiate=false", "-c", "advice.detachedHead=false", ...args], {
      cwd, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 256 * 1024 * 1024,
    }).trim();
}

/**
 * Clone one branch of the data repository without its SBOM blobs: only the
 * small files are downloaded, SBOMs are fetched on demand. Returns false when
 * the branch does not exist yet.
 */
export function cloneData(git: Git, remote: string, branch: string, dir: string): boolean {
  git(dir, "init", "-q");
  git(dir, "remote", "add", "origin", remote);
  git(dir, "config", "remote.origin.promisor", "true");
  git(dir, "config", "remote.origin.partialclonefilter", "blob:none");
  try {
    git(dir, "fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", `+refs/heads/${branch}:refs/remotes/origin/${branch}`);
  } catch {
    return false;
  }
  git(dir, "sparse-checkout", "set", "--no-cone", "/*", "!/sboms/");
  git(dir, "checkout", "-q", "--detach", `origin/${branch}`);
  return true;
}

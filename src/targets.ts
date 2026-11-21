/** Renovate report -> images in use and the updates Renovate proposes for them. */
import { makeRef, registryOf } from "./refs.ts";
import type { Image, RepoTargets } from "./types.ts";

// Update types that do not change what runs.
const SKIP_UPDATE_TYPES = new Set(["pin", "pinDigest", "rollback", "lockfileUpdate", "lockFileMaintenance"]);
// skipReasons that still leave a concrete, pullable reference: a non-semver
// tag such as "latest" is still what runs.
const SCANNABLE_SKIP_REASONS = new Set([undefined, null, "invalid-value", "invalid-version", "disabled", "ignored"]);

interface RenovateDep {
  datasource?: string;
  depType?: string;
  depName?: string;
  packageName?: string;
  currentValue?: string;
  currentDigest?: string;
  skipReason?: string | null;
  updates?: {
    updateType?: string;
    newValue?: string;
    newDigest?: string;
    newName?: string;
    branchName?: string;
  }[];
}

interface RenovateReport {
  repositories?: Record<string, { packageFiles?: Record<string, { packageFile?: string; deps?: RenovateDep[] }[]> }>;
}

function depRef(dep: RenovateDep): { name: string; ref: string } | undefined {
  if (!SCANNABLE_SKIP_REASONS.has(dep.skipReason)) return undefined;
  const name = dep.packageName ?? dep.depName;
  if (!name || !(dep.currentValue || dep.currentDigest)) return undefined;
  // Unresolved templates and variables are not references.
  if (/[{}$\s]/.test(`${name}${dep.currentValue ?? ""}`)) return undefined;
  return { name, ref: makeRef(name, dep.currentValue, dep.currentDigest) };
}

export interface TargetOptions {
  /** Name to use for the single repository of a `--platform=local` report. */
  localRepository?: string;
  skipRegistries?: string[];
}

export function targetsFromReport(report: RenovateReport, opts: TargetOptions = {}): RepoTargets[] {
  const skip = new Set(opts.skipRegistries ?? []);
  const out: RepoTargets[] = [];
  for (const [key, repo] of Object.entries(report.repositories ?? {})) {
    const repository = key === "local" ? (opts.localRepository ?? "local") : key;
    const images = new Map<string, Image>();
    for (const files of Object.values(repo.packageFiles ?? {})) {
      for (const pf of files) {
        for (const dep of pf.deps ?? []) {
          // OCI Helm charts use the docker datasource too.
          if (dep.datasource !== "docker" || dep.depType === "HelmChart") continue;
          const cur = depRef(dep);
          if (!cur) continue;
          let image = images.get(cur.ref);
          if (!image) {
            image = {
              ref: cur.ref,
              name: cur.name,
              currentValue: dep.currentValue,
              currentDigest: dep.currentDigest,
              files: [],
              updates: [],
              ...(skip.has(registryOf(cur.name)) ? { skipped: true } : {}),
            };
            images.set(cur.ref, image);
          }
          if (pf.packageFile && !image.files.includes(pf.packageFile)) image.files.push(pf.packageFile);
          for (const upd of dep.updates ?? []) {
            if (upd.updateType && SKIP_UPDATE_TYPES.has(upd.updateType)) continue;
            // A "replacement" update also renames the image.
            const name = upd.newName ?? cur.name;
            const ref = makeRef(name, upd.newValue ?? dep.currentValue, upd.newDigest);
            if (ref === cur.ref || image.updates.some((u) => u.ref === ref && u.branchName === upd.branchName)) continue;
            image.updates.push({
              ref,
              name,
              newValue: upd.newValue,
              newDigest: upd.newDigest,
              updateType: upd.updateType,
              branchName: upd.branchName,
            });
          }
        }
      }
    }
    out.push({ repository, images: [...images.values()].sort((a, b) => a.ref.localeCompare(b.ref)) });
  }
  return out;
}

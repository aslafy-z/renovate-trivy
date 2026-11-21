export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] as const;
export type Severity = (typeof SEVERITIES)[number];
export const GATE: readonly Severity[] = ["CRITICAL", "HIGH"];

/** An update Renovate proposes for an image. */
export interface Update {
  ref: string;
  name: string;
  newValue?: string;
  newDigest?: string;
  updateType?: string;
  branchName?: string;
}

/** An image reference in use in a repository, with Renovate's proposed updates. */
export interface Image {
  ref: string;
  name: string;
  currentValue?: string;
  currentDigest?: string;
  files: string[];
  updates: Update[];
  skipped?: boolean;
}

/** Any update Renovate proposes, whatever its datasource: used to release whole branches. */
export interface BranchUpdate {
  datasource: string;
  name: string;
  currentValue?: string;
  newValue?: string;
  newDigest?: string;
  branchName: string;
}

export interface RepoTargets {
  repository: string;
  images: Image[];
  branchUpdates: BranchUpdate[];
}

/** One finding, as Trivy reports it (one per package). */
export interface Vuln {
  id: string;
  pkg: string;
  installed: string;
  fixed: string;
  severity: Severity;
  title: string;
  url: string;
}

/** One CVE, collapsed over the packages it affects. */
export interface Cve extends Vuln {
  pkgs: string[];
}

export interface ScanOk {
  ok: true;
  digest?: string;
  os: string;
  eosl: boolean;
  cached: boolean;
  vulns: Vuln[];
}
export interface ScanError {
  ok: false;
  error: string;
}
export type Scan = ScanOk | ScanError;

export interface Diff {
  fixed: Cve[];
  introduced: Cve[];
  fixedGate: number;
  introducedGate: number;
}

export interface AnalysedUpdate extends Update {
  from: string;
  fromName: string;
  currentValue?: string;
  fromCounts: Record<Severity, number>;
  toCounts: Record<Severity, number>;
  diff: Diff;
}

export interface AnalysedImage extends Image {
  scan: ScanOk;
  counts: Record<Severity, number>;
  fixableGate: number;
}

export interface Analysis {
  repository: string;
  images: AnalysedImage[];
  updates: AnalysedUpdate[];
  errors: { ref: string; error: string }[];
  skipped: string[];
  branchUpdates: BranchUpdate[];
}

export interface ScanMeta {
  scannedAt: string;
  platform: string;
  trivyVersion: string;
  dbUpdatedAt: string;
}

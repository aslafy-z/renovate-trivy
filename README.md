# renovate-trivy

A [Trivy](https://trivy.dev) companion for [Renovate](https://docs.renovatebot.com):
it finds the CVEs inside the container images your repositories deploy and
hands the result to Renovate, which then opens, labels and annotates the pull
requests that fix them.

One central job serves any number of repositories. A repository takes part by
extending one preset, the same line for all of them, so it can sit in an
organisation preset and no repository needs a change of its own.

> **Status: early.** Tested on GitHub with the hosted Renovate app. The CLI
> only needs `git`, so other hosts should work, but they are not exercised yet.

## Why

Renovate already reports vulnerabilities for *language* dependencies, through
[OSV](https://docs.renovatebot.com/configuration-options/#osvvulnerabilityalerts)
and GitHub's Dependabot alerts. It cannot do the same for container images: an
image tag says nothing about the OS packages and binaries inside, and Renovate
never pulls images. Trivy does, but knows nothing about Renovate.

| | Renovate alone | with renovate-trivy |
|---|---|---|
| `nginx:1.27` has 3 critical CVEs | not known | in the Dependency Dashboard and a report |
| `1.27` → `1.28` fixes them | a routine update, waits for the schedule | released from the schedule, labelled `security`, CVE diff in the PR body |
| `1.27` → `1.28` adds new ones | not known | warning in the PR body |

## How it works

```
 repositories            data repository                              Renovate
┌────────────┐  clone   ┌──────────────────────────────────────┐     ┌──────────┐
│ acme/infra │ ◄─────── │ main:  the workflow                  │     │          │
│ acme/apps  │          │   lookup → scan → publish            │     │ next run │
│ …          │          │ data:  renovate-trivy.json  ◄─────── extends ───────── │
└────────────┘          │        repos/<repo>/report.md        │     └────┬─────┘
       ▲                │        sboms/<digest>                │          │
       │                └──────────────────────────────────────┘          │
       └────── PRs released from schedule, labelled, annotated ◄──────────┘
```

1. **Lookup.** Each repository is cloned and Renovate runs on the clone,
   read-only (`--platform=local --dry-run=lookup`), with the repository's own
   config. Its report lists every image it tracks and every update it would
   propose. Whatever a Renovate manager detects gets scanned: manifests, Helm
   values, custom regex managers, Dockerfiles.
2. **Scan.** Every distinct image, across all repositories, is resolved to its
   digest with a registry `HEAD` request. A new digest is pulled once and its
   package inventory archived as a CycloneDX SBOM; a known one is only
   re-matched against today's vulnerability database (`trivy sbom`), in
   seconds, without pulling anything. A CVE published tomorrow for an image
   scanned last month is still found.
3. **Publish.** The `data` branch receives the preset, a report per
   repository and the SBOM archive, as a single commit replaced on every run.

The preset is the only thing Renovate sees. renovate-trivy never calls a
platform API and never touches an issue or a pull request, which is why it
works wherever Renovate does and cannot conflict with it.

### The preset

A rule describes an image update, not a repository: what `prowlarr 2.7.0 →
3.0.2` fixes is the same for everybody.

```json
{
  "matchDatasources": ["docker"],
  "matchPackageNames": ["lscr.io/linuxserver/prowlarr"],
  "matchCurrentValue": "/^2\\.7\\.0$/",
  "matchNewValue": "/^3\\.0\\.2$/",
  "schedule": ["at any time"],
  "prPriority": 10,
  "addLabels": ["security"],
  "prBodyNotes": ["🛡️ **Trivy**: … fixes **2 critical** and **21 high** CVEs (…). 0 critical / 1 high remain · [full report](…/repos/{{{repository}}}/report.md)"]
}
```

So the preset grows with the number of distinct image updates, not with the
number of repositories, and Renovate fills in the repository in the report
link. Two things are per repository and kept small:

- Renovate schedules a branch as a whole, so the other updates of a fixing
  update's *group* branch are released with it. Those rules name the
  repositories whose grouping puts them together.
- The Dependency Dashboard summary: one block per repository in the dashboard
  footer, each rendered only for its repository, within a size budget. Past
  the budget, the largest summaries become a link to the report.

Once the rules outgrow one file they move to `shards/` files that the preset
extends itself; the line repositories extend never changes.

### The SBOM archive

One SBOM per image digest and platform, shared by every repository. An SBOM
is tied to its image three ways: its name is the image digest, the image is
pulled *by that digest* (so the registry client verifies the content), and the
digest Trivy records inside the SBOM is checked against the name both when it
is archived and each time it is reused. It is regenerated when Trivy's minor
version changes or after 30 days.

Only the central workflow writes the archive. Jobs fetch just the SBOMs they
need (a blobless clone), so its size does not slow runs down.

## Set up (GitHub)

1. Create a **public** repository, e.g. `acme/renovate-trivy-data`. (It will
   hold package inventories and CVE lists of your images; a private one works
   only if your Renovate can read it.)
2. Add [`examples/github-workflow.yml`](examples/github-workflow.yml) as
   `.github/workflows/renovate-trivy.yml` and list your repositories in it.
   Public repositories need no secret at all: the workflow publishes to its
   own repository with the built-in token. For private ones, add a read-only
   token as the secret `RENOVATE_TRIVY_READ_TOKEN`.
3. Run it once, and check that the `data` branch now has `renovate-trivy.json`.
4. Only then make Renovate extend it:

   ```json
   { "extends": ["github>acme/renovate-trivy-data:renovate-trivy#data"] }
   ```

   Put that line wherever suits you, it is the same for every repository:
   - in each repository's Renovate config;
   - in a shared preset your repositories already extend;
   - in `org-inherited-config.json` of your `renovate-config` repository, where
     [inherited config](https://docs.renovatebot.com/config-overview/#inherited-config)
     is enabled;
   - in `globalExtends` of a self-hosted Renovate.

   The order matters: Renovate stops with a config error on a repository that
   extends a preset it cannot find. Never delete the `data` branch while
   something still extends it.

A working example: [renovate-trivy-data](https://github.com/aslafy-z/renovate-trivy-data)
scans [renovate-trivy-demo](https://github.com/aslafy-z/renovate-trivy-demo).

## Other platforms

The action wraps a CLI that needs Node.js ≥ 24, `git`, and `trivy` for the
scan step:

```sh
node src/cli.ts lookup  --git-base https://gitlab.example.com --repositories "acme/infra acme/apps"
node src/cli.ts scan    --data-remote https://gitlab.example.com/acme/renovate-trivy-data.git \
                        --web-url https://gitlab.example.com/acme/renovate-trivy-data/-/blob/data
node src/cli.ts publish --remote https://gitlab.example.com/acme/renovate-trivy-data.git \
                        --web-url https://gitlab.example.com/acme/renovate-trivy-data/-/blob/data
```

`RENOVATE_TRIVY_READ_TOKEN` (clone) and `RENOVATE_TRIVY_DATA_TOKEN` (data
branch) are sent to git as an HTTP header. Then extend
`gitlab>acme/renovate-trivy-data:renovate-trivy#data`.
`node src/cli.ts --help` lists every option.

## What you get

- **In Renovate PRs** that fix critical/high CVEs: released from the schedule
  (with the rest of their group branch), the `security` label, a raised
  `prPriority`, and a note in the body with the CVE diff. Only the schedule
  is lifted: `minimumReleaseAge`, PR limits and Dependency Dashboard approval
  still apply. Updates that *introduce* critical/high CVEs get a warning note
  and nothing else.
- **In the Dependency Dashboard**: a short section at the bottom of the issue,
  below Renovate's own content: the totals, the pending updates that fix
  CVEs (each linked to its pull request) and the exposed images nothing
  fixes yet. Renovate writes it itself. `dashboard-report: false` keeps it out.
- **On the data branch**: `repos/<repo>/report.md`, with every image ranked by
  critical/high count, its best available update, the CVE list, and anything
  that could not be scanned.

## Limits

- Only images Renovate detects are scanned. Images a Helm chart sets by
  default, without an override Renovate can see, are invisible to both.
- The lookup sees each repository's own config and the presets it extends.
  Settings that only exist in a hosted app's or a self-hosted bot's global or
  inherited config are not applied; if they change grouping, a group branch
  may not be released as a whole.
- A rule is keyed by image name and versions. Two repositories using the same
  name for different images (a registry alias) would share it.
- Repositories are listed explicitly; there is no autodiscovery yet.
- "Fixes N CVEs" compares two scans by CVE ID, for one platform
  (`linux/amd64` by default).
- Renovate reads the preset when it runs: changes show up on its next pass.
- If a repository's lookup or an image's scan fails, the previous run's
  result for it is kept rather than dropped.
- Docker Hub rate-limits anonymous pulls per IP and refuses even `HEAD`
  requests once that is spent; renovate-trivy then falls back to
  `mirror.gcr.io`. Log in to Docker Hub in the scan job for reliable runs.
- One job scans everything, so the first run of a large estate is long.
  Later runs only pull new digests.

## Security

- Three jobs, least privilege each: `lookup` runs Renovate with read access
  to the repositories; `scan` runs Trivy with read access to the data branch
  only; `publish` runs only `git` and this tool and is the only one that can
  write, to the data repository only.
- `publish` treats what the other jobs hand it as untrusted. It reads known
  files only, re-serialises them, accepts only the rule shape shown above (no
  other Renovate option, no template), and refuses an SBOM that does not name
  the digest it is filed under.
- A preset is configuration Renovate trusts. Anyone who can push to the data
  repository can change how Renovate behaves on every repository extending
  it: protect it like your Renovate config.
- Trivy is installed with [mise](https://mise.jdx.dev) from the aqua
  registry, which verifies release checksums and their cosign signature.
  Trivy's release channel was compromised in March 2026
  ([CVE-2026-33634](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)),
  so this repository holds Trivy and Renovate updates for a week.
- Pin the action to a commit SHA in production.

## Development

```sh
npm ci
npm test          # node:test, no build step: Node runs the TypeScript directly
npm run typecheck
```

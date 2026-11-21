# renovate-trivy

A [Trivy](https://trivy.dev) companion for [Renovate](https://docs.renovatebot.com):
it finds the CVEs inside the container images your repositories deploy and
hands the result to Renovate, which then opens, labels and annotates the pull
requests that fix them.

> **Status: early.** Tested on GitHub with the hosted Renovate app. The CLI is
> platform-neutral, but the GitLab and self-hosted paths below are documented,
> not yet exercised.

## Why

Renovate already reports vulnerabilities for *language* dependencies, through
[OSV](https://docs.renovatebot.com/configuration-options/#osvvulnerabilityalerts)
and GitHub's Dependabot alerts. It cannot do the same for container images: an
image tag says nothing about the OS packages and binaries inside, and Renovate
never pulls images. Trivy does, but knows nothing about Renovate.

renovate-trivy joins the two:

| | Renovate alone | with renovate-trivy |
|---|---|---|
| `nginx:1.27` has 3 critical CVEs | not known | reported per repository |
| `1.27` → `1.28` fixes them | a routine update, waits for the schedule | PR opened now, labelled `security`, CVE diff in the PR body |
| `1.27` → `1.28` adds new ones | not known | warning in the PR body |

## How it works

```
 your repository                       data repository                  Renovate
┌──────────────────┐   scan (CI job)   ┌────────────────────┐  extends  ┌──────────┐
│ manifests, Helm  │ ───────────────►  │ renovate-trivy.json│ ◄──────── │ next run │
│ values, …        │  1. Renovate      │ repos/<repo>/…     │           └────┬─────┘
│ renovate.json    │     lookup        │ sboms/<digest>…    │                │
└──────────────────┘  2. Trivy         └────────────────────┘                ▼
         ▲                                                          PRs: released from
         └──────────────────────────────────────────────────────── schedule, labelled,
                                                                    CVE note in the body
```

1. **Lookup.** Renovate runs read-only on the checkout (`--platform=local
   --dry-run=lookup`) with the repository's own config. Its report lists every
   image it tracks and every update it would propose. Whatever Renovate
   detects, in any manager or custom regex, gets scanned; nothing else needs
   configuring.
2. **Scan.** Each current and proposed image is resolved to its digest with a
   registry `HEAD` request. A new digest is pulled once and its package
   inventory archived as a CycloneDX SBOM; a known digest is only re-matched
   against today's vulnerability database (`trivy sbom`), in seconds and
   without pulling anything. A CVE published tomorrow for an image scanned
   last month is still found.
3. **Publish.** The data repository receives a generated Renovate preset, a
   Markdown report per repository and the SBOM archive, as a single commit
   that is replaced on every run.

The preset is the only thing Renovate sees. For each proposed update that
removes critical or high CVEs it holds one rule, matching the repository, the
package and the exact versions:

```json
{
  "matchRepositories": ["acme/infra"],
  "matchDatasources": ["docker"],
  "matchPackageNames": ["lscr.io/linuxserver/prowlarr"],
  "matchCurrentValue": "/^2\\.7\\.0$/",
  "matchNewValue": "/^3\\.0\\.2$/",
  "schedule": ["at any time"],
  "addLabels": ["security"],
  "prPriority": 10,
  "prBodyNotes": ["🛡️ **Trivy**: … fixes **2 critical** and **21 high** CVEs (…). 0 critical / 1 high remain · [full report](…)"]
}
```

Renovate does the rest on its next run. renovate-trivy never calls a platform
API and never touches an issue or a pull request, which is why it works
wherever Renovate does and cannot conflict with it.

## Quick start (GitHub)

You need a **public data repository** and a token that can push to it. (It
holds package inventories and CVE lists of your images. A private one is not
supported yet: the scan job and Renovate both read it anonymously.)

1. Create an empty repository, e.g. `acme/renovate-trivy-data`.
2. Create a fine-grained personal access token with **Contents: read and
   write** on that repository only, and save it as the secret
   `RENOVATE_TRIVY_DATA_TOKEN` in the repository you want scanned.
3. Add the workflow:

   ```yaml
   name: renovate-trivy
   on:
     schedule:
       - cron: "17 3 * * *"
     workflow_dispatch:
     push:
       branches: [main]
   permissions: {}
   jobs:
     scan:                       # Renovate + Trivy, read-only
       runs-on: ubuntu-latest
       permissions:
         contents: read
       steps:
         - uses: actions/checkout@v7
           with:
             persist-credentials: false
         - uses: aslafy-z/renovate-trivy@main
           with:
             step: scan
             data-repository: acme/renovate-trivy-data
         - uses: actions/upload-artifact@v7
           with:
             name: delta
             path: ${{ runner.temp }}/renovate-trivy-delta
             include-hidden-files: true
     publish:                    # git only; holds the write token
       needs: scan
       runs-on: ubuntu-latest
       permissions: {}
       steps:
         - uses: actions/download-artifact@v8
           with:
             name: delta
             path: ${{ runner.temp }}/renovate-trivy-delta
         - uses: aslafy-z/renovate-trivy@main
           with:
             step: publish
             data-repository: acme/renovate-trivy-data
             data-token: ${{ secrets.RENOVATE_TRIVY_DATA_TOKEN }}
   ```

4. Run it once, and check that `renovate-trivy.json` now exists in the data
   repository.
5. **Only then** extend the preset in your Renovate config:

   ```json
   { "extends": ["config:recommended", "github>acme/renovate-trivy-data:renovate-trivy"] }
   ```

   The order matters: Renovate stops with a config error on a repository that
   extends a preset it cannot find. For the same reason, never delete the data
   repository or its branch while a config still extends it.

A working example lives in
[renovate-trivy-demo](https://github.com/aslafy-z/renovate-trivy-demo).

## Several repositories

Point every repository's workflow at the **same** data repository. Each run
replaces only its own `repos/<owner>/<name>/` entry; the preset is rebuilt from
all of them and every rule is scoped with `matchRepositories`, so one `extends`
line (in an organisation preset, or in a self-hosted bot's global config)
serves them all. An image used by ten repositories is pulled once.

Concurrent runs are safe: the push uses a lease and retries, with backoff, on
top of whatever landed first. Spread the cron minutes anyway.

Repositories sharing a data repository share its SBOM archive. Publish only
lets a run write its own repository's entry, and never replaces an archived
SBOM that is still fresh, but the first run to see a digest is the one that
describes it to the others: share a data repository between repositories that
trust each other's CI.

## Other platforms

The action is a thin wrapper around a CLI that needs Node.js ≥ 24, `git` and
`trivy` on the PATH:

```sh
git clone --depth 1 https://gitlab.example.com/acme/renovate-trivy-data.git data || true
node src/cli.ts scan --repository "$CI_PROJECT_PATH" --data-dir data \
  --web-url https://gitlab.example.com/acme/renovate-trivy-data/-/blob/main
RENOVATE_TRIVY_DATA_TOKEN=… node src/cli.ts publish --repository "$CI_PROJECT_PATH" \
  --remote https://gitlab.example.com/acme/renovate-trivy-data.git \
  --web-url https://gitlab.example.com/acme/renovate-trivy-data/-/blob/main
```

Then extend `gitlab>acme/renovate-trivy-data:renovate-trivy` (or
`local>acme/renovate-trivy-data:renovate-trivy` on a self-hosted Renovate; the
scan's own lookup cannot resolve `local>`, so prefer the explicit form).
`node src/cli.ts --help` lists every option.

## What you get

- **In Renovate PRs** that fix critical/high CVEs: released from the schedule
  (with the rest of their group branch, since Renovate schedules a branch as
  a whole), the `security` label, a raised `prPriority`, and a note in the
  body with the CVE diff. Only the schedule is lifted: `minimumReleaseAge`,
  PR limits and Dependency Dashboard approval still apply. Updates that *introduce* critical/high
  CVEs get a warning note and nothing else.
- **In the Dependency Dashboard**: a link to the repository's report.
- **In the data repository**: `repos/<repo>/report.md`, with every image
  ranked by critical/high count, its best available update, the CVE list, and
  anything that could not be scanned.

## Limits

- Only images Renovate detects are scanned. Images a Helm chart sets by
  default, without an override Renovate can see, are invisible to both.
- "Fixes N CVEs" compares two scans by CVE ID. A note describes the exact
  versions compared and is refreshed on the next run; between runs it can be
  one release behind for digest-only updates.
- Updates your config disables may appear in the report. Their rule never
  enables them.
- Renovate reads the preset when it runs: after a scan, changes show up on
  Renovate's next pass, not immediately.
- One platform per image (`linux/amd64` by default).
- Docker Hub rate-limits anonymous pulls per IP and refuses even
  `HEAD` requests once that is spent; renovate-trivy then falls back to
  `mirror.gcr.io`. Log in to Docker Hub in the scan job for reliable runs.

## Security

- The scan job runs Renovate and Trivy with a read-only token; the publish
  job runs only `git` and this tool, and is the only one holding the data
  token. That token can write one repository that contains generated data.
- Publish treats the scan's output as untrusted. It reads only its own
  repository's entry and SBOM files, re-serialises them, and accepts only the
  rule shape shown above: rules scoped to that repository, with no key beyond
  the match fields, `schedule`, `addLabels`, `prPriority` and `prBodyNotes`.
  A compromised scan cannot add `automerge` or a registry, or touch another
  repository's rules. Keep the two steps in separate jobs (`step: all` exists
  for trusted, single-purpose setups).
- If an image cannot be scanned in one run, its previous rule is kept rather
  than dropped.
- A preset is configuration Renovate trusts. Anyone who can push to the data
  repository can change how Renovate behaves on every repository extending
  it, so protect it like your Renovate config.
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

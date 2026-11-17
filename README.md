# malguard

A CI gate that stops malware before it merges or deploys.

malguard scans a repository for the tricks used by malware aimed at
developers, and checks every dependency against the
[OSV](https://osv.dev) list of known-malicious packages. If it finds
anything, the job fails. Every project calls the same shared workflow by a
version tag, so a rule added here protects all of them at once.

It was written after the PolinRider incident, where a VS Code task that ran
on folder open executed a "font" file that was really JavaScript.

## What it catches

| Kind | Examples | Severity |
|---|---|---|
| Known loader signatures | PolinRider, EtherHiding, BeaverTail, Shai-Hulud and GlassWorm markers; workflows that dump every secret; exfiltration webhooks; wallet and browser-credential stealers | HIGH |
| Disguised payloads | Fonts, images and media that are really JavaScript; Node code inside `.svg`, `.md` or `.txt` | HIGH |
| Auto-run traps | VS Code tasks that run on folder open; repos that turn automatic tasks on | HIGH / MEDIUM |
| Worm artifacts | Auto-push batch files; a `.gitignore` that hides itself | HIGH |
| Hidden code | Long runs of invisible Unicode; code pushed far right behind whitespace; `exec` of decoded Python | HIGH |
| Obfuscation | JavaScript obfuscator patterns (HIGH in build config files) | MEDIUM |
| Risky install scripts | `preinstall`/`postinstall`/`prepare` scripts that download or run code | HIGH |
| Malicious dependencies | Any npm or PyPI package in a lockfile or manifest that OSV lists as malicious (`MAL-*`), plus known hijacked releases | HIGH |

Dependencies are read from `package-lock.json`, `npm-shrinkwrap.json`,
`yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `package.json`,
`requirements*.txt`, `constraints.txt`, `poetry.lock`, `uv.lock`, `pdm.lock`
and `Pipfile.lock`.

- **A pinned version is checked exactly.** A malicious-package advisory for
  that release fails the build.
- **A dependency with no version fails only if every release is
  malicious.** That covers ranges in `package.json` and unpinned
  requirements. Which version you actually install is the lockfile's
  answer, and the lockfile is checked too.

**Any HIGH or MEDIUM finding fails the job.**

**If the scan can't finish, the job fails too.** That covers an unreachable
OSV service and an unreadable exceptions file. A scan that didn't happen is
never treated as clean.

## Use it in a project

### 1. Add the workflow

Copy [`examples/malguard.yml`](examples/malguard.yml) to
`.github/workflows/malguard.yml`:

```yaml
name: malguard
on:
  pull_request:
  push:
    branches: ["**"]
  schedule:
    - cron: "17 5 * * *"
  workflow_dispatch:
permissions:
  contents: read
jobs:
  malguard:
    uses: Marvellous-is-cool/malguard/.github/workflows/scan.yml@v1
```

It runs on:

- **Every pull request.** It catches malware before merge.
- **Every push to any branch.** It catches what was merged or pushed
  directly.
- **Once a day.** It catches a dependency that was declared malicious after
  it was merged.

### 2. Gate your deploys

A deploy must never run on a tree malguard hasn't passed. In every workflow
that deploys, add the same job and make the deploy jobs depend on it:

```yaml
jobs:
  malguard:
    uses: Marvellous-is-cool/malguard/.github/workflows/scan.yml@v1

  deploy:
    needs: [malguard, test]   # keep the existing needs, add malguard
    ...
```

### 3. Make the check required

On each protected branch (`main`, `staging`, ...) make the status check
**`malguard / malguard`** required. With the GitHub CLI, a ruleset adds it
without touching the existing branch protection:

```sh
gh api -X POST repos/OWNER/REPO/rulesets --input - <<'JSON'
{
  "name": "malguard required",
  "target": "branch",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH", "refs/heads/staging"], "exclude": []}},
  "rules": [{"type": "required_status_checks", "parameters": {
    "strict_required_status_checks_policy": false,
    "required_status_checks": [{"context": "malguard / malguard"}]}}]
}
JSON
```

GitHub enforces rulesets on public repos, and on private repos on the paid
plans (Pro, Team, Enterprise). On a free private repo the ruleset is saved
but not enforced. There, the deploy gate in step 2 is what stops a bad tree.

If your organisation only allows selected actions, an admin must allow
`Marvellous-is-cool/malguard@*` under Settings → Actions.

## Exceptions: `.malguard-allow`

Strict means strict, but heuristics can misfire. A vendored minified library
can look obfuscated, for example. A reviewed false positive goes in
`.malguard-allow` at the repository root, one per line:

```text
# path glob :: text in the finding :: why it is safe (required)
static/vendor/*.js :: obfuscation pattern :: vendored chart.js 4.4.1, checked against the npm tarball 2026-11-17
```

**The rules:**

- **The reason is required.** A line without one fails the scan.
- **Only heuristic findings can be excused.** A known malware signature or
  a known-malicious package can never be excused. Remove the file or the
  dependency.
- **Stale entries are reported.** An exception that no longer matches
  anything is flagged, so dead entries get cleaned up.
- **Excused findings stay visible.** They're listed in the job summary, and
  every change to the file shows in the pull request diff.

## Run it locally

```sh
python3 malguard_scan.py /path/to/repo           # text report, exit 1 on findings
python3 malguard_scan.py /path/to/repo --json    # machine-readable
```

It needs Python 3.9 or later and only the standard library. Exit codes:

| Code | Meaning |
|---|---|
| 0 | Clean |
| 1 | Findings |
| 2 | The scan could not finish |

## Changing the rules

Rules live in `malguard_scan.py`; tests live in `tests/`.

1. **Open a pull request** with the rule and a test that proves it fires.
2. **Assemble test fixtures from fragments.** Look at the `j(...)` helper:
   a literal signature in a test file would trip malguard itself, in CI and
   on your machine.
3. **Break up literal markers in the rules too.** Wrap one character in a
   class, for example `Sha1-[H]ulud`, so this repository never matches its
   own rules. `test_the_scanner_does_not_flag_its_own_source` enforces
   this.
4. **Wait for `self-test` to go green.** It runs the tests on Python 3.9 and
   3.12, then scans this repo through the action.
5. **Release.** Tag the merge commit with the exact version (`v1.0.1`), then
   move the major tag:

   ```sh
   git tag v1.0.1 && git tag -f v1
   git push origin v1.0.1 && git push -f origin v1
   ```

   Every project on `@v1` uses the new rules from its next run.
6. **Breaking change?** A change that would fail projects that pass today
   gets a new major tag (`v2`). Projects then move to it deliberately.

**Before moving `v1`:** a new rule can turn every project red at once.
Scan your projects with the new version first:

```sh
python3 malguard_scan.py ~/code/<project>
```

## Layout

| Path | What |
|---|---|
| `malguard_scan.py` | The scanner (rules, dependency check, exceptions, reporting) |
| `action.yml` | Composite action that runs the scanner |
| `.github/workflows/scan.yml` | The reusable workflow projects call |
| `.github/workflows/self-test.yml` | This repo's own CI |
| `examples/malguard.yml` | The workflow to copy into a project |
| `tests/` | Self-tests |

## License

MIT

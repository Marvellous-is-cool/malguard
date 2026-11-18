malguard is a CI gate that stops developer-targeted malware before it merges
or deploys. It scans your repository for the tricks these campaigns use:
VS Code tasks that run on folder open, "fonts" that are really JavaScript,
hidden and obfuscated loaders. It also checks every npm and PyPI dependency
against [OSV](https://osv.dev)'s list of known-malicious packages. Any
finding fails the job, and so does a scan that can't finish. It's one Python
file using only the standard library.

## What it catches

| Kind | Examples |
|---|---|
| Known loader signatures | PolinRider, EtherHiding, BeaverTail, Shai-Hulud and GlassWorm markers; secret-dumping workflows; exfiltration webhooks; credential stealers |
| Disguised payloads | Fonts, images and media that are really JavaScript |
| Auto-run traps | VS Code tasks that run on folder open |
| Hidden code | Invisible Unicode, code pushed off-screen behind whitespace, `exec` of decoded Python, obfuscated JavaScript |
| Risky install scripts | `preinstall`/`postinstall` scripts that download or run code |
| Malicious dependencies | Any npm or PyPI package OSV lists as malicious |

## Add it to a project

Save this as `.github/workflows/malguard.yml`:

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

Then make the `malguard / malguard` check required, and make your deploy
jobs depend on it. To review every rule change before it reaches your CI,
[pin to a commit SHA](https://github.com/Marvellous-is-cool/malguard/blob/v1.0.1/README.md#pin-to-a-commit-sha)
instead of `@v1`.

## New in v1.0.1

- **Pinning the workflow to a SHA now pins the scanner too.** It runs from
  the workflow's own commit, never from a moving tag.
- **Every third-party action is pinned to a commit SHA**, and Dependabot keeps
  them current.
- **Added [Limitations](https://github.com/Marvellous-is-cool/malguard/blob/v1.0.1/README.md#limitations)
  and a [security policy](https://github.com/Marvellous-is-cool/malguard/blob/v1.0.1/SECURITY.md).**

## Know its limits

malguard is a gate, not an antivirus. Its rules are mostly text patterns, and
its dependency check is only as current as OSV's data. Read
[Limitations](https://github.com/Marvellous-is-cool/malguard/blob/v1.0.1/README.md#limitations)
before you rely on it.

Found a way past it? [Report it privately](https://github.com/Marvellous-is-cool/malguard/security/advisories/new).

**Full changelog:** [CHANGELOG.md](https://github.com/Marvellous-is-cool/malguard/blob/v1.0.1/CHANGELOG.md)

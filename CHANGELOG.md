# Changelog

Every release of malguard. Versions follow [Semantic Versioning](https://semver.org):

- **Minor releases add rules.** A new rule can fail a project that passed
  before, if the project has a real problem or a false positive to excuse.
- **Patch releases fix bugs.**
- **Major releases change how projects call malguard:** workflow inputs, the
  check name, exit codes or the `.malguard-allow` format.

## [1.1.0] - unreleased

### Added

- **Entropy detection.** A string of 200+ base64 or base64url characters
  with 5 or more bits of entropy per character is a MEDIUM heuristic finding.
  It means a likely encoded payload with no known signature.
  - It applies to the same code and config files as the other heuristics.
  - The finding names the line, the length and the entropy.
  - Exempt: npm, pnpm and Composer lockfiles, and `.min.` files.
  - Also exempt: embedded images, fonts, audio and inline source maps. Only
    when the `data:` URI names the type and the decoded bytes start with that
    format's file signature, so labelling a payload `data:image/png` doesn't
    hide it.
  - Like every heuristic, it can be excused in `.malguard-allow`.

### Changed

- The versioning policy above now says what each kind of release may do.

## [1.0.1] - unreleased

The public launch release.

### Changed

- **Pinning the workflow now pins the scanner.** The reusable workflow runs
  the scanner from its own commit (`job.workflow_sha`) instead of fetching it
  by `@v1`. A project that pins `scan.yml` to a SHA runs exactly that
  release's rules.
- **Third-party actions are pinned to commit SHAs.** `actions/checkout` is
  pinned to v7.0.1 (from `@v4`) and `actions/setup-python` to v7.1.0 (from
  `@v5`).

### Added

- README sections: "Pin to a commit SHA", "Limitations" and "Report a
  bypass".
- `SECURITY.md`: how to report a bypass privately, and what happens next.
- Dependabot for malguard's own actions, with a 7-day cooldown on new
  releases.
- The self-test now runs the reusable workflow against this repository, as
  well as the action.
- This changelog.

## [1.0.0] - 2026-11-17

The first release.

### Added

- **The scanner** (`malguard_scan.py`), standard library only, Python 3.9+.
  It detects:
  - known loader signatures (PolinRider, EtherHiding, BeaverTail, Shai-Hulud,
    GlassWorm), secret-dumping workflows, exfiltration webhooks and
    credential stealers;
  - payloads disguised as fonts, images, media, `.svg`, `.md` or `.txt`;
  - VS Code tasks that run on folder open;
  - worm artifacts, invisible Unicode, code hidden behind whitespace and
    `exec` of decoded Python;
  - JavaScript obfuscation and risky install scripts.
- **The malicious-dependency check.** npm and PyPI packages from lockfiles and
  manifests are checked against OSV's `MAL-*` advisories.
- **Fail-closed behaviour.** A scan that can't finish exits 2.
- **Exceptions** through `.malguard-allow`, for heuristic findings only. Each
  needs a reason, and stale entries are reported.
- **The composite action** (`action.yml`), the **reusable workflow**
  (`.github/workflows/scan.yml`) and an example caller workflow.
- **The self-test workflow**, with 29 tests on Python 3.9 and 3.12.

[1.0.1]: https://github.com/Marvellous-is-cool/malguard/compare/v1.0.0...main
[1.0.0]: https://github.com/Marvellous-is-cool/malguard/releases/tag/v1.0.0

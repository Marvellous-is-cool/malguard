# Security policy

malguard is a security gate, so the most useful report you can send is one
that shows how to get past it.

## Report privately

Use GitHub's private vulnerability reporting:
[**Report a vulnerability**](https://github.com/Marvellous-is-cool/malguard/security/advisories/new)
(or the **Security** tab, then **Report a vulnerability**).

Please don't open a public issue for a bypass. Every project that runs
malguard would be exposed until a fix is released.

**Report privately:**

- **A bypass or a missed detection.** Malicious code or a known campaign that
  malguard should catch but doesn't.
- **A way to make the gate pass a tree it should fail.** For example, making
  the scanner exit 0 after an error, excusing a signature through
  `.malguard-allow`, or making the dependency check skip a package silently.
- **A vulnerability in the workflow or action itself.** For example, exposing
  the job's token or injecting commands through an input.

**Open a public issue instead** for false positives, feature requests and
documentation problems.

## What to include

- The malguard version or commit you tested.
- What you expected malguard to flag, and what it did.
- A minimal example. A description or a defanged sample is enough. If the
  only way to show it is live malware, say so in the report first and we'll
  agree how to share it.

## What happens next

| When | What |
|---|---|
| Within 3 working days | We acknowledge your report. |
| Within 7 days | We confirm whether it's a real gap, and tell you the plan. |
| As soon as it's fixed | A patch release on the current major version, so every project on `@v1` gets it on its next run. Projects pinned to a SHA get a Dependabot pull request. |
| After the release | We publish a security advisory, crediting you unless you'd rather not be named. |

Please keep the details private until the fix is released, or for 90 days
from your report, whichever comes first.

## Supported versions

Only the latest release of the current major version (`v1`) gets fixes.

#!/usr/bin/env python3
"""malguard scan: the CI malware gate for a repository.

Scans a checked-out working tree for the signs of developer-targeted malware
(disguised payloads, auto-run editor tasks, obfuscated loaders, worm artifacts,
risky install scripts) and checks every dependency in its lockfiles against the
OSV database of known-malicious packages (MAL-* advisories).

Exit codes:
  0  clean (or every finding is covered by a reviewed exception)
  1  findings: HIGH or MEDIUM, not covered by an exception
  2  the scan could not finish (fails closed: an unfinished scan is never clean)

Standard library only, Python 3.9+. The detection rules are the same ones the
local malguard gate uses; change them here and every project picks them up.

Usage:
  python3 malguard_scan.py [PATH] [--allow FILE] [--json] [--offline]

  PATH       repository root to scan (default: current directory)
  --allow    exceptions file (default: PATH/.malguard-allow)
  --json     print findings as JSON instead of text
  --offline  skip the OSV lookup (local experiments only; CI never passes it)
"""

import fnmatch
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

VERSION = "1.0.0"

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"
OSV_BATCH_SIZE = 1000
OSV_TIMEOUT_SECONDS = 60
OSV_MAX_PAGES = 20
OSV_ATTEMPTS = 3
OSV_BACKOFF_SECONDS = (2, 4)
"""A dropped connection, a 429 or a 5xx is retried after 2s, then 4s. A 4xx
is our request's fault and is not retried. When every attempt fails the scan
fails closed."""

MAX_TEXT_BYTES = 3_000_000
MAX_LOCKFILE_BYTES = 80_000_000

SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", "__pycache__", ".mypy_cache",
             ".pytest_cache", ".ruff_cache", "staticfiles", ".turbo", ".expo", "coverage",
             "site-packages", ".gradle", "Pods", ".dart_tool", ".venv", "venv", "env", ".tox"}
TEXT_EXT = (".js", ".cjs", ".mjs", ".ts", ".tsx", ".jsx", ".py", ".sh", ".json", ".yml", ".yaml",
            ".toml", ".bat", ".cmd", ".ps1", ".rb", ".php")
DISGUISE_EXT = (".ttf", ".otf", ".woff", ".woff2", ".eot", ".png", ".jpg", ".jpeg", ".gif", ".ico",
                ".webp", ".mp3", ".mp4", ".wav", ".lkf", ".lfk", ".dat", ".bin", ".map", ".svg", ".txt", ".md")
WORM_FILES = {"temp_auto_push.bat", "temp_interactive_push.bat", "branch_structure.json"}
CFG_NAMES = re.compile(r"^(next|tailwind|postcss|vite|vue|nuxt|webpack|babel|eslint|jest|vitest|metro|app|astro|"
                       r"svelte|rollup|tsup|prettier|playwright|gulpfile|gruntfile)(\.config)?\.(js|cjs|mjs|ts)$|"
                       r"^\.eslintrc(\.js|\.cjs)?$", re.I)
# Written with escapes, not the characters themselves, so this file never
# contains a run of invisible characters.
INVIS = re.compile("[︀-️\U000e0100-\U000e01ef\U000e0000-\U000e007f"
                   "​-‏⁠-⁤‪-‮]{8,}")
PADDED = re.compile(r"(^|\n)[ \t]{120,}\S")
OBF_JS = re.compile(r"_0x[0-9a-f]{4,}\(|global\[['\"](\\u00[0-9a-fA-F]{2}|!)['\"]\]\s*=|"
                    r"String\.fromCharCode\((\d+,\s*){30,}|eval\(atob|new Function\(atob|"
                    r"require\(['\"](node:)?child_process['\"]\)\.exec\(")
OBF_PY = re.compile(r"exec\((base64|zlib|marshal|bytes\.fromhex|codecs\.decode|__import__)|marshal\.loads\(|"
                    r"b64decode\(['\"][A-Za-z0-9+/=]{300,}")

# Signatures of known developer-targeting loaders (PolinRider, EtherHiding,
# BeaverTail, Shai-Hulud, GlassWorm). Each literal marker has one character
# wrapped in a class ([x]) so this file never matches its own rules: a copy of
# the scanner in a repository must not look like the malware it detects.
SIGNATURES = [
    (re.compile(r"/0x/[c]ls|/0x/[l]s\b"), "PolinRider C2 path"),
    (re.compile(r'"n\*\*-8A"\.split'), "PolinRider loader marker"),
    (re.compile(r"eth_get[T]ransactionCount[\s\S]{0,4000}(child_[p]rocess|spawn)|"
                r"(child_[p]rocess|spawn)[\s\S]{0,4000}eth_get[T]ransactionCount"),
     "EtherHiding loader (C2 address from Ethereum tx + spawn)"),
    (re.compile(r"global\[['\"]\\u0072['\"]\]\s*=\s*require"), "obfuscated global require alias"),
    (re.compile(r"Sha1-[H]ulud|shai-hulud-[w]orkflow|bun_[e]nvironment\.js|setup_[b]un\.js"), "Shai-Hulud worm marker"),
    (re.compile(r"toJSON\(secrets\)"), "GitHub workflow dumping all secrets"),
    (re.compile(r"webhook\.site/[0-9a-f-]{20,}"), "exfiltration webhook"),
    (re.compile(r"(Login [D]ata|Local [S]tate|Local [E]xtension Settings)[\s\S]{0,600}"
                r"(exodus|metamask|nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa)", re.I),
     "browser credential / wallet stealer strings"),
]

LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepublish", "preuninstall")
RISKY_SCRIPT = re.compile(r"curl |wget |node -e|node --eval|base64|https?://|\| *(ba)?sh|powershell|python -c|eval ")

# Known-bad releases that OSV may list under a GHSA id instead of MAL-.
BUILTIN_BAD = {"npm": {
    "chalk": ["5.6.1"], "debug": ["4.4.2"], "ansi-styles": ["6.2.2"], "strip-ansi": ["7.1.1"], "ansi-regex": ["6.2.1"],
    "color-convert": ["3.1.1"], "color-name": ["2.0.1"], "supports-color": ["10.2.1"], "wrap-ansi": ["9.0.1"],
    "slice-ansi": ["7.1.1"], "color-string": ["2.1.1"], "simple-swizzle": ["0.2.3"], "is-arrayish": ["0.3.3"],
    "error-ex": ["1.3.3"], "backslash": ["0.2.1"], "has-ansi": ["6.0.1"], "chalk-template": ["1.1.1"],
    "supports-hyperlinks": ["4.1.1"], "@ctrl/tinycolor": ["4.1.1", "4.1.2"],
    "nx": ["20.9.0", "20.10.0", "20.11.0", "20.12.0", "21.5.0", "21.6.0", "21.7.0", "21.8.0"],
    "eslint-config-prettier": ["8.10.1", "9.1.1", "10.1.6", "10.1.7"], "eslint-plugin-prettier": ["4.2.2", "4.2.3"],
    "synckit": ["0.11.9"], "@pkgr/core": ["0.2.8"], "napi-postinstall": ["0.3.1"], "is": ["3.3.1", "5.0.0"]},
    "PyPI": {}}

SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}

# Finding kinds. Only heuristics may be excused by .malguard-allow: a known
# malware signature or a known-malicious package is never an acceptable risk.
SIGNATURE, DEPENDENCY, HEURISTIC = "signature", "dependency", "heuristic"


class ScanError(Exception):
    """The scan could not finish. Treated as a failure, never as clean."""


class Finding:
    __slots__ = ("severity", "path", "message", "kind")

    def __init__(self, severity, path, message, kind=HEURISTIC):
        self.severity, self.path, self.message, self.kind = severity, path, message, kind

    def as_dict(self):
        return {"severity": self.severity, "path": self.path, "message": self.message, "kind": self.kind}

    def __repr__(self):
        return f"Finding({self.severity}, {self.path}, {self.message})"


# ---------------------------------------------------------------- files
def read_text(path, limit=MAX_TEXT_BYTES):
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        return None
    if b"\x00" in raw[:8192]:
        return None  # binary
    return raw.decode("utf-8", "ignore")


def scan_file(root, rel):
    """Every finding for one file (path relative to the repository root)."""

    path = os.path.join(root, rel)
    rel = rel.replace(os.sep, "/")
    name = os.path.basename(rel)
    low = name.lower()
    out = []
    if name in WORM_FILES:
        out.append(Finding("HIGH", rel, "worm auto-push artifact", SIGNATURE))
    if low.endswith((".lkf", ".lfk")):
        out.append(Finding("HIGH", rel, "file type used by the PolinRider payload", SIGNATURE))
    text = read_text(path)
    if text is None:
        return out
    if rel.endswith(".vscode/tasks.json") and "folderOpen" in text:
        out.append(Finding("HIGH", rel, "VS Code task set to run automatically on folder open"))
    if rel.endswith(".vscode/settings.json"):
        if "allowAutomaticTasks" in text:
            out.append(Finding("HIGH", rel, "repo tries to enable automatic VS Code tasks"))
        if re.search(r"runOn\"?\s*:\s*\"folderOpen", text):
            out.append(Finding("MEDIUM", rel, "folderOpen task defined in settings.json"))
    if name == ".gitignore":
        lines = {line.strip() for line in text.splitlines()}
        if (".gitignore" in lines and rel == ".gitignore") or lines & WORM_FILES:
            out.append(Finding("HIGH", rel, ".gitignore hides itself or worm artifacts", SIGNATURE))
    if low.endswith(DISGUISE_EXT) and not low.endswith((".svg", ".md", ".txt", ".map")):
        if re.search(r"require\(|global\[|_0x[0-9a-f]{4}|child_process|process\.env", text):
            ext = low.rsplit(".", 1)[-1]
            out.append(Finding("HIGH", rel, f"'{ext}' file is actually JavaScript (disguised payload)"))
    if low.endswith((".svg", ".md", ".txt")) and re.search(r"require\(['\"](node:)?(child_process|https?)['\"]\)", text):
        out.append(Finding("HIGH", rel, "text/asset file contains executable Node code"))
    for rx, label in SIGNATURES:
        if rx.search(text):
            out.append(Finding("HIGH", rel, label, SIGNATURE))
    is_code = low.endswith(TEXT_EXT) or CFG_NAMES.match(name)
    if is_code and ".min." not in low:
        if INVIS.search(text):
            out.append(Finding("HIGH", rel, "long run of invisible Unicode (GlassWorm-style hidden code)"))
        if low.endswith((".js", ".cjs", ".mjs", ".ts", ".tsx", ".jsx", ".json")):
            if PADDED.search(text):
                out.append(Finding("HIGH", rel, "code hidden behind a long run of whitespace"))
            m = OBF_JS.search(text)
            if m:
                sev = "HIGH" if CFG_NAMES.match(name) else "MEDIUM"
                out.append(Finding(sev, rel, f"obfuscation pattern: {m.group(0)[:40]}"))
            if CFG_NAMES.match(name) and max((len(line) for line in text.splitlines()), default=0) > 1500:
                out.append(Finding("HIGH", rel, "build config file with a very long line"))
        if low.endswith(".py"):
            m = OBF_PY.search(text)
            if m:
                out.append(Finding("HIGH", rel, f"python exec/decode of hidden code: {m.group(0)[:40]}"))
    if name == "package.json" and "node_modules" not in rel:
        try:
            scripts = json.loads(text).get("scripts") or {}
        except (ValueError, AttributeError):
            scripts = {}
        for key in LIFECYCLE:
            value = scripts.get(key)
            if isinstance(value, str) and RISKY_SCRIPT.search(value):
                out.append(Finding("HIGH", rel, f"risky npm {key} script: {value[:80]}"))
    if rel.startswith(".github/workflows/") and re.search(r"hulud", rel, re.I):
        out.append(Finding("HIGH", rel, "Shai-Hulud workflow", SIGNATURE))
    return out


def walk(root):
    """Relative paths of every file worth scanning."""

    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for f in sorted(files):
            yield os.path.relpath(os.path.join(current, f), root)


# ---------------------------------------------------------- dependencies
def norm(eco, name):
    name = name.strip()
    if eco == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "package.json",
             "poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock", "constraints.txt"}


def is_depfile(name):
    return name in LOCKFILES or bool(re.match(r"requirements.*\.txt$", name))


def deps_from_file(path):
    """Yield (ecosystem, name, version-or-None) from a lockfile or manifest."""

    base = os.path.basename(path)
    text = read_text(path, limit=MAX_LOCKFILE_BYTES)
    if text is None:
        return
    if base in ("package-lock.json", "npm-shrinkwrap.json"):
        try:
            d = json.loads(text)
        except ValueError:
            return
        for key, v in (d.get("packages") or {}).items():
            if key and "node_modules/" in key and isinstance(v, dict) and v.get("version"):
                yield "npm", v.get("name") or key.rsplit("node_modules/", 1)[1], v["version"]

        def nested(deps):
            for name, v in (deps or {}).items():
                if isinstance(v, dict):
                    if v.get("version"):
                        yield "npm", name, v["version"]
                    yield from nested(v.get("dependencies"))
        yield from nested(d.get("dependencies"))
    elif base == "yarn.lock":
        current = []
        for line in text.splitlines():
            if line and not line.startswith((" ", "#")):
                current = []
                for spec in line.rstrip(":").split(","):
                    spec = spec.strip().strip('"')
                    m = re.match(r"^(@?[^@]+)@", spec)
                    if m:
                        current.append(m.group(1))
            else:
                m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
                if m and current:
                    for n in set(current):
                        yield "npm", n, m.group(1)
                    current = []
    elif base == "pnpm-lock.yaml":
        for m in re.finditer(r"^\s{2,4}['\"]?/?(@?[^@\s'\"/]+(?:/[^@\s'\"]+)?)@(\d[^:'\"\s(]*)", text, re.M):
            yield "npm", m.group(1), m.group(2)
    elif base == "bun.lock":
        for m in re.finditer(r'"(@?[^"@\s]+(?:/[^"@\s]+)?)@(\d[^"]*)"', text):
            yield "npm", m.group(1), m.group(2)
    elif base == "package.json":
        try:
            d = json.loads(text)
        except ValueError:
            return
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            for n, spec in (d.get(section) or {}).items():
                v = spec if isinstance(spec, str) and re.fullmatch(r"\d+\.\d+\.\d+[\w.-]*", spec) else None
                yield "npm", n, v
    elif re.match(r"requirements.*\.txt$", base) or base == "constraints.txt":
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(==\s*([^\s;,]+))?", line)
            if m and not line.startswith("-"):
                yield "PyPI", m.group(1), m.group(3)
    elif base in ("poetry.lock", "uv.lock", "pdm.lock"):
        for m in re.finditer(r'^name\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', text, re.M):
            yield "PyPI", m.group(1), m.group(2)
    elif base == "Pipfile.lock":
        try:
            d = json.loads(text)
        except ValueError:
            return
        for section in ("default", "develop"):
            for n, v in (d.get(section) or {}).items():
                yield "PyPI", n, (v.get("version") or "").lstrip("=") or None


def _request_json(request):
    """Fetch and decode JSON, retrying transient failures (OSV_ATTEMPTS)."""

    last = None
    for attempt in range(OSV_ATTEMPTS):
        if attempt:
            time.sleep(OSV_BACKOFF_SECONDS[min(attempt - 1, len(OSV_BACKOFF_SECONDS) - 1)])
        try:
            with urllib.request.urlopen(request, timeout=OSV_TIMEOUT_SECONDS) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            last = exc
            if exc.code != 429 and exc.code < 500:
                break
        except (urllib.error.URLError, OSError, ValueError) as exc:
            last = exc
    raise ScanError(f"OSV lookup failed: {last}")


def _post_json(url, body):
    return _request_json(urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}
    ))


def _get_json(url):
    return _request_json(urllib.request.Request(url))


def covers_every_version(advisory, eco, name):
    """Does this advisory mark every release of the package malicious?

    Same rule the local engine applies when it builds its database: no listed
    versions or ranges, or a range introduced at 0 that is never fixed.
    """

    for affected in advisory.get("affected") or []:
        package = affected.get("package") or {}
        if package.get("ecosystem") != eco or norm(eco, package.get("name") or "") != norm(eco, name):
            continue
        if not affected.get("versions") and not affected.get("ranges"):
            return True
        for r in affected.get("ranges") or []:
            events = r.get("events") or []
            if any(e.get("introduced") == "0" for e in events) and not any(
                    "fixed" in e or "last_affected" in e for e in events):
                return True
    return False


def osv_malicious_ids(packages, post=_post_json):
    """{(eco, name, version): [MAL-* ids]} for the packages OSV lists as malicious.

    One querybatch per 1000 packages; a query with more results than fit on
    one page is followed through its page tokens. Any network or parse error
    raises ScanError, so a lookup that did not happen is never read as clean.
    """

    found = {}
    for start in range(0, len(packages), OSV_BATCH_SIZE):
        chunk = packages[start:start + OSV_BATCH_SIZE]
        pending = [(pkg, None) for pkg in chunk]
        for _ in range(OSV_MAX_PAGES):
            if not pending:
                break
            queries = []
            for (eco, name, version), token in pending:
                query = {"package": {"ecosystem": eco, "name": name}}
                if version:
                    query["version"] = version
                if token:
                    query["page_token"] = token
                queries.append(query)
            results = post(OSV_QUERYBATCH, {"queries": queries}).get("results")
            if not isinstance(results, list) or len(results) != len(queries):
                raise ScanError("OSV answered with an unexpected shape")
            next_pending = []
            for (pkg, _token), result in zip(pending, results):
                ids = [v.get("id", "") for v in (result or {}).get("vulns") or []]
                malicious = [i for i in ids if i.startswith("MAL-")]
                if malicious:
                    found.setdefault(pkg, []).extend(malicious)
                if (result or {}).get("next_page_token"):
                    next_pending.append((pkg, result["next_page_token"]))
            pending = next_pending
        else:
            raise ScanError("OSV paging did not finish")
    return found


def scan_dependencies(root, depfiles, offline=False, post=_post_json, fetch=_get_json):
    """HIGH findings for known-malicious dependencies in the given files.

    A pinned version (lockfiles, `==` requirements) is flagged when OSV lists
    that release as malicious. A dependency with no version (a range in
    package.json, an unpinned requirement) is flagged only when an advisory
    covers every release: the exact version is the lockfile's to answer, and
    flagging axios because one past release was hijacked would be noise.
    """

    where = {}
    for rel in depfiles:
        for eco, name, version in deps_from_file(os.path.join(root, rel)):
            key = (eco, norm(eco, name), version or None)
            where.setdefault(key, (rel.replace(os.sep, "/"), name))
    out = []
    for (eco, key_name, version), (rel, name) in where.items():
        bad = BUILTIN_BAD.get(eco, {}).get(key_name)
        if bad and version in bad:
            out.append(Finding("HIGH", rel, f"{eco} {name}@{version}: known compromised release", DEPENDENCY))
    if offline or not where:
        return out
    flagged = osv_malicious_ids(sorted(where, key=lambda k: (k[0], k[1], k[2] or "")), post=post)
    for (eco, key_name, version), ids in sorted(flagged.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2] or "")):
        rel, name = where[(eco, key_name, version)]
        if version is None:
            ids = [i for i in sorted(set(ids)) if covers_every_version(fetch(OSV_VULN.format(id=i)), eco, name)]
            if not ids:
                continue
        out.append(Finding("HIGH", rel, f"{eco} {name}@{version or '?'}: malicious package ({', '.join(sorted(set(ids))[:3])})",
                           DEPENDENCY))
    return out


# ------------------------------------------------------------ exceptions
class AllowRule:
    __slots__ = ("pattern", "text", "reason", "line", "used")

    def __init__(self, pattern, text, reason, line):
        self.pattern, self.text, self.reason, self.line, self.used = pattern, text, reason, line, False

    def covers(self, finding):
        return (finding.kind == HEURISTIC and fnmatch.fnmatch(finding.path, self.pattern)
                and self.text in finding.message)


def load_allow(path):
    """Read .malguard-allow. Each line: `path-glob :: finding text :: reason`.

    The reason is required, so every exception says why it is safe. A malformed
    line is a configuration error (the scan fails) rather than being skipped.
    """

    rules = []
    if not path or not os.path.exists(path):
        return rules
    with open(path, encoding="utf-8") as f:
        for number, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("::")]
            if len(parts) != 3 or not all(parts):
                raise ScanError(
                    f"{os.path.basename(path)} line {number}: expected `path-glob :: finding text :: reason`"
                )
            rules.append(AllowRule(parts[0], parts[1], parts[2], number))
    return rules


# ------------------------------------------------------------------- run
def scan(root, allow_path=None, offline=False, post=_post_json, fetch=_get_json):
    """(failures, excused, unused_rules, scanned_files) for the tree at root."""

    root = os.path.abspath(root)
    if not os.path.isdir(root):
        raise ScanError(f"{root} is not a directory")
    allow = load_allow(allow_path if allow_path is not None else os.path.join(root, ".malguard-allow"))
    files = list(walk(root))
    findings = []
    for rel in files:
        findings += scan_file(root, rel)
    findings += scan_dependencies(root, [f for f in files if is_depfile(os.path.basename(f))],
                                  offline=offline, post=post, fetch=fetch)
    failures, excused = [], []
    for finding in findings:
        if finding.severity not in ("HIGH", "MEDIUM"):
            continue
        rule = next((r for r in allow if r.covers(finding)), None)
        if rule:
            rule.used = True
            excused.append((finding, rule))
        else:
            failures.append(finding)
    failures.sort(key=lambda f: (SEV_ORDER.get(f.severity, 9), f.path))
    return failures, excused, [r for r in allow if not r.used], len(files)


def _escape(value):
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A").replace(",", "%2C").replace(":", "%3A")


def report(failures, excused, unused, scanned, as_json=False):
    if as_json:
        print(json.dumps({
            "version": VERSION,
            "scanned_files": scanned,
            "failures": [f.as_dict() for f in failures],
            "excused": [{**f.as_dict(), "reason": r.reason} for f, r in excused],
            "unused_exceptions": [{"line": r.line, "pattern": r.pattern, "text": r.text} for r in unused],
        }, indent=2))
    else:
        print(f"malguard {VERSION}: scanned {scanned} files")
        for f in failures:
            print(f"  {f.severity:<6} {f.path}: {f.message}")
        for f, r in excused:
            print(f"  EXCUSED {f.path}: {f.message} ({r.reason})")
        for r in unused:
            print(f"  WARNING .malguard-allow line {r.line} matches nothing; remove it ({r.pattern} :: {r.text})")
        print("  result: " + ("FAILED" if failures else "clean"))

    if os.environ.get("GITHUB_ACTIONS") == "true":
        for f in failures:
            print(f"::error file={_escape(f.path)},title=malguard {f.severity}::{_escape(f.message)}")
        for r in unused:
            print(f"::warning file=.malguard-allow,line={r.line},title=malguard::exception matches nothing")
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as out:
                out.write(f"## malguard {VERSION}: {'FAILED' if failures else 'clean'}\n\n")
                out.write(f"Scanned {scanned} files and their lockfiles.\n\n")
                if failures:
                    out.write("| Severity | File | Finding |\n|---|---|---|\n")
                    for f in failures:
                        out.write(f"| {f.severity} | `{f.path}` | {f.message.replace('|', '/')} |\n")
                    out.write("\nRemove the file, or, if a heuristic finding is a reviewed false positive, add "
                              "it to `.malguard-allow` with the reason. Known malware signatures and malicious "
                              "packages cannot be excused.\n")
                if excused:
                    out.write("\n**Excused by `.malguard-allow`:**\n\n")
                    for f, r in excused:
                        out.write(f"- `{f.path}`: {f.message} ({r.reason})\n")


def main(argv):
    args = list(argv)
    as_json = "--json" in args
    offline = "--offline" in args
    allow_path = None
    if "--allow" in args:
        i = args.index("--allow")
        if i + 1 >= len(args):
            print("malguard: --allow needs a file", file=sys.stderr)
            return 2
        allow_path = args[i + 1]
        del args[i:i + 2]
    positional = [a for a in args if not a.startswith("--")]
    if "--help" in args or "-h" in args:
        print(__doc__)
        return 0
    root = positional[0] if positional else os.getcwd()
    try:
        failures, excused, unused, scanned = scan(root, allow_path=allow_path, offline=offline)
    except ScanError as exc:
        print(f"malguard: BLOCKED, the scan could not finish ({exc}). An unfinished scan is never clean.",
              file=sys.stderr)
        if os.environ.get("GITHUB_ACTIONS") == "true":
            print(f"::error title=malguard::scan could not finish: {_escape(str(exc))}")
        return 2
    report(failures, excused, unused, scanned, as_json=as_json)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

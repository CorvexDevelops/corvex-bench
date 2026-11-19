# Author: CorvexDevelops
"""Tests for corvex-bench: benchmark, scoring and web targets.

    python -m unittest discover -s tests -v       (from the repository root)

Offline: no test talks to the internet. The web targets start on 127.0.0.1 on free ports.
"""
import contextlib
import importlib.util
import io
import ipaddress
import json
import os
import random
import shutil
import socket
import struct
import sys
import tempfile
import unittest
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for sub in ('bench', 'pcapgen'):
    sys.path.insert(0, os.path.join(ROOT, sub))

import bench  # noqa: E402
import pcapgen as G  # noqa: E402


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="corvexai-tests-")
        self._quiet = contextlib.redirect_stdout(io.StringIO())  # the command-line tools print reports
        self._quiet.__enter__()

    def tearDown(self):
        self._quiet.__exit__(None, None, None)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def path(self, name):
        return os.path.join(self.tmp, name)


# --------------------------------------------------------------------------- pcapgen + pcapread


def sarif(results, rules=None):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "fake", "rules": rules or []}}, "results": results}]}


def res(rule, msg, uri, line=None, level="warning"):
    loc = {"physicalLocation": {"artifactLocation": {"uri": uri}}}
    if line:
        loc["physicalLocation"]["region"] = {"startLine": line}
    return {"ruleId": rule, "message": {"text": msg}, "level": level, "locations": [loc]}


class Bench(Tmp):
    def write(self, name, doc):
        with open(self.path(name), "w") as f:
            json.dump(doc, f)

    def test_expected_is_consistent(self):
        exp = bench.load_expected()
        ids = [e["id"] for s in exp["targets"].values() for e in s.get("expected", [])]
        self.assertEqual(len(ids), len(set(ids)))
        for name, spec in exp["targets"].items():
            for e in spec.get("expected", []):
                self.assertTrue(e["keywords"], e["id"])
                if spec["kind"] == "code":
                    self.assertTrue(os.path.exists(os.path.join(bench.TARGETS_DIR, name, e["file"])), e["id"])
                    if e.get("contains"):
                        bench.resolve_line(name, e["file"], e["contains"])
        self.assertEqual([e["signal"] for e in exp["targets"]["traffic-attacks"]["expected"]], [s["id"] for s in G.SIGNALS])

    def test_clean_code_has_no_flaw_snippets(self):
        snippets = {e["contains"] for e in bench.load_expected()["targets"]["code-vulnerable"]["expected"] if e.get("contains")}
        for base, _, files in os.walk(os.path.join(bench.TARGETS_DIR, "code-clean")):
            for fn in files:
                text = open(os.path.join(base, fn), encoding="utf-8").read()
                for s in snippets - {'"axios"', '"express"', '"jsonwebtoken"', '"lodash"', '"minimist"', "Math.random()"}:
                    self.assertNotIn(s, text, f"{fn}: {s}")

    def test_cwe_parsing(self):
        self.assertEqual(bench.cwes("CWE-89", ["external/cwe/cwe-079"], 22, "cwe_352", "nothing"), {89, 79, 22, 352})

    def test_sarif_scoring_and_matching(self):
        rules = [{"id": "py.sqli", "properties": {"tags": ["CWE-89"]}}, {"id": "hash", "properties": {"cwe": "CWE-328"}}]
        self.write("code-vulnerable.sarif", sarif([
            res("py.sqli", "query built from input", "file:///tmp/x/code-vulnerable/app.py", 24),   # CWE match, line within 2
            res("hash", "weak digest", "app.py", 47),                                             # CWE match
            res("random", "insecure random generator", "./app.py", 48),                           # keyword match
            res("random", "insecure random generator", "app.py", 48),                             # duplicate: uncatalogued
            res("sqli", "SQL injection", "server.js", 99),                                         # wrong line
            res("vuln-dep", "pyyaml 5.3.1 has known flaws", "requirements.txt", 3),                # dependency, exact line
            res("vuln-dep", "flask 2.0.1 has known flaws", "requirements.txt", 2),                 # wrong line for flask (tolerance 0)
            res("root", "container runs as root", "Dockerfile"),                                   # file only
        ], rules))
        self.write("code-clean.json", [{"rule": "debug", "message": "debug on", "file": "app.py", "line": 18},
                                       {"rule": "lic", "message": "unknown licence", "file": "package.json"}])
        rep = bench.score(self.tmp)
        t = rep["targets"]["code-vulnerable"]
        found = {i.split("/")[1] for i in t["found"]}
        self.assertEqual(found, {"C01", "C09", "C10", "C24", "C23"})
        self.assertEqual(len(t["uncatalogued"]), 3)
        self.assertEqual(rep["targets"]["code-clean"]["false_alarms"], ["code-clean · debug · app.py:18"])
        self.assertIn("web-vulnerable", rep["skipped"])

    def test_one_finding_counts_once_and_matching_is_maximal(self):
        exp = {"kind": "web", "expected": [
            {"id": "A", "title": "a", "cwe": [693], "keywords": ["csp"], "path": ""},
            {"id": "B", "title": "b", "cwe": [693], "keywords": ["nosniff"], "path": ""}]}
        one = [bench._finding("h", "missing headers", [693], location="http://h/")]
        self.assertEqual(len(bench.score_target("t", exp, one, {})["found"]), 1)
        two = [bench._finding("h", "missing CSP", [693], location="http://h/"),     # could serve A or B
               bench._finding("x", "other", [693], location="http://h/")]           # only via CWE
        self.assertEqual(len(bench.score_target("t", exp, two, {})["found"]), 2)

    def test_web_and_traffic_locations(self):
        self.write("web-vulnerable.json", {"findings": [
            {"rule": "xss", "message": "Reflected XSS", "location": "http://127.0.0.1:9/search?q=x"},
            {"rule": "xss", "message": "Reflected XSS", "location": "http://127.0.0.1:9/product?id=1"},
            {"rule": "redir", "cwe": "CWE-601", "location": "http://127.0.0.1:9/logout?next=//evil"}]})
        self.write("traffic-attacks.json", [{"rule": "beacon", "message": "periodic connections to 198.51.100.77:443"},
                                            {"rule": "beacon", "message": "periodic connections to 198.51.100.99"}])
        rep = bench.score(self.tmp)
        self.assertEqual(rep["targets"]["web-vulnerable"]["found"], ["web-vulnerable/W11", "web-vulnerable/W13"])
        self.assertEqual(len(rep["targets"]["traffic-attacks"]["found"]), 1)

    def test_baseline(self):
        self.write("code-vulnerable.json", [{"rule": "sql", "message": "SQL injection", "file": "app.py", "line": 23}])
        base = self.path("baseline.json")
        self.assertEqual(bench.main(["score", self.tmp, "--baseline", base, "--update"]), 0)
        self.assertEqual(bench.main(["score", self.tmp, "--baseline", base]), 0)
        self.write("code-vulnerable.json", [])
        self.assertEqual(bench.main(["score", self.tmp, "--baseline", base]), 1)
        diff = bench.compare(bench.score(self.tmp), json.load(open(base)))
        self.assertEqual(diff["lost"], ["code-vulnerable/C01"])
        os.remove(self.path("code-vulnerable.json"))
        self.write("web-clean.json", [])  # other targets only: the code baseline is not compared
        self.assertEqual(bench.compare(bench.score(self.tmp), json.load(open(base)))["lost"], [])

    def test_min_level(self):
        self.write("code-clean.sarif", sarif([res("x", "style", "app.py", 1, level="note")]))
        self.assertEqual(len(bench.score(self.tmp)["targets"]["code-clean"]["false_alarms"]), 1)
        self.assertEqual(len(bench.score(self.tmp, min_level="warning")["targets"]["code-clean"]["false_alarms"]), 0)

    def test_prepare(self):
        out = self.path("work")
        self.assertEqual(bench.main(["prepare", out]), 0)
        for name in ("code-vulnerable/app.py", "code-clean/app.py", "traffic-attacks.pcap", "traffic-clean.pcap", "indicators.json"):
            self.assertTrue(os.path.exists(os.path.join(out, name)), name)


class WebTargets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vuln = load("web_vulnerable", os.path.join(bench.TARGETS_DIR, "web-vulnerable", "server.py"))
        cls.clean = load("web_clean", os.path.join(bench.TARGETS_DIR, "web-clean", "server.py"))
        cls.ports = []
        cls.servers = []
        for mod in (cls.vuln, cls.clean):
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
            s.close()
            cls.servers.append(mod.start_background(port))
            cls.ports.append(port)

    @classmethod
    def tearDownClass(cls):
        for s in cls.servers:
            s.shutdown()
            s.server_close()

    def get(self, which, path, data=None):
        url = f"http://127.0.0.1:{self.ports[which]}{path}"
        opener = urllib.request.build_opener(type("NoRedirect", (urllib.request.HTTPRedirectHandler,), {"redirect_request": lambda *a: None}))
        try:
            r = opener.open(urllib.request.Request(url, data=data, headers={"Origin": "https://evil.example"}), timeout=5)
            return r.status, dict(r.headers), r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read().decode()

    def test_vulnerable_behaves_as_described(self):
        self.assertIn("<script>x</script>", self.get(0, "/search?q=<script>x</script>")[2])
        self.assertEqual(self.get(0, "/product?id=1'")[0], 500)
        self.assertEqual(self.get(0, "/logout?next=https://evil.example")[1]["Location"], "https://evil.example")
        self.assertEqual(self.get(0, "/")[1]["Access-Control-Allow-Origin"], "https://evil.example")
        self.assertEqual(self.get(0, "/.env")[0], 200)
        self.assertIn("__schema", self.get(0, "/graphql", b'{"query":"{__schema{types{name}}}"}')[2])

    def test_clean_behaves_safely(self):
        self.assertNotIn("<script>x</script>", self.get(1, "/search?q=<script>x</script>")[2])
        self.assertEqual(self.get(1, "/product?id=1'")[0], 400)
        self.assertEqual(self.get(1, "/logout?next=https://evil.example")[1]["Location"], "/")
        h = self.get(1, "/")[1]
        self.assertNotIn("Access-Control-Allow-Origin", h)
        self.assertIn("frame-ancestors 'none'", h["Content-Security-Policy"])
        self.assertEqual(self.get(1, "/.env")[0], 404)
        codes = [self.get(1, "/login", b"email=a&password=b")[0] for _ in range(7)]
        self.assertEqual(codes[-1], 429)


# --------------------------------------------------------------------------- nvdmatch


if __name__ == "__main__":
    unittest.main()

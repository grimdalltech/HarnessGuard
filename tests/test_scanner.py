from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from harnessguard.cli import main
from harnessguard.reporters import render_sarif
from harnessguard.rules import all_rules
from harnessguard.scanner import scan_path


def write(root: Path, name: str, content: str) -> Path:
    path = root / name
    path.write_text(content, encoding="utf-8")
    return path


def ids(result):
    return {item.rule_id for item in result.findings}


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_thirty_rules_are_registered(self):
        self.assertEqual(len(all_rules()), 30)
        self.assertEqual({r.id for r in all_rules()}, {f"HG{i:03d}" for i in range(1, 31)})

    def test_detects_execution_and_deserialization(self):
        path = write(self.root, "bad.py", """
import pickle, subprocess, yaml

def f(user):
    eval(user)
    exec(user)
    subprocess.run(user, shell=True)
    pickle.loads(user)
    yaml.load(user)
""")
        self.assertTrue({"HG001", "HG002", "HG003", "HG005", "HG006"} <= ids(scan_path(path)))

    def test_detects_agent_harness_controls(self):
        path = write(self.root, "agents.py", """
from crewai import Agent

def f(graph):
    Agent(role='x', allow_delegation=True, allow_code_execution=True, human_input=False)
    graph.invoke({'messages': []})
""")
        self.assertTrue({"HG011", "HG012", "HG014", "HG015", "HG016"} <= ids(scan_path(path)))

    def test_detects_tool_ssrf_path_and_timeout(self):
        path = write(self.root, "tools.py", """
import requests

def tool(f): return f

@tool
def fetch(url):
    return requests.get(url).text

@tool
def load(path):
    return open(path).read()
""")
        self.assertTrue({"HG019", "HG024", "HG025"} <= ids(scan_path(path)))

    def test_config_ignore_and_exclude(self):
        write(self.root, "a.py", "eval(user_input)\n")
        write(self.root, "skip.py", "exec(user_input)\n")
        (self.root / ".harnessguard.json").write_text(json.dumps({"ignore": ["HG001"], "exclude": ["skip.py"]}), encoding="utf-8")
        self.assertFalse(scan_path(self.root).findings)

    def test_sarif_is_valid_json(self):
        path = write(self.root, "bad.py", "eval(user_input)\n")
        payload = json.loads(render_sarif(scan_path(path)))
        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(payload["runs"][0]["results"][0]["ruleId"], "HG001")

    def test_cli_exit_threshold_and_json_output(self):
        path = write(self.root, "bad.py", "import requests\nrequests.get('https://example.invalid')\n")
        output = self.root / "report.json"
        self.assertEqual(main([str(path), "--format", "json", "--output", str(output), "--severity", "high"]), 0)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["findings"][0]["rule_id"], "HG019")

    def test_baseline_suppresses_existing_finding(self):
        path = write(self.root, "bad.py", "eval(user_input)\n")
        baseline = self.root / "baseline.json"
        self.assertEqual(main([str(path), "--write-baseline", str(baseline), "--output", str(self.root / "out.txt")]), 1)
        self.assertEqual(scan_path(path, baseline_path=str(baseline)).findings, [])


if __name__ == "__main__":
    unittest.main()

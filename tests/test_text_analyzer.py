import tempfile
import unittest
from pathlib import Path

from harnessguard.scanner import scan_path


class TextAnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_config_security_patterns(self):
        path = self.root / "agents.yaml"
        path.write_text("""
api_key: abcdefghijklmnop
tools: '*'
permissions: admin
filesystem: /
verify_ssl: false
""", encoding="utf-8")
        found = {x.rule_id for x in scan_path(path).findings}
        self.assertTrue({"HG008", "HG017", "HG018", "HG026", "HG030"} <= found)

    def test_placeholder_secret_is_not_reported(self):
        path = self.root / ".env"
        path.write_text("API_KEY=${API_KEY}\n", encoding="utf-8")
        self.assertFalse(scan_path(path).findings)


if __name__ == "__main__":
    unittest.main()

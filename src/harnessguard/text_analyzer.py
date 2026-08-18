from __future__ import annotations

import re
from pathlib import Path

from .models import Finding
from .rules import RULES


SECRET = re.compile(r"(?i)\b(api[_-]?key|secret|access[_-]?token|auth[_-]?token|password)\b\s*[:=]\s*['\"]?([A-Za-z0-9_./+\-=]{12,})")
WILDCARD = re.compile(r"(?i)(allowed[_-]?tools|tools|permissions|capabilities)\s*[:=]\s*(?:\[\s*)?['\"]?\*['\"]?")
ADMIN = re.compile(r"(?i)(tools|permissions|capabilities|role)\s*[:=].*\b(admin|root|superuser|all[_-]?access)\b")
FILESYSTEM = re.compile(r"(?i)(workspace|root|allowed[_-]?paths?|filesystem)\s*[:=]\s*['\"]?(?:/|[A-Za-z]:[\\/]|\*|~/?)(?:[\s'\",}\]]|$)")
ENV_DUMP = re.compile(r"(?i)(print|log|prompt|message|checkpoint).*(os\.environ|process\.env)|(?:os\.environ|process\.env).*(print|log|prompt|message|checkpoint)")


def _add(items: list[Finding], rule_id: str, display_path: str, line: int, column: int, snippet: str) -> None:
    rule = RULES[rule_id]
    items.append(Finding(rule.id, rule.name, rule.severity, rule.category, display_path, line, column, rule.message, rule.fix, snippet.strip()[:240]))


def analyze_text(path: Path, display_path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if "harnessguard: ignore" in line.lower():
            continue
        match = SECRET.search(line)
        if match and not any(token in line.lower() for token in ("example", "placeholder", "your_", "<", "${", "env", "dummy", "test")):
            _add(findings, "HG008", display_path, line_no, match.start() + 1, line)
        match = WILDCARD.search(line)
        if match:
            _add(findings, "HG017", display_path, line_no, match.start() + 1, line)
        match = ADMIN.search(line)
        if match:
            _add(findings, "HG018", display_path, line_no, match.start() + 1, line)
        match = FILESYSTEM.search(line)
        if match:
            _add(findings, "HG026", display_path, line_no, match.start() + 1, line)
        match = ENV_DUMP.search(line)
        if match:
            _add(findings, "HG009", display_path, line_no, match.start() + 1, line)
        if re.search(r"(?i)\b(verify_ssl|tls_verify|verify)\s*[:=]\s*false\b", line):
            _add(findings, "HG030", display_path, line_no, 1, line)
    return findings

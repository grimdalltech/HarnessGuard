from __future__ import annotations

import json

from .models import Finding
from .rules import RULES
from .scanner import ScanResult


COLORS = {"critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[96m", "info": "\033[94m"}
RESET = "\033[0m"


def render_text(result: ScanResult, color: bool = False) -> str:
    lines: list[str] = []
    for item in result.findings:
        sev = item.severity.upper()
        if color:
            sev = f"{COLORS[item.severity]}{sev}{RESET}"
        lines.append(f"{item.path}:{item.line}:{item.column}  {sev:<8} {item.rule_id} {item.rule_name}")
        lines.append(f"  {item.message}")
        lines.append(f"  Fix: {item.fix}")
    counts = {level: sum(1 for x in result.findings if x.severity == level) for level in ("critical", "high", "medium", "low", "info")}
    lines.append("")
    lines.append(f"Scanned {result.files_scanned} files; found {len(result.findings)} issues " + " ".join(f"{k}={v}" for k, v in counts.items() if v))
    if result.errors:
        lines.append(f"Parse/read warnings: {len(result.errors)}")
    return "\n".join(lines) + "\n"


def render_json(result: ScanResult) -> str:
    payload = {"tool": {"name": "HarnessGuard", "version": "0.1.0"}, "root": result.root, "files_scanned": result.files_scanned, "findings": [x.to_dict() for x in result.findings], "errors": result.errors}
    return json.dumps(payload, indent=2) + "\n"


def render_sarif(result: ScanResult) -> str:
    rules = []
    for rule in RULES.values():
        rules.append({"id": rule.id, "name": rule.name.replace(" ", ""), "shortDescription": {"text": rule.name}, "fullDescription": {"text": rule.message}, "help": {"text": rule.fix}, "defaultConfiguration": {"level": {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}[rule.severity]}})
    results = []
    for item in result.findings:
        results.append({"ruleId": item.rule_id, "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}[item.severity], "message": {"text": item.message}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": item.path.replace("\\", "/")}, "region": {"startLine": item.line, "startColumn": item.column}}}], "partialFingerprints": {"primaryLocationLineHash": item.fingerprint}})
    payload = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "HarnessGuard", "version": "0.1.0", "informationUri": "https://github.com/", "rules": rules}}, "results": results}]}
    return json.dumps(payload, indent=2) + "\n"

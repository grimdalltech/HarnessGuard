from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .baseline import write_baseline
from .models import SEVERITY_RANK
from .reporters import render_json, render_sarif, render_text
from .rules import all_rules
from .scanner import scan_path


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog="harnessguard", description="Offline static analysis for AI-agent orchestration harnesses")
    value.add_argument("path", nargs="?", default=".", help="file or directory to scan")
    value.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    value.add_argument("--output", "-o", help="write report to this file")
    value.add_argument("--severity", choices=tuple(SEVERITY_RANK), default="high", help="minimum severity that causes exit code 1")
    value.add_argument("--config", help="path to .harnessguard.json")
    value.add_argument("--baseline", help="suppress findings listed in baseline JSON")
    value.add_argument("--write-baseline", metavar="FILE", help="save current findings as a baseline")
    value.add_argument("--list-rules", action="store_true", help="list all built-in checks")
    value.add_argument("--no-color", action="store_true")
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.list_rules:
        for rule in all_rules():
            print(f"{rule.id} {rule.severity:<8} {rule.category:<18} {rule.name}")
        return 0
    try:
        result = scan_path(args.path, args.config, args.baseline)
    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"harnessguard: {exc}", file=sys.stderr)
        return 2
    if args.write_baseline:
        write_baseline(args.write_baseline, result.findings)
    renderer = {"text": render_text, "json": render_json, "sarif": render_sarif}[args.format]
    output = renderer(result, color=sys.stdout.isatty() and not args.no_color) if args.format == "text" else renderer(result)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
    threshold = SEVERITY_RANK[args.severity]
    return 1 if any(SEVERITY_RANK[item.severity] >= threshold for item in result.findings) else (2 if result.errors else 0)

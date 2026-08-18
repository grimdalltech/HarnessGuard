from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .baseline import load_baseline
from .config import Config, load_config
from .models import Finding
from .python_analyzer import analyze_python
from .text_analyzer import analyze_text


SUPPORTED = {".py", ".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env", ".md", ".txt"}
SPECIAL_NAMES = {"dockerfile", "mcp.json", "mcp_config.json", "requirements.txt"}


@dataclass
class ScanResult:
    findings: list[Finding]
    files_scanned: int
    errors: list[str]
    root: str


def _iter_files(target: Path, root: Path, config: Config):
    candidates = [target] if target.is_file() else target.rglob("*")
    for path in candidates:
        if not path.is_file():
            continue
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            rel = path.name
        if config.excluded(rel):
            continue
        if path.suffix.lower() not in SUPPORTED and path.name.lower() not in SPECIAL_NAMES:
            continue
        try:
            if path.stat().st_size > config.max_file_size:
                continue
        except OSError:
            continue
        yield path, rel


def scan_path(target: str | Path, config_path: str | None = None, baseline_path: str | None = None) -> ScanResult:
    target = Path(target).resolve()
    if not target.exists():
        raise FileNotFoundError(f"scan target does not exist: {target}")
    root = target if target.is_dir() else target.parent
    config = load_config(root, config_path)
    baseline = load_baseline(baseline_path)
    findings: list[Finding] = []
    errors: list[str] = []
    count = 0
    for path, rel in _iter_files(target, root, config):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            errors.append(f"{rel}: {exc}")
            continue
        count += 1
        file_findings = analyze_text(path, rel, text)
        if path.suffix.lower() == ".py":
            python_findings, error = analyze_python(path, rel, text)
            file_findings.extend(python_findings)
            if error:
                errors.append(error)
        findings.extend(item for item in file_findings if item.rule_id not in config.ignore and item.fingerprint not in baseline)
    findings.sort(key=lambda item: (item.path, item.line, item.rule_id))
    return ScanResult(findings, count, errors, str(root))

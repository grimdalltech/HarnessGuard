from __future__ import annotations

import json
from pathlib import Path

from .models import Finding


def load_baseline(path: str | None) -> set[str]:
    if not path:
        return set()
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("fingerprints", [])
    return {str(item) for item in data}


def write_baseline(path: str, findings: list[Finding]) -> None:
    payload = {"version": 1, "fingerprints": sorted({f.fingerprint for f in findings})}
    Path(path).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

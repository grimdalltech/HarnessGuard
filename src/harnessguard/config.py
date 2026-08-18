from __future__ import annotations

from dataclasses import dataclass, field
import fnmatch
import json
from pathlib import Path


DEFAULT_EXCLUDES = [
    ".git/*", ".venv/*", "venv/*", "node_modules/*", "dist/*", "build/*",
    "__pycache__/*", ".pytest_cache/*", ".mypy_cache/*", ".ruff_cache/*",
]


@dataclass
class Config:
    exclude: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    ignore: set[str] = field(default_factory=set)
    max_file_size: int = 1_000_000

    def excluded(self, relative_path: str) -> bool:
        value = relative_path.replace("\\", "/")
        return any(fnmatch.fnmatch(value, pattern) or fnmatch.fnmatch("/" + value, pattern) for pattern in self.exclude)


def load_config(root: Path, explicit: str | None = None) -> Config:
    config = Config()
    path = Path(explicit) if explicit else root / ".harnessguard.json"
    if not path.exists():
        return config
    data = json.loads(path.read_text(encoding="utf-8"))
    config.exclude.extend(str(x) for x in data.get("exclude", []))
    config.ignore.update(str(x).upper() for x in data.get("ignore", []))
    config.max_file_size = int(data.get("max_file_size", config.max_file_size))
    return config

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    category: str
    message: str
    fix: str


@dataclass(frozen=True)
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    category: str
    path: str
    line: int
    column: int
    message: str
    fix: str
    snippet: str = ""

    @property
    def fingerprint(self) -> str:
        raw = f"{self.rule_id}:{self.path}:{self.line}:{self.snippet.strip()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        value = asdict(self)
        value["fingerprint"] = self.fingerprint
        return value

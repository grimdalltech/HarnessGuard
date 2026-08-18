"""HarnessGuard: offline static analysis for AI-agent harnesses."""

from .models import Finding, Rule
from .scanner import ScanResult, scan_path

__all__ = ["Finding", "Rule", "ScanResult", "scan_path"]
__version__ = "0.1.0"

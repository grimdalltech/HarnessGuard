# HarnessGuard usage guide

This guide covers installing, configuring, and running HarnessGuard in detail. For the short version, see the README quickstart.

## Installation

HarnessGuard requires Python 3.10+ and has no runtime dependencies.

Install into the current environment:

```bash
python -m pip install -e .
```

Run without installing by putting `src` on the module path:

```bash
PYTHONPATH=src python -m harnessguard path/to/agent-project
```

PowerShell:

```powershell
$env:PYTHONPATH="src"
python -m harnessguard .
```

## Scanning basics

Scan a file or a directory. A directory is walked recursively; excluded patterns and file-size limits apply:

```bash
harnessguard path/to/agent-project
harnessguard src/harness.py
```

Set the minimum severity that causes a failing exit code:

```bash
harnessguard . --severity critical
harnessguard . --severity medium
```

Severities, weakest to strongest: `info`, `low`, `medium`, `high`, `critical`. The default policy threshold is `high`.

List every built-in check, its severity, and its category:

```bash
harnessguard --list-rules
```

## CLI reference

| Flag | Description |
|---|---|
| `path` | File or directory to scan. Defaults to `.`. |
| `--format text` | Human-readable report (default). |
| `--format json` | Structured JSON report. |
| `--format sarif` | SARIF 2.1 report for code-scanning tooling. |
| `--output FILE`, `-o FILE` | Write the report to a file instead of stdout. |
| `--severity LEVEL` | Minimum severity that fails the run (`info`..`critical`, default `high`). |
| `--config FILE` | Path to a `.harnessguard.json` config. Defaults to the scan root. |
| `--baseline FILE` | Suppress findings already recorded in the baseline. |
| `--write-baseline FILE` | Save the current findings as a baseline. |
| `--list-rules` | Print all built-in checks and exit. |
| `--no-color` | Disable ANSI color in text output. |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed and no finding reached the severity threshold. |
| `1` | Policy failed: at least one finding reached the severity threshold. |
| `2` | Scanner, config, or read error. |

## Configuration

Create `.harnessguard.json` in the scan root:

```json
{
  "exclude": ["generated/*", "vendor/*"],
  "ignore": ["HG029"],
  "max_file_size": 1000000
}
```

A template lives at `.harnessguard.example.json`.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `exclude` | string[] | common build/cache dirs | Glob patterns, relative to the scan root. |
| `ignore` | string[] | `[]` | Rule IDs to skip entirely. Prefer only after a security review. |
| `max_file_size` | int | `1000000` | Files larger than this many bytes are skipped. |

### Inline suppression

Suppress one line in any text or config file by including `harnessguard: ignore` on that line:

```python
app.secret = "sk-live-..."  # harnessguard: ignore
```

## Baselines

Adopt the scanner in an existing project without failing on old findings:

```bash
harnessguard . --write-baseline .harnessguard-baseline.json
harnessguard . --baseline .harnessguard-baseline.json
```

Fingerprints include rule, path, line, and snippet. A finding changes fingerprint when its rule, path, line, or snippet changes, so genuinely new findings reappear even when they land near an old one. Re-run `--write-baseline` after a deliberate remediation sweep.

## Output formats

Text, for humans:

```bash
harnessguard . --format text
```

JSON, for scripts:

```bash
harnessguard . --format json --output report.json
```

SARIF, for code-scanning platforms:

```bash
harnessguard . --format sarif --output harnessguard.sarif
```

Every finding carries rule ID, name, severity, category, path, line, column, message, suggested fix, and a stable fingerprint.

## Example walkthrough

The repository ships an intentionally vulnerable harness:

```powershell
$env:PYTHONPATH="src"
python -m harnessguard examples/vulnerable_harness.py --severity high
```

The demo contains dynamic `eval`-class sinks, unsafe subprocess use, pickle deserialization, unbounded delegation, code execution enabled, disabled human approval, missing HTTP timeout, environment leakage, and untrusted input concatenated into a prompt. The scan reports each as a finding with a fix hint. Do not deploy this file.

## CI

A least-privilege workflow is included at `.github/workflows/harnessguard.yml`. It scans on every push and pull request and uploads SARIF to GitHub code scanning:

```yaml
name: HarnessGuard
on:
  push:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Scan agent harness
        run: python -m harnessguard . --severity high --format sarif --output harnessguard.sarif
        env:
          PYTHONPATH: src
      - name: Upload SARIF
        if: ${{ always() && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository) }}
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: harnessguard.sarif
```

The `security-events: write` permission is required for the SARIF upload. The conditional guard prevents unauthorized uploads from forked pull requests.

## Rule lifecycle

Rule IDs are stable API. New rules add new IDs; released IDs never silently change meaning. When you add a detector, add a test that demonstrates the missed unsafe pattern or the false positive first.
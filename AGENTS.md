# HarnessGuard Integration Guide for Coding Agents

> **Read this file when you are an AI coding agent asked to add a security check to HarnessGuard, run HarnessGuard against a project, or wire HarnessGuard into CI.**
>
> Your job is to review harness source and configuration for deterministic, reviewable signals. Do not execute, patch, or "fix" the scanned project unless the user explicitly asks.

HarnessGuard is a zero-cost, offline static analyzer for AI-agent orchestration code. It reports **findings** — rule ID, severity, file, line, snippet, and a fix hint — never a proof of exploitability.

---

## 1. Core contract (do not violate)

- **Never call an LLM.** Detectors are deterministic AST and regular-expression checks over source text.
- **Never execute scanned code.** The scanner only reads supported text files and parses Python with the standard-library `ast` module.
- **Never upload code.** There is no endpoint, token, account, or network call in the scanner.
- **No runtime dependencies.** The scanner uses only the Python standard library (Python 3.10+).
- **Rule IDs are stable API.** Add new IDs; never silently change the meaning of a released ID.

---

## 2. Run HarnessGuard locally

Install:

```bash
python -m pip install -e .
harnessguard path/to/agent-project
```

Or run without installing by putting `src` on the module path:

```bash
# Linux / macOS
PYTHONPATH=src python -m harnessguard path/to/agent-project

# Windows PowerShell
$env:PYTHONPATH="src"
python -m harnessguard path/to/agent-project
```

Useful invocations:

```bash
harnessguard --list-rules                                  # print all built-in checks
harnessguard . --severity high                             # fail on high+ findings
harnessguard . --format json --output report.json          # structured output
harnessguard . --format sarif --output harnessguard.sarif  # GitHub code scanning
harnessguard . --write-baseline .harnessguard-baseline.json
```

Exit codes: `0` no finding at/above threshold; `1` policy failed; `2` scanner/config/read error.

---

## 3. Integrate HarnessGuard into a project

1. Add `.harnessguard.json` to the scan root (see `.harnessguard.example.json`).
2. Prefer `--severity high` in CI and review lower-severity findings manually.
3. Adopt into an existing project without failing on old findings using a baseline:

   ```bash
   harnessguard . --write-baseline .harnessguard-baseline.json
   harnessguard . --baseline .harnessguard-baseline.json
   ```

4. Add the least-privilege workflow (see `.github/workflows/harnessguard.yml`) to upload SARIF to GitHub code scanning.
5. Never disable a rule with `.harnessguard.json` `ignore` or inline `harnessguard: ignore` without a security review.

---

## 4. Add a new check

A new check is three small, coordinated changes plus a test.

### Step 1 — register the rule in `src/harnessguard/rules.py`

```python
_r("HG031", "Unsafe XYZ", "high", "some-category",
   "Describe the unsafe boundary you detected.",
   "Describe the safe remediation."),
```

Pick the **next unused ID** and a severity from `info` / `low` / `medium` / `high` / `critical`. Update the rule table in `README.md`.

### Step 2 — add the detector

- **Python (AST-aware)** — edit `src/harnessguard/python_analyzer.py`, add a `visit_*` method or extend `visit_Call`, and call `self.add("HG031", node)`. Use the existing helpers (`dotted`, `kw`, `kw_bool`, `kw_number`, `contains_name`, `literal`) instead of re-implementing them.
- **Text / config (line-level)** — edit `src/harnessguard/text_analyzer.py`, add a `re.compile(...)` pattern and call `_add(findings, "HG031", display_path, line_no, col, line)`.

Keep detectors conservative: prefer high-signal local patterns over inventing data flow the tool does not track.

### Step 3 — add a test

Add a test in `tests/test_scanner.py` or `tests/test_text_analyzer.py` that writes a small fixture and asserts the new rule ID appears. Run:

```bash
python -m unittest discover -s tests -v
```

A rule is not complete without a test that demonstrates both the caught pattern and (where relevant) a false-positive it should not fire on.

---

## 5. Verification checklist before declaring work done

- [ ] `harnessguard --list-rules` shows the correct rule count and IDs.
- [ ] `python -m unittest discover -s tests` passes.
- [ ] `harnessguard examples/vulnerable_harness.py --severity high` reports the expected findings.
- [ ] Any new rule has a test; any changed detector did not break existing tests.
- [ ] No third-party dependency was added; `dependencies = []` still holds.
- [ ] No scanned project module was imported or executed.
- [ ] README rule table, `docs/USAGE.md`, and this file are updated if behavior changed.

---

## 6. Copy-paste prompts for vibe coders

### Prompt: add a new detector

```text
Read https://github.com/grimdalltech/HarnessGuard/blob/main/AGENTS.md first.

Add a new deterministic check to HarnessGuard that detects <unsafe pattern>. Register the next unused rule ID and severity in src/harnessguard/rules.py, add the detector in src/harnessguard/python_analyzer.py (AST) or src/harnessguard/text_analyzer.py (regex), and add a unit test in tests/ that proves both a true positive and any important false negative. Do not add third-party dependencies, do not call an LLM, and do not execute scanned code. Update the README rule table.
```

### Prompt: wire HarnessGuard into CI

```text
Read https://github.com/grimdalltech/HarnessGuard/blob/main/AGENTS.md first.

Add HarnessGuard scanning to this project's CI. Install it with pip install -e . (or PYTHONPATH=src), run `harnessguard . --severity high --format sarif --output harnessguard.sarif`, and upload the SARIF to GitHub code scanning with least-privilege permissions and a fork-PR guard. Add a .harnessguard.json config that excludes generated/vendor directories and a baseline so existing findings do not fail the build. Do not send code to any external service.
```

### Prompt: audit a HarnessGuard setup

```text
Read https://github.com/grimdalltech/HarnessGuard/blob/main/AGENTS.md first.

Audit this HarnessGuard setup. Verify the scanner runs, the severity threshold and exit codes are correct, exclusions and rule ignores are justified, the baseline suppresses only intended findings, and the SARIF upload is least-privilege and fork-safe. Report verified evidence rather than assumptions and fix any gap without adding runtime dependencies.
```

---

## 7. Definition of done

A check is done only when it is deterministic, registered with a stable ID, backed by a test, documented in the README rule table, and does not introduce any runtime dependency or network call. A CI integration is done only when the scanner runs, produces SARIF, and uploads it with least-privilege, fork-safe permissions.

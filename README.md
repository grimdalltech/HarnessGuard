# HarnessGuard

**A zero-cost, offline static analyzer for AI-agent orchestration code.**

HarnessGuard finds security and reliability mistakes where agents, tools, state, and control loops are wired together. It never calls an LLM, never uploads code, and never executes the project it scans.

> Status: working alpha MVP. Findings are review signals, not proof of exploitability.

## Why this exists

The recurring failures reported across agent frameworks are not only model failures. They are ordinary engineering defects amplified by autonomous tools:

- agents loop until recursion or budget exhaustion;
- model-controlled text reaches shell, `eval`, files, or URLs;
- unsafe checkpoints deserialize attacker-controlled state;
- one compromised agent delegates to another without authorization;
- concurrent agents overwrite shared state;
- waits and HTTP calls hang without deadlines;
- prompts, environment variables, and tool output leak into logs;
- broad tool and filesystem permissions multiply blast radius.

Existing open-source tools mainly red-team live models, benchmark prompt injection, or scan MCP components. HarnessGuard targets the **harness source and configuration before execution**, fully locally.

## Fast start

Requires Python 3.10+ and no runtime dependencies.

```bash
python -m pip install -e .
harnessguard path/to/agent-project
```

Without installation:

```bash
PYTHONPATH=src python -m harnessguard path/to/agent-project
```

Windows PowerShell:

```powershell
$env:PYTHONPATH="src"
python -m harnessguard .
```

Scan the intentionally vulnerable example:

```powershell
$env:PYTHONPATH="src"
python -m harnessguard examples/vulnerable_harness.py --severity high
```

Exit codes: `0` no finding at/above threshold; `1` policy failed; `2` scanner/config/read error.

## Outputs and CI

```bash
harnessguard . --format text
harnessguard . --format json --output report.json
harnessguard . --format sarif --output harnessguard.sarif
harnessguard . --severity medium
```

A least-privilege GitHub Actions workflow is included at `.github/workflows/harnessguard.yml`. SARIF can appear in GitHub code scanning when code-security upload is available for the repository.

## The 30 built-in checks

| ID | Severity | Check |
|---|---|---|
| HG001 | critical | Dynamic `eval` |
| HG002 | critical | Dynamic `exec` |
| HG003 | critical | Dynamic shell command |
| HG004 | high | Unsafe subprocess arguments |
| HG005 | critical | Pickle/dill deserialization |
| HG006 | high | YAML load without `SafeLoader` |
| HG007 | critical | Dangerous deserialization enabled |
| HG008 | critical | Secret-like literal |
| HG009 | high | Whole environment sent to model/log |
| HG010 | critical | Environment secrets imported into serializer |
| HG011 | high | LangGraph-style invocation without recursion limit |
| HG012 | high | CrewAI agent without `max_iter` |
| HG013 | critical | Zero, negative, or huge execution budget |
| HG014 | high | Automatic delegation without a budget |
| HG015 | critical | Agent code execution enabled |
| HG016 | medium | Human approval explicitly disabled |
| HG017 | high | Wildcard tool permission |
| HG018 | high | Admin/root/all-access capability grant |
| HG019 | medium | HTTP request without timeout |
| HG020 | high | Blocking wait without timeout |
| HG021 | medium | Thread join without timeout |
| HG022 | high | Unbounded retry/agent loop |
| HG023 | medium | Async shared-state mutation without visible lock |
| HG024 | high | Tool parameter used directly as file path |
| HG025 | high | Tool parameter used directly as URL |
| HG026 | high | Root/full-filesystem access |
| HG027 | medium | Untrusted data concatenated into prompt |
| HG028 | medium | Raw agent-output handoff |
| HG029 | high | Sensitive prompt/message logging |
| HG030 | high | TLS verification disabled |

List rules from the CLI:

```bash
harnessguard --list-rules
```

## Configuration and baselines

Create `.harnessguard.json` in the scan root:

```json
{
  "exclude": ["generated/*", "vendor/*"],
  "ignore": ["HG029"],
  "max_file_size": 1000000
}
```

Suppress one line inline in text/config files by including `harnessguard: ignore`. Prefer project-level rule ignores only after a security review.

Adopt the scanner in an existing project without failing on old findings:

```bash
harnessguard . --write-baseline .harnessguard-baseline.json
harnessguard . --baseline .harnessguard-baseline.json
```

Fingerprints include rule, path, line, and snippet; changed findings reappear.

## Detection model

Python gets AST-aware checks. JSON, JSONC, YAML, TOML, INI, environment, Markdown, and text files get conservative line-level checks. Large, generated, dependency, and binary files are skipped. No imported project modules are loaded.

This MVP emphasizes high-signal local patterns and deliberately avoids claiming full taint analysis. A finding means “review this boundary.” Future versions should add language-neutral data flow, framework adapters, dependency advisory matching, and policy-as-code.

## Research evidence

Public reports demonstrate the pain:

- [LangGraph #6731: recursion limit can allow many expensive calls](https://github.com/langchain-ai/langgraph/issues/6731)
- [LangGraph #7313: numeric recursion limit is a poor stopping contract](https://github.com/langchain-ai/langgraph/issues/7313)
- [CrewAI #737: repeated identical tool calls](https://github.com/crewAIInc/crewAI/issues/737)
- [CrewAI #2997: task stuck in a silent THINKING hang](https://github.com/crewAIInc/crewAI/issues/2997)
- [AutoGen #7144: shared state across planner/executor/reviewer agents](https://github.com/microsoft/autogen/discussions/7144)
- [AutoGen #7726: governance controls around multi-agent tool execution](https://github.com/microsoft/autogen/discussions/7726)
- [AutoGen #7784: prompt-injected delegation](https://github.com/microsoft/autogen/discussions/7784)
- [LangChain advisory GHSA-c67j-w6g6-q2cm: unsafe deserialization](https://github.com/langchain-ai/langchain/security/advisories/GHSA-c67j-w6g6-q2cm)
- [Microsoft analysis: prompts reaching unsafe framework functions](https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/)
- [Prompt Infection research: injection propagating between agents](https://arxiv.org/html/2410.07283v1)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

Nearby tools include [garak](https://github.com/NVIDIA/garak), [PyRIT](https://github.com/Azure/PyRIT), [AgentDojo](https://github.com/ethz-spylab/agentdojo), and [Snyk Agent Scan](https://github.com/snyk/agent-scan). Their scopes differ: HarnessGuard’s MVP is deterministic static scanning of orchestration code with no endpoint, token, account, or paid API.

## Roadmap

1. Benchmark rules against real vulnerable and fixed framework examples.
2. Add taint tracking from prompt/tool inputs to dangerous sinks.
3. Add framework adapters for LangGraph, CrewAI, AutoGen, Semantic Kernel, PydanticAI, smolagents, and MCP.
4. Add JavaScript/TypeScript and C# parsers without compromising offline use.
5. Map checks to OWASP Agentic categories and published advisories in machine-readable metadata.
6. Add safe autofix suggestions and reusable pre-commit integration.

## Development

```bash
python -m pip install -e .
python -m unittest discover -s tests
harnessguard .
```

See `CONTRIBUTING.md` and `SECURITY.md`. Licensed under MIT.

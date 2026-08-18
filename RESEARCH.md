# GitHub-first problem validation

Research date: 2026-08-18.

## Validated pain

| Pain | Public evidence | Product implication |
|---|---|---|
| Runaway loops and repeated calls | [LangGraph #6731](https://github.com/langchain-ai/langgraph/issues/6731), [LangGraph #7313](https://github.com/langchain-ai/langgraph/issues/7313), [CrewAI #737](https://github.com/crewAIInc/crewAI/issues/737) | Detect absent or unsafe iteration, recursion, delegation, retry, and timeout budgets. |
| Silent hangs | [CrewAI #2997](https://github.com/crewAIInc/crewAI/issues/2997), [CrewAI #3871](https://github.com/crewAIInc/crewAI/issues/3871) | Detect waits and network calls without deadlines. |
| Governance and cross-agent authorization | [AutoGen #7726](https://github.com/microsoft/autogen/discussions/7726), [AutoGen #7784](https://github.com/microsoft/autogen/discussions/7784), [CrewAI #3235](https://github.com/crewAIInc/crewAI/discussions/3235) | Analyze delegation, broad tool grants, approval gates, and shared identities. |
| Shared-state safety | [AutoGen #7144](https://github.com/microsoft/autogen/discussions/7144) | Warn on uncoordinated async state mutation. |
| Unsafe execution exposed to prompts | [Microsoft security analysis](https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/), [LangChain experimental advisories](https://advisories.gitlab.com/pkg/pypi/langchain-experimental/) | Trace model/tool inputs toward code, shell, file, URL, and deserialization sinks. |
| Injection propagation | [Prompt Infection](https://arxiv.org/html/2410.07283v1), [cross-agent injection research](https://arxiv.org/html/2506.23260v1) | Flag raw handoffs and untrusted data mixed with instructions. |
| Agentic risk is systemic | [OWASP Agentic Top 10 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | Report findings as harness controls, not merely model defects. |

## Existing-tool gap

| Tool | Strength | Gap relative to this project |
|---|---|---|
| [garak](https://github.com/NVIDIA/garak) | Model vulnerability probes | Needs a live target; does not lint orchestration source/config. |
| [PyRIT](https://github.com/Azure/PyRIT) | Extensible generative-AI red teaming | Orchestrates attacks against endpoints rather than deterministic source scanning. |
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) | Agent prompt-injection benchmark | Evaluation environment, not a local harness linter. |
| [Snyk Agent Scan](https://github.com/snyk/agent-scan) | Scans agent components and MCP assets | Account/token-backed product scope; not a dependency-free orchestration-code SAST. |

## Chosen wedge

A small offline CLI has a credible adoption wedge because it can run on a laptop, pre-commit hook, or CI runner without sending proprietary agent code to a vendor. The MVP makes no model calls and uses only Python’s standard library.

The differentiator is not a generic “AI security scanner.” It is a **control-plane linter**: it checks how autonomous components are allowed to loop, delegate, execute tools, access state, ingest untrusted content, and stop.

## MVP success criteria

- Runs on Python 3.10+ with no runtime dependencies.
- Does not import or execute scanned projects.
- Ships 30 named checks across security and coordination reliability.
- Produces human-readable, JSON, and SARIF reports.
- Supports severity policy, exclusions, rule ignores, and adoption baselines.
- Includes a vulnerable sample, automated tests, MIT license, contribution guide, security policy, and GitHub Actions workflow.

## Known limitations

The MVP is Python-first and uses heuristic scanning for configuration files. It is not a proof of exploitability, a replacement for dependency scanning, or a complete interprocedural taint engine. Precision must be measured on real repositories before a 1.0 release.

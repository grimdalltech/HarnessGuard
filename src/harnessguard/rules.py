from __future__ import annotations

from .models import Rule


def _r(id: str, name: str, severity: str, category: str, message: str, fix: str) -> Rule:
    return Rule(id, name, severity, category, message, fix)


RULES = {
    r.id: r
    for r in [
        _r("HG001", "Dynamic eval", "critical", "unsafe-execution", "Dynamic eval() may execute model-controlled text.", "Remove eval or parse with a strict, typed parser."),
        _r("HG002", "Dynamic exec", "critical", "unsafe-execution", "Dynamic exec() may execute model-controlled text.", "Remove exec and expose a narrow allowlisted operation."),
        _r("HG003", "Shell command injection", "critical", "unsafe-execution", "A shell command is constructed dynamically.", "Use an argument array, shell=False, and validate every argument."),
        _r("HG004", "Unsafe subprocess", "high", "unsafe-execution", "A subprocess call uses non-literal input.", "Use fixed executables and an allowlist for arguments."),
        _r("HG005", "Unsafe pickle load", "critical", "deserialization", "pickle can execute code while loading agent state.", "Use JSON or a typed schema; never load untrusted pickle data."),
        _r("HG006", "Unsafe YAML load", "high", "deserialization", "yaml.load without SafeLoader can construct arbitrary objects.", "Use yaml.safe_load or SafeLoader."),
        _r("HG007", "Dangerous deserialization enabled", "critical", "deserialization", "Dangerous deserialization is explicitly enabled.", "Disable the option and migrate the artifact to a safe format."),
        _r("HG008", "Secret-like literal", "critical", "secrets", "A likely credential is embedded in source or configuration.", "Revoke it, remove it from history, and load it from a secret store."),
        _r("HG009", "Environment dumped to model/log", "high", "secrets", "The complete process environment may reach a model, log, or checkpoint.", "Pass an explicit allowlist of non-secret values."),
        _r("HG010", "Secrets imported into serialization", "critical", "secrets", "Serializer is configured to import environment secrets.", "Set secrets_from_env=False and rotate exposed credentials."),
        _r("HG011", "Unbounded LangGraph invocation", "high", "runaway-agency", "Graph invocation has no explicit recursion limit.", "Pass config with a conservative recursion_limit and handle the limit error."),
        _r("HG012", "CrewAI iterations unbounded", "high", "runaway-agency", "Agent configuration does not define max_iter.", "Set max_iter and enforce a separate run deadline."),
        _r("HG013", "Unlimited framework iterations", "critical", "runaway-agency", "An iteration/step/recursion budget is zero, negative, or excessively high.", "Use a small positive limit appropriate for the workflow."),
        _r("HG014", "Automatic delegation without budget", "high", "authorization", "Delegation is enabled without visible iteration/delegation limits.", "Set delegation depth and call budgets; require authorization for handoffs."),
        _r("HG015", "Code execution enabled", "critical", "unsafe-execution", "Agent-side code execution is enabled.", "Disable it or run an isolated, disposable sandbox with no secrets/network."),
        _r("HG016", "Human approval disabled", "medium", "authorization", "A high-agency workflow explicitly disables human approval.", "Add approval for irreversible or high-impact tool calls."),
        _r("HG017", "Wildcard tool permission", "high", "authorization", "An agent or MCP configuration grants wildcard tool access.", "Replace '*' with the minimum required tool names."),
        _r("HG018", "Admin capability exposed", "high", "authorization", "Admin/root/all-access capability appears in an agent tool grant.", "Use a least-privilege service identity and scoped tools."),
        _r("HG019", "Unbounded HTTP request", "medium", "availability", "HTTP call has no explicit timeout.", "Set connect/read timeouts and a total workflow deadline."),
        _r("HG020", "Blocking wait without timeout", "high", "availability", "A blocking wait can hang the coordinator indefinitely.", "Set a timeout and handle cancellation/partial completion."),
        _r("HG021", "Thread join without timeout", "medium", "availability", "Thread join has no timeout.", "Pass a timeout and surface an explicit failure state."),
        _r("HG022", "Unbounded retry loop", "high", "availability", "An unconditional loop contains retry/agent activity but no obvious bound.", "Use capped exponential backoff and a terminal failure state."),
        _r("HG023", "Concurrent shared-state write", "medium", "concurrency", "Shared state is mutated inside async code without visible synchronization.", "Use immutable state transitions, a lock, or versioned compare-and-swap."),
        _r("HG024", "LLM-controlled file path", "high", "path-traversal", "A model/tool parameter flows directly into a file operation.", "Resolve beneath an allowlisted root and reject traversal/symlinks."),
        _r("HG025", "LLM-controlled URL fetch", "high", "ssrf", "A model/tool parameter flows directly into a network request.", "Allowlist schemes/hosts and block private/link-local address ranges."),
        _r("HG026", "Overbroad filesystem access", "high", "authorization", "Agent configuration grants root or full-filesystem access.", "Mount a narrow workspace and deny sensitive paths."),
        _r("HG027", "Prompt concatenation with untrusted input", "medium", "prompt-injection", "Untrusted input is concatenated into instructions.", "Keep instructions separate from data and validate tool decisions."),
        _r("HG028", "Raw agent-output handoff", "medium", "prompt-injection", "Raw agent output is forwarded to another agent.", "Use a typed schema, provenance labels, and an authorization gate."),
        _r("HG029", "Sensitive prompt logging", "high", "secrets", "Prompt/message content may be written directly to logs.", "Redact credentials and personal data before structured logging."),
        _r("HG030", "TLS verification disabled", "high", "transport", "TLS certificate verification is disabled.", "Enable verification and configure a trusted CA bundle."),
    ]
}


def all_rules() -> tuple[Rule, ...]:
    return tuple(RULES.values())

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable

from .models import Finding
from .rules import RULES


TOOL_DECORATORS = {"tool", "function_tool", "kernel_function", "mcp.tool", "server.tool"}
NETWORK_CALLS = {"requests.get", "requests.post", "requests.put", "requests.delete", "requests.request", "httpx.get", "httpx.post", "urllib.request.urlopen"}
BLOCKING_WAITS = {"future.result", "queue.get", "event.wait", "condition.wait", "process.wait", "subprocess.run", "subprocess.call", "subprocess.check_output"}
FILE_CALLS = {"open", "pathlib.Path", "Path", "os.remove", "os.unlink", "shutil.rmtree", "shutil.copy", "shutil.move"}
HANDOFF_NAMES = {"send", "handoff", "delegate", "delegate_task", "initiate_chat", "run_agent", "transfer_to_agent"}


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = dotted(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def literal(node: ast.AST | None) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(literal(x) for x in node.elts)
    return False


def kw(call: ast.Call, name: str) -> ast.AST | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


def kw_bool(call: ast.Call, name: str) -> bool | None:
    value = kw(call, name)
    if isinstance(value, ast.Constant) and isinstance(value.value, bool):
        return value.value
    return None


def kw_number(call: ast.Call, name: str) -> int | float | None:
    value = kw(call, name)
    if isinstance(value, ast.Constant) and isinstance(value.value, (int, float)):
        return value.value
    if isinstance(value, ast.UnaryOp) and isinstance(value.op, ast.USub) and isinstance(value.operand, ast.Constant):
        if isinstance(value.operand.value, (int, float)):
            return -value.operand.value
    return None


def contains_name(node: ast.AST, names: set[str]) -> bool:
    return any(isinstance(x, ast.Name) and x.id in names for x in ast.walk(node))


class PythonAnalyzer(ast.NodeVisitor):
    def __init__(self, path: Path, display_path: str, text: str) -> None:
        self.path = path
        self.display_path = display_path
        self.lines = text.splitlines()
        self.findings: list[Finding] = []
        self.tool_params: list[set[str]] = []
        self.async_depth = 0
        self.loop_depth = 0
        self.lock_depth = 0

    def add(self, rule_id: str, node: ast.AST, message: str | None = None) -> None:
        rule = RULES[rule_id]
        line = getattr(node, "lineno", 1)
        column = getattr(node, "col_offset", 0) + 1
        snippet = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        self.findings.append(Finding(rule.id, rule.name, rule.severity, rule.category, self.display_path, line, column, message or rule.message, rule.fix, snippet[:240]))

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.async_depth += 1
        self._visit_function(node)
        self.async_depth -= 1

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        decorator_names = {dotted(x.func if isinstance(x, ast.Call) else x) for x in node.decorator_list}
        is_tool = bool(decorator_names & TOOL_DECORATORS or any(x.endswith(".tool") for x in decorator_names))
        params = {arg.arg for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)} if is_tool else set()
        self.tool_params.append(params)
        for child in node.body:
            self.visit(child)
        self.tool_params.pop()

    def visit_With(self, node: ast.With) -> None:
        locked = any("lock" in dotted(item.context_expr).lower() for item in node.items)
        self.lock_depth += int(locked)
        self.generic_visit(node)
        self.lock_depth -= int(locked)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self.visit_With(node)  # type: ignore[arg-type]

    def visit_While(self, node: ast.While) -> None:
        self.loop_depth += 1
        if isinstance(node.test, ast.Constant) and node.test.value is True:
            source_names = {dotted(x.func).lower() for x in ast.walk(node) if isinstance(x, ast.Call)}
            if any(any(token in name for token in ("retry", "agent", "invoke", "run", "kickoff")) for name in source_names):
                self.add("HG022", node)
        self.generic_visit(node)
        self.loop_depth -= 1

    def visit_Call(self, node: ast.Call) -> None:
        name = dotted(node.func)
        lower = name.lower()
        args = node.args

        if name == "eval" or lower.endswith(".eval"):
            self.add("HG001", node)
        if name == "exec" or lower.endswith(".exec"):
            self.add("HG002", node)
        if name in {"pickle.load", "pickle.loads", "dill.load", "dill.loads"}:
            self.add("HG005", node)
        if name == "yaml.load" and dotted(kw(node, "Loader") or ast.Constant()).lower() not in {"safeloader", "yaml.safeloader"}:
            self.add("HG006", node)
        if kw_bool(node, "allow_dangerous_deserialization") is True:
            self.add("HG007", node)
        if kw_bool(node, "secrets_from_env") is True:
            self.add("HG010", node)
        if lower.endswith((".invoke", ".ainvoke", ".stream", ".astream")) and ("graph" in lower or "app." in lower):
            has_config = kw(node, "config") is not None or len(args) > 1
            if not has_config:
                self.add("HG011", node)
        if lower.endswith(("agent", "assistantagent")) or name in {"Agent", "crewai.Agent"}:
            has_max = any(item.arg in {"max_iter", "max_iterations", "max_steps"} for item in node.keywords)
            if ("crewai" in lower or name == "Agent") and not has_max:
                self.add("HG012", node)
        for budget in ("max_iter", "max_iterations", "max_steps", "recursion_limit"):
            value = kw_number(node, budget)
            if value is not None and (value <= 0 or value > 1000):
                self.add("HG013", node, f"{budget}={value} is not a safe execution budget.")
        if kw_bool(node, "allow_delegation") is True:
            has_budget = any(item.arg in {"max_iter", "max_iterations", "max_steps", "max_delegations"} for item in node.keywords)
            if not has_budget:
                self.add("HG014", node)
        if kw_bool(node, "allow_code_execution") is True:
            self.add("HG015", node)
        for approval in ("human_input", "human_approval", "require_approval", "interrupt_before"):
            if kw_bool(node, approval) is False:
                self.add("HG016", node)
        if kw_bool(node, "verify") is False:
            self.add("HG030", node)

        is_subprocess = name in {"os.system", "subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call"}
        if is_subprocess:
            shell = name == "os.system" or kw_bool(node, "shell") is True
            dynamic = bool(args) and not literal(args[0])
            if shell and dynamic:
                self.add("HG003", node)
            elif dynamic:
                self.add("HG004", node)

        if name in NETWORK_CALLS:
            if kw(node, "timeout") is None:
                self.add("HG019", node)
            if args and self._uses_tool_param(args[0]):
                self.add("HG025", node)
        if any(lower == wait or lower.endswith("." + wait) for wait in BLOCKING_WAITS):
            if kw(node, "timeout") is None:
                self.add("HG020", node)
        if lower.endswith(".join") and kw(node, "timeout") is None and len(args) == 0:
            self.add("HG021", node)
        if name in FILE_CALLS and args and self._uses_tool_param(args[0]):
            self.add("HG024", node)
        if any(lower.endswith("." + item) or lower == item for item in HANDOFF_NAMES):
            payload = kw(node, "message") or kw(node, "task") or (args[0] if args else None)
            if payload is not None and not literal(payload):
                self.add("HG028", node)
        if lower.endswith(("logger.info", "logger.debug", "logging.info", "logging.debug", "print")):
            if any(contains_name(arg, {"prompt", "messages", "api_key", "token", "secret"}) for arg in args):
                self.add("HG029", node)

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if self.async_depth and self.lock_depth == 0:
            for target in node.targets:
                if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and target.value.id in {"state", "shared_state", "context", "memory"}:
                    self.add("HG023", node)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if self.async_depth and self.lock_depth == 0 and isinstance(node.target, (ast.Subscript, ast.Attribute)):
            root = node.target.value if isinstance(node.target, ast.Attribute) else node.target.value
            if isinstance(root, ast.Name) and root.id in {"state", "shared_state", "context", "memory"}:
                self.add("HG023", node)
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        if isinstance(node.op, ast.Add) and contains_name(node, {"user_input", "tool_output", "web_content", "email_body", "document_text"}):
            if contains_name(node, {"prompt", "system_prompt", "instructions"}):
                self.add("HG027", node)
        self.generic_visit(node)

    def _uses_tool_param(self, node: ast.AST) -> bool:
        params = set().union(*self.tool_params) if self.tool_params else set()
        return bool(params and contains_name(node, params))


def analyze_python(path: Path, display_path: str, text: str) -> tuple[list[Finding], str | None]:
    try:
        tree = ast.parse(text, filename=display_path)
    except SyntaxError as exc:
        return [], f"{display_path}:{exc.lineno}: could not parse Python: {exc.msg}"
    analyzer = PythonAnalyzer(path, display_path, text)
    analyzer.visit(tree)
    return analyzer.findings, None

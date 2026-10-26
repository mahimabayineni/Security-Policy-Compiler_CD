
"""Static Application Security Testing (SAST) for generated Python code.

This module inspects Python source without executing it. It detects selected
risky patterns; it is not a complete security audit or sandbox.
"""

import ast
from dataclasses import dataclass
from typing import List


@dataclass
class SASTFinding:
    rule_id: str
    severity: str
    line: int
    message: str
    recommendation: str

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": self.line,
            "message": self.message,
            "recommendation": self.recommendation,
        }


class _SecurityVisitor(ast.NodeVisitor):
    """Collect selected risky Python source patterns."""

    def __init__(self):
        self.findings: List[SASTFinding] = []

    def add(self, node, rule_id, severity, message, recommendation):
        self.findings.append(
            SASTFinding(
                rule_id=rule_id,
                severity=severity,
                line=getattr(node, "lineno", 1),
                message=message,
                recommendation=recommendation,
            )
        )

    def visit_Call(self, node):
        func = node.func

        # Direct calls such as eval(...) or exec(...).
        if isinstance(func, ast.Name) and func.id in {"eval", "exec"}:
            self.add(
                node,
                "PY001",
                "HIGH",
                f"Dynamic code execution using {func.id}() can execute code strings.",
                "Avoid dynamic execution where possible; use explicit parsing "
                "or a restricted, purpose-built interpreter.",
            )

        # os.system(...) and subprocess functions.
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            module = func.value.id
            name = func.attr

            if module == "os" and name == "system":
                self.add(
                    node,
                    "PY002",
                    "HIGH",
                    "os.system() invokes a system command through a shell.",
                    "Prefer a fixed executable and argument list, with shell=False.",
                )

            if module == "subprocess" and name in {
                "run", "Popen", "call", "check_call", "check_output"
            }:
                shell_true = any(
                    kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                    for kw in node.keywords
                )
                if shell_true:
                    self.add(
                        node,
                        "PY003",
                        "HIGH",
                        f"subprocess.{name}() uses shell=True.",
                        "Avoid shell=True; pass a fixed executable and argument "
                        "list, and validate untrusted arguments.",
                    )

            if module == "pickle" and name in {"load", "loads"}:
                self.add(
                    node,
                    "PY004",
                    "HIGH",
                    f"pickle.{name}() can execute code when loading malicious data.",
                    "Do not deserialize untrusted pickle data; use a safer "
                    "data format such as JSON.",
                )

        self.generic_visit(node)


def analyze_python_source(source: str) -> List[SASTFinding]:
    """Statically analyze Python source and return findings.

    Raises SyntaxError if the supplied source is not valid Python.
    The source is parsed but never executed.
    """
    tree = ast.parse(source)
    visitor = _SecurityVisitor()
    visitor.visit(tree)

    # Keep output deterministic and avoid duplicate findings.
    unique = {}
    for finding in visitor.findings:
        key = (
            finding.rule_id,
            finding.line,
            finding.message,
        )
        unique[key] = finding

    return sorted(
        unique.values(),
        key=lambda item: (item.line, item.rule_id),
    )


def format_sast_report(findings: List[SASTFinding]) -> str:
    """Format findings as a readable terminal report."""
    if not findings:
        return "[PASS] SAST found no configured risky patterns."

    lines = [f"[WARN] SAST found {len(findings)} potential issue(s):"]
    for finding in findings:
        lines.append(
            f"  [{finding.severity}] {finding.rule_id} "
            f"(line {finding.line}): {finding.message}"
        )
        lines.append(f"      Recommendation: {finding.recommendation}")

    return "\n".join(lines)

"""
Phase 3: Semantic Analysis (semantic_analyzer.py)

Context-sensitive checks that a context-free grammar cannot express:
- rule names are unique
- protocol is one of TCP, UDP, ICMP, ANY
- port is 1-65535 or ANY (ICMP rules: ANY or 0, since ICMP has no ports)
- source is a named source, a valid IPv4 address, or a valid IPv4 CIDR block
- action is ALLOW or BLOCK (DENY is normalized to BLOCK by the parser)

Errors are fatal and point at the offending token. Warnings are non-fatal.
After a successful analysis, normalized_policy() returns a canonical AST
(ICMP PORT 0 -> ANY, CIDR host bits cleared) for the later phases.
"""

import ipaddress
from typing import List, Set

from src.parser import PolicyNode, RuleNode


class SemanticError:
    """A single semantic diagnostic (used for both errors and warnings)."""

    def __init__(self, rule_name: str, message: str, line: int, column: int, kind: str = "Error"):
        self.rule_name = rule_name
        self.message = message
        self.line = line
        self.column = column
        self.kind = kind

    def __repr__(self) -> str:
        return f"Semantic{self.kind}(rule='{self.rule_name}', line={self.line}, col={self.column}, msg='{self.message}')"

    def format(self) -> str:
        return f"Semantic {self.kind} in rule '{self.rule_name}' [Line {self.line}, Col {self.column}]: {self.message}"


class SemanticAnalysisError(Exception):
    """Raised when one or more fatal semantic errors are found."""

    def __init__(self, errors: List[SemanticError]):
        self.errors = errors
        details = "\n".join(f"  - {err.format()}" for err in errors)
        super().__init__(f"Semantic analysis failed with {len(errors)} error(s):\n{details}")


class SemanticAnalyzer:
    """Checks an AST against the DSL's static semantic rules."""

    VALID_PROTOCOLS = {"TCP", "UDP", "ICMP", "ANY"}
    VALID_ACTIONS = {"ALLOW", "BLOCK"}
    VALID_NAMED_SOURCES = {"ANY", "UNKNOWN", "INTERNAL", "EXTERNAL"}

    def __init__(self, ast: PolicyNode):
        self.ast = ast
        self.errors: List[SemanticError] = []
        self.warnings: List[SemanticError] = []
        self.defined_rule_names: Set[str] = set()

    # ---- public API -------------------------------------------------------------
    def analyze(self) -> List[SemanticError]:
        """Runs all checks. Returns the list of fatal errors (warnings are in self.warnings)."""
        self.errors.clear()
        self.warnings.clear()
        self.defined_rule_names.clear()

        for rule in self.ast.rules:
            self._validate_rule_identifier(rule)
            self._validate_protocol(rule)
            self._validate_port(rule)
            self._validate_source(rule)
            self._validate_action(rule)
        return self.errors

    def analyze_or_raise(self) -> None:
        if self.analyze():
            raise SemanticAnalysisError(self.errors)

    def normalized_policy(self) -> PolicyNode:
        """Canonical copy of the AST. Only valid after analyze() returned no errors."""
        rules = []
        for rule in self.ast.rules:
            port = rule.port
            if rule.protocol == "ICMP" and port == 0:
                port = "ANY"
            source = rule.source
            if source.upper() in self.VALID_NAMED_SOURCES:
                source = source.upper()
            elif "/" in source:
                source = str(ipaddress.ip_network(source, strict=False))
            rules.append(rule.copy(port=port, source=source))
        return PolicyNode(rules)

    # ---- helpers -------------------------------------------------------------------
    def _error(self, rule: RuleNode, field: str, message: str) -> None:
        line, col = rule.pos(field)
        self.errors.append(SemanticError(rule.name, message, line, col))

    def _warn(self, rule: RuleNode, field: str, message: str) -> None:
        line, col = rule.pos(field)
        self.warnings.append(SemanticError(rule.name, message, line, col, kind="Warning"))

    # ---- checks ----------------------------------------------------------------------
    def _validate_rule_identifier(self, rule: RuleNode) -> None:
        if rule.name in self.defined_rule_names:
            self._error(rule, "name",
                        f"Duplicate rule identifier '{rule.name}'. Rule names must be unique within a policy.")
        else:
            self.defined_rule_names.add(rule.name)

    def _validate_protocol(self, rule: RuleNode) -> None:
        if rule.protocol not in self.VALID_PROTOCOLS:
            self._error(rule, "protocol",
                        f"Unsupported transport protocol '{rule.protocol}'. "
                        f"Supported protocols are: {', '.join(sorted(self.VALID_PROTOCOLS))}.")

    def _validate_port(self, rule: RuleNode) -> None:
        port = rule.port
        if isinstance(port, str):
            if port.upper() != "ANY":
                self._error(rule, "port",
                            f"Invalid port value '{port}'. Port must be an integer between 1 and 65535, or 'ANY'.")
            return

        if rule.protocol == "ICMP":
            # ICMP is a network-layer protocol: it has no transport port numbers.
            if port != 0:
                self._error(rule, "port",
                            f"Protocol ICMP does not use TCP/UDP port numbers (found port {port}). "
                            "Specify port 'ANY' (or 0) for ICMP rules.")
            return

        if not (1 <= port <= 65535):
            self._error(rule, "port",
                        f"Port number {port} out of range. Valid network port range is 1 to 65535.")

    def _validate_source(self, rule: RuleNode) -> None:
        src = rule.source.strip()
        if src.upper() in self.VALID_NAMED_SOURCES:
            return
        if "/" not in src and self._is_valid_ipv4(src):
            return
        if "/" in src:
            address = src.split("/", 1)[0]
            if self._is_valid_ipv4(address):
                try:
                    strict_net = ipaddress.ip_network(src, strict=True)
                    if strict_net.prefixlen == 0:
                        self._warn(rule, "source", f"'{src}' matches every IPv4 address; consider SOURCE ANY.")
                    return
                except ValueError:
                    try:
                        net = ipaddress.ip_network(src, strict=False)
                        self._warn(rule, "source",
                                   f"CIDR '{src}' has host bits set; it is treated as network '{net}'.")
                        return
                    except ValueError:
                        pass
        self._error(rule, "source",
                    f"Invalid source condition '{src}'. Must be ANY, UNKNOWN, INTERNAL, EXTERNAL, "
                    "a valid IPv4 address (e.g. 192.168.1.1), or a CIDR subnet (e.g. 10.0.0.0/24).")

    @staticmethod
    def _is_valid_ipv4(val: str) -> bool:
        parts = val.split(".")
        if len(parts) != 4:
            return False
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

    def _validate_action(self, rule: RuleNode) -> None:
        if rule.action not in self.VALID_ACTIONS:
            self._error(rule, "action",
                        f"Invalid action '{rule.action}'. Permitted actions are ALLOW or BLOCK (DENY = BLOCK).")


def format_semantic_report(errors: List[SemanticError], warnings: List[SemanticError] = None) -> str:
    """Formats semantic analysis results for presentation."""
    warnings = warnings or []
    lines = []
    if not errors:
        lines.append("[PASS] Semantic Analysis: 0 errors detected. Policy is semantically valid.")
    else:
        lines.append(f"[FAIL] Semantic Analysis: {len(errors)} semantic error(s) detected:")
        for i, err in enumerate(errors, 1):
            lines.append(f"  {i}. {err.format()}")
    for w in warnings:
        lines.append(f"  [warn] {w.format()}")
    return "\n".join(lines)

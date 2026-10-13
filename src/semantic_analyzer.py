"""
Phase 3: Semantic Analysis (semantic_analyzer.py)

Performs static semantic checks on the Abstract Syntax Tree (AST):
- Validates protocol names (TCP, UDP, ICMP, ANY)
- Validates port numbers (range 1-65535 or ANY)
- Validates protocol-port compatibility (e.g., ICMP does not use TCP/UDP ports)
- Validates source specifications (ANY, UNKNOWN, INTERNAL, EXTERNAL, IPv4, CIDR)
- Validates actions (ALLOW, BLOCK)
- Detects duplicate rule identifiers (names)
"""

import ipaddress
import re
from typing import List, Optional, Set
from src.parser import PolicyNode, RuleNode


class SemanticError:
    """Represents a single semantic validation error."""

    def __init__(self, rule_name: str, message: str, line: int, column: int):
        self.rule_name = rule_name
        self.message = message
        self.line = line
        self.column = column

    def __repr__(self) -> str:
        return f"SemanticError(rule='{self.rule_name}', line={self.line}, col={self.column}, msg='{self.message}')"

    def format(self) -> str:
        return f"Semantic Error in rule '{self.rule_name}' [Line {self.line}, Col {self.column}]: {self.message}"


class SemanticAnalysisError(Exception):
    """Raised when one or more fatal semantic errors are found in the policy."""

    def __init__(self, errors: List[SemanticError]):
        self.errors = errors
        error_details = "\n".join(f"  - {err.format()}" for err in errors)
        super().__init__(f"Semantic analysis failed with {len(errors)} error(s):\n{error_details}")


class SemanticAnalyzer:
    """Analyzes AST nodes against security DSL semantic rules."""

    VALID_PROTOCOLS = {"TCP", "UDP", "ICMP", "ANY"}
    VALID_ACTIONS = {"ALLOW", "BLOCK"}
    VALID_NAMED_SOURCES = {"ANY", "UNKNOWN", "INTERNAL", "EXTERNAL"}

    def __init__(self, ast: PolicyNode):
        self.ast = ast
        self.errors: List[SemanticError] = []
        self.defined_rule_names: Set[str] = set()

    def analyze(self) -> List[SemanticError]:
        """Runs all semantic checks on the AST. Returns list of SemanticError objects."""
        self.errors.clear()
        self.defined_rule_names.clear()

        for rule in self.ast.rules:
            self._validate_rule_identifier(rule)
            self._validate_protocol(rule)
            self._validate_port(rule)
            self._validate_protocol_port_compatibility(rule)
            self._validate_source(rule)
            self._validate_action(rule)

        return self.errors

    def analyze_or_raise(self) -> None:
        """Runs semantic analysis and raises SemanticAnalysisError if any error exists."""
        errors = self.analyze()
        if errors:
            raise SemanticAnalysisError(errors)

    def _validate_rule_identifier(self, rule: RuleNode) -> None:
        if rule.name in self.defined_rule_names:
            self.errors.append(
                SemanticError(
                    rule_name=rule.name,
                    message=f"Duplicate rule identifier '{rule.name}'. Rule names must be unique within a policy.",
                    line=rule.line,
                    column=rule.column,
                )
            )
        else:
            self.defined_rule_names.add(rule.name)

    def _validate_protocol(self, rule: RuleNode) -> None:
        if rule.protocol not in self.VALID_PROTOCOLS:
            self.errors.append(
                SemanticError(
                    rule_name=rule.name,
                    message=(
                        f"Unsupported transport protocol '{rule.protocol}'. "
                        f"Supported protocols are: {', '.join(sorted(self.VALID_PROTOCOLS))}."
                    ),
                    line=rule.line,
                    column=rule.column,
                )
            )

    def _validate_port(self, rule: RuleNode) -> None:
        if isinstance(rule.port, str):
            if rule.port.upper() == "ANY":
                return
            # Non-numeric string port
            self.errors.append(
                SemanticError(
                    rule_name=rule.name,
                    message=f"Invalid port value '{rule.port}'. Port must be an integer between 1 and 65535, or 'ANY'.",
                    line=rule.line,
                    column=rule.column,
                )
            )
            return

        if isinstance(rule.port, int):
            if not (1 <= rule.port <= 65535):
                self.errors.append(
                    SemanticError(
                        rule_name=rule.name,
                        message=f"Port number {rule.port} out of range. Valid network port range is 1 to 65535.",
                        line=rule.line,
                        column=rule.column,
                    )
                )

    def _validate_protocol_port_compatibility(self, rule: RuleNode) -> None:
        """ICMP is a network layer protocol without TCP/UDP transport port numbers."""
        if rule.protocol == "ICMP":
            if rule.port != "ANY" and rule.port != 0:
                self.errors.append(
                    SemanticError(
                        rule_name=rule.name,
                        message=(
                            f"Protocol ICMP does not use TCP/UDP port numbers (found port {rule.port}). "
                            "Specify port 'ANY' for ICMP rules."
                        ),
                        line=rule.line,
                        column=rule.column,
                    )
                )

    def _validate_source(self, rule: RuleNode) -> None:
        src = rule.source.strip()
        upper_src = src.upper()

        if upper_src in self.VALID_NAMED_SOURCES:
            return

        # Check IPv4 address
        if self._is_valid_ipv4(src):
            return

        # Check IPv4 CIDR
        if self._is_valid_cidr(src):
            return

        self.errors.append(
            SemanticError(
                rule_name=rule.name,
                message=(
                    f"Invalid source condition '{src}'. Must be ANY, UNKNOWN, INTERNAL, "
                    f"EXTERNAL, a valid IPv4 address (e.g. 192.168.1.1), or a CIDR subnet (e.g. 10.0.0.0/24)."
                ),
                line=rule.line,
                column=rule.column,
            )
        )

    def _is_valid_ipv4(self, val: str) -> bool:
        parts = val.split('.')
        if len(parts) != 4:
            return False
        for p in parts:
            if not p.isdigit():
                return False
            n = int(p)
            if not (0 <= n <= 255):
                return False
        return True

    def _is_valid_cidr(self, val: str) -> bool:
        try:
            ipaddress.ip_network(val, strict=False)
            return True
        except ValueError:
            return False

    def _validate_action(self, rule: RuleNode) -> None:
        if rule.action not in self.VALID_ACTIONS:
            self.errors.append(
                SemanticError(
                    rule_name=rule.name,
                    message=f"Invalid action '{rule.action}'. Permitted actions are ALLOW or BLOCK.",
                    line=rule.line,
                    column=rule.column,
                )
            )


def format_semantic_report(errors: List[SemanticError]) -> str:
    """Formats semantic analysis results into a presentation report."""
    if not errors:
        return "[PASS] Semantic Analysis: 0 errors detected. Policy is semantically valid."
    
    lines = [f"[FAIL] Semantic Analysis: {len(errors)} semantic error(s) detected:"]
    for i, err in enumerate(errors, 1):
        lines.append(f"  {i}. {err.format()}")
    return "\n".join(lines)

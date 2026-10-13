"""
Phase 4: Intermediate Representation (intermediate_code.py)

Translates the Abstract Syntax Tree (AST) into a machine-independent
Intermediate Representation (IR), featuring:
1. Linearized Three-Address Code (TAC)
2. Quadruple instruction formatting (Op, Arg1, Arg2, Result)

Provides clear, printable IR for Compiler Design faculty demonstration.
"""

from typing import List, Optional
from src.parser import PolicyNode, RuleNode


class Quadruple:
    """Represents a standard compiler quadruple: (operator, arg1, arg2, result)."""

    def __init__(self, op: str, arg1: Optional[str] = None, arg2: Optional[str] = None, result: Optional[str] = None):
        self.op = op
        self.arg1 = str(arg1) if arg1 is not None else ""
        self.arg2 = str(arg2) if arg2 is not None else ""
        self.result = str(result) if result is not None else ""

    def __repr__(self) -> str:
        return f"({self.op:<12}, {self.arg1:<16}, {self.arg2:<16}, {self.result:<16})"

    def to_tac_string(self) -> str:
        """Converts the quadruple into human-readable Three-Address Code (TAC) syntax."""
        if self.op == "LABEL":
            return f"{self.result}:"
        elif self.op == "TEST_PROTO":
            return f"    {self.result} = (packet.protocol == {self.arg1})"
        elif self.op == "TEST_PORT":
            return f"    {self.result} = (packet.port == {self.arg1})"
        elif self.op == "TEST_SRC":
            return f"    {self.result} = MATCH_SOURCE(packet.source, {self.arg1})"
        elif self.op == "AND":
            return f"    {self.result} = {self.arg1} AND {self.arg2}"
        elif self.op == "IF_FALSE_GOTO":
            return f"    IF NOT {self.arg1} GOTO {self.result}"
        elif self.op == "RETURN_ACTION":
            return f"    RETURN ACTION({self.arg1}) [Rule: {self.arg2}]"
        elif self.op == "GOTO":
            return f"    GOTO {self.result}"
        elif self.op == "COMMENT":
            return f"\n    # {self.arg1}"
        return f"    {self.op} {self.arg1} {self.arg2} -> {self.result}"


class IRRule:
    """Intermediate representation of an individual security rule."""

    def __init__(self, rule_node: RuleNode, rule_index: int):
        self.rule_name = rule_node.name
        self.rule_index = rule_index
        self.protocol = rule_node.protocol
        self.port = rule_node.port
        self.source = rule_node.source
        self.action = rule_node.action
        self.line = rule_node.line

        self.label_start = f"LABEL_{self.rule_name}"
        self.label_next = f"LABEL_RULE_{rule_index + 1}"
        self.quadruples: List[Quadruple] = []


class IntermediateProgram:
    """Represents the complete compiled Intermediate Code for a policy."""

    def __init__(self, ast: PolicyNode):
        self.ast = ast
        self.rules_ir: List[IRRule] = []
        self.quadruples: List[Quadruple] = []
        self._temp_counter = 0

    def _new_temp(self) -> str:
        temp = f"t{self._temp_counter}"
        self._temp_counter += 1
        return temp

    def generate(self) -> "IntermediateProgram":
        """Translates the AST into Three-Address Code quadruples."""
        self.rules_ir.clear()
        self.quadruples.clear()
        self._temp_counter = 0

        self.quadruples.append(Quadruple("COMMENT", "Begin Security Policy Evaluation"))
        self.quadruples.append(Quadruple("LABEL", result="POLICY_ENTRY"))

        total_rules = len(self.ast.rules)

        for idx, rule in enumerate(self.ast.rules):
            ir_rule = IRRule(rule, idx)
            next_label = f"LABEL_RULE_{idx + 1}" if idx + 1 < total_rules else "LABEL_DEFAULT_FALLBACK"

            # Rule Label
            ir_rule.quadruples.append(Quadruple("LABEL", result=ir_rule.label_start))

            # 1. Test Protocol
            t_proto = self._new_temp()
            proto_val = "ANY" if ir_rule.protocol == "ANY" else f"'{ir_rule.protocol}'"
            ir_rule.quadruples.append(Quadruple("TEST_PROTO", proto_val, None, t_proto))

            # 2. Test Port
            t_port = self._new_temp()
            port_val = "ANY" if ir_rule.port == "ANY" else str(ir_rule.port)
            ir_rule.quadruples.append(Quadruple("TEST_PORT", port_val, None, t_port))

            # Combine proto and port
            t_cond1 = self._new_temp()
            ir_rule.quadruples.append(Quadruple("AND", t_proto, t_port, t_cond1))

            # 3. Test Source
            t_src = self._new_temp()
            src_val = f"'{ir_rule.source}'"
            ir_rule.quadruples.append(Quadruple("TEST_SRC", src_val, None, t_src))

            # Final match condition
            t_match = self._new_temp()
            ir_rule.quadruples.append(Quadruple("AND", t_cond1, t_src, t_match))

            # Branching: if false jump to next rule
            ir_rule.quadruples.append(Quadruple("IF_FALSE_GOTO", t_match, None, next_label))

            # Action execution: return action
            ir_rule.quadruples.append(Quadruple("RETURN_ACTION", ir_rule.action, ir_rule.rule_name, None))

            self.rules_ir.append(ir_rule)
            self.quadruples.extend(ir_rule.quadruples)

        # Default Deny/Block Fallback
        self.quadruples.append(Quadruple("COMMENT", "Default Fallback Action (First-Match Semantics)"))
        self.quadruples.append(Quadruple("LABEL", result="LABEL_DEFAULT_FALLBACK"))
        self.quadruples.append(Quadruple("RETURN_ACTION", "BLOCK", "DEFAULT_POLICY", None))

        return self

    def format_tac(self) -> str:
        """Returns readable Three-Address-Code string representation."""
        lines = ["# --- Three-Address Code (TAC) Representation ---"]
        for quad in self.quadruples:
            lines.append(quad.to_tac_string())
        return "\n".join(lines)

    def format_quadruples(self) -> str:
        """Formats the quadruples into a standard compiler table."""
        header = f"{'Index':<6} | {'Operator':<16} | {'Arg 1':<20} | {'Arg 2':<12} | {'Result':<24}"
        separator = "-" * len(header)
        lines = [
            "# --- Intermediate Code Quadruples Table ---",
            separator,
            header,
            separator,
        ]
        idx = 0
        for quad in self.quadruples:
            if quad.op == "COMMENT":
                continue
            lines.append(f"{idx:<6} | {quad.op:<16} | {quad.arg1:<20} | {quad.arg2:<12} | {quad.result:<24}")
            idx += 1
        lines.append(separator)
        return "\n".join(lines)


def generate_ir(ast: PolicyNode) -> IntermediateProgram:
    """Helper function to compile AST to Intermediate Program."""
    ir_prog = IntermediateProgram(ast)
    return ir_prog.generate()

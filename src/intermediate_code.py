"""
Phase 6: Intermediate Code Generation and IR Optimization (intermediate_code.py)

Lowers the OPTIMIZED policy AST into Three-Address Code (TAC), stored as
quadruples (op, arg1, arg2, result). This IR is the input to the back end:
the IR virtual machine (ir_vm.py) executes it and the code generator
translates it to Python.

Instruction set
  LABEL          result=label
  COMMENT        arg1=text
  TEST_PROTO     arg1=protocol           result=temp    temp = packet.protocol == arg1
  TEST_PORT      arg1=port               result=temp    temp = packet.port == arg1
  TEST_SRC       arg1=source             result=temp    temp = MATCH_SOURCE(packet.source, arg1)
  AND            arg1=temp arg2=temp     result=temp
  ASSIGN         arg1=TRUE               result=temp
  IF_FALSE_GOTO  arg1=temp               result=label
  GOTO                                   result=label
  RETURN_ACTION  arg1=action arg2=rule

The peephole optimizer (optimize_ir) then applies classic IR optimizations:
  1. constant folding        tests against ANY become  t = TRUE
  2. copy/constant propagation  t2 = t0 AND t1 with t0 = TRUE  becomes  t2 := t1
  3. branch elimination      IF NOT TRUE GOTO L is never taken and is deleted
  4. dead code elimination   assignments whose result is never used are deleted
  5. unreachable code elimination  instructions no control path reaches are deleted
"""

from collections import Counter
from typing import Dict, List, Optional, Set

from src.parser import PolicyNode
from src.policy_semantics import effective_port

TEST_OPS = ("TEST_PROTO", "TEST_PORT", "TEST_SRC")
PURE_OPS = TEST_OPS + ("AND", "ASSIGN")


class Quadruple:
    """A single quadruple (op, arg1, arg2, result)."""

    def __init__(self, op: str, arg1: Optional[str] = None, arg2: Optional[str] = None, result: Optional[str] = None):
        self.op = op
        self.arg1 = arg1
        self.arg2 = arg2
        self.result = result

    def to_tac_string(self) -> str:
        op = self.op
        if op == "LABEL":
            return f"{self.result}:"
        if op == "COMMENT":
            return f"    # {self.arg1}"
        if op == "TEST_PROTO":
            return f"    {self.result} = (packet.protocol == '{self.arg1}')"
        if op == "TEST_PORT":
            return f"    {self.result} = (packet.port == {self.arg1})"
        if op == "TEST_SRC":
            return f"    {self.result} = MATCH_SOURCE(packet.source, '{self.arg1}')"
        if op == "AND":
            return f"    {self.result} = {self.arg1} AND {self.arg2}"
        if op == "ASSIGN":
            return f"    {self.result} = {self.arg1}"
        if op == "IF_FALSE_GOTO":
            return f"    IF NOT {self.arg1} GOTO {self.result}"
        if op == "GOTO":
            return f"    GOTO {self.result}"
        if op == "RETURN_ACTION":
            return f"    RETURN ACTION({self.arg1}) [Rule: {self.arg2}]"
        return f"    {op} {self.arg1} {self.arg2} {self.result}"

    def __repr__(self) -> str:
        return f"Quad({self.op}, {self.arg1}, {self.arg2}, {self.result})"


class IntermediateProgram:
    """A linear IR program."""

    def __init__(self, ast: Optional[PolicyNode] = None, quadruples: Optional[List[Quadruple]] = None):
        self.ast = ast
        self.quadruples: List[Quadruple] = list(quadruples or [])
        self.temp_counter = 0

    def new_temp(self) -> str:
        t = f"t{self.temp_counter}"
        self.temp_counter += 1
        return t

    def emit(self, op: str, arg1=None, arg2=None, result=None) -> None:
        self.quadruples.append(Quadruple(op, arg1, arg2, result))

    def generate(self) -> "IntermediateProgram":
        rules = self.ast.rules
        labels = [f"R{i}_{rule.name}" for i, rule in enumerate(rules, 1)] + ["DEFAULT_FALLBACK"]

        self.emit("COMMENT", "First-match policy evaluation, default BLOCK")
        for idx, rule in enumerate(rules):
            self.emit("LABEL", result=labels[idx])
            t_proto = self.new_temp()
            self.emit("TEST_PROTO", rule.protocol, None, t_proto)
            t_port = self.new_temp()
            self.emit("TEST_PORT", str(effective_port(rule)), None, t_port)
            t_pp = self.new_temp()
            self.emit("AND", t_proto, t_port, t_pp)
            t_src = self.new_temp()
            self.emit("TEST_SRC", rule.source, None, t_src)
            t_all = self.new_temp()
            self.emit("AND", t_pp, t_src, t_all)
            self.emit("IF_FALSE_GOTO", t_all, None, labels[idx + 1])
            self.emit("RETURN_ACTION", rule.action, rule.name)

        self.emit("LABEL", result=labels[-1])
        self.emit("RETURN_ACTION", "BLOCK", "DEFAULT_FALLBACK")
        return self

    def format_tac(self) -> str:
        lines = ["# --- Three-Address Code (TAC) ---"]
        lines.extend(q.to_tac_string() for q in self.quadruples)
        return "\n".join(lines)

    def format_quadruples(self) -> str:
        lines = [
            "+-------+-----------------+----------------------+----------------------+--------------------------+",
            "| INDEX | OPERATOR        | ARG 1                | ARG 2                | RESULT                   |",
            "+-------+-----------------+----------------------+----------------------+--------------------------+",
        ]
        for i, q in enumerate(self.quadruples):
            a1 = (str(q.arg1) if q.arg1 is not None else "-")[:20]
            a2 = (str(q.arg2) if q.arg2 is not None else "-")[:20]
            res = (str(q.result) if q.result is not None else "-")[:24]
            lines.append(f"| {i:<5} | {q.op:<15} | {a1:<20} | {a2:<20} | {res:<24} |")
        lines.append(lines[0])
        return "\n".join(lines)


class IROptimizationReport:
    def __init__(self, before: int, after: int, stats: Counter):
        self.before = before
        self.after = after
        self.stats = stats

    def format_report(self) -> str:
        names = {
            "constant_folded": "Constant folding (tests against ANY -> TRUE)",
            "propagated": "Copy/constant propagation (AND with TRUE)",
            "branch_eliminated": "Branch elimination (IF NOT TRUE)",
            "dead_removed": "Dead code elimination (unused temporaries)",
            "unreachable_removed": "Unreachable code elimination",
        }
        lines = [f"IR quadruples: {self.before} -> {self.after} after peephole optimization"]
        for key, label in names.items():
            if self.stats.get(key):
                lines.append(f"  - {label}: {self.stats[key]}")
        if self.before == self.after:
            lines.append("  (no IR-level simplifications applied)")
        return "\n".join(lines)


def _clone(q: Quadruple) -> Quadruple:
    return Quadruple(q.op, q.arg1, q.arg2, q.result)


def optimize_ir(program: IntermediateProgram):
    """Peephole-optimizes an IR program. Returns (new_program, IROptimizationReport)."""
    stats: Counter = Counter()
    before = len(program.quadruples)
    known_true: Set[str] = set()
    alias: Dict[str, str] = {}

    def resolve(t: str) -> str:
        while t in alias:
            t = alias[t]
        return t

    # 1-3: folding, propagation, branch elimination (single forward pass)
    out: List[Quadruple] = []
    for q in program.quadruples:
        if q.op in TEST_OPS and str(q.arg1).upper() == "ANY":
            out.append(Quadruple("ASSIGN", "TRUE", None, q.result))
            known_true.add(q.result)
            stats["constant_folded"] += 1
        elif q.op == "AND":
            a, b = resolve(q.arg1), resolve(q.arg2)
            if a in known_true and b in known_true:
                out.append(Quadruple("ASSIGN", "TRUE", None, q.result))
                known_true.add(q.result)
                stats["propagated"] += 1
            elif a in known_true:
                alias[q.result] = b
                stats["propagated"] += 1
            elif b in known_true:
                alias[q.result] = a
                stats["propagated"] += 1
            else:
                out.append(Quadruple("AND", a, b, q.result))
        elif q.op == "IF_FALSE_GOTO":
            t = resolve(q.arg1)
            if t in known_true:
                stats["branch_eliminated"] += 1
            else:
                out.append(Quadruple("IF_FALSE_GOTO", t, None, q.result))
        else:
            out.append(_clone(q))

    # 4: dead code elimination, repeated until stable
    while True:
        used = set()
        for q in out:
            if q.op == "AND":
                used.update((q.arg1, q.arg2))
            elif q.op == "IF_FALSE_GOTO":
                used.add(q.arg1)
        kept = [q for q in out if not (q.op in PURE_OPS and q.result not in used)]
        if len(kept) == len(out):
            break
        stats["dead_removed"] += len(out) - len(kept)
        out = kept

    # 5: unreachable code elimination (reachability over the control-flow graph)
    label_at = {q.result: i for i, q in enumerate(out) if q.op == "LABEL"}
    reachable: Set[int] = set()
    work = [0] if out else []
    while work:
        i = work.pop()
        if i in reachable or i >= len(out):
            continue
        reachable.add(i)
        q = out[i]
        if q.op == "RETURN_ACTION":
            continue
        if q.op == "GOTO":
            work.append(label_at[q.result])
            continue
        if q.op == "IF_FALSE_GOTO":
            work.append(label_at[q.result])
        work.append(i + 1)
    stats["unreachable_removed"] = sum(1 for i, q in enumerate(out) if i not in reachable and q.op != "COMMENT")
    out = [q for i, q in enumerate(out) if i in reachable]

    # Renumber temporaries densely (t0, t1, ...) for readability.
    rename: Dict[str, str] = {}
    for q in out:
        if q.op in PURE_OPS and q.result not in rename:
            rename[q.result] = f"t{len(rename)}"
    for q in out:
        if q.op in PURE_OPS:
            q.result = rename[q.result]
        if q.op == "AND":
            q.arg1, q.arg2 = rename[q.arg1], rename[q.arg2]
        elif q.op == "IF_FALSE_GOTO":
            q.arg1 = rename[q.arg1]

    optimized = IntermediateProgram(program.ast, out)
    optimized.temp_counter = len(rename)
    return optimized, IROptimizationReport(before, len(out), stats)


def generate_ir(ast: PolicyNode) -> IntermediateProgram:
    """Helper function to generate the (unoptimized) IR for a policy AST."""
    return IntermediateProgram(ast).generate()

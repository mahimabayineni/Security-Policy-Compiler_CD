"""
Phase 7: Code Generation (code_generator.py)

Translates the optimized IR (quadruples) into a standalone Python program.
Each IR instruction maps to one Python statement:

  TEST_PROTO t, P     ->  t = (proto == 'P')
  TEST_PORT  t, N     ->  t = (port == N)
  TEST_SRC   t, S     ->  t = match_source(src, 'S')
  AND        t, a, b  ->  t = a and b
  ASSIGN     t, TRUE  ->  t = True
  IF_FALSE_GOTO t, L  ->  if t:   (L must be the next label: a structured forward jump)
  RETURN_ACTION A, R  ->  return {...}
  LABEL L             ->  # L:

The source-matching runtime (runtime.py) is copied into the output, so the
generated program behaves exactly like the compiler's own simulator.

This module also holds the reference AST interpreter (evaluate_packet), which
serves as the "specification" the compiled code is verified against.

ACADEMIC SIMULATION ONLY: generated code evaluates plain Python dictionaries.
It never touches sockets, interfaces, or real firewall configuration.
"""

import inspect
import json
from typing import Any, Dict, List, Union

from src import runtime
from src.intermediate_code import IntermediateProgram, Quadruple, generate_ir, optimize_ir
from src.parser import PolicyNode
from src.policy_semantics import effective_port
from src.runtime import match_source


class CodeGenError(Exception):
    pass


class SimulatedPacket:
    """A synthetic packet for simulation."""

    def __init__(self, protocol: str, port: int, source: str):
        self.protocol = protocol.upper()
        self.port = port
        self.source = source

    def to_dict(self) -> Dict[str, Any]:
        return {"protocol": self.protocol, "port": self.port, "source": self.source}


# ---------------------------------------------------------------------------
# Reference semantics: AST interpreter
# ---------------------------------------------------------------------------
def match_source_condition(packet_source: str, rule_source: str) -> bool:
    """Kept for backward compatibility; delegates to the shared runtime."""
    return match_source(packet_source, rule_source)


def evaluate_packet(policy: PolicyNode, packet: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluates a packet against the AST under first-match, default-BLOCK semantics."""
    pkt_proto = str(packet.get("protocol", "")).strip().upper()
    pkt_port = int(packet.get("port", 0))
    pkt_src = str(packet.get("source", "")).strip()

    for rule in policy.rules:
        if rule.protocol != "ANY" and rule.protocol != pkt_proto:
            continue
        port = effective_port(rule)
        if port != "ANY" and int(port) != pkt_port:
            continue
        if not match_source(pkt_src, rule.source):
            continue
        return {"action": rule.action, "matched_rule": rule.name, "reason": f"Matched rule '{rule.name}'"}

    return {"action": "BLOCK", "matched_rule": "DEFAULT_FALLBACK",
            "reason": "No matching rule found. Default BLOCK policy applied."}


def simulate_packets(policy: PolicyNode, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Evaluates a list of packets with the reference interpreter."""
    return [{"packet": p, **evaluate_packet(policy, p)} for p in packets]


# ---------------------------------------------------------------------------
# Back end: IR -> Python
# ---------------------------------------------------------------------------
def _runtime_source() -> str:
    text = inspect.getsource(runtime)
    marker = "# --- runtime begin ---"
    return text[text.index(marker) + len(marker):].strip() + "\n"


def _next_label(quads: List[Quadruple], idx: int):
    for q in quads[idx + 1:]:
        if q.op == "LABEL":
            return q.result
    return None


def _emit_body(quads: List[Quadruple]) -> List[str]:
    lines: List[str] = []
    in_branch = False
    for idx, q in enumerate(quads):
        op = q.op
        if op == "LABEL":
            in_branch = False
            lines.append(f"    # {q.result}:")
            continue
        if op == "COMMENT":
            lines.append(f"    # {q.arg1}")
            continue
        if op in ("IF_FALSE_GOTO", "GOTO"):
            if q.result != _next_label(quads, idx):
                raise CodeGenError(f"Unstructured jump to '{q.result}' cannot be translated")
            if op == "GOTO":
                continue
            if in_branch:
                raise CodeGenError("Nested conditional branch in one basic block")
            lines.append(f"    if {q.arg1}:")
            in_branch = True
            continue

        ind = "        " if in_branch else "    "
        if op == "TEST_PROTO":
            lines.append(f"{ind}{q.result} = (proto == {q.arg1!r})")
        elif op == "TEST_PORT":
            lines.append(f"{ind}{q.result} = (port == {int(q.arg1)})")
        elif op == "TEST_SRC":
            lines.append(f"{ind}{q.result} = match_source(src, {q.arg1!r})")
        elif op == "AND":
            lines.append(f"{ind}{q.result} = {q.arg1} and {q.arg2}")
        elif op == "ASSIGN":
            lines.append(f"{ind}{q.result} = {q.arg1 == 'TRUE'}")
        elif op == "RETURN_ACTION":
            if q.arg2 == "DEFAULT_FALLBACK":
                reason = "No matching rule found. Default BLOCK policy applied."
            else:
                reason = f"Matched rule '{q.arg2}'"
            lines.append(f"{ind}return {{'action': {q.arg1!r}, 'matched_rule': {q.arg2!r}, 'reason': {reason!r}}}")
        else:
            raise CodeGenError(f"Unknown IR operator '{op}'")
    return lines


DEMO_PACKETS = [
    {"protocol": "TCP", "port": 22, "source": "UNKNOWN"},
    {"protocol": "TCP", "port": 443, "source": "192.168.1.100"},
    {"protocol": "TCP", "port": 22, "source": "192.168.1.25"},
    {"protocol": "TCP", "port": 80, "source": "203.0.113.9"},
    {"protocol": "UDP", "port": 53, "source": "8.8.8.8"},
    {"protocol": "ICMP", "port": 0, "source": "INTERNAL"},
]

_MAIN_TEMPLATE = '''

DEMO_PACKETS = {demo}


def _parse_cli_packet(args):
    if len(args) != 3:
        raise SystemExit("usage: python {{prog}} PROTOCOL PORT SOURCE   e.g.  TCP 22 10.0.0.5".format(prog=sys.argv[0]))
    return {{"protocol": args[0], "port": int(args[1]), "source": args[2]}}


def _main(argv):
    if not argv:
        packets = DEMO_PACKETS
    elif argv[0] == "--packets":
        with open(argv[1], encoding="utf-8") as fh:
            packets = json.load(fh)
    else:
        packets = [_parse_cli_packet(argv)]
    for pkt in packets:
        res = evaluate_packet(pkt)
        print("{{:<5}} {{:<6}} {{:<20}} -> {{:<6}} ({{}})".format(
            str(pkt.get("protocol", "")).upper(), pkt.get("port", 0), pkt.get("source", ""),
            res["action"], res["matched_rule"]))


if __name__ == "__main__":
    _main(sys.argv[1:])
'''


def generate_python_code(program: Union[PolicyNode, IntermediateProgram], source_name: str = "<policy>",
                         rule_count: int = None) -> str:
    """Generates a standalone Python policy from an IR program.

    Passing a PolicyNode is also accepted: its IR is generated and peephole-optimized first.
    """
    if isinstance(program, PolicyNode):
        rule_count = len(program.rules) if rule_count is None else rule_count
        program, _ = optimize_ir(generate_ir(program))
    if rule_count is None:
        rule_count = len(program.ast.rules) if program.ast is not None else 0

    # Windows paths contain backslashes, which are escape sequences inside a docstring.
    source_name = str(source_name).replace("\\", "/").replace('"' * 3, "'" * 3)
    header = f'''"""
Auto-generated security policy evaluator.
Compiled by : Domain-Specific Security Policy Compiler v2.0
Source      : {source_name}
Rules       : {rule_count} (after optimization)
Semantics   : first-match, default BLOCK
Target      : Python 3 (generated from the optimized IR)

Usage:
  python <this file>                         run the built-in demo packets
  python <this file> TCP 22 10.0.0.5         evaluate one packet
  python <this file> --packets packets.json  evaluate a JSON list of packets

ACADEMIC SIMULATION ONLY - evaluates plain dictionaries, never real traffic.
"""

import json
import sys
'''
    body = _emit_body(program.quadruples)
    func = [
        "",
        "",
        "def evaluate_packet(packet):",
        '    """Returns {action, matched_rule, reason} for a packet dict {protocol, port, source}."""',
        "    proto = str(packet.get('protocol', '')).strip().upper()",
        "    port = int(packet.get('port', 0))",
        "    src = str(packet.get('source', '')).strip()",
        *body,
    ]
    demo = json.dumps(DEMO_PACKETS, indent=4)
    return header + "\n" + _runtime_source() + "\n".join(func) + "\n" + _MAIN_TEMPLATE.format(demo=demo)


def format_simulation_table(results: List[Dict[str, Any]]) -> str:
    show_steps = any("steps" in r for r in results)
    steps_w = 7  # width of the STEPS column value cell
    if show_steps:
        border = "+" + "-" * 38 + "+" + "-" * 26 + "+" + "-" * 10 + "+" + "-" * (steps_w + 2) + "+"
        header = (f"| {'PACKET (Proto:Port src=Source)':<36} | {'MATCHED RULE':<24} |"
                  f" {'ACTION':<8} | {'STEPS':>{steps_w}} |")
    else:
        border = "+" + "-" * 38 + "+" + "-" * 26 + "+" + "-" * 10 + "+"
        header = f"| {'PACKET (Proto:Port src=Source)':<36} | {'MATCHED RULE':<24} | {'ACTION':<8} |"
    lines = [border, header, border]
    for res in results:
        p = res["packet"]
        desc = f"{str(p.get('protocol', '')).upper()}:{p.get('port', 0)} src={p.get('source', '')}"
        row = f"| {desc[:36]:<36} | {str(res['matched_rule'])[:24]:<24} | {res['action']:<8} |"
        if show_steps:
            row += f" {res['steps']:>{steps_w}} |"
        lines.append(row)
    lines.append(border)
    return "\n".join(lines)

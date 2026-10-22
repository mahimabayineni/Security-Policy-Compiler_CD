"""
Translation Validation (verifier.py)

Checks that the compiled program behaves exactly like the source policy.
Three implementations are compared on every packet class:

  1. the ORIGINAL policy AST    (reference interpreter, before any optimization)
  2. the OPTIMIZED IR           (executed by the IR virtual machine)
  3. the GENERATED Python code  (executed with exec)

Packets are drawn from equivalence classes. A rule only tests protocol
equality, port equality and source membership, so two packets that agree on
"which protocol constant / which port constant / which source region" get the
same decision from every rule. The verifier generates one representative for
every class:
  - protocols: each protocol in the policy plus TCP/UDP/ICMP and one other
  - ports: each port number in the policy plus one unused port and 0
  - sources: one address in every region of the Venn diagram formed by all
    CIDR blocks in the policy and the RFC 1918 ranges, plus each label
For this DSL the check is therefore exhaustive, not just a sample.
"""

import ipaddress
from typing import Any, Dict, List, Optional

from src.code_generator import evaluate_packet
from src.intermediate_code import Quadruple
from src.ir_vm import execute_ir
from src.parser import PolicyNode
from src.policy_semantics import effective_port, source_value
from src.runtime import INTERNAL_NETWORKS


def _region_representatives(nets: List[ipaddress.IPv4Network]) -> List[str]:
    reps = []
    for n in nets:
        pieces = [n]
        for c in nets:
            if c == n or not c.subnet_of(n):
                continue
            nxt = []
            for p in pieces:
                if p.subnet_of(c):
                    continue
                if c.subnet_of(p):
                    nxt.extend(p.address_exclude(c))
                else:
                    nxt.append(p)
            pieces = nxt
        if pieces:
            reps.append(str(min(pieces).network_address))
    return reps


def representative_packets(policy: PolicyNode) -> List[Dict[str, Any]]:
    protocols = {"TCP", "UDP", "ICMP", "GRE"} | {r.protocol for r in policy.rules if r.protocol != "ANY"}
    ports = {0}
    for r in policy.rules:
        p = effective_port(r)
        if p != "ANY":
            ports.add(int(p))
    ports.add(next(p for p in range(1, 65536) if p not in ports))

    nets = {ipaddress.ip_network("0.0.0.0/0"), *INTERNAL_NETWORKS}
    for r in policy.rules:
        v = source_value(r.source)
        if isinstance(v, ipaddress.IPv4Network):
            nets.add(v)
    sources = _region_representatives(sorted(nets)) + ["UNKNOWN", "INTERNAL", "EXTERNAL", "unlabelled-host"]

    return [{"protocol": pr, "port": po, "source": s}
            for pr in sorted(protocols) for po in sorted(ports) for s in sources]


class VerificationResult:
    def __init__(self, checked: int, mismatches: List[Dict[str, Any]], compared: List[str]):
        self.checked = checked
        self.mismatches = mismatches
        self.compared = compared

    @property
    def passed(self) -> bool:
        return not self.mismatches

    def format_report(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        lines = [f"[{status}] Equivalence check ({' vs '.join(self.compared)}): "
                 f"{self.checked} packet classes, {len(self.mismatches)} mismatch(es)."]
        for m in self.mismatches[:10]:
            lines.append(f"  MISMATCH {m}")
        return "\n".join(lines)


def verify(original: PolicyNode, optimized_ir: List[Quadruple], generated_code: Optional[str] = None) -> VerificationResult:
    gen_eval = None
    compared = ["original AST", "optimized IR"]
    if generated_code is not None:
        namespace: Dict[str, Any] = {"__name__": "generated_policy"}
        exec(compile(generated_code, "<generated_policy>", "exec"), namespace)
        gen_eval = namespace["evaluate_packet"]
        compared.append("generated Python")

    packets = representative_packets(original)
    mismatches = []
    for pkt in packets:
        expected = evaluate_packet(original, pkt)["action"]
        got_ir = execute_ir(optimized_ir, pkt)["action"]
        got_gen = gen_eval(pkt)["action"] if gen_eval else expected
        if not (expected == got_ir == got_gen):
            mismatches.append({"packet": pkt, "original": expected, "ir": got_ir, "generated": got_gen})
    return VerificationResult(len(packets), mismatches, compared)

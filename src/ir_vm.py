"""
IR Virtual Machine (ir_vm.py)

Executes an IR program (a list of quadruples) directly on a packet. This is
the "interpreter" back end: it proves the IR is executable on its own, and it
is used for the packet simulation and the equivalence verifier.
"""

from typing import Any, Dict, List

from src.intermediate_code import Quadruple
from src.runtime import match_source


class IRExecutionError(Exception):
    pass


def execute_ir(quadruples: List[Quadruple], packet: Dict[str, Any], max_steps: int = 100000) -> Dict[str, Any]:
    proto = str(packet.get("protocol", "")).strip().upper()
    port = int(packet.get("port", 0))
    src = str(packet.get("source", "")).strip()

    labels = {q.result: i for i, q in enumerate(quadruples) if q.op == "LABEL"}
    env: Dict[str, bool] = {}
    pc, steps = 0, 0

    while pc < len(quadruples):
        steps += 1
        if steps > max_steps:
            raise IRExecutionError("Step limit exceeded (possible infinite loop in IR)")
        q = quadruples[pc]
        op = q.op
        if op in ("LABEL", "COMMENT"):
            pass
        elif op == "TEST_PROTO":
            env[q.result] = q.arg1 == "ANY" or proto == q.arg1
        elif op == "TEST_PORT":
            env[q.result] = q.arg1 == "ANY" or port == int(q.arg1)
        elif op == "TEST_SRC":
            env[q.result] = match_source(src, q.arg1)
        elif op == "AND":
            env[q.result] = env[q.arg1] and env[q.arg2]
        elif op == "ASSIGN":
            env[q.result] = q.arg1 == "TRUE"
        elif op == "IF_FALSE_GOTO":
            if not env[q.arg1]:
                if q.result not in labels:
                    raise IRExecutionError(f"Jump to undefined label '{q.result}'")
                pc = labels[q.result]
                continue
        elif op == "GOTO":
            pc = labels[q.result]
            continue
        elif op == "RETURN_ACTION":
            return {"action": q.arg1, "matched_rule": q.arg2, "steps": steps}
        else:
            raise IRExecutionError(f"Unknown IR operator '{op}'")
        pc += 1

    raise IRExecutionError("IR program ended without RETURN_ACTION")

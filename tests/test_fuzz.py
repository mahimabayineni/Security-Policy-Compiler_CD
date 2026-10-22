"""
Randomized differential testing: compile many random policies (O1 and O2) and
check that the optimized IR and the generated Python agree with the original
policy on every packet equivalence class. Seeded, so results are reproducible.
"""

import random
import unittest

from src.main import compile_source

PROTOCOLS = ["TCP", "UDP", "ICMP", "ANY"]
PORTS = ["22", "80", "443", "ANY"]
SOURCES = ["ANY", "INTERNAL", "EXTERNAL", "UNKNOWN", "10.0.0.0/8", "10.1.0.0/16", "10.1.2.3",
           "192.168.1.0/24", "8.8.8.0/24", "8.8.8.8", "0.0.0.0/1", "172.16.0.0/12"]


def random_policy(rng: random.Random) -> str:
    lines = []
    for i in range(rng.randint(1, 9)):
        proto = rng.choice(PROTOCOLS)
        port = "ANY" if proto == "ICMP" else rng.choice(PORTS)
        lines.append(f"RULE R{i} WHEN {proto} PORT {port} IF SOURCE {rng.choice(SOURCES)} "
                     f"THEN {rng.choice(['ALLOW', 'BLOCK'])}")
    return "\n".join(lines)


class TestFuzz(unittest.TestCase):

    def test_random_policies_are_compiled_correctly(self):
        rng = random.Random(2026)
        for _ in range(150):
            src = random_policy(rng)
            for aggressive in (False, True):
                res = compile_source(src, aggressive=aggressive)
                self.assertTrue(res.verification.passed, f"aggressive={aggressive}\n{src}\n"
                                + res.verification.format_report())


if __name__ == "__main__":
    unittest.main()

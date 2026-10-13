"""
Unit tests for Phase 7: Code Generator & Simulation (code_generator.py)
"""

import unittest
from src.lexer import tokenize
from src.parser import parse
from src.code_generator import evaluate_packet, generate_python_code, simulate_packets


class TestCodeGenerator(unittest.TestCase):

    def setUp(self):
        self.source = """
        RULE BLOCK_SSH
        WHEN TCP PORT 22
        IF SOURCE UNKNOWN
        THEN BLOCK

        RULE ALLOW_HTTPS
        WHEN TCP PORT 443
        IF SOURCE ANY
        THEN ALLOW

        RULE ALLOW_INTERNAL_SSH
        WHEN TCP PORT 22
        IF SOURCE 192.168.1.0/24
        THEN ALLOW
        """
        self.ast = parse(tokenize(self.source))

    def test_generated_python_code_is_syntactically_valid(self):
        code_str = generate_python_code(self.ast)
        # compile() raises SyntaxError if invalid
        compiled_code = compile(code_str, "<generated_policy>", "exec")
        self.assertIsNotNone(compiled_code)

    def test_generated_code_execution_matches_simulation(self):
        code_str = generate_python_code(self.ast)
        namespace = {}
        exec(code_str, namespace)
        self.assertIn("evaluate_packet", namespace)
        target_func = namespace["evaluate_packet"]

        # Test packet 1: Block SSH from UNKNOWN
        pkt1 = {"protocol": "TCP", "port": 22, "source": "UNKNOWN"}
        res_sim = evaluate_packet(self.ast, pkt1)
        res_exec = target_func(pkt1)
        self.assertEqual(res_sim["action"], res_exec["action"])
        self.assertEqual(res_exec["action"], "BLOCK")

        # Test packet 2: Allow HTTPS from anywhere
        pkt2 = {"protocol": "TCP", "port": 443, "source": "10.0.0.1"}
        res_sim = evaluate_packet(self.ast, pkt2)
        res_exec = target_func(pkt2)
        self.assertEqual(res_sim["action"], res_exec["action"])
        self.assertEqual(res_exec["action"], "ALLOW")

        # Test packet 3: Allow Internal SSH from subnet
        pkt3 = {"protocol": "TCP", "port": 22, "source": "192.168.1.15"}
        res_sim = evaluate_packet(self.ast, pkt3)
        res_exec = target_func(pkt3)
        self.assertEqual(res_sim["action"], res_exec["action"])
        self.assertEqual(res_exec["action"], "ALLOW")

        # Test packet 4: Unmatched packet defaults to BLOCK
        pkt4 = {"protocol": "UDP", "port": 9999, "source": "8.8.8.8"}
        res_sim = evaluate_packet(self.ast, pkt4)
        res_exec = target_func(pkt4)
        self.assertEqual(res_sim["action"], res_exec["action"])
        self.assertEqual(res_exec["action"], "BLOCK")

    def test_simulate_packets_batch(self):
        packets = [
            {"protocol": "TCP", "port": 443, "source": "1.2.3.4"},
            {"protocol": "TCP", "port": 22, "source": "UNKNOWN"},
        ]
        results = simulate_packets(self.ast, packets)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["action"], "ALLOW")
        self.assertEqual(results[1]["action"], "BLOCK")


if __name__ == "__main__":
    unittest.main()

"""
Unit tests for Phase 6: Optimizer (optimizer.py)
Includes behavioral equivalence verification before and after optimization.
"""

import unittest
from src.lexer import tokenize
from src.parser import parse
from src.optimizer import optimize_policy
from src.code_generator import evaluate_packet


class TestOptimizer(unittest.TestCase):

    def test_eliminate_exact_duplicate_rules(self):
        source = """
        RULE ALLOW_HTTPS
        WHEN TCP PORT 443
        IF SOURCE ANY
        THEN ALLOW

        RULE ALLOW_HTTPS_DUP
        WHEN TCP PORT 443
        IF SOURCE ANY
        THEN ALLOW
        """
        ast = parse(tokenize(source))
        self.assertEqual(len(ast.rules), 2)

        opt_result = optimize_policy(ast)
        self.assertEqual(opt_result.original_count, 2)
        self.assertEqual(opt_result.optimized_count, 1)
        self.assertEqual(opt_result.optimized_policy.rules[0].name, "ALLOW_HTTPS")

    def test_eliminate_subsumed_rules(self):
        source = """
        RULE ALLOW_ALL_INTERNAL
        WHEN ANY PORT ANY
        IF SOURCE INTERNAL
        THEN ALLOW

        RULE ALLOW_INTERNAL_PORT80
        WHEN TCP PORT 80
        IF SOURCE INTERNAL
        THEN ALLOW
        """
        ast = parse(tokenize(source))
        opt_result = optimize_policy(ast)
        self.assertEqual(opt_result.original_count, 2)
        self.assertEqual(opt_result.optimized_count, 1)
        self.assertEqual(opt_result.optimized_policy.rules[0].name, "ALLOW_ALL_INTERNAL")

    def test_eliminate_dead_conflict_rules(self):
        source = """
        RULE ALLOW_PORT_80
        WHEN TCP PORT 80
        IF SOURCE ANY
        THEN ALLOW

        RULE DEAD_BLOCK_PORT_80
        WHEN TCP PORT 80
        IF SOURCE ANY
        THEN BLOCK
        """
        ast = parse(tokenize(source))
        opt_result = optimize_policy(ast)
        self.assertEqual(opt_result.original_count, 2)
        self.assertEqual(opt_result.optimized_count, 1)
        self.assertEqual(opt_result.optimized_policy.rules[0].name, "ALLOW_PORT_80")

    def test_behavior_preservation_original_vs_optimized(self):
        """
        CRITICAL COMPILER REQUIREMENT:
        Verifies that evaluating the original policy AST and the optimized policy AST
        produces identical actions across a diverse suite of sample test packets.
        """
        source = """
        RULE BLOCK_TELNET
        WHEN TCP PORT 23
        IF SOURCE ANY
        THEN BLOCK

        # Exact duplicate (will be pruned)
        RULE BLOCK_TELNET_COPY
        WHEN TCP PORT 23
        IF SOURCE ANY
        THEN BLOCK

        RULE ALLOW_WEB
        WHEN TCP PORT 80
        IF SOURCE ANY
        THEN ALLOW

        # Dead code conflict (will be pruned)
        RULE BLOCK_WEB_DEAD
        WHEN TCP PORT 80
        IF SOURCE ANY
        THEN BLOCK

        RULE ALLOW_ALL_INTERNAL
        WHEN ANY PORT ANY
        IF SOURCE INTERNAL
        THEN ALLOW

        # Subsumed rule (will be pruned)
        RULE ALLOW_INTERNAL_SSH
        WHEN TCP PORT 22
        IF SOURCE INTERNAL
        THEN ALLOW

        RULE BLOCK_EXTERNAL_SSH
        WHEN TCP PORT 22
        IF SOURCE EXTERNAL
        THEN BLOCK
        """
        original_ast = parse(tokenize(source))
        opt_res = optimize_policy(original_ast)
        optimized_ast = opt_res.optimized_policy

        self.assertLess(len(optimized_ast.rules), len(original_ast.rules))

        # Comprehensive packet test suite
        test_packets = [
            # Matches Telnet block
            {"protocol": "TCP", "port": 23, "source": "192.168.1.5"},
            {"protocol": "TCP", "port": 23, "source": "100.64.0.1"},
            # Matches Web allow
            {"protocol": "TCP", "port": 80, "source": "8.8.8.8"},
            {"protocol": "TCP", "port": 80, "source": "192.168.1.10"},
            # Matches Internal allow
            {"protocol": "TCP", "port": 22, "source": "192.168.1.20"},
            {"protocol": "UDP", "port": 53, "source": "10.0.0.5"},
            {"protocol": "ICMP", "port": 0, "source": "172.16.0.1"},
            # Matches External SSH block
            {"protocol": "TCP", "port": 22, "source": "203.0.113.5"},
            # Matches Fallback default block
            {"protocol": "UDP", "port": 9999, "source": "203.0.113.10"},
        ]

        for pkt in test_packets:
            res_orig = evaluate_packet(original_ast, pkt)
            res_opt = evaluate_packet(optimized_ast, pkt)

            # Both original and optimized must yield the exact same security decision!
            self.assertEqual(
                res_orig["action"],
                res_opt["action"],
                f"Action mismatch for packet {pkt}: original={res_orig['action']}, optimized={res_opt['action']}",
            )


if __name__ == "__main__":
    unittest.main()

"""Tests for the IR, peephole optimizer, IR VM, verifier and the full pipeline."""

import glob
import os
import subprocess
import sys
import unittest

from src.code_generator import evaluate_packet
from src.intermediate_code import generate_ir, optimize_ir
from src.ir_vm import execute_ir
from src.lexer import tokenize
from src.main import compile_source
from src.parser import parse
from src.semantic_analyzer import SemanticAnalysisError
from src.verifier import representative_packets, verify

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

POLICY = """
RULE BLOCK_SSH WHEN TCP PORT 22 IF SOURCE UNKNOWN THEN BLOCK
RULE ALLOW_WEB WHEN TCP PORT 443 IF SOURCE ANY THEN ALLOW
RULE ALLOW_LAN WHEN ANY PORT ANY IF SOURCE 192.168.0.0/16 THEN ALLOW
"""


class TestIR(unittest.TestCase):

    def setUp(self):
        self.ast = parse(tokenize(POLICY))
        self.ir = generate_ir(self.ast)

    def test_all_jump_targets_are_defined(self):
        labels = {q.result for q in self.ir.quadruples if q.op == "LABEL"}
        for q in self.ir.quadruples:
            if q.op in ("IF_FALSE_GOTO", "GOTO"):
                self.assertIn(q.result, labels)

    def test_peephole_folds_any_tests(self):
        opt, report = optimize_ir(self.ir)
        self.assertLess(report.after, report.before)
        self.assertFalse(any(q.op.startswith("TEST") and q.arg1 == "ANY" for q in opt.quadruples))
        self.assertGreater(report.stats["constant_folded"], 0)

    def test_unconditional_rule_makes_rest_unreachable(self):
        ast = parse(tokenize("RULE ALL WHEN ANY PORT ANY IF SOURCE ANY THEN ALLOW"))
        opt, report = optimize_ir(generate_ir(ast))
        ops = [q.op for q in opt.quadruples if q.op not in ("COMMENT", "LABEL")]
        self.assertEqual(ops, ["RETURN_ACTION"])
        self.assertGreater(report.stats["unreachable_removed"], 0)

    def test_vm_matches_reference_interpreter(self):
        opt, _ = optimize_ir(self.ir)
        for pkt in representative_packets(self.ast):
            self.assertEqual(execute_ir(self.ir.quadruples, pkt)["action"], evaluate_packet(self.ast, pkt)["action"])
            self.assertEqual(execute_ir(opt.quadruples, pkt)["action"], evaluate_packet(self.ast, pkt)["action"])


class TestPipeline(unittest.TestCase):

    def test_examples_compile_and_verify(self):
        for path in glob.glob(os.path.join(ROOT, "examples", "*.spol")):
            with open(path, encoding="utf-8") as fh:
                src = fh.read()
            if "invalid" in os.path.basename(path):
                with self.assertRaises(SemanticAnalysisError):
                    compile_source(src, path)
                continue
            res = compile_source(src, path)
            self.assertTrue(res.verification.passed, path)
            self.assertTrue(compile_source(src, path, aggressive=True).verification.passed, path)

    def test_verifier_detects_a_wrong_program(self):
        res = compile_source(POLICY)
        wrong = parse(tokenize("RULE X WHEN ANY PORT ANY IF SOURCE ANY THEN ALLOW"))
        bad_ir, _ = optimize_ir(generate_ir(wrong))
        self.assertFalse(verify(res.normalized, bad_ir.quadruples).passed)

    def test_aggressive_removes_default_redundant_block(self):
        res = compile_source(POLICY, aggressive=True)
        names = [r.name for r in res.optimization.optimized_policy.rules]
        self.assertNotIn("BLOCK_SSH", names)
        self.assertTrue(res.verification.passed)

    def test_cli_and_generated_program(self):
        out = os.path.join(ROOT, "output", "_test_policy.py")
        cmd = [sys.executable, os.path.join(ROOT, "src", "main.py"), "-o", out,
               "--packet", "TCP 22 10.0.0.5", os.path.join(ROOT, "examples", "sample_policy.spol")]
        self.assertEqual(subprocess.run(cmd, capture_output=True, cwd=ROOT).returncode, 0)
        run = subprocess.run([sys.executable, out, "TCP", "22", "192.168.1.25"], capture_output=True, text=True)
        self.assertIn("ALLOW", run.stdout)
        os.remove(out)


class TestIRStepCounts(unittest.TestCase):
    """Focused tests for IR step-count reporting (requirement 3)."""

    # A policy with non-trivial conditions: proto + port + source checks on
    # each rule, so the raw IR will contain TEST_ANY folding candidates and
    # the optimized IR will be strictly shorter.
    STEP_POLICY = """
RULE ALLOW_WEB   WHEN TCP PORT 443 IF SOURCE ANY  THEN ALLOW
RULE ALLOW_DNS   WHEN UDP PORT 53  IF SOURCE ANY  THEN ALLOW
RULE ALLOW_LAN   WHEN ANY PORT ANY IF SOURCE 10.0.0.0/8 THEN ALLOW
"""

    def _compile(self, src=None, **kwargs):
        return compile_source(src or self.STEP_POLICY, **kwargs)

    # ------------------------------------------------------------------
    # Test 1: optimisation reduces measured interpreter steps for a packet
    # that matches a rule guarded by ANY conditions.
    # ------------------------------------------------------------------
    def test_any_condition_produces_fewer_steps_after_optimization(self):
        """A packet matching an ANY-conditioned rule executes fewer IR steps
        after the peephole optimizer removes redundant constant tests."""
        res = self._compile()
        packet = {"protocol": "TCP", "port": 443, "source": "1.2.3.4"}

        raw_steps = execute_ir(res.ir_raw.quadruples, packet)["steps"]
        opt_steps = execute_ir(res.ir.quadruples, packet)["steps"]

        # The optimized IR must be a different (smaller) object than the raw IR.
        self.assertIsNot(res.ir, res.ir_raw)
        # After folding tests against ANY we expect strictly fewer steps.
        self.assertLess(opt_steps, raw_steps,
                        f"Expected opt steps ({opt_steps}) < raw steps ({raw_steps})")

    # ------------------------------------------------------------------
    # Test 2: step-count ordering is consistent with IR semantics.
    # A packet that matches the first rule should require no more steps
    # than a packet that falls all the way through to the default fallback,
    # because the optimized IR stops early on a match.
    # ------------------------------------------------------------------
    def test_early_match_takes_no_more_steps_than_default_fallback(self):
        """A first-rule match must execute <= steps compared to a packet
        that exhausts all rules and hits the default BLOCK."""
        res = self._compile()
        quads = res.ir.quadruples

        # Packet hitting the very first rule.
        first_rule_pkt = {"protocol": "TCP", "port": 443, "source": "1.2.3.4"}
        # Packet that matches no rule and falls through to DEFAULT_FALLBACK.
        fallback_pkt = {"protocol": "ICMP", "port": 9999, "source": "255.255.255.255"}

        first_steps = execute_ir(quads, first_rule_pkt)["steps"]
        fallback_steps = execute_ir(quads, fallback_pkt)["steps"]

        # Semantic guarantee: first rule match ≤ full walk-through.
        self.assertLessEqual(first_steps, fallback_steps,
                             f"first_steps={first_steps}, fallback_steps={fallback_steps}")

        # Sanity: both paths must actually execute the correct action.
        self.assertEqual(execute_ir(quads, first_rule_pkt)["action"], "ALLOW")
        self.assertEqual(execute_ir(quads, fallback_pkt)["action"], "BLOCK")

    # ------------------------------------------------------------------
    # Test 3: compile_source() exposes usable raw and optimized IRs
    # with measurable step counts for the reporting code.
    # ------------------------------------------------------------------
    def test_compile_source_exposes_raw_and_optimized_ir_steps(self):
        """compile_source() must set both ir_raw and ir so that each can
        be executed with execute_ir() and returns a non-zero 'steps' key."""
        res = self._compile()

        # Both IRs must be present and distinct when optimization is on.
        self.assertIsNotNone(res.ir_raw)
        self.assertIsNotNone(res.ir)
        self.assertIsNot(res.ir, res.ir_raw)

        packet = {"protocol": "UDP", "port": 53, "source": "10.0.0.1"}
        raw_result = execute_ir(res.ir_raw.quadruples, packet)
        opt_result = execute_ir(res.ir.quadruples, packet)

        self.assertIn("steps", raw_result)
        self.assertIn("steps", opt_result)
        self.assertGreater(raw_result["steps"], 0)
        self.assertGreater(opt_result["steps"], 0)

        # Both must agree on the final action (semantic equivalence).
        self.assertEqual(raw_result["action"], opt_result["action"])


if __name__ == "__main__":
    unittest.main()

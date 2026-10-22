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


if __name__ == "__main__":
    unittest.main()

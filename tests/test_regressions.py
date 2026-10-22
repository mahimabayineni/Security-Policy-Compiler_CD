"""
Regression tests for the bugs fixed in v2.0. Each test reproduces a bug found in v1.0.
"""

import unittest

from src.code_generator import evaluate_packet, generate_python_code
from src.lexer import tokenize
from src.optimizer import optimize_policy
from src.parser import parse
from src.rule_analyzer import AnomalyType, analyze_rules
from src.semantic_analyzer import SemanticAnalyzer


def P(src):
    return parse(tokenize(src))


class TestRegressions(unittest.TestCase):

    def test_internal_label_does_not_match_external_rule(self):
        policy = P("RULE A WHEN TCP PORT 22 IF SOURCE EXTERNAL THEN ALLOW")
        for label in ("INTERNAL", "UNKNOWN", "garbage"):
            pkt = {"protocol": "TCP", "port": 22, "source": label}
            self.assertEqual(evaluate_packet(policy, pkt)["action"], "BLOCK", label)
            ns = {}
            exec(generate_python_code(policy), ns)
            self.assertEqual(ns["evaluate_packet"](pkt)["action"], "BLOCK", label)
        self.assertEqual(evaluate_packet(policy, {"protocol": "TCP", "port": 22, "source": "EXTERNAL"})["action"], "ALLOW")

    def test_icmp_port_zero_is_accepted(self):
        sem = SemanticAnalyzer(P("RULE A WHEN ICMP PORT 0 IF SOURCE ANY THEN ALLOW"))
        self.assertEqual(sem.analyze(), [])
        self.assertEqual(sem.normalized_policy().rules[0].port, "ANY")

    def test_port_zero_rejected_for_tcp(self):
        errors = SemanticAnalyzer(P("RULE A WHEN TCP PORT 0 IF SOURCE ANY THEN ALLOW")).analyze()
        self.assertEqual(len(errors), 1)

    def test_lowercase_named_source_is_normalized(self):
        policy = P("RULE A WHEN TCP PORT 80 IF SOURCE any THEN ALLOW\n"
                   "RULE B WHEN TCP PORT 80 IF SOURCE 1.2.3.4 THEN BLOCK")
        self.assertEqual(policy.rules[0].source, "ANY")
        types = [a.anomaly_type for a in analyze_rules(policy).anomalies]
        self.assertEqual(types, [AnomalyType.SHADOWED_RULE])

    def test_shadowed_rule_is_removed_by_optimizer(self):
        policy = P("RULE A WHEN ANY PORT ANY IF SOURCE EXTERNAL THEN BLOCK\n"
                   "RULE B WHEN TCP PORT 443 IF SOURCE EXTERNAL THEN ALLOW")
        res = optimize_policy(policy)
        self.assertEqual([r.name for r in res.optimized_policy.rules], ["A"])
        self.assertEqual(res.actions[0].action_type, "ELIMINATE_SHADOWED")

    def test_internal_covers_private_cidr(self):
        policy = P("RULE A WHEN ANY PORT ANY IF SOURCE INTERNAL THEN BLOCK\n"
                   "RULE B WHEN TCP PORT 22 IF SOURCE 192.168.1.0/24 THEN ALLOW")
        types = [a.anomaly_type for a in analyze_rules(policy).anomalies]
        self.assertEqual(types, [AnomalyType.SHADOWED_RULE])

    def test_semantic_error_points_at_offending_token(self):
        src = "RULE A\nWHEN TCP PORT 70000\nIF SOURCE ANY\nTHEN ALLOW"
        err = SemanticAnalyzer(P(src)).analyze()[0]
        self.assertEqual((err.line, err.column), (2, 15))

    def test_windows_path_in_header_gives_no_warning(self):
        import warnings
        code = generate_python_code(P("RULE A WHEN TCP PORT 22 IF SOURCE ANY THEN ALLOW"),
                                    source_name="E:\\Sem 5 projects\\CD Proj\\policy.spol")
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            compile(code, "<generated_policy>", "exec")


if __name__ == "__main__":
    unittest.main()

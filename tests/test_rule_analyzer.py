"""
Unit tests for Phase 5: Rule Analyzer (rule_analyzer.py)
"""

import unittest
from src.lexer import tokenize
from src.parser import parse
from src.rule_analyzer import AnomalyType, analyze_rules


class TestRuleAnalyzer(unittest.TestCase):

    def _get_anomalies(self, source: str):
        tokens = tokenize(source)
        ast = parse(tokens)
        report = analyze_rules(ast)
        return report.anomalies

    def test_detect_exact_duplicate_rules(self):
        source = """
        RULE R1
        WHEN TCP PORT 80
        IF SOURCE ANY
        THEN ALLOW

        RULE R2
        WHEN TCP PORT 80
        IF SOURCE ANY
        THEN ALLOW
        """
        anomalies = self._get_anomalies(source)
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0].anomaly_type, AnomalyType.EXACT_DUPLICATE)
        self.assertEqual(anomalies[0].prior_rule.name, "R1")
        self.assertEqual(anomalies[0].later_rule.name, "R2")

    def test_detect_conflicting_rules(self):
        source = """
        RULE ALLOW_RULE
        WHEN TCP PORT 80
        IF SOURCE ANY
        THEN ALLOW

        RULE BLOCK_RULE
        WHEN TCP PORT 80
        IF SOURCE ANY
        THEN BLOCK
        """
        anomalies = self._get_anomalies(source)
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0].anomaly_type, AnomalyType.CONFLICT)
        self.assertIn("Under first-match semantics", anomalies[0].explanation)

    def test_detect_shadowed_rule_by_broader_prior_rule(self):
        source = """
        RULE BLOCK_ALL_EXTERNAL
        WHEN ANY PORT ANY
        IF SOURCE EXTERNAL
        THEN BLOCK

        RULE ALLOW_EXTERNAL_HTTPS
        WHEN TCP PORT 443
        IF SOURCE EXTERNAL
        THEN ALLOW
        """
        anomalies = self._get_anomalies(source)
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0].anomaly_type, AnomalyType.SHADOWED_RULE)

    def test_detect_redundant_subsumed_rule(self):
        source = """
        RULE ALLOW_ALL_INTERNAL
        WHEN ANY PORT ANY
        IF SOURCE INTERNAL
        THEN ALLOW

        RULE ALLOW_INTERNAL_SSH
        WHEN TCP PORT 22
        IF SOURCE INTERNAL
        THEN ALLOW
        """
        anomalies = self._get_anomalies(source)
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0].anomaly_type, AnomalyType.REDUNDANT_SUBSUMED)

    def test_different_ports_or_protocols_are_not_conflicts(self):
        source = """
        RULE ALLOW_WEB
        WHEN TCP PORT 443
        IF SOURCE ANY
        THEN ALLOW

        RULE BLOCK_HTTP
        WHEN TCP PORT 80
        IF SOURCE ANY
        THEN BLOCK

        RULE ALLOW_DNS
        WHEN UDP PORT 53
        IF SOURCE ANY
        THEN ALLOW
        """
        anomalies = self._get_anomalies(source)
        self.assertEqual(len(anomalies), 0)


if __name__ == "__main__":
    unittest.main()

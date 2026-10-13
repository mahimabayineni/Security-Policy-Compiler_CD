"""
Unit tests for Phase 3: Semantic Analyzer (semantic_analyzer.py)
"""

import unittest
from src.lexer import tokenize
from src.parser import parse
from src.semantic_analyzer import SemanticAnalysisError, SemanticAnalyzer


class TestSemanticAnalyzer(unittest.TestCase):

    def _analyze(self, source: str):
        tokens = tokenize(source)
        ast = parse(tokens)
        analyzer = SemanticAnalyzer(ast)
        return analyzer.analyze()

    def test_valid_policy_passes_cleanly(self):
        source = """
        RULE ALLOW_HTTP
        WHEN TCP PORT 80
        IF SOURCE ANY
        THEN ALLOW
        """
        errors = self._analyze(source)
        self.assertEqual(len(errors), 0)

    def test_duplicate_rule_name_detected(self):
        source = """
        RULE RULE_ONE
        WHEN TCP PORT 80
        IF SOURCE ANY
        THEN ALLOW

        RULE RULE_ONE
        WHEN TCP PORT 443
        IF SOURCE ANY
        THEN ALLOW
        """
        errors = self._analyze(source)
        self.assertEqual(len(errors), 1)
        self.assertIn("Duplicate rule identifier 'RULE_ONE'", errors[0].message)

    def test_invalid_port_range_detected(self):
        source = """
        RULE OUT_OF_BOUNDS_PORT
        WHEN TCP PORT 70000
        IF SOURCE ANY
        THEN ALLOW
        """
        errors = self._analyze(source)
        self.assertEqual(len(errors), 1)
        self.assertIn("Port number 70000 out of range", errors[0].message)

    def test_unsupported_protocol_detected(self):
        source = """
        RULE BAD_PROTO
        WHEN HTTP PORT 80
        IF SOURCE ANY
        THEN ALLOW
        """
        errors = self._analyze(source)
        self.assertEqual(len(errors), 1)
        self.assertIn("Unsupported transport protocol 'HTTP'", errors[0].message)

    def test_icmp_port_compatibility(self):
        source = """
        RULE ICMP_WITH_TCP_PORT
        WHEN ICMP PORT 80
        IF SOURCE ANY
        THEN ALLOW
        """
        errors = self._analyze(source)
        self.assertEqual(len(errors), 1)
        self.assertIn("Protocol ICMP does not use TCP/UDP port numbers", errors[0].message)

    def test_invalid_source_format(self):
        source = """
        RULE BAD_SOURCE
        WHEN TCP PORT 80
        IF SOURCE 999.999.999.999
        THEN ALLOW
        """
        errors = self._analyze(source)
        self.assertEqual(len(errors), 1)
        self.assertIn("Invalid source condition", errors[0].message)


if __name__ == "__main__":
    unittest.main()

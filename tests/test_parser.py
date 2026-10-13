"""
Unit tests for Phase 2: Syntax Analysis (parser.py)
"""

import unittest
from src.lexer import tokenize
from src.parser import ParserError, parse


class TestParser(unittest.TestCase):

    def test_parse_valid_single_rule(self):
        source = """
        RULE ALLOW_HTTPS
        WHEN TCP PORT 443
        IF SOURCE ANY
        THEN ALLOW
        """
        tokens = tokenize(source)
        ast = parse(tokens)

        self.assertEqual(len(ast.rules), 1)
        rule = ast.rules[0]
        self.assertEqual(rule.name, "ALLOW_HTTPS")
        self.assertEqual(rule.protocol, "TCP")
        self.assertEqual(rule.port, 443)
        self.assertEqual(rule.source, "ANY")
        self.assertEqual(rule.action, "ALLOW")

    def test_parse_multiple_rules(self):
        source = """
        RULE R1
        WHEN TCP PORT 80
        IF SOURCE ANY
        THEN BLOCK

        RULE R2
        WHEN UDP PORT 53
        IF SOURCE 10.0.0.1
        THEN ALLOW
        """
        tokens = tokenize(source)
        ast = parse(tokens)
        self.assertEqual(len(ast.rules), 2)
        self.assertEqual(ast.rules[0].name, "R1")
        self.assertEqual(ast.rules[1].name, "R2")

    def test_missing_when_clause_raises_parser_error(self):
        source = """
        RULE BROKEN_RULE
        TCP PORT 80
        IF SOURCE ANY
        THEN BLOCK
        """
        tokens = tokenize(source)
        with self.assertRaises(ParserError) as ctx:
            parse(tokens)
        self.assertIn("Expected 'WHEN' clause", str(ctx.exception))

    def test_missing_then_action_raises_parser_error(self):
        source = """
        RULE BROKEN_RULE
        WHEN TCP PORT 80
        IF SOURCE ANY
        ALLOW
        """
        tokens = tokenize(source)
        with self.assertRaises(ParserError) as ctx:
            parse(tokens)
        self.assertIn("Expected 'THEN' keyword", str(ctx.exception))

    def test_empty_input_raises_parser_error(self):
        tokens = tokenize("")
        with self.assertRaises(ParserError) as ctx:
            parse(tokens)
        self.assertIn("Empty policy file", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

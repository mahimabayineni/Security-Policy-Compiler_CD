"""
Unit tests for Phase 1: Lexical Analyzer (lexer.py)
"""

import unittest
from src.lexer import Lexer, LexerError, TokenType, tokenize


class TestLexer(unittest.TestCase):

    def test_tokenize_basic_keywords_and_identifiers(self):
        source = "RULE ALLOW_SSH WHEN TCP PORT 22 IF SOURCE ANY THEN ALLOW"
        tokens = tokenize(source)

        expected_types = [
            TokenType.KW_RULE,
            TokenType.IDENTIFIER,
            TokenType.KW_WHEN,
            TokenType.KW_TCP,
            TokenType.KW_PORT,
            TokenType.NUMBER,
            TokenType.KW_IF,
            TokenType.KW_SOURCE,
            TokenType.KW_ANY,
            TokenType.KW_THEN,
            TokenType.KW_ALLOW,
            TokenType.EOF,
        ]

        self.assertEqual(len(tokens), len(expected_types))
        for tok, exp_type in zip(tokens, expected_types):
            self.assertEqual(tok.type, exp_type)

    def test_tokenize_numbers_and_ip_and_cidr(self):
        source = "443 192.168.1.1 10.0.0.0/24"
        tokens = tokenize(source)

        self.assertEqual(tokens[0].type, TokenType.NUMBER)
        self.assertEqual(tokens[0].value, "443")

        self.assertEqual(tokens[1].type, TokenType.IP_ADDRESS)
        self.assertEqual(tokens[1].value, "192.168.1.1")

        self.assertEqual(tokens[2].type, TokenType.CIDR)
        self.assertEqual(tokens[2].value, "10.0.0.0/24")

    def test_comments_and_whitespace_skipped(self):
        source = """
        # This is a full comment line
        RULE TEST_R # Inline comment
        WHEN UDP PORT 53
        """
        tokens = tokenize(source)
        token_values = [t.value for t in tokens if t.type != TokenType.EOF]
        self.assertEqual(token_values, ["RULE", "TEST_R", "WHEN", "UDP", "PORT", "53"])

    def test_line_and_column_tracking(self):
        source = "\n\n  RULE TEST"
        tokens = tokenize(source)
        # Line 3, column 3 (1-based index after 2 leading spaces)
        self.assertEqual(tokens[0].line, 3)
        self.assertEqual(tokens[0].column, 3)

    def test_invalid_character_raises_lexer_error(self):
        source = "RULE BAD @$ WHEN TCP"
        with self.assertRaises(LexerError) as ctx:
            tokenize(source)
        self.assertIn("Unrecognized character '@'", str(ctx.exception))
        self.assertEqual(ctx.exception.line, 1)
        self.assertEqual(ctx.exception.column, 10)


if __name__ == "__main__":
    unittest.main()

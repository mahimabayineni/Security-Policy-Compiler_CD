"""
Phase 1: Lexical Analysis (lexer.py)

Converts DSL source text into a stream of discrete tokens.
Tracks line numbers and column numbers for precise diagnostics.
"""

from enum import Enum, auto
import re
from typing import List, Optional, Tuple


class TokenType(Enum):
    # Keywords
    KW_RULE = auto()
    KW_WHEN = auto()
    KW_PORT = auto()
    KW_IF = auto()
    KW_SOURCE = auto()
    KW_THEN = auto()
    KW_ALLOW = auto()
    KW_BLOCK = auto()
    KW_DENY = auto()

    # Protocol keywords
    KW_TCP = auto()
    KW_UDP = auto()
    KW_ICMP = auto()
    KW_ANY = auto()

    # Source condition keywords
    KW_UNKNOWN = auto()
    KW_INTERNAL = auto()
    KW_EXTERNAL = auto()

    # Literals and Identifiers
    IDENTIFIER = auto()
    NUMBER = auto()
    IP_ADDRESS = auto()
    CIDR = auto()

    # End of File
    EOF = auto()


# Keyword lookup table
KEYWORDS = {
    "RULE": TokenType.KW_RULE,
    "WHEN": TokenType.KW_WHEN,
    "PORT": TokenType.KW_PORT,
    "IF": TokenType.KW_IF,
    "SOURCE": TokenType.KW_SOURCE,
    "THEN": TokenType.KW_THEN,
    "ALLOW": TokenType.KW_ALLOW,
    "BLOCK": TokenType.KW_BLOCK,
    "DENY": TokenType.KW_DENY,
    "TCP": TokenType.KW_TCP,
    "UDP": TokenType.KW_UDP,
    "ICMP": TokenType.KW_ICMP,
    "ANY": TokenType.KW_ANY,
    "UNKNOWN": TokenType.KW_UNKNOWN,
    "INTERNAL": TokenType.KW_INTERNAL,
    "EXTERNAL": TokenType.KW_EXTERNAL,
}


class Token:
    """Represents a single token in the Security Policy DSL."""

    def __init__(self, token_type: TokenType, value: str, line: int, column: int):
        self.type = token_type
        self.value = value
        self.line = line
        self.column = column

    def __repr__(self) -> str:
        return f"Token({self.type.name}, '{self.value}', line={self.line}, col={self.column})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Token):
            return False
        return (
            self.type == other.type
            and self.value == other.value
            and self.line == other.line
            and self.column == other.column
        )


class LexerError(Exception):
    """Raised when an invalid character or ill-formed token is encountered."""

    def __init__(self, message: str, line: int, column: int):
        self.message = message
        self.line = line
        self.column = column
        super().__init__(f"Lexical Error [Line {line}, Col {column}]: {message}")


class Lexer:
    """Lexical analyzer for Security Policy DSL."""

    def __init__(self, source_code: str):
        self.source = source_code
        self.length = len(source_code)
        self.position = 0
        self.line = 1
        self.column = 1

    def _peek(self, offset: int = 0) -> Optional[str]:
        idx = self.position + offset
        if idx < self.length:
            return self.source[idx]
        return None

    def _advance(self) -> Optional[str]:
        if self.position >= self.length:
            return None
        char = self.source[self.position]
        self.position += 1
        if char == '\n':
            self.line += 1
            self.column = 1
        else:
            self.column += 1
        return char

    def tokenize(self) -> List[Token]:
        tokens: List[Token] = []

        while self.position < self.length:
            char = self._peek()

            if char is None:
                break

            # Skip Whitespace
            if char in ' \t\r\n':
                self._advance()
                continue

            # Skip single-line comments (# ...)
            if char == '#':
                while self._peek() is not None and self._peek() != '\n':
                    self._advance()
                continue

            start_line = self.line
            start_col = self.column

            # Number, IP address, or CIDR (starts with a digit)
            if char.isdigit():
                val, token_type = self._read_number_or_ip(start_line, start_col)
                tokens.append(Token(token_type, val, start_line, start_col))
                continue

            # Identifiers and Keywords (starts with a letter or underscore)
            if char.isalpha() or char == '_':
                val = self._read_identifier()
                upper = val.upper()
                if upper in KEYWORDS:
                    tokens.append(Token(KEYWORDS[upper], val, start_line, start_col))
                else:
                    tokens.append(Token(TokenType.IDENTIFIER, val, start_line, start_col))
                continue

            # Unrecognized character
            bad_char = self._advance()
            raise LexerError(f"Unrecognized character '{bad_char}'", start_line, start_col)

        tokens.append(Token(TokenType.EOF, "", self.line, self.column))
        return tokens

    def _read_identifier(self) -> str:
        chars = []
        while self._peek() is not None:
            c = self._peek()
            if c.isalnum() or c in '_-':
                chars.append(self._advance())
            else:
                break
        return "".join(chars)

    def _read_number_or_ip(self, start_line: int, start_col: int) -> Tuple[str, TokenType]:
        chars = []
        while self._peek() is not None and (self._peek().isdigit() or self._peek() in './'):
            chars.append(self._advance())

        val = "".join(chars)

        # CIDR: e.g., 192.168.1.0/24
        cidr_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$'
        if re.match(cidr_pattern, val):
            return val, TokenType.CIDR

        # IP address: e.g., 10.0.0.1
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, val):
            return val, TokenType.IP_ADDRESS

        # Simple integer
        if val.isdigit():
            return val, TokenType.NUMBER

        raise LexerError(f"Malformed numeric or IP token '{val}'", start_line, start_col)


def tokenize(source_code: str) -> List[Token]:
    """Convenience helper to tokenize source code."""
    lexer = Lexer(source_code)
    return lexer.tokenize()


def format_tokens(tokens: List[Token]) -> str:
    """Format tokens into a clean ASCII table for demonstration."""
    lines = [
        "+" + "-" * 12 + "+" + "-" * 18 + "+" + "-" * 26 + "+",
        f"| {'LINE:COL':<10} | {'TOKEN TYPE':<16} | {'VALUE':<24} |",
        "+" + "-" * 12 + "+" + "-" * 18 + "+" + "-" * 26 + "+",
    ]
    for tok in tokens:
        pos = f"{tok.line}:{tok.column}"
        lines.append(f"| {pos:<10} | {tok.type.name:<16} | {tok.value:<24} |")
    lines.append("+" + "-" * 12 + "+" + "-" * 18 + "+" + "-" * 26 + "+")
    return "\n".join(lines)

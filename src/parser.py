"""
Phase 2: Syntax Analysis (parser.py)

Constructs an Abstract Syntax Tree (AST) from the token stream using
a recursive-descent parsing technique. Reports precise syntax errors.
"""

from typing import Any, Dict, List, Optional, Union
from src.lexer import Token, TokenType


class ParserError(Exception):
    """Raised when the parser encounters a syntax violation."""

    def __init__(self, message: str, line: int, column: int):
        self.message = message
        self.line = line
        self.column = column
        super().__init__(f"Syntax Error [Line {line}, Col {column}]: {message}")


class ASTNode:
    """Base class for all AST nodes."""

    def to_dict(self) -> Dict[str, Any]:
        raise NotImplementedError


class RuleNode(ASTNode):
    """Represents an individual security rule AST node."""

    def __init__(
        self,
        name: str,
        protocol: str,
        port: Union[int, str],
        source: str,
        action: str,
        line: int,
        column: int,
    ):
        self.name = name
        self.protocol = protocol.upper()
        self.port = port
        self.source = source
        self.action = action.upper()
        self.line = line
        self.column = column

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "Rule",
            "name": self.name,
            "protocol": self.protocol,
            "port": self.port,
            "source": self.source,
            "action": self.action,
            "line": self.line,
            "column": self.column,
        }

    def __repr__(self) -> str:
        return (
            f"RuleNode({self.name}, {self.protocol}:{self.port}, "
            f"src={self.source} -> {self.action})"
        )


class PolicyNode(ASTNode):
    """Root node representing an entire security policy comprising multiple rules."""

    def __init__(self, rules: List[RuleNode]):
        self.rules = rules

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "Policy",
            "rules": [rule.to_dict() for rule in self.rules],
        }

    def __repr__(self) -> str:
        return f"PolicyNode(rules_count={len(self.rules)})"


class Parser:
    """Recursive-descent parser for the Security Policy DSL."""

    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.current = 0

    def _peek(self) -> Token:
        if self.current < len(self.tokens):
            return self.tokens[self.current]
        return self.tokens[-1]  # Return EOF token

    def _previous(self) -> Token:
        return self.tokens[self.current - 1]

    def _is_at_end(self) -> bool:
        return self._peek().type == TokenType.EOF

    def _advance(self) -> Token:
        if not self._is_at_end():
            self.current += 1
        return self._previous()

    def _check(self, token_type: TokenType) -> bool:
        if self._is_at_end():
            return token_type == TokenType.EOF
        return self._peek().type == token_type

    def _consume(self, token_type: TokenType, err_msg: str) -> Token:
        if self._check(token_type):
            return self._advance()
        tok = self._peek()
        raise ParserError(f"{err_msg}. Got '{tok.value}' ({tok.type.name})", tok.line, tok.column)

    def parse(self) -> PolicyNode:
        """Parses the entire token stream into a PolicyNode AST."""
        rules: List[RuleNode] = []

        if self._is_at_end():
            tok = self._peek()
            raise ParserError("Empty policy file: at least one RULE definition is required", tok.line, tok.column)

        while not self._is_at_end():
            rules.append(self._parse_rule())

        return PolicyNode(rules)

    def _parse_rule(self) -> RuleNode:
        """Parses a single RULE block according to the DSL grammar."""
        rule_tok = self._consume(TokenType.KW_RULE, "Expected 'RULE' keyword at start of rule")
        
        # Rule name identifier
        name_tok = self._peek()
        if name_tok.type not in (TokenType.IDENTIFIER, TokenType.KW_BLOCK, TokenType.KW_ALLOW):
            # If user named a rule something else, or identifier
            pass
        if name_tok.type == TokenType.IDENTIFIER:
            self._advance()
            rule_name = name_tok.value
        else:
            raise ParserError("Expected a valid rule name identifier after 'RULE'", name_tok.line, name_tok.column)

        # WHEN clause
        self._consume(TokenType.KW_WHEN, f"Expected 'WHEN' clause in rule '{rule_name}'")
        protocol = self._parse_protocol()

        self._consume(TokenType.KW_PORT, f"Expected 'PORT' keyword after protocol in rule '{rule_name}'")
        port = self._parse_port()

        # IF SOURCE clause
        self._consume(TokenType.KW_IF, f"Expected 'IF' keyword in rule '{rule_name}'")
        self._consume(TokenType.KW_SOURCE, f"Expected 'SOURCE' keyword after 'IF' in rule '{rule_name}'")
        source = self._parse_source()

        # THEN clause
        self._consume(TokenType.KW_THEN, f"Expected 'THEN' keyword in rule '{rule_name}'")
        action = self._parse_action()

        return RuleNode(
            name=rule_name,
            protocol=protocol,
            port=port,
            source=source,
            action=action,
            line=rule_tok.line,
            column=rule_tok.column,
        )

    def _parse_protocol(self) -> str:
        tok = self._peek()
        if tok.type in (TokenType.KW_TCP, TokenType.KW_UDP, TokenType.KW_ICMP, TokenType.KW_ANY):
            self._advance()
            return tok.value.upper()
        # Allow identifier for protocol (e.g. CUSTOM) to let semantic analyzer catch invalid protocols
        if tok.type == TokenType.IDENTIFIER:
            self._advance()
            return tok.value.upper()
        raise ParserError(f"Expected protocol (TCP, UDP, ICMP, ANY), got '{tok.value}'", tok.line, tok.column)

    def _parse_port(self) -> Union[int, str]:
        tok = self._peek()
        if tok.type == TokenType.NUMBER:
            self._advance()
            return int(tok.value)
        if tok.type == TokenType.KW_ANY:
            self._advance()
            return "ANY"
        if tok.type == TokenType.IDENTIFIER:
            # Allow identifier (e.g. 'SSH' or 'EIGHTY') to let semantic analyzer flag invalid port values
            self._advance()
            return tok.value
        raise ParserError(f"Expected integer port number (1-65535) or 'ANY', got '{tok.value}'", tok.line, tok.column)

    def _parse_source(self) -> str:
        tok = self._peek()
        valid_types = (
            TokenType.KW_ANY,
            TokenType.KW_UNKNOWN,
            TokenType.KW_INTERNAL,
            TokenType.KW_EXTERNAL,
            TokenType.IP_ADDRESS,
            TokenType.CIDR,
            TokenType.IDENTIFIER,
        )
        if tok.type in valid_types:
            self._advance()
            return tok.value
        raise ParserError(
            f"Expected source condition (ANY, UNKNOWN, INTERNAL, EXTERNAL, IP, CIDR), got '{tok.value}'",
            tok.line,
            tok.column,
        )

    def _parse_action(self) -> str:
        tok = self._peek()
        if tok.type in (TokenType.KW_ALLOW, TokenType.KW_BLOCK, TokenType.KW_DENY):
            self._advance()
            # Normalize DENY to BLOCK
            return "BLOCK" if tok.type == TokenType.KW_DENY else tok.value.upper()
        if tok.type == TokenType.IDENTIFIER:
            self._advance()
            return tok.value.upper()
        raise ParserError(f"Expected action (ALLOW or BLOCK), got '{tok.value}'", tok.line, tok.column)


def parse(tokens: List[Token]) -> PolicyNode:
    """Helper function to parse tokens into an AST."""
    parser = Parser(tokens)
    return parser.parse()


def format_ast(node: PolicyNode) -> str:
    """Formats the AST into a structured tree view for presentation."""
    lines = ["Policy AST Root"]
    for i, rule in enumerate(node.rules, 1):
        is_last = i == len(node.rules)
        prefix = "\\-- " if is_last else "+-- "
        child_prefix = "    " if is_last else "|   "

        lines.append(f"{prefix}Rule: {rule.name} [Line {rule.line}]")
        lines.append(f"{child_prefix}+-- Protocol : {rule.protocol}")
        lines.append(f"{child_prefix}+-- Port     : {rule.port}")
        lines.append(f"{child_prefix}+-- Source   : {rule.source}")
        lines.append(f"{child_prefix}\\-- Action   : {rule.action}")
    return "\n".join(lines)

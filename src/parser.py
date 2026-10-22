"""
Phase 2: Syntax Analysis (parser.py)

Builds an Abstract Syntax Tree (AST) from the token stream with a
recursive-descent parser. The grammar (docs/grammar.md) is LL(1): every
choice is decided by the single next token, so no backtracking is needed.

Each RuleNode records the source position of every field, so later phases
can point diagnostics at the exact offending token.
"""

from typing import Any, Dict, List, Optional, Tuple, Union

from src.lexer import Token, TokenType

Position = Tuple[int, int]


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
    """An individual security rule."""

    def __init__(
        self,
        name: str,
        protocol: str,
        port: Union[int, str],
        source: str,
        action: str,
        line: int,
        column: int,
        positions: Optional[Dict[str, Position]] = None,
    ):
        self.name = name
        self.protocol = protocol.upper()
        self.port = port
        self.source = source
        self.action = action.upper()
        self.line = line
        self.column = column
        # Position of each field's token; defaults to the RULE keyword.
        self.positions: Dict[str, Position] = positions or {}

    def pos(self, field: str) -> Position:
        return self.positions.get(field, (self.line, self.column))

    def copy(self, **changes) -> "RuleNode":
        values = dict(
            name=self.name, protocol=self.protocol, port=self.port, source=self.source,
            action=self.action, line=self.line, column=self.column, positions=dict(self.positions),
        )
        values.update(changes)
        return RuleNode(**values)

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
        return f"RuleNode({self.name}, {self.protocol}:{self.port}, src={self.source} -> {self.action})"


class PolicyNode(ASTNode):
    """Root node: an ordered list of rules (order matters under first-match semantics)."""

    def __init__(self, rules: List[RuleNode]):
        self.rules = rules

    def to_dict(self) -> Dict[str, Any]:
        return {"type": "Policy", "rules": [rule.to_dict() for rule in self.rules]}

    def __repr__(self) -> str:
        return f"PolicyNode(rules_count={len(self.rules)})"


class Parser:
    """Recursive-descent parser for the Security Policy DSL."""

    PROTOCOL_TOKENS = (TokenType.KW_TCP, TokenType.KW_UDP, TokenType.KW_ICMP, TokenType.KW_ANY)
    NAMED_SOURCE_TOKENS = (TokenType.KW_ANY, TokenType.KW_UNKNOWN, TokenType.KW_INTERNAL, TokenType.KW_EXTERNAL)
    ACTION_TOKENS = (TokenType.KW_ALLOW, TokenType.KW_BLOCK, TokenType.KW_DENY)

    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.current = 0

    # ---- token stream helpers -------------------------------------------------
    def _peek(self) -> Token:
        if self.current < len(self.tokens):
            return self.tokens[self.current]
        return self.tokens[-1]

    def _is_at_end(self) -> bool:
        return self._peek().type == TokenType.EOF

    def _advance(self) -> Token:
        tok = self._peek()
        if not self._is_at_end():
            self.current += 1
        return tok

    def _consume(self, token_type: TokenType, err_msg: str) -> Token:
        if self._peek().type == token_type:
            return self._advance()
        tok = self._peek()
        raise ParserError(f"{err_msg}. Got '{tok.value}' ({tok.type.name})", tok.line, tok.column)

    # ---- grammar productions -----------------------------------------------------
    def parse(self) -> PolicyNode:
        """Policy ::= Rule+ EOF"""
        if self._is_at_end():
            tok = self._peek()
            raise ParserError("Empty policy file: at least one RULE definition is required", tok.line, tok.column)

        rules: List[RuleNode] = []
        while not self._is_at_end():
            rules.append(self._parse_rule())
        return PolicyNode(rules)

    def _parse_rule(self) -> RuleNode:
        """Rule ::= RULE Identifier WHEN Protocol PORT PortSpec IF SOURCE SourceSpec THEN Action"""
        rule_tok = self._consume(TokenType.KW_RULE, "Expected 'RULE' keyword at start of rule")

        name_tok = self._peek()
        if name_tok.type != TokenType.IDENTIFIER:
            raise ParserError(
                f"Expected a rule name after 'RULE' (keywords cannot be rule names). Got '{name_tok.value}'",
                name_tok.line, name_tok.column,
            )
        self._advance()
        name = name_tok.value

        self._consume(TokenType.KW_WHEN, f"Expected 'WHEN' clause in rule '{name}'")
        protocol, proto_tok = self._parse_protocol()
        self._consume(TokenType.KW_PORT, f"Expected 'PORT' keyword after protocol in rule '{name}'")
        port, port_tok = self._parse_port()
        self._consume(TokenType.KW_IF, f"Expected 'IF' keyword in rule '{name}'")
        self._consume(TokenType.KW_SOURCE, f"Expected 'SOURCE' keyword after 'IF' in rule '{name}'")
        source, source_tok = self._parse_source()
        self._consume(TokenType.KW_THEN, f"Expected 'THEN' keyword in rule '{name}'")
        action, action_tok = self._parse_action()

        return RuleNode(
            name=name,
            protocol=protocol,
            port=port,
            source=source,
            action=action,
            line=rule_tok.line,
            column=rule_tok.column,
            positions={
                "name": (name_tok.line, name_tok.column),
                "protocol": (proto_tok.line, proto_tok.column),
                "port": (port_tok.line, port_tok.column),
                "source": (source_tok.line, source_tok.column),
                "action": (action_tok.line, action_tok.column),
            },
        )

    def _parse_protocol(self) -> Tuple[str, Token]:
        tok = self._peek()
        # Identifiers are accepted here on purpose so the semantic analyzer can give a
        # precise "unsupported protocol" message (e.g. FTP) instead of a generic syntax error.
        if tok.type in self.PROTOCOL_TOKENS or tok.type == TokenType.IDENTIFIER:
            self._advance()
            return tok.value.upper(), tok
        raise ParserError(f"Expected protocol (TCP, UDP, ICMP, ANY), got '{tok.value}'", tok.line, tok.column)

    def _parse_port(self) -> Tuple[Union[int, str], Token]:
        tok = self._peek()
        if tok.type == TokenType.NUMBER:
            self._advance()
            return int(tok.value), tok
        if tok.type == TokenType.KW_ANY:
            self._advance()
            return "ANY", tok
        if tok.type == TokenType.IDENTIFIER:  # e.g. SSH: reported by the semantic analyzer
            self._advance()
            return tok.value, tok
        raise ParserError(f"Expected port number (1-65535) or 'ANY', got '{tok.value}'", tok.line, tok.column)

    def _parse_source(self) -> Tuple[str, Token]:
        tok = self._peek()
        if tok.type in self.NAMED_SOURCE_TOKENS:
            self._advance()
            return tok.value.upper(), tok  # keywords are case-insensitive; normalize them
        if tok.type in (TokenType.IP_ADDRESS, TokenType.CIDR, TokenType.IDENTIFIER):
            self._advance()
            return tok.value, tok
        raise ParserError(
            f"Expected source condition (ANY, UNKNOWN, INTERNAL, EXTERNAL, IP, CIDR), got '{tok.value}'",
            tok.line, tok.column,
        )

    def _parse_action(self) -> Tuple[str, Token]:
        tok = self._peek()
        if tok.type in self.ACTION_TOKENS:
            self._advance()
            return ("BLOCK" if tok.type == TokenType.KW_DENY else tok.value.upper()), tok
        if tok.type == TokenType.IDENTIFIER:
            self._advance()
            return tok.value.upper(), tok
        raise ParserError(f"Expected action (ALLOW, BLOCK or DENY), got '{tok.value}'", tok.line, tok.column)


def parse(tokens: List[Token]) -> PolicyNode:
    """Helper function to parse tokens into an AST."""
    return Parser(tokens).parse()


def format_ast(node: PolicyNode) -> str:
    """Formats the AST as a tree for presentation."""
    lines = ["Policy AST Root"]
    for i, rule in enumerate(node.rules, 1):
        is_last = i == len(node.rules)
        prefix = "\\-- " if is_last else "+-- "
        child = "    " if is_last else "|   "
        lines.append(f"{prefix}Rule: {rule.name} [Line {rule.line}]")
        lines.append(f"{child}+-- Protocol : {rule.protocol}")
        lines.append(f"{child}+-- Port     : {rule.port}")
        lines.append(f"{child}+-- Source   : {rule.source}")
        lines.append(f"{child}\\-- Action   : {rule.action}")
    return "\n".join(lines)

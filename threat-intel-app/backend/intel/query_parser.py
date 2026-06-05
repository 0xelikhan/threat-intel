"""
Query DSL: lexer + parser + AST + evaluator.

A self-contained implementation of the (Attribute Operator Value) query
language emitted by the /api/detection action=query handler. Two use
cases inside RECON:

  1. Validation. LLM-generated queries are compiled through parse() and
     rejected on SyntaxError so the analyst never sees a broken query.
     Same retry-on-failure pattern as generate_validated_sigma /
     generate_validated_yara.

  2. Client-side evaluation. evaluate(ast, record) returns True/False
     for any dict-shaped record, so the same query that runs in an
     external portal can also pre-filter enrichment data locally
     without a network round-trip.

Grammar (informal):

    query        := or_expr
    or_expr      := and_expr ( OR and_expr )*           # left-assoc
    and_expr     := primary ( AND primary )*            # left-assoc
    primary      := '(' or_expr ')'
                  | attribute_expr
    attribute_expr := ATTR cmp_op VALUE
                    | ATTR ( CONTAINS | NOT CONTAINS ) STRING
                    | ATTR ( LIKE     | NOT LIKE )     STRING
                    | ATTR ( IN       | NOT IN )       array
    cmp_op       := '=' | '!=' | '>' | '>=' | '<' | '<='
    array        := '(' value ( SEP? value )* ')'       # SEP optional, whitespace OK
    VALUE        := STRING | NUMBER
    STRING       := '"' ( escaped_char )* '"'           # '\\"' escapes the quote
    NUMBER       := -? digit+ ( '.' digit+ )?

Spec quirks honoured:
  - Operators are case-insensitive (AND / and / And all parse).
  - Attribute names are case-sensitive (preserved verbatim in the AST).
  - No spaces required between tokens: `Attr="abc"` and `Attr = "abc"`
    parse identically; `NOTLIKE` (no space) parses the same as `NOT LIKE`.
  - NOT only combines with IN / LIKE / CONTAINS — never bare `NOT =`.
  - Left-to-right associativity for AND/OR at the same precedence level;
    parens override.

Never raises on user input except via SyntaxError from parse(). The
evaluator never raises — missing attrs / type mismatches resolve to
False rather than blowing up.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Union


# ─── Tokens ─────────────────────────────────────────────────────────────────
class TokenType(IntEnum):
    TEXT             = 1    # attribute / bareword
    STRING           = 2    # "..."
    INTEGER          = 3    # 42 or 3.14 (we lump floats in here)
    EQUAL            = 5    # =
    NOT_EQUAL        = 6    # !=
    AND              = 7
    OR               = 8
    CONTAINS         = 9
    IN               = 10
    LIKE             = 11
    NOT_CONTAINS     = 12
    NOT_IN           = 13
    NOT_LIKE         = 14
    LPAREN           = 15   # (
    RPAREN           = 16   # )
    GREATER_THAN     = 17
    LESS_THAN        = 18
    GREATER_EQUAL    = 19
    LESS_EQUAL       = 20
    COMMA            = 21   # only used inside arrays


@dataclass
class Token:
    type:     TokenType
    value:    Any
    position: int


class SyntaxError(Exception):
    """Raised on lex/parse failure. Carries the character offset that
    triggered the problem so the analyst can point at it."""

    def __init__(self, message: str, position: int = -1, source: str = ""):
        super().__init__(message)
        self.position = position
        self.source   = source

    def __str__(self) -> str:
        base = super().__str__()
        if self.position < 0:
            return base
        # Caret-pointer view of the offending character.
        return f"{base} (at column {self.position + 1})"


# ─── Lexer ──────────────────────────────────────────────────────────────────
# Keywords are case-insensitive — we lowercase before lookup.
_KEYWORDS = {
    "and":      TokenType.AND,
    "or":       TokenType.OR,
    "contains": TokenType.CONTAINS,
    "in":       TokenType.IN,
    "like":     TokenType.LIKE,
}

# Multi-word operators that may appear with or without internal whitespace.
# The lexer tries each prefix in turn so `NOTLIKE`, `NOT LIKE`,
# `Not   Like` all collapse to the same single token.
_NOT_COMBINATIONS = [
    ("notcontains", TokenType.NOT_CONTAINS),
    ("notin",       TokenType.NOT_IN),
    ("notlike",     TokenType.NOT_LIKE),
]


def tokenize(source: str) -> List[Token]:
    """Split a Query string into Token objects. Raises SyntaxError on
    invalid characters or unterminated strings."""
    if source is None:
        raise SyntaxError("source is None", 0, "")
    tokens: List[Token] = []
    i, n = 0, len(source)

    while i < n:
        ch = source[i]

        # ── whitespace ──
        if ch.isspace():
            i += 1
            continue

        # ── parens + comma ──
        if ch == "(":
            tokens.append(Token(TokenType.LPAREN, "(", i)); i += 1; continue
        if ch == ")":
            tokens.append(Token(TokenType.RPAREN, ")", i)); i += 1; continue
        if ch == ",":
            tokens.append(Token(TokenType.COMMA, ",", i)); i += 1; continue

        # ── comparison operators (two-char before one-char) ──
        if ch == "!" and i + 1 < n and source[i + 1] == "=":
            tokens.append(Token(TokenType.NOT_EQUAL, "!=", i)); i += 2; continue
        if ch == ">" and i + 1 < n and source[i + 1] == "=":
            tokens.append(Token(TokenType.GREATER_EQUAL, ">=", i)); i += 2; continue
        if ch == "<" and i + 1 < n and source[i + 1] == "=":
            tokens.append(Token(TokenType.LESS_EQUAL, "<=", i)); i += 2; continue
        if ch == "=":
            tokens.append(Token(TokenType.EQUAL, "=", i)); i += 1; continue
        if ch == ">":
            tokens.append(Token(TokenType.GREATER_THAN, ">", i)); i += 1; continue
        if ch == "<":
            tokens.append(Token(TokenType.LESS_THAN, "<", i)); i += 1; continue

        # ── string literal: " … " with \" escape and \\ escape ──
        if ch == '"' or ch == '“' or ch == '”':
            # Accept ASCII " and smart quotes "/". Many copy-pastes
            # from docs / chat clients silently convert the ASCII quote
            # to a curly one — refusing those would be unhelpful.
            start = i
            i += 1
            buf: List[str] = []
            closed = False
            while i < n:
                c = source[i]
                if c == "\\" and i + 1 < n:
                    nxt = source[i + 1]
                    if nxt == '"':
                        buf.append('"'); i += 2; continue
                    if nxt == "\\":
                        buf.append("\\"); i += 2; continue
                    if nxt == "n":
                        buf.append("\n"); i += 2; continue
                    if nxt == "t":
                        buf.append("\t"); i += 2; continue
                    # Unknown escape — keep the backslash literal.
                    buf.append(c); i += 1; continue
                if c == '"' or c == '“' or c == '”':
                    closed = True
                    i += 1
                    break
                buf.append(c); i += 1
            if not closed:
                raise SyntaxError("unterminated string literal", start, source)
            tokens.append(Token(TokenType.STRING, "".join(buf), start))
            continue

        # ── number ──
        if ch.isdigit() or (ch == "-" and i + 1 < n and source[i + 1].isdigit()):
            start = i
            if ch == "-":
                i += 1
            while i < n and source[i].isdigit():
                i += 1
            if i < n and source[i] == "." and i + 1 < n and source[i + 1].isdigit():
                i += 1
                while i < n and source[i].isdigit():
                    i += 1
            raw = source[start:i]
            try:
                val = float(raw) if "." in raw else int(raw)
            except ValueError:
                raise SyntaxError(f"invalid number: {raw}", start, source)
            tokens.append(Token(TokenType.INTEGER, val, start))
            continue

        # ── identifier / keyword ──
        if ch.isalpha() or ch == "_":
            start = i
            while i < n and (source[i].isalnum() or source[i] == "_"):
                i += 1
            word = source[start:i]
            lower = word.lower()

            # Multi-word NOT-combinations: try to swallow optional
            # whitespace + a following keyword to collapse `NOT LIKE`
            # / `NOT IN` / `NOT CONTAINS` into one token.
            if lower == "not":
                # Skip any whitespace between NOT and the next word.
                j = i
                while j < n and source[j].isspace():
                    j += 1
                if j < n and (source[j].isalpha() or source[j] == "_"):
                    word_start = j
                    while j < n and (source[j].isalnum() or source[j] == "_"):
                        j += 1
                    second = source[word_start:j].lower()
                    combined = "not" + second
                    for prefix, tt in _NOT_COMBINATIONS:
                        if combined == prefix:
                            tokens.append(Token(tt, combined.upper(), start))
                            i = j
                            break
                    else:
                        raise SyntaxError(
                            f"NOT must be followed by IN, LIKE, or CONTAINS "
                            f"(got NOT {source[word_start:j]})",
                            start, source,
                        )
                    continue
                else:
                    raise SyntaxError(
                        "NOT must be followed by IN, LIKE, or CONTAINS",
                        start, source,
                    )

            # Glued NOT-combinations: `NOTLIKE`, `NOTIN`, `NOTCONTAINS`
            # are valid per the spec's "no spaces required" rule.
            for prefix, tt in _NOT_COMBINATIONS:
                if lower == prefix:
                    tokens.append(Token(tt, lower.upper(), start))
                    break
            else:
                if lower in _KEYWORDS:
                    tokens.append(Token(_KEYWORDS[lower], lower.upper(), start))
                else:
                    # Preserve original case for attribute names — the
                    # spec mandates attributes are case-sensitive.
                    tokens.append(Token(TokenType.TEXT, word, start))
            continue

        raise SyntaxError(f"unexpected character: {ch!r}", i, source)

    return tokens


# ─── AST node types ─────────────────────────────────────────────────────────
@dataclass
class Comparison:
    """ATTR cmp_op VALUE — the equality / inequality / numeric ops."""
    attribute: str
    op:        TokenType
    value:     Union[str, int, float]


@dataclass
class StringOp:
    """ATTR (CONTAINS | LIKE | NOT_CONTAINS | NOT_LIKE) STRING."""
    attribute: str
    op:        TokenType
    value:     str


@dataclass
class ListMembership:
    """ATTR (IN | NOT_IN) ( values… )."""
    attribute: str
    op:        TokenType
    values:    List[Union[str, int, float]] = field(default_factory=list)


@dataclass
class BinaryOp:
    """LEFT (AND | OR) RIGHT."""
    op:    TokenType
    left:  "Expr"
    right: "Expr"


Expr = Union[Comparison, StringOp, ListMembership, BinaryOp]


# ─── Parser ─────────────────────────────────────────────────────────────────
class _Parser:
    """Hand-rolled recursive-descent. AND/OR are left-associative at the
    same precedence so `A OR B AND C` reads as `(A OR B) AND C`, per the
    spec example."""

    def __init__(self, tokens: List[Token], source: str):
        self.tokens = tokens
        self.source = source
        self.pos    = 0

    def _peek(self, offset: int = 0) -> Optional[Token]:
        i = self.pos + offset
        return self.tokens[i] if 0 <= i < len(self.tokens) else None

    def _eat(self, expected: Optional[TokenType] = None) -> Token:
        tok = self._peek()
        if tok is None:
            raise SyntaxError(
                f"unexpected end of query (expected {expected.name if expected else 'token'})",
                len(self.source),
                self.source,
            )
        if expected is not None and tok.type != expected:
            raise SyntaxError(
                f"expected {expected.name}, got {tok.type.name} ({tok.value!r})",
                tok.position,
                self.source,
            )
        self.pos += 1
        return tok

    def parse(self) -> Expr:
        if not self.tokens:
            raise SyntaxError("empty query", 0, self.source)
        node = self._parse_or()
        if self.pos < len(self.tokens):
            tok = self.tokens[self.pos]
            raise SyntaxError(
                f"unexpected trailing token {tok.value!r}",
                tok.position,
                self.source,
            )
        return node

    # or_expr := and_expr ( OR and_expr )*
    def _parse_or(self) -> Expr:
        # Spec is explicit that AND and OR share precedence and chain
        # left-to-right ("Attribute1 = ... OR ... AND ..." reads as
        # ((... OR ...) AND ...)). So a single loop over either keyword
        # at this level is the correct shape.
        node = self._parse_primary()
        while True:
            tok = self._peek()
            if tok is None or tok.type not in (TokenType.AND, TokenType.OR):
                break
            self._eat()
            right = self._parse_primary()
            node = BinaryOp(tok.type, node, right)
        return node

    # primary := '(' or_expr ')' | attribute_expr
    def _parse_primary(self) -> Expr:
        tok = self._peek()
        if tok is None:
            raise SyntaxError("expected expression", len(self.source), self.source)
        if tok.type == TokenType.LPAREN:
            self._eat(TokenType.LPAREN)
            inner = self._parse_or()
            self._eat(TokenType.RPAREN)
            return inner
        return self._parse_attribute_expr()

    def _parse_attribute_expr(self) -> Expr:
        attr_tok = self._eat(TokenType.TEXT)
        attr     = attr_tok.value
        op_tok   = self._peek()
        if op_tok is None:
            raise SyntaxError(
                f"attribute {attr!r} not followed by an operator",
                attr_tok.position, self.source,
            )

        # Equality / numeric comparison: value must be string OR number.
        if op_tok.type in (TokenType.EQUAL, TokenType.NOT_EQUAL,
                           TokenType.GREATER_THAN, TokenType.LESS_THAN,
                           TokenType.GREATER_EQUAL, TokenType.LESS_EQUAL):
            self._eat()
            val_tok = self._eat()
            if val_tok.type not in (TokenType.STRING, TokenType.INTEGER):
                raise SyntaxError(
                    f"expected value after {op_tok.value}, got {val_tok.type.name}",
                    val_tok.position, self.source,
                )
            return Comparison(attribute=attr, op=op_tok.type, value=val_tok.value)

        # String ops (CONTAINS / LIKE / NOT_CONTAINS / NOT_LIKE):
        # value must be a STRING.
        if op_tok.type in (TokenType.CONTAINS, TokenType.LIKE,
                           TokenType.NOT_CONTAINS, TokenType.NOT_LIKE):
            self._eat()
            val_tok = self._eat(TokenType.STRING)
            return StringOp(attribute=attr, op=op_tok.type, value=val_tok.value)

        # IN / NOT IN: value is a parenthesised list.
        if op_tok.type in (TokenType.IN, TokenType.NOT_IN):
            self._eat()
            self._eat(TokenType.LPAREN)
            values: List[Union[str, int, float]] = []
            # Walk values; commas + whitespace are interchangeable.
            while True:
                t = self._peek()
                if t is None:
                    raise SyntaxError("unterminated list", op_tok.position, self.source)
                if t.type == TokenType.RPAREN:
                    self._eat(TokenType.RPAREN)
                    break
                if t.type == TokenType.COMMA:
                    self._eat(); continue
                if t.type in (TokenType.STRING, TokenType.INTEGER):
                    values.append(t.value); self._eat(); continue
                raise SyntaxError(
                    f"expected value or ')' inside list, got {t.type.name}",
                    t.position, self.source,
                )
            return ListMembership(attribute=attr, op=op_tok.type, values=values)

        raise SyntaxError(
            f"unexpected operator {op_tok.value!r} after attribute {attr!r}",
            op_tok.position, self.source,
        )


def parse(source: str) -> Expr:
    """Top-level parse — tokenizes then builds the AST. Raises
    SyntaxError on any lex/parse failure with a useful column number."""
    return _Parser(tokenize(source), source).parse()


# ─── Evaluator ──────────────────────────────────────────────────────────────
def _coerce_for_compare(left: Any, right: Any) -> tuple:
    """Best-effort numeric coercion for >, >=, <, <= so the AI can write
    `FileSize > "1048576"` and have it still work. Returns the pair
    unchanged if coercion fails — the caller falls back to False."""
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left, right
    try:
        if isinstance(left, str):  left  = float(left)
        if isinstance(right, str): right = float(right)
        return left, right
    except (TypeError, ValueError):
        return left, right


def evaluate(ast: Expr, record: Dict[str, Any]) -> bool:
    """Walk the AST against a record (dict of attribute -> value).
    Returns True/False. Missing attributes / type mismatches resolve to
    False rather than raising — same defensive shape as our enrichment
    parsers."""
    if ast is None or record is None:
        return False

    if isinstance(ast, BinaryOp):
        left  = evaluate(ast.left,  record)
        # Short-circuit (matches the spec's AST example for OR collapsing
        # subtrees once one operand wins).
        if ast.op == TokenType.AND:
            return bool(left) and bool(evaluate(ast.right, record))
        if ast.op == TokenType.OR:
            return bool(left) or  bool(evaluate(ast.right, record))
        return False

    if isinstance(ast, Comparison):
        rec_val = record.get(ast.attribute)
        if rec_val is None:
            return False
        if ast.op == TokenType.EQUAL:
            return rec_val == ast.value or str(rec_val) == str(ast.value)
        if ast.op == TokenType.NOT_EQUAL:
            return not (rec_val == ast.value or str(rec_val) == str(ast.value))
        # Numeric comparisons: coerce + compare; non-numeric -> False.
        a, b = _coerce_for_compare(rec_val, ast.value)
        if not (isinstance(a, (int, float)) and isinstance(b, (int, float))):
            return False
        if ast.op == TokenType.GREATER_THAN:  return a >  b
        if ast.op == TokenType.LESS_THAN:     return a <  b
        if ast.op == TokenType.GREATER_EQUAL: return a >= b
        if ast.op == TokenType.LESS_EQUAL:    return a <= b
        return False

    if isinstance(ast, StringOp):
        rec_val = record.get(ast.attribute)
        if rec_val is None:
            return False
        haystack = rec_val if isinstance(rec_val, str) else str(rec_val)
        needle   = ast.value
        if ast.op == TokenType.CONTAINS:
            return needle in haystack
        if ast.op == TokenType.NOT_CONTAINS:
            return needle not in haystack
        if ast.op in (TokenType.LIKE, TokenType.NOT_LIKE):
            try:
                # search() not fullmatch() — caller anchors with ^ $ if
                # they want full-string match (matches the spec example).
                hit = re.search(needle, haystack) is not None
            except re.error:
                return False
            return hit if ast.op == TokenType.LIKE else not hit
        return False

    if isinstance(ast, ListMembership):
        rec_val = record.get(ast.attribute)
        if rec_val is None:
            return ast.op == TokenType.NOT_IN  # nothing IS not-in [], etc.
        present = rec_val in ast.values or str(rec_val) in [str(v) for v in ast.values]
        return present if ast.op == TokenType.IN else not present

    return False


# ─── Pretty-print AST (for debugging / future explain-this-query UI) ────────
def explain(ast: Expr, indent: int = 0) -> str:
    """Render the AST as an indented tree. Useful for debugging the
    parser and for surfacing 'this is how I interpreted your query' in
    the UI."""
    pad = "  " * indent
    if isinstance(ast, BinaryOp):
        return (f"{pad}{ast.op.name}\n"
                f"{explain(ast.left,  indent + 1)}\n"
                f"{explain(ast.right, indent + 1)}")
    if isinstance(ast, Comparison):
        return f"{pad}{ast.attribute} {ast.op.name} {ast.value!r}"
    if isinstance(ast, StringOp):
        return f"{pad}{ast.attribute} {ast.op.name} {ast.value!r}"
    if isinstance(ast, ListMembership):
        return f"{pad}{ast.attribute} {ast.op.name} {ast.values!r}"
    return f"{pad}<unknown {type(ast).__name__}>"


# ─── Public API used by the /api/detection validator ────────────────────────
def validate(source: str) -> Dict[str, Any]:
    """Compile-only check. Returns {ok, error, position, ast?}.
    Used by the LLM-generated-query validator in main.py to retry on
    parse failure (same pattern as Sigma + YARA validation)."""
    try:
        ast = parse(source)
        return {"ok": True, "error": None, "position": -1, "ast": ast}
    except SyntaxError as e:
        return {"ok": False, "error": str(e), "position": e.position, "ast": None}

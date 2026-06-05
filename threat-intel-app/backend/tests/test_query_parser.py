"""Tests for the Query DSL lexer + parser + AST evaluator.

Coverage groups:
  * Lexer: each token type, escaped quotes, smart quotes, no-spaces,
    NOT-combinations (spaced + glued), invalid chars
  * Parser: every operator + every NOT variant, precedence, grouping,
    error reporting with column numbers, empty / malformed inputs
  * Evaluator: every operator semantics, missing attrs, type coercion,
    regex LIKE, AND/OR short-circuit
"""

from __future__ import annotations

import pytest

from intel.query_parser import (
    tokenize, parse, evaluate, validate, explain,
    TokenType, BinaryOp, Comparison, StringOp, ListMembership,
    SyntaxError as QSyntaxError,
)


# ═══ Lexer tests ════════════════════════════════════════════════════════════
def test_lex_simple_equality():
    toks = tokenize('ProcessName = "powershell.exe"')
    types = [t.type for t in toks]
    assert types == [TokenType.TEXT, TokenType.EQUAL, TokenType.STRING]
    assert toks[0].value == "ProcessName"
    assert toks[2].value == "powershell.exe"


def test_lex_no_spaces_around_operator():
    toks = tokenize('ProcessName="powershell.exe"')
    types = [t.type for t in toks]
    assert types == [TokenType.TEXT, TokenType.EQUAL, TokenType.STRING]


def test_lex_escaped_quote_in_string():
    toks = tokenize(r'CmdLineParameters = "Set-ExecutionPolicy \"Bypass\""')
    assert toks[2].value == 'Set-ExecutionPolicy "Bypass"'


def test_lex_smart_quotes_accepted():
    # Curly-quote pasted from a doc client must still parse.
    toks = tokenize('PolicyName = “Block Macros”')
    assert toks[2].type == TokenType.STRING
    assert toks[2].value == "Block Macros"


def test_lex_integer_and_negative():
    toks = tokenize("FileSize > -42 AND FileSize <= 1048576")
    nums = [t.value for t in toks if t.type == TokenType.INTEGER]
    assert nums == [-42, 1048576]


def test_lex_not_combinations_with_space():
    toks = tokenize('ProcessName NOT IN ("a")')
    assert toks[1].type == TokenType.NOT_IN
    toks = tokenize('SHA256 NOT LIKE "^0+$"')
    assert toks[1].type == TokenType.NOT_LIKE
    toks = tokenize('CmdLineParameters NOT CONTAINS "test"')
    assert toks[1].type == TokenType.NOT_CONTAINS


def test_lex_not_combinations_glued():
    toks = tokenize('ProcessName NOTIN ("a")')
    assert toks[1].type == TokenType.NOT_IN
    toks = tokenize('SHA256 NOTLIKE "x"')
    assert toks[1].type == TokenType.NOT_LIKE


def test_lex_keywords_are_case_insensitive():
    for kw in ("AND", "And", "and", "aNd"):
        toks = tokenize(f'A = "x" {kw} B = "y"')
        assert toks[3].type == TokenType.AND


def test_lex_attribute_preserves_case():
    # Spec requires attributes are case-sensitive.
    toks = tokenize('PolicyName = "x" AND policyname = "y"')
    attr_names = [t.value for t in toks if t.type == TokenType.TEXT]
    assert "PolicyName" in attr_names
    assert "policyname" in attr_names


def test_lex_unterminated_string_raises():
    with pytest.raises(QSyntaxError) as exc:
        tokenize('A = "no closing quote')
    assert "unterminated" in str(exc.value)


def test_lex_bare_not_without_target_raises():
    with pytest.raises(QSyntaxError):
        tokenize('A NOT = "x"')


# ═══ Parser tests ═══════════════════════════════════════════════════════════
def test_parse_single_equality():
    ast = parse('ProcessName = "powershell.exe"')
    assert isinstance(ast, Comparison)
    assert ast.attribute == "ProcessName"
    assert ast.op == TokenType.EQUAL
    assert ast.value == "powershell.exe"


def test_parse_numeric_comparison():
    ast = parse("FileSize > 1024")
    assert isinstance(ast, Comparison)
    assert ast.op == TokenType.GREATER_THAN
    assert ast.value == 1024


def test_parse_contains():
    ast = parse('CmdLineParameters CONTAINS "-enc"')
    assert isinstance(ast, StringOp)
    assert ast.op == TokenType.CONTAINS


def test_parse_not_contains():
    ast = parse('CmdLineParameters NOT CONTAINS "test"')
    assert isinstance(ast, StringOp)
    assert ast.op == TokenType.NOT_CONTAINS


def test_parse_like_regex():
    ast = parse(r'SHA256 LIKE "^[0-9a-f]{64}$"')
    assert isinstance(ast, StringOp)
    assert ast.op == TokenType.LIKE


def test_parse_in_list_with_commas():
    ast = parse('ProcessName IN ("a", "b", "c")')
    assert isinstance(ast, ListMembership)
    assert ast.values == ["a", "b", "c"]


def test_parse_in_list_no_commas():
    ast = parse('ProcessName IN ("a" "b" "c")')
    assert isinstance(ast, ListMembership)
    assert ast.values == ["a", "b", "c"]


def test_parse_in_list_mixed_types():
    ast = parse('DestinationPort IN (80, 443, "8080")')
    assert isinstance(ast, ListMembership)
    assert ast.values == [80, 443, "8080"]


def test_parse_and_chain_is_left_associative():
    ast = parse('A = "1" AND B = "2" AND C = "3"')
    # Should parse as ((A AND B) AND C)
    assert isinstance(ast, BinaryOp) and ast.op == TokenType.AND
    assert isinstance(ast.left,  BinaryOp) and ast.left.op == TokenType.AND
    assert isinstance(ast.right, Comparison)


def test_parse_or_then_and_default_precedence():
    # Spec example: A OR B OR C AND D  =>  ((A OR B) OR C) AND D
    ast = parse('A = "1" OR B = "2" OR C = "3" AND D = "4"')
    assert ast.op == TokenType.AND
    assert isinstance(ast.left,  BinaryOp) and ast.left.op  == TokenType.OR
    assert isinstance(ast.right, Comparison) and ast.right.attribute == "D"


def test_parse_parens_override_precedence():
    # A OR B OR (C AND D)
    ast = parse('A = "1" OR B = "2" OR (C = "3" AND D = "4")')
    assert ast.op == TokenType.OR
    # Right side should be the (C AND D) group, NOT just C.
    assert isinstance(ast.right, BinaryOp) and ast.right.op == TokenType.AND


def test_parse_nested_groups():
    ast = parse('((A = "1" OR B = "2") AND C = "3") OR D = "4"')
    assert ast.op == TokenType.OR
    assert isinstance(ast.left, BinaryOp) and ast.left.op == TokenType.AND


def test_parse_empty_input_raises():
    with pytest.raises(QSyntaxError):
        parse("")


def test_parse_trailing_token_raises():
    with pytest.raises(QSyntaxError):
        parse('A = "1" "stray"')


def test_parse_missing_value_raises():
    with pytest.raises(QSyntaxError):
        parse("A =")


def test_parse_error_includes_column():
    try:
        parse('A = "x" AND')
    except QSyntaxError as e:
        assert e.position >= 0
    else:
        pytest.fail("expected SyntaxError")


# ═══ Evaluator tests ════════════════════════════════════════════════════════
def test_eval_equality_str():
    ast = parse('ProcessName = "powershell.exe"')
    assert evaluate(ast, {"ProcessName": "powershell.exe"}) is True
    assert evaluate(ast, {"ProcessName": "notepad.exe"})    is False
    assert evaluate(ast, {})                                 is False


def test_eval_inequality():
    ast = parse('ProcessName != "notepad.exe"')
    assert evaluate(ast, {"ProcessName": "powershell.exe"}) is True
    assert evaluate(ast, {"ProcessName": "notepad.exe"})    is False


def test_eval_numeric_compare():
    ast = parse("FileSize > 1024")
    assert evaluate(ast, {"FileSize": 2048}) is True
    assert evaluate(ast, {"FileSize": 512})  is False
    # String coercion: "2048" should compare numerically.
    assert evaluate(ast, {"FileSize": "2048"}) is True


def test_eval_contains_and_not_contains():
    yes = parse('CmdLineParameters CONTAINS "-enc"')
    no  = parse('CmdLineParameters NOT CONTAINS "-enc"')
    rec = {"CmdLineParameters": "powershell -enc abc"}
    assert evaluate(yes, rec) is True
    assert evaluate(no,  rec) is False


def test_eval_like_regex():
    ast = parse(r'SHA256 LIKE "^[0-9a-f]{64}$"')
    good = "d" * 64
    bad  = "not a hash"
    assert evaluate(ast, {"SHA256": good}) is True
    assert evaluate(ast, {"SHA256": bad})  is False


def test_eval_not_like_with_invalid_regex_returns_false():
    # Caller wrote a bad regex; eval should NOT raise.
    ast = parse(r'X LIKE "(unclosed"')
    assert evaluate(ast, {"X": "test"}) is False


def test_eval_in_and_not_in():
    yes = parse('ProcessName IN ("a" "b" "c")')
    no  = parse('ProcessName NOT IN ("a" "b" "c")')
    assert evaluate(yes, {"ProcessName": "b"}) is True
    assert evaluate(yes, {"ProcessName": "z"}) is False
    assert evaluate(no,  {"ProcessName": "z"}) is True
    assert evaluate(no,  {"ProcessName": "a"}) is False


def test_eval_in_handles_missing_attr():
    yes_ast = parse('X IN ("a" "b")')
    not_ast = parse('X NOT IN ("a" "b")')
    # Missing attr: IN is False, NOT IN is True.
    assert evaluate(yes_ast, {}) is False
    assert evaluate(not_ast, {}) is True


def test_eval_and_or_combination():
    ast = parse('ProcessName = "powershell.exe" AND CmdLineParameters CONTAINS "-enc"')
    assert evaluate(ast, {"ProcessName": "powershell.exe",
                          "CmdLineParameters": "-enc abc"}) is True
    assert evaluate(ast, {"ProcessName": "powershell.exe",
                          "CmdLineParameters": "no flag"}) is False
    assert evaluate(ast, {"ProcessName": "notepad.exe",
                          "CmdLineParameters": "-enc abc"}) is False


def test_eval_parens_change_outcome():
    # (A OR B) AND C   vs   A OR (B AND C)
    rec = {"A": "1", "B": "x", "C": "no"}
    grouped = parse('(A = "1" OR B = "2") AND C = "yes"')
    nested  = parse('A = "1" OR (B = "2" AND C = "yes")')
    assert evaluate(grouped, rec) is False    # C != "yes"
    assert evaluate(nested,  rec) is True     # A = "1" satisfies OR


def test_eval_realistic_powershell_detection():
    ast = parse(
        'ProcessName = "powershell.exe" AND '
        '(CmdLineParameters CONTAINS "-enc" OR CmdLineParameters CONTAINS "FromBase64String")'
    )
    rec1 = {"ProcessName": "powershell.exe",
            "CmdLineParameters": "-w hidden -enc SQBFAFgA"}
    rec2 = {"ProcessName": "powershell.exe",
            "CmdLineParameters": "iex (FromBase64String('AAA'))"}
    rec3 = {"ProcessName": "powershell.exe",
            "CmdLineParameters": "Get-Process"}
    rec4 = {"ProcessName": "notepad.exe",
            "CmdLineParameters": "-enc SQBFAFgA"}
    assert evaluate(ast, rec1) is True
    assert evaluate(ast, rec2) is True
    assert evaluate(ast, rec3) is False
    assert evaluate(ast, rec4) is False


# ═══ validate() public API ══════════════════════════════════════════════════
def test_validate_ok_for_valid_query():
    r = validate('ProcessName = "powershell.exe"')
    assert r["ok"] is True
    assert r["error"] is None
    assert r["ast"] is not None


def test_validate_returns_error_with_position():
    r = validate('A = "x" AND')
    assert r["ok"] is False
    assert r["error"]
    assert r["position"] >= 0


# ═══ explain() debug helper ═════════════════════════════════════════════════
def test_explain_renders_tree():
    ast = parse('A = "1" AND (B = "2" OR C = "3")')
    out = explain(ast)
    assert "AND" in out
    assert "OR" in out
    # Indented sub-trees should appear.
    assert "  " in out

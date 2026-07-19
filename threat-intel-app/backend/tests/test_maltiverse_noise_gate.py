"""Regression: Maltiverse aggregates ~40 feeds and returns huge
historical `blacklist` arrays + noisy `tag` lists even for public
DNS servers (e.g. 8.8.8.8 shows a 44-entry blacklist and tags like
"asyncrat, c2, backdoor" because DNS reflection attacks *target*
public DNS).

The AI investigation prompt reads that blob and writes prose like
"Maltiverse associates this IP with AsyncRAT" — even when Maltiverse's
own definitive `classification` field says whitelist.

Fix: only surface blacklist + tag when classification is
malicious/suspicious. Whitelist/neutral IPs get just the classification
+ benign metadata.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


def _fake_json(payload):
    """Build an aiohttp session mock that returns `payload` from get()."""
    class _R:
        status = 200
        async def json(self):    return payload
        async def __aenter__(self): return self
        async def __aexit__(self, *_a): return False
    class _S:
        def get(self, *_a, **_k): return _R()
        async def __aenter__(self): return self
        async def __aexit__(self, *_a): return False
    return _S()


def test_maltiverse_drops_noise_for_whitelist_ip():
    """8.8.8.8 shape: whitelist verdict + 44 stale blacklist entries +
    'asyncrat, c2, backdoor' tags. After the noise gate, callers see
    classification='whitelist' with EMPTY blacklist + EMPTY tag arrays."""
    from intel import maltiverse
    fake = {
        "classification": "whitelist",
        "blacklist": [{"description": "AsyncRAT", "source": "ThreatFox Abuse.ch"},
                       {"description": "Malicious URL", "source": "Hybrid-Analysis"}],
        "tag": ["dns", "reflection", "asyncrat", "c2", "backdoor"],
        "asn_name": "GOOGLE",
        "country_code": "US",
    }
    with patch("aiohttp.ClientSession", return_value=_fake_json(fake)):
        r = asyncio.run(maltiverse.lookup("ip", "8.8.8.8"))
    assert r["classification"] == "whitelist"
    assert r["hit"] is False
    assert r["blacklist"] == []
    assert r["tag"] == []
    # Benign metadata still comes through so the analyst UI can show
    # ASN + country context.
    assert r["asn_name"] == "GOOGLE"
    assert r["country"] == "US"


def test_maltiverse_drops_noise_for_neutral_ip():
    """No classification data at all — still zeroed."""
    from intel import maltiverse
    fake = {
        "blacklist": [{"description": "old-report", "source": "X"}],
        "tag": ["something-scary"],
    }
    with patch("aiohttp.ClientSession", return_value=_fake_json(fake)):
        r = asyncio.run(maltiverse.lookup("ip", "10.0.0.1"))
    assert r["classification"] == "neutral"
    assert r["hit"] is False
    assert r["blacklist"] == []
    assert r["tag"] == []


def test_maltiverse_preserves_noise_for_suspicious_ip():
    """The real-spammer case (149.40.62.132 shape): classification is
    suspicious and there are two current blacklist entries — the AI
    NEEDS to see those to attribute the alert correctly."""
    from intel import maltiverse
    fake = {
        "classification": "suspicious",
        "blacklist": [
            {"description": "HTTP Spammer", "source": "StopForumSpam.com",
             "labels": ["malicious-activity"]},
            {"description": "SSH Bruteforce", "source": "DShield"},
        ],
        "tag": ["bot", "abuse", "anonymization"],
        "asn_name": "DATACAMP LIMITED",
        "country_code": "US",
    }
    with patch("aiohttp.ClientSession", return_value=_fake_json(fake)):
        r = asyncio.run(maltiverse.lookup("ip", "149.40.62.132"))
    assert r["classification"] == "suspicious"
    assert r["hit"] is True
    assert r["blacklist"] == ["HTTP Spammer", "SSH Bruteforce"]
    assert "bot" in r["tag"]
    assert "abuse" in r["tag"]


def test_maltiverse_preserves_noise_for_malicious_hash():
    """Confirmed-malicious classification: full context passes through
    so the AI can cite the specific families."""
    from intel import maltiverse
    fake = {
        "classification": "malicious",
        "blacklist": [{"description": "Emotet C2", "source": "Feodo"}],
        "tag": ["emotet", "banker"],
    }
    with patch("aiohttp.ClientSession", return_value=_fake_json(fake)):
        r = asyncio.run(maltiverse.lookup("hash", "a" * 64))
    assert r["classification"] == "malicious"
    assert r["hit"] is True
    assert r["blacklist"] == ["Emotet C2"]
    assert r["tag"] == ["emotet", "banker"]

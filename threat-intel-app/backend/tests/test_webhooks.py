"""Regression tests for the outbound webhook integrations.

Anchors fixes shipped against:

  - Slack mrkdwn: AI summaries containing <, >, or & broke the renderer
    because Slack's mrkdwn requires HTML-entity encoding for those
    three characters. Triple-backtick code blocks also fell apart when
    a sample IOC happened to contain a backtick (rare but possible
    with malformed URL paths).

  - TheHive 5: severity_map had CRITICAL and HIGH both mapped to 3.
    TheHive 5's scale is 1..4, so CRITICAL alerts were getting filed
    one level too low and never sorted to the top of the queue.
"""

from __future__ import annotations


def test_slack_summary_escapes_angle_brackets():
    from intel.webhooks import _build_slack_blocks
    result = {
        "response_summary": {
            "threat_level": "HIGH",
            "summary":      "User <john> & admin role granted to <attacker>",
            "confidence":   0.85,
        },
        "iocs": {"ips": ["1.2.3.4"]},
    }
    payload = _build_slack_blocks(result)
    body = payload["blocks"][1]["text"]["text"]
    assert "&lt;john&gt;" in body
    assert "&amp;" in body
    # Raw '<' must not survive past the escape
    assert "<john>" not in body


def test_slack_attribution_escapes_ampersand():
    from intel.webhooks import _build_slack_blocks
    result = {
        "response_summary": {
            "threat_level": "HIGH",
            "summary":      "ok",
            "confidence":   0.5,
            "matched_actors": [{"name": "Some & Group"}],
        },
        "iocs": {},
    }
    payload = _build_slack_blocks(result)
    found = False
    for b in payload["blocks"]:
        for f in (b.get("fields") or []):
            if "Attribution" in f.get("text", ""):
                assert "&amp;" in f["text"]
                assert " & " not in f["text"].replace("&amp;", "")
                found = True
    assert found, "Attribution field missing"


def test_slack_code_block_escapes_triple_backtick():
    from intel.webhooks import _slack_code_safe
    # A maliciously-shaped IOC that closes the markdown block early
    assert "```" not in _slack_code_safe("evil```break")


def test_thehive_critical_maps_to_severity_four():
    from intel.webhooks import send_thehive  # imported for visibility
    # Inline assertion against the literal map without standing up a
    # real TheHive server. The fix is the data in the map.
    import inspect
    src = inspect.getsource(send_thehive)
    assert '"CRITICAL": 4' in src, (
        "TheHive 5 supports severity 1..4 (1=Low .. 4=Critical). "
        "Mapping CRITICAL to anything other than 4 collapses it into HIGH."
    )
    assert '"HIGH": 3'    in src
    assert '"MEDIUM": 2'  in src
    assert '"LOW": 1'     in src

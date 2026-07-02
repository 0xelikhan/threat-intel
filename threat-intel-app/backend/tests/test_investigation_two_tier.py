"""Tests for the investigation calibration upgrades:
  * compute_enrichment_summary tally + line formatter
  * PRINCIPLE 7 (confirmed vs analysis) wording in the prompt
  * PRINCIPLE 8 (calibrated language) wording in the prompt
  * DEFAULT-BENIGN RULE wording in the prompt
  * Probing temperature lowered to 0.1
"""

from __future__ import annotations

import re

from agents import investigation
from agents.investigation import compute_enrichment_summary


# ─── compute_enrichment_summary ──────────────────────────────────────────────
def test_summary_log_only_alert():
    s = compute_enrichment_summary({})
    assert "No enrichment sources ran" in s["line"]
    assert s["returned_count"] == 0
    assert s["total_count"] == 0
    assert s["flagged_count"] == 0


def test_summary_dell_clean_hash():
    enr = {"hashes": {"AABB": {
        "virustotal":    {"malicious": 0, "detection_ratio": "0/96"},
        "malwarebazaar": {"found": False},
        "threatfox":     {},
        "otx":           {"pulseCount": 0},
    }}}
    s = compute_enrichment_summary(enr)
    # threatfox returns an empty dict → counts as "not returned"
    assert s["returned_count"] == 3
    assert s["total_count"] == 4
    assert s["flagged_count"] == 0
    assert "0 sources flagged any IOC as malicious" in s["line"]


def test_summary_cobalt_strike_multiple_flags():
    enr = {
        "ips": {"185.220.101.45": {
            "abuseipdb": {"abuseScore": 95},
            "virustotal": {"malicious": 12},
            "tor":        {"isExitNode": True},
        }},
        "hashes": {"AABB": {
            "virustotal":    {"malicious": 42},
            "malwarebazaar": {"found": True, "malware_family": "Cobalt Strike"},
            "threatfox":     {"found": True},
        }},
    }
    s = compute_enrichment_summary(enr)
    assert s["flagged_count"] >= 3
    assert len(s["flagged_iocs"]) == 2
    assert "185.220.101.45" in s["flagged_per_ioc"]
    assert "AABB" in s["flagged_per_ioc"]
    assert "virustotal" in s["flagged_per_ioc"]["AABB"]
    assert "flagged 2 IOCs" in s["line"]


def test_summary_handles_errors_and_skipped():
    enr = {"ips": {"8.8.8.8": {
        "abuseipdb": {"abuseScore": 0, "country": "US"},      # returned, not flagged
        "virustotal": {"error": "auth_failed", "error_type": "auth_failed"},  # not returned
        "otx":       {"skipped": True, "error": "no key"},     # not returned
    }}}
    s = compute_enrichment_summary(enr)
    assert s["returned_count"] == 1
    assert s["total_count"] == 3
    assert s["flagged_count"] == 0


def test_summary_tor_exit_does_not_count_as_flag():
    """TOR exit node membership is contextual signal — not a malicious
    verdict on its own. Only flag if other sources concur."""
    enr = {"ips": {"185.220.101.45": {
        "tor": {"isExitNode": True},
    }}}
    s = compute_enrichment_summary(enr)
    assert s["flagged_count"] == 0


# ─── Prompt wording regression ───────────────────────────────────────────────
def test_prompt_rebuts_cloud_provider_false_positive():
    """User-reported false positive: 'IP resolves to AWS, which is often
    associated with malicious activity'. AWS / Azure / GCP / Cloudflare host
    the majority of legitimate internet traffic; flagging them by attribution
    alone is a guaranteed alert-on-everything pattern. PRINCIPLE 1 must call
    this out explicitly."""
    p = investigation.PROMPT
    assert "AWS" in p and "Azure" in p and "GCP" in p
    # The prompt must explicitly rule out the failing phrasing pattern
    # (matched with whitespace-tolerant regex because of the line wrap).
    assert re.search(
        r"often\s+associated\s+with\s+malicious\s+activity", p, re.IGNORECASE,
    ), "PRINCIPLE 1 must forbid the exact phrasing pattern the user reported"


def test_prompt_explains_oauth2_authorize_is_normal():
    """OAuth2:Authorize is the standard SSO authorization-code flow —
    the AI must NOT call it 'credential harvesting' without additional
    evidence."""
    p = investigation.PROMPT
    assert "OAuth2:Authorize" in p
    assert "standard OAuth 2.0" in p.lower() or "STANDARD" in p
    # Match across the line wrap — the literal phrase wraps at column 80.
    assert re.search(r"credential\s+harvesting", p, re.IGNORECASE)


def test_prompt_contains_default_benign_rule():
    """PRINCIPLE 3 must instruct the AI to default-benign when 0 sources
    flag any IOC as malicious."""
    p = investigation.PROMPT
    assert "DEFAULT-BENIGN RULE" in p, "PRINCIPLE 3 missing the default-benign rule"
    assert "0 sources flagged any IOC" in p


def test_prompt_contains_principle_7_confirmed_vs_analysis():
    p = investigation.PROMPT
    assert "PRINCIPLE 7" in p
    assert "confirmed_facts" in p
    assert "analysis_assessment" in p
    assert "directly traceable to enrichment data" in p


def test_prompt_contains_principle_8_calibrated_language():
    p = investigation.PROMPT
    assert "PRINCIPLE 8" in p
    assert "Calibrated confidence language" in p
    # The exact rewrite examples the user asked for
    assert "consistent with Cobalt Strike" in p.lower() or "consistent with" in p
    assert "insufficient evidence to attribute" in p.lower()


def test_prompt_contains_enrichment_summary_placeholder():
    """The PROMPT template must declare an {enrichment_summary_line} slot
    so the single-shot fallback can render it. Without this slot the
    fallback would KeyError on .format()."""
    assert "{enrichment_summary_line}" in investigation.PROMPT


def test_prompt_has_two_tier_schema_in_json_template():
    """The JSON schema in the prompt must list confirmed_facts and
    analysis_assessment as required output fields."""
    p = investigation.PROMPT
    # Find the JSON block
    json_block_start = p.find('"threat_level": "CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL"')
    assert json_block_start >= 0
    json_section = p[json_block_start:json_block_start + 8000]
    assert '"confirmed_facts"' in json_section
    assert '"analysis_assessment"' in json_section


# ─── Probing temperature ─────────────────────────────────────────────────────
def test_probing_temperature_is_0_1():
    """The probing-questions synth call must run at temperature 0.1 — the
    earlier 0.55 added creative variation but the ANCHORING RULE in the
    probing prompt already prevents template-y output. Higher temperature
    just risks speculation."""
    with open(investigation.__file__, encoding="utf-8") as f:
        src = f.read()
    # Look for the synth call for probing — the literal call site uses
    # _synth(probing_instr, ..., temperature=0.1)
    m = re.search(
        r"_synth\(probing_instr,\s*\d+,\s*temperature\s*=\s*([0-9.]+)",
        src,
    )
    assert m is not None, "couldn't find the probing _synth call"
    assert float(m.group(1)) == 0.1, (
        f"probing temperature is {m.group(1)} but must be 0.1 per the "
        f"calibration spec — higher values risk creative speculation"
    )

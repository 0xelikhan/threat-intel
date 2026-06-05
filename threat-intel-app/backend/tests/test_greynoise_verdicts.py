"""Tests for the GreyNoise verdict semantics.

User reported that an inbound RDP authentication from an Azure IP
(13.66.190.166) was cleared because GreyNoise's RIOT entry matched.
The fix: RIOT-only matches get a distinct CLEAN_INFRA verdict (not
CLEAN), and the parser emits an explicit note steering the AI away
from treating cloud-provider attribution as exonerating evidence.
"""

from __future__ import annotations

from agents.enrichment import _p_gn


def test_observed_malicious_scanner_is_malicious():
    r = {"ip": "1.2.3.4", "noise": True, "riot": False,
         "classification": "malicious", "name": "Some Botnet"}
    out = _p_gn(r)
    assert out["verdict"] == "MALICIOUS"


def test_observed_benign_scanner_is_clean_with_note():
    r = {"ip": "1.2.3.4", "noise": True, "riot": False,
         "classification": "benign", "name": "Shodan.io"}
    out = _p_gn(r)
    assert out["verdict"] == "CLEAN"
    assert "benign_note" in out
    assert "scanning" in out["benign_note"].lower()


def test_riot_only_is_clean_infra_not_clean():
    """The bug case: Azure IP that's in RIOT but not seen scanning.
    Old behaviour: verdict='CLEAN' (misleading — the AI then cleared
    inbound-RDP alerts because GreyNoise said 'benign'). New behaviour:
    verdict='CLEAN_INFRA' + an explicit note that this identifies the
    OWNER, not the legitimacy of the specific traffic."""
    r = {"ip": "13.66.190.166", "noise": False, "riot": True,
         "classification": "benign", "name": "Microsoft Azure"}
    out = _p_gn(r)
    assert out["verdict"] == "CLEAN_INFRA"
    assert out["verdict"] != "CLEAN"
    assert "infra_note" in out
    note = out["infra_note"].lower()
    assert "azure" in note
    assert "owner" in note or "infrastructure" in note
    # The note must explicitly warn against using this as exonerating
    # evidence for inbound-auth / lateral-movement / C2 contexts.
    assert "inbound" in note or "lateral" in note or "exonerat" in note


def test_unknown_classification_is_suspicious():
    r = {"ip": "1.2.3.4", "noise": True, "riot": False,
         "classification": "unknown"}
    out = _p_gn(r)
    assert out["verdict"] == "SUSPICIOUS"


def test_no_classification_and_no_riot_yields_no_verdict():
    # Not seen by sensors, not in RIOT — no verdict, but the source
    # card still renders (with the noise/riot=False signals visible).
    r = {"ip": "1.2.3.4", "noise": False, "riot": False, "classification": ""}
    out = _p_gn(r)
    assert "verdict" not in out
    assert out["noise"] is False
    assert out["riot"]  is False


def test_riot_with_concurrent_noise_keeps_malicious_when_observed():
    # Edge case: RIOT match AND seen scanning maliciously. The malicious
    # observation must win — RIOT membership doesn't whitewash actual
    # observed scanning.
    r = {"ip": "1.2.3.4", "noise": True, "riot": True,
         "classification": "malicious", "name": "Microsoft Azure"}
    out = _p_gn(r)
    assert out["verdict"] == "MALICIOUS"

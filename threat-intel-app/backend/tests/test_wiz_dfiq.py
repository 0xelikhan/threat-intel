"""Coverage for round-18 items 4-5 (last of the Yeti-mined shortlist):

  - intel/wiz_cloud_threats.py     Wiz threats.wiz.io slug index
  - intel/dfiq.py                  Google DFIQ questions catalog

Every test stubs the network so the suite stays offline.
"""

from __future__ import annotations

import time
from unittest.mock import patch

from intel import wiz_cloud_threats, dfiq


# ─── Wiz cloud threats ───────────────────────────────────────────────
def test_wiz_lookup_matches_slug_exact_and_loose():
    """0ktapus + TeamTNT + 8220-gang should be exact matches; loose
    substring should catch 'Amadey' inside 'amadey-loader'."""
    wiz_cloud_threats._state.update({
        "loaded_at":     time.time(),
        "by_slug":       {},
        "by_name":       {
            "0ktapus":       {"slug": "0ktapus",       "category": "actor",
                              "url":  "https://threats.wiz.io/all-actors/0ktapus",
                              "display": "0ktapus"},
            "teamtnt":       {"slug": "teamtnt",       "category": "actor",
                              "url":  "https://threats.wiz.io/all-actors/teamtnt",
                              "display": "teamtnt"},
            "8220 gang":     {"slug": "8220-gang",     "category": "actor",
                              "url":  "https://threats.wiz.io/all-actors/8220-gang",
                              "display": "8220 gang"},
            "amadey loader": {"slug": "amadey-loader", "category": "tool",
                              "url":  "https://threats.wiz.io/all-tools/amadey-loader",
                              "display": "amadey loader"},
        },
        "count_by_cat":  {"actors": 3, "tools": 1},
    })
    assert wiz_cloud_threats.lookup("0ktapus")["match"] == "exact"
    assert wiz_cloud_threats.lookup("TeamTNT")["match"] == "exact"
    assert wiz_cloud_threats.lookup("8220 Gang")["match"] == "exact"
    # LAPSUS$ punctuation stripped by normaliser but no slug — should miss
    assert wiz_cloud_threats.lookup("LAPSUS$") is None
    # Loose containment finds tool by family name
    hit = wiz_cloud_threats.lookup("Amadey")
    assert hit is not None and hit["match"] == "loose"
    assert hit["category"] == "tool"


def test_wiz_lookup_rejects_short_or_empty_query():
    """A 3-letter query like 'apt' would match every APT-actor slug
    via loose containment — the min-length gate prevents that noise."""
    wiz_cloud_threats._state.update({
        "loaded_at": time.time(),
        "by_name":   {"apt29": {"slug": "apt29", "category": "actor",
                                  "url": "x", "display": "apt29"}},
    })
    # Empty and whitespace-only queries
    assert wiz_cloud_threats.lookup("") is None
    assert wiz_cloud_threats.lookup("   ") is None
    # 3-char query short-circuits loose match — no false positive
    assert wiz_cloud_threats.lookup("apt") is None
    # 4-char exact still works
    wiz_cloud_threats._state["by_name"]["ta29"] = {
        "slug": "ta29", "category": "actor", "url": "x", "display": "ta29"}
    assert wiz_cloud_threats.lookup("TA29")["match"] == "exact"


# ─── DFIQ ─────────────────────────────────────────────────────────────
def test_dfiq_get_questions_scores_by_keyword_overlap():
    """Alert-type seed keywords + tokenised raw text should pick the
    highest-scoring DFIQ questions. Score is the term overlap count."""
    dfiq._state.update({
        "loaded_at": time.time(),
        "questions": [
            {"id": "Q1001", "name": "What files were downloaded using a web browser?",
             "facet_ids": ["F1001"], "keywords": {"files", "downloaded", "web", "browser"}},
            {"id": "Q1024", "name": "Was an Incognito/Private browser session used?",
             "facet_ids": ["F1002"], "keywords": {"incognito", "private", "browser", "session"}},
            {"id": "Q1075", "name": "Is the recipient account controlled by the sender?",
             "facet_ids": ["F1009"], "keywords": {"recipient", "account", "controlled", "sender"}},
        ],
    })
    # Phishing seed keywords include 'browser' and 'download' — those
    # match Q1001 (2 overlap) and Q1024 (1 overlap).
    hits = dfiq.get_questions(alert_type="phishing", raw_text="", max_results=3)
    ids = [h["id"] for h in hits]
    assert "Q1001" in ids
    assert "Q1024" in ids
    # Q1075 has no overlap with phishing seed keywords → absent
    assert "Q1075" not in ids


def test_dfiq_get_questions_uses_raw_text_when_type_thin():
    dfiq._state.update({
        "loaded_at": time.time(),
        "questions": [
            {"id": "Q1050", "name": "Are there any GCS buckets shared externally?",
             "facet_ids": ["F1017"], "keywords": {"gcs", "buckets", "shared", "externally"}},
        ],
    })
    # Empty alert_type but raw text mentions GCS bucket
    hits = dfiq.get_questions(alert_type="", raw_text="anomalous gcs bucket access",
                                max_results=3)
    assert hits and hits[0]["id"] == "Q1050"


def test_dfiq_returns_empty_when_no_keywords_match():
    dfiq._state.update({
        "loaded_at": time.time(),
        "questions": [
            {"id": "Q9999", "name": "Some unrelated forensic question",
             "facet_ids": [], "keywords": {"unrelated", "forensic"}},
        ],
    })
    hits = dfiq.get_questions(alert_type="phishing", raw_text="", max_results=3)
    assert hits == []


def test_dfiq_stopwords_do_not_produce_matches():
    """A question whose only keywords are common stopwords ('the',
    'is', 'was') would false-positive against any query; the tokeniser
    filters those out so it can't happen."""
    q = {"id": "QX", "name": "Was the file the same?",
         "facet_ids": [], "keywords": dfiq._tokenise("Was the file the same?")}
    # After stopword removal only 'file' + 'same' should remain
    # ('file' is in _STOPWORDS so it's stripped too — leaving just 'same')
    assert q["keywords"] == {"same"}

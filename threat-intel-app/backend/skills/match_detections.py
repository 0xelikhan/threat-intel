"""
MatchDetectionsSkill — fan out across every bundled detection corpus and
return citations grouped by source.

Wraps:
  * intel.sigma_corpus      (SigmaHQ)
  * intel.panther_rules     (panther-analysis)
  * intel.splunk_content    (Splunk security_content)
  * intel.mitre_car         (MITRE CAR analytics)
  * intel.hunter_playbook   (OTRF ThreatHunter-Playbook)

All consume the same `mitre_techniques` input and return ranked
metadata. Skill-side this lets the investigation node make ONE call
and surface a structured "matching public detections" block. Granular
per-corpus access is still available via match_sigma_rules.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from providers.base import LLMProvider

from .base import Skill


class MatchDetectionsSkill(Skill):
    @property
    def name(self) -> str:
        return "match_detections"

    @property
    def description(self) -> str:
        return ("Cross-reference an analysis's MITRE techniques against ALL "
                "bundled detection corpora (SigmaHQ, panther-analysis, "
                "Splunk security_content, MITRE CAR, OTRF ThreatHunter-"
                "Playbook). Returns citations grouped by source.")

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "mitre_techniques": "list[str]",
            "per_source_max":   "int (optional, default 8)",
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "sigma":            "list[dict]",
            "panther":          "list[dict]",
            "splunk":           "list[dict]",
            "mitre_car":        "list[dict]",
            "hunter_playbook":  "list[dict]",
            "sublime":          "list[dict]",
            "chronicle":        "list[dict]",
            "olafhartong":      "list[dict]",
            "falco":            "list[dict]",
            "stratus":          "list[dict]",
            "total":            "int",
            "corpus_stats":     "dict[str, dict]",
        }

    @property
    def test_input(self) -> Dict[str, Any]:
        return {"mitre_techniques": ["T1059.001", "T1027"], "per_source_max": 4}

    async def execute(
        self,
        inputs:   Dict[str, Any],
        provider: Optional[LLMProvider] = None,
    ) -> Dict[str, Any]:
        techniques = list((inputs or {}).get("mitre_techniques") or [])
        per_max    = int((inputs or {}).get("per_source_max") or 8)

        sigma:        List[Dict[str, Any]] = []
        panther:      List[Dict[str, Any]] = []
        splunk:       List[Dict[str, Any]] = []
        car:          List[Dict[str, Any]] = []
        playbook:     List[Dict[str, Any]] = []
        sublime:      List[Dict[str, Any]] = []
        chronicle:    List[Dict[str, Any]] = []
        olafhartong:  List[Dict[str, Any]] = []
        falco:        List[Dict[str, Any]] = []
        stratus:      List[Dict[str, Any]] = []
        corpus_stats: Dict[str, Any] = {}

        # Each lookup is purely in-memory after first call; failures are
        # silent because the missing corpus is reported via corpus_stats.
        try:
            from intel.sigma_corpus import match_by_techniques as _s
            from intel.sigma_corpus import stats as _ss
            sigma = _s(techniques, max_results=per_max)
            corpus_stats["sigma"] = _ss()
        except Exception as e:
            corpus_stats["sigma"] = {"error": str(e)[:120]}

        try:
            from intel.panther_rules import match_by_techniques as _p
            from intel.panther_rules import stats as _ps
            panther = _p(techniques, max_results=per_max)
            corpus_stats["panther"] = _ps()
        except Exception as e:
            corpus_stats["panther"] = {"error": str(e)[:120]}

        try:
            from intel.splunk_content import match_by_techniques as _sp
            from intel.splunk_content import stats as _sps
            splunk = _sp(techniques, max_results=per_max)
            corpus_stats["splunk"] = _sps()
        except Exception as e:
            corpus_stats["splunk"] = {"error": str(e)[:120]}

        try:
            from intel.mitre_car import match_by_techniques as _c
            from intel.mitre_car import stats as _cs
            car = _c(techniques, max_results=per_max)
            corpus_stats["mitre_car"] = _cs()
        except Exception as e:
            corpus_stats["mitre_car"] = {"error": str(e)[:120]}

        try:
            from intel.hunter_playbook import match_by_techniques as _h
            from intel.hunter_playbook import stats as _hs
            playbook = _h(techniques, max_results=per_max)
            corpus_stats["hunter_playbook"] = _hs()
        except Exception as e:
            corpus_stats["hunter_playbook"] = {"error": str(e)[:120]}

        try:
            from intel.sublime_rules import match_by_techniques as _sub
            from intel.sublime_rules import stats as _subs
            sublime = _sub(techniques, max_results=per_max)
            corpus_stats["sublime"] = _subs()
        except Exception as e:
            corpus_stats["sublime"] = {"error": str(e)[:120]}

        try:
            from intel.chronicle_rules import match_by_techniques as _cr
            from intel.chronicle_rules import stats as _crs
            chronicle = _cr(techniques, max_results=per_max)
            corpus_stats["chronicle"] = _crs()
        except Exception as e:
            corpus_stats["chronicle"] = {"error": str(e)[:120]}

        try:
            from intel.olafhartong_th import match_by_techniques as _oh
            from intel.olafhartong_th import stats as _ohs
            olafhartong = _oh(techniques, max_results=per_max)
            corpus_stats["olafhartong"] = _ohs()
        except Exception as e:
            corpus_stats["olafhartong"] = {"error": str(e)[:120]}

        try:
            from intel.falco_rules import match_by_techniques as _fr
            from intel.falco_rules import stats as _frs
            falco = _fr(techniques, max_results=per_max)
            corpus_stats["falco"] = _frs()
        except Exception as e:
            corpus_stats["falco"] = {"error": str(e)[:120]}

        try:
            from intel.stratus_techniques import match_by_techniques as _st
            from intel.stratus_techniques import stats as _sts
            stratus = _st(techniques, max_results=per_max)
            corpus_stats["stratus"] = _sts()
        except Exception as e:
            corpus_stats["stratus"] = {"error": str(e)[:120]}

        return {
            "sigma":           sigma,
            "panther":         panther,
            "splunk":          splunk,
            "mitre_car":       car,
            "hunter_playbook": playbook,
            "sublime":         sublime,
            "chronicle":       chronicle,
            "olafhartong":     olafhartong,
            "falco":           falco,
            "stratus":         stratus,
            "total":           sum(len(x) for x in
                                   (sigma, panther, splunk, car, playbook,
                                    sublime, chronicle, olafhartong,
                                    falco, stratus)),
            "corpus_stats":    corpus_stats,
        }

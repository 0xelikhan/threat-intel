"""
Emerging Threats Open + Snort Community IDS/IPS rule corpus loader.

Sources:
  - https://rules.emergingthreats.net/open/ (Proofpoint, MIT/BSD on
    the data — ET Open rules are freely usable for any purpose).
  - https://www.snort.org/downloads/community/ (Cisco, GPL on engine
    but VRT Community rules are explicitly redistributable).

Each rule is a single line of Suricata/Snort DSL with shape:

  alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"ET EXPLOIT ..."; \
    flow:established,to_server; content:"|FF SMB|..."; reference:cve,2017-0144; \
    classtype:attempted-admin; sid:2024792; rev:3; \
    metadata:attack_target Server_Endpoint, deployment Perimeter, signature_severity Major;)

We parse the metadata fields (sid, msg, classtype, reference, mitre tags
where present) and build inverted indexes by:

  by_cve:       {CVE-id, [rule]}
  by_classtype: {classtype, [rule]}
  by_keyword:   {lowercase token, [rule]}  (for free-text routing)

RECON's response stage generates Suricata rules; this corpus gives it
a reference catalogue. When a CVE IOC is extracted, the analyst sees
"ET Open has 4 active Suricata rules for this CVE: SID 2030001 ...".
"""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_log = logging.getLogger("recon.intel.ids_rules")

_ROOT_CANDIDATES = [
    Path(__file__).parent.parent.parent / "vendor" / "emerging-threats-open",
    Path(__file__).parent.parent.parent / "vendor" / "snort-community",
]

_SID_RE        = re.compile(r"\bsid\s*:\s*(\d+)")
_MSG_RE        = re.compile(r'\bmsg\s*:\s*"([^"]+)"')
_CLASSTYPE_RE  = re.compile(r"\bclasstype\s*:\s*([\w\-]+)")
_REFERENCE_RE  = re.compile(r"\breference\s*:\s*([^;]+)")
_CVE_RE        = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)
_MITRE_RE      = re.compile(r"\battack_target_(T\d{4}(?:\.\d{3})?)", re.IGNORECASE)

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":         False,
    "rules":          [],   # list[dict]
    "by_cve":         {},
    "by_classtype":   {},
    "by_sid":         {},
    "by_keyword":     {},
    "by_source":      {},
    "error":          None,
}


def _extract_cves(rule_line: str) -> List[str]:
    """ET/Snort rules express CVE refs via `reference:cve,YYYY-NNNN` or
    inline mentions in the msg. We accept both."""
    cves: List[str] = []
    # `reference:cve,2017-0144` shape
    for m in _REFERENCE_RE.finditer(rule_line):
        ref = m.group(1).strip()
        if ref.lower().startswith("cve,"):
            year_nnnn = ref.split(",", 1)[1].strip()
            cves.append(f"CVE-{year_nnnn}".upper())
    # Inline `CVE-YYYY-NNNN` mentions
    for m in _CVE_RE.finditer(rule_line):
        cves.append(m.group(1).upper())
    return list(dict.fromkeys(cves))


def _keywords_from_msg(msg: str) -> List[str]:
    """Pull lowercased tokens from the rule msg useful for routing
    free-text alerts. Drops common ET-prefix words."""
    if not msg:
        return []
    text = msg.lower()
    # Drop the ET classification prefix tokens, they're meta-routing.
    text = re.sub(r"\bet (open|exploit|trojan|malware|policy|info|web_server|user_agents|inappropriate|dos|attack_response|current_events)\b",
                  " ", text)
    toks = re.findall(r"[a-z][a-z0-9\-]{3,}", text)
    drop = {"http", "tcp", "udp", "any", "rule", "snort", "open"}
    return list(dict.fromkeys(t for t in toks if t not in drop))[:10]


def _ingest_rule_line(line: str, source: str,
                     rules: List[Dict[str, Any]],
                     by_cve: Dict[str, List[Dict[str, Any]]],
                     by_classtype: Dict[str, List[Dict[str, Any]]],
                     by_sid: Dict[str, Dict[str, Any]],
                     by_keyword: Dict[str, List[Dict[str, Any]]],
                     by_source: Dict[str, List[Dict[str, Any]]]) -> None:
    line = line.strip()
    if not line or line.startswith("#") or len(line) > 8_000:
        return
    if not (line.startswith("alert") or line.startswith("drop") or
            line.startswith("pass") or line.startswith("reject")):
        return
    m_sid = _SID_RE.search(line)
    if not m_sid:
        return
    sid = m_sid.group(1)
    m_msg = _MSG_RE.search(line)
    msg = (m_msg.group(1) if m_msg else "")[:240]
    m_ct = _CLASSTYPE_RE.search(line)
    classtype = (m_ct.group(1) if m_ct else "").strip().lower()
    cves = _extract_cves(line)
    # MITRE-ish metadata is rare in Snort but ET 5.0+ sometimes carries
    # `metadata:tag mitre_tactic_id TA0001, mitre_technique_id T1190;`
    techniques = list(dict.fromkeys(
        m.group(1).upper() for m in re.finditer(
            r"\bmitre_technique_id\s+(T\d{4}(?:\.\d{3})?)", line, re.IGNORECASE)
    ))

    meta = {
        "sid":         sid,
        "msg":         msg,
        "classtype":   classtype,
        "cves":        cves,
        "techniques":  techniques,
        "source":      source,
    }
    rules.append(meta)
    by_sid[sid] = meta
    for cve in cves:
        by_cve.setdefault(cve, []).append(meta)
    if classtype:
        by_classtype.setdefault(classtype, []).append(meta)
    for kw in _keywords_from_msg(msg):
        by_keyword.setdefault(kw, []).append(meta)
    by_source.setdefault(source, []).append(meta)


def _build_index() -> None:
    rules:        List[Dict[str, Any]] = []
    by_cve:       Dict[str, List[Dict[str, Any]]] = {}
    by_classtype: Dict[str, List[Dict[str, Any]]] = {}
    by_sid:       Dict[str, Dict[str, Any]] = {}
    by_keyword:   Dict[str, List[Dict[str, Any]]] = {}
    by_source:    Dict[str, List[Dict[str, Any]]] = {}

    found_any_dir = False
    for root in _ROOT_CANDIDATES:
        if not root.exists():
            continue
        found_any_dir = True
        source_label = ("Emerging Threats Open"
                        if "emerging-threats" in root.name
                        else "Snort Community")
        for path in root.rglob("*.rules"):
            if not path.is_file() or path.stat().st_size > 8_000_000:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for line in text.splitlines():
                _ingest_rule_line(line, source_label, rules, by_cve,
                                  by_classtype, by_sid, by_keyword, by_source)

    if not found_any_dir:
        _state["error"] = ("IDS rule corpora not present at any of "
                           f"{[str(p) for p in _ROOT_CANDIDATES]}")
    _state["rules"]        = rules
    _state["by_cve"]       = by_cve
    _state["by_classtype"] = by_classtype
    _state["by_sid"]       = by_sid
    _state["by_keyword"]   = by_keyword
    _state["by_source"]    = by_source
    _state["loaded"]       = True
    _log.info("IDS rules loaded: %d rules | %d CVEs | %d classtypes | %d keywords",
              len(rules), len(by_cve), len(by_classtype), len(by_keyword))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def match_by_cve(cve_id: str, max_results: int = 8) -> List[Dict[str, Any]]:
    _ensure_loaded()
    if not cve_id:
        return []
    rows = (_state.get("by_cve") or {}).get(cve_id.upper().strip(), [])
    return rows[:max_results]


def match_by_techniques(technique_ids: Iterable[str],
                        max_results: int = 8) -> List[Dict[str, Any]]:
    _ensure_loaded()
    wanted = {t.upper().strip() for t in (technique_ids or [])
              if isinstance(t, str) and t.strip()}
    if not wanted:
        return []
    seen: Dict[str, Dict[str, Any]] = {}
    for meta in (_state.get("rules") or []):
        if set(meta.get("techniques") or []) & wanted:
            seen.setdefault(meta["sid"], meta)
    return list(seen.values())[:max_results]


def match_by_keyword(text: str, max_results: int = 6) -> List[Dict[str, Any]]:
    """Free-text routing: tokenise input text, look up tokens in the
    msg-keyword inverted index. Useful when triage hasn't extracted
    MITRE techniques yet."""
    _ensure_loaded()
    if not text:
        return []
    by_kw = _state.get("by_keyword") or {}
    text_l = text.lower()
    candidates: Dict[str, Dict[str, Any]] = {}
    for kw, metas in by_kw.items():
        if kw in text_l:
            for meta in metas[:5]:
                candidates.setdefault(meta["sid"], meta)
    return list(candidates.values())[:max_results]


def lookup_sid(sid: str) -> Optional[Dict[str, Any]]:
    _ensure_loaded()
    return (_state.get("by_sid") or {}).get(str(sid).strip())


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":     bool(_state["loaded"]),
        "rules":      len(_state.get("rules") or []),
        "cves":       len(_state.get("by_cve") or {}),
        "classtypes": len(_state.get("by_classtype") or {}),
        "sources":    list((_state.get("by_source") or {}).keys()),
        "error":      _state.get("error"),
    }

"""
Maltego GraphML export for RECON investigation results.

Adapted from cti-expert (MIT, Hieu Ngo, chongluadao.vn) connectors/
maltego-export.md. Analyst teams that live in Maltego CE / XL can
import this file and get the case as a node-edge graph for link
analysis — RECON's existing STIX / SARIF / CACAO exports are great
for SOAR / SIEM / scanning pipelines but don't render as a graph.

We use the standard `maltego.*` entity types (Domain / IPv4Address /
URL / EmailAddress / Hash) so a fresh Maltego install can import the
file without registering custom entity profiles. Relationships use
plain edge labels (`resolves_to`, `references`, `matched_by`) so a
target-side transform isn't required.

Shape of the produced GraphML:

  graphml
    keys: type, label, notes, confidence, source
    keys for edges: relationship, evidence
    graph
      <run-id node> ← root
        ─ verdict edge → threat-level node
      <ioc nodes...> connected to each other by:
        domain → resolves_to → ip
        url    → on_domain   → domain
        hash   → seen_in     → url   (when sandbox data ties them)
      <actor / malware nodes> connected to ioc nodes by:
        actor  → attributed_to → ioc
        family → distributed_via → ioc

We don't pull every field — Maltego graphs get unreadable past ~150
nodes. Cap each IOC type at 50 nodes; this matches the analyst's
practical link-analysis budget.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Tuple
from xml.sax.saxutils import escape as _xml_escape

_log = logging.getLogger("recon.intel.maltego_export")


# How many of each IOC type we emit. Past these caps the Maltego canvas
# becomes a hairball — the analyst will pull more on demand via Maltego
# transforms on the seed nodes we DO emit.
_CAPS = {
    "ips":     50,
    "domains": 50,
    "urls":    50,
    "hashes":  30,
    "emails":  30,
    "actors":  10,
}


def _safe_id(prefix: str, value: str) -> str:
    """Maltego entity IDs need to be XML-safe. Strip everything but
    alphanumeric + dash + underscore, and prefix with a kind tag so
    IDs don't collide across types (1.2.3.4 the IP vs 1.2.3.4 in a URL)."""
    cleaned = re.sub(r"[^A-Za-z0-9._\-]", "_", value or "")
    return f"{prefix}_{cleaned}"[:120]


def _esc(s: Any) -> str:
    """XML-escape for inline text values."""
    return _xml_escape(str(s if s is not None else ""))


def _emit_node(
    parts: List[str],
    *,
    node_id: str,
    entity_type: str,
    label: str,
    notes: str = "",
    confidence: str = "Medium",
    source: str = "RECON",
) -> None:
    """Append one Maltego node XML block to `parts`."""
    parts.append(f'    <node id="{_esc(node_id)}">')
    parts.append(f'      <data key="type">{_esc(entity_type)}</data>')
    parts.append(f'      <data key="label">{_esc(label)}</data>')
    if notes:
        parts.append(f'      <data key="notes">{_esc(notes)}</data>')
    parts.append(f'      <data key="confidence">{_esc(confidence)}</data>')
    parts.append(f'      <data key="source">{_esc(source)}</data>')
    parts.append("    </node>")


def _emit_edge(
    parts: List[str],
    *,
    source_id: str,
    target_id: str,
    relationship: str,
    evidence: str = "",
) -> None:
    parts.append(
        f'    <edge source="{_esc(source_id)}" target="{_esc(target_id)}">'
    )
    parts.append(f'      <data key="relationship">{_esc(relationship)}</data>')
    if evidence:
        parts.append(f'      <data key="evidence">{_esc(evidence)}</data>')
    parts.append("    </edge>")


def _summarise_ioc(per_source: Dict[str, Any]) -> Tuple[str, str]:
    """Compress one IOC's per-source enrichment into (confidence, note)
    for the Maltego node. We pull the strongest signal — VirusTotal
    detections, AbuseIPDB confidence, GreyNoise label — into the note
    so the graph view is informative without expanding every node."""
    if not isinstance(per_source, dict):
        return "Low", ""
    bits: List[str] = []
    confidence = "Medium"
    vt = per_source.get("virustotal") or {}
    if isinstance(vt, dict) and not vt.get("error"):
        mal = vt.get("malicious") or 0
        if mal:
            bits.append(f"VT {mal} engines flagged")
            confidence = "High" if mal >= 5 else "Medium"
    ai = per_source.get("abuseipdb") or {}
    if isinstance(ai, dict) and not ai.get("error"):
        score = ai.get("abuseScore") or ai.get("abuse_confidence")
        if score:
            bits.append(f"AbuseIPDB {score}%")
            if isinstance(score, (int, float)) and score >= 75:
                confidence = "High"
    gn = per_source.get("greynoise") or {}
    if isinstance(gn, dict) and not gn.get("error"):
        cls = gn.get("classification") or gn.get("label")
        if cls:
            bits.append(f"GreyNoise: {cls}")
    return confidence, " · ".join(bits)


def to_graphml(result: Dict[str, Any]) -> str:
    """Serialise a RECON investigation result dict to a Maltego GraphML
    document. `result` is the same dict the SSE `event: complete`
    payload carries — iocs / enrichments / response_summary /
    matched_actors / malware_family."""
    if not isinstance(result, dict):
        result = {}

    iocs = result.get("iocs") or {}
    enrichments = result.get("enrichments") or {}
    response_summary = result.get("response_summary") or {}
    matched_actors = response_summary.get("matched_actors") or []
    malware_family = response_summary.get("malware_family") or result.get("malware_family")
    threat_level = response_summary.get("threat_level") or result.get("threat_level") or "UNKNOWN"
    run_id = result.get("runId") or result.get("run_id") or "recon-run"

    parts: List[str] = []
    parts.append('<?xml version="1.0" encoding="UTF-8"?>')
    parts.append('<graphml xmlns="http://graphml.graphdrawing.org/xmlns">')
    parts.append('  <key id="type"       for="node" attr.name="Entity Type" attr.type="string"/>')
    parts.append('  <key id="label"      for="node" attr.name="Label"       attr.type="string"/>')
    parts.append('  <key id="notes"      for="node" attr.name="Notes"       attr.type="string"/>')
    parts.append('  <key id="confidence" for="node" attr.name="Confidence"  attr.type="string"/>')
    parts.append('  <key id="source"     for="node" attr.name="Source"      attr.type="string"/>')
    parts.append('  <key id="relationship" for="edge" attr.name="Relationship" attr.type="string"/>')
    parts.append('  <key id="evidence"     for="edge" attr.name="Evidence"     attr.type="string"/>')
    parts.append(f'  <graph id="recon-{_esc(run_id)}" edgedefault="directed">')

    # Root investigation node
    root_id = _safe_id("recon", str(run_id))
    _emit_node(
        parts,
        node_id=root_id,
        entity_type="maltego.Phrase",
        label=f"RECON {run_id} · {threat_level}",
        notes=(response_summary.get("summary") or "")[:300],
        confidence="High",
    )

    # Threat-level node (so the verdict shows up on the graph)
    tl_id = _safe_id("threatlvl", threat_level)
    _emit_node(
        parts,
        node_id=tl_id,
        entity_type="maltego.Phrase",
        label=f"Verdict: {threat_level}",
        confidence="High",
    )
    _emit_edge(
        parts,
        source_id=root_id,
        target_id=tl_id,
        relationship="verdict",
        evidence=(response_summary.get("threat_level_reasoning") or "")[:200],
    )

    # Malware family node when present
    if isinstance(malware_family, str) and malware_family.strip():
        fam_id = _safe_id("family", malware_family)
        _emit_node(
            parts,
            node_id=fam_id,
            entity_type="maltego.MalwareFamily",
            label=malware_family,
            confidence="Medium",
            notes="Family identified by RECON investigation.",
        )
        _emit_edge(
            parts,
            source_id=root_id,
            target_id=fam_id,
            relationship="identifies",
        )

    # Threat-actor nodes
    actor_ids: Dict[str, str] = {}
    for actor in (matched_actors or [])[: _CAPS["actors"]]:
        if not isinstance(actor, dict):
            continue
        name = actor.get("name") or actor.get("group") or ""
        if not name:
            continue
        aid = _safe_id("actor", name)
        actor_ids[name] = aid
        _emit_node(
            parts,
            node_id=aid,
            entity_type="maltego.ThreatActor",
            label=name,
            notes=f"Score {actor.get('score')} via {actor.get('origin') or 'MITRE'}",
            confidence="Medium",
            source=actor.get("origin") or "MITRE",
        )
        _emit_edge(
            parts,
            source_id=root_id,
            target_id=aid,
            relationship="attributed_to",
            evidence=f"Match score {actor.get('score')}",
        )

    # IOC nodes — IPs / domains / URLs / hashes / emails
    def _ioc_bucket(kind: str, type_name: str, cap_key: str):
        ids: Dict[str, str] = {}
        bucket = iocs.get(kind) or []
        if not isinstance(bucket, list):
            return ids
        per_bucket = (enrichments or {}).get(
            {"ips": "ips", "domains": "domains", "urls": "urls",
             "hashes": "hashes", "emails": "emails"}.get(kind, kind)
        ) or {}
        for value in bucket[: _CAPS[cap_key]]:
            if not isinstance(value, str) or not value.strip():
                continue
            nid = _safe_id(kind, value)
            ids[value] = nid
            conf, note = _summarise_ioc(per_bucket.get(value) or {})
            _emit_node(
                parts,
                node_id=nid,
                entity_type=type_name,
                label=value,
                notes=note,
                confidence=conf,
            )
            _emit_edge(
                parts,
                source_id=root_id,
                target_id=nid,
                relationship="observed",
            )
        return ids

    ip_ids     = _ioc_bucket("ips",     "maltego.IPv4Address",  "ips")
    domain_ids = _ioc_bucket("domains", "maltego.Domain",       "domains")
    url_ids    = _ioc_bucket("urls",    "maltego.URL",          "urls")
    hash_ids   = _ioc_bucket("hashes",  "maltego.Hash",         "hashes")
    email_ids  = _ioc_bucket("emails",  "maltego.EmailAddress", "emails")

    # Derived relationships
    # URL → on_domain → Domain (parse the hostname out of each URL).
    for url, uid in url_ids.items():
        m = re.match(r"https?://([^/?#]+)", url, re.I)
        if not m:
            continue
        host = m.group(1).lower().split(":")[0]
        if host in domain_ids:
            _emit_edge(parts, source_id=uid, target_id=domain_ids[host],
                       relationship="on_domain")

    # Domain → resolves_to → IP (only when we have the resolved IP in
    # the per-source whois/dns payload).
    dom_enr = (enrichments or {}).get("domains") or {}
    for dom, did in domain_ids.items():
        info = dom_enr.get(dom) or {}
        if not isinstance(info, dict):
            continue
        ips_resolved = []
        whois = info.get("whois") or {}
        if isinstance(whois, dict):
            for v in whois.values():
                if isinstance(v, str) and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v.strip()):
                    ips_resolved.append(v.strip())
        for ip in ips_resolved:
            if ip in ip_ids:
                _emit_edge(parts, source_id=did, target_id=ip_ids[ip],
                           relationship="resolves_to",
                           evidence="WHOIS / DNS resolved IP")

    # Actor → attributed_to → top-level IOC types we have intel on
    for name, aid in actor_ids.items():
        for ids in (domain_ids, ip_ids, hash_ids):
            for value, nid in ids.items():
                _emit_edge(parts, source_id=aid, target_id=nid,
                           relationship="seen_with")
                break  # one anchor per type is enough

    parts.append("  </graph>")
    parts.append("</graphml>")
    return "\n".join(parts) + "\n"


def stats() -> Dict[str, Any]:
    return {
        "loaded":     True,
        "caps":       dict(_CAPS),
        "format":     "GraphML 1.0 (Maltego CE / XL compatible)",
    }

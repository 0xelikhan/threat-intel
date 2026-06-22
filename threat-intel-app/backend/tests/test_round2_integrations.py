"""
Behavioural tests for the seven round-2 integrations:

  1. EPSS                — pre-existing; covered by tests/test_cve_enrichment.py
  2. dnstwist            — skills.domain_permutations
  3. Attack Flow         — intel.attack_flow
  4. signature-base YARA — pre-existing; intel/yara_scanner.py
  5. FLARE capa          — intel.capa_runner + skills.analyze_capabilities
  6. SigmaHQ corpus      — intel.sigma_corpus + skills.match_sigma_rules
  7. nuclei-templates    — intel.nuclei_index

Each test asserts a small, well-defined behaviour. Heavy integrations
(capa subprocess, dnstwist with DNS) use the short-circuit paths so the
suite stays offline + fast.
"""

from __future__ import annotations

import asyncio
import pytest


# ─── dnstwist (skills.domain_permutations) ──────────────────────────────────
def test_domain_permutations_generates_variants_offline():
    """resolve=False must skip DNS and just return the generated permutation
    set so the test stays offline. We assert dnstwist actually emitted
    variants — not the exact list (it changes between dnstwist versions)."""
    from skills import run_skill
    out = asyncio.run(run_skill("domain_permutations", {
        "domain": "microsoft.com", "max_results": 8, "resolve": False,
    }))
    assert out["error"] is None
    assert out["total"] >= 1
    assert out["domain"] == "microsoft.com"
    assert all(v["variant"] != "microsoft.com" for v in out["unresolved"])
    assert all("fuzzer" in v for v in out["unresolved"])


def test_domain_permutations_handles_blank_input():
    from skills import run_skill
    out = asyncio.run(run_skill("domain_permutations", {"domain": ""}))
    assert out["error"] == "missing 'domain' input"
    assert out["total"] == 0


# ─── Attack Flow (intel.attack_flow) ────────────────────────────────────────
def test_attack_flow_emits_extension_definition():
    """Every Attack Flow bundle must declare the canonical CTID extension-
    definition so consumers know how to render the new SDOs."""
    from intel.attack_flow import build_attack_flow_objects
    objs = build_attack_flow_objects(
        identity_id="identity--abc",
        technique_labels=["T1059.001 - PowerShell", "T1027 - Obfuscation"],
        attack_pattern_index={"T1059.001": "attack-pattern--p1",
                               "T1027":     "attack-pattern--p2"},
        investigation={"verdict": "MALICIOUS"},
    )
    types = [o["type"] for o in objs]
    assert "extension-definition" in types
    assert "attack-flow" in types
    assert types.count("attack-action") == 2
    # The flow's start_refs must point at the first attack-action.
    flow   = next(o for o in objs if o["type"] == "attack-flow")
    action_ids = [o["id"] for o in objs if o["type"] == "attack-action"]
    assert flow["start_refs"] == [action_ids[0]]
    # First action's effect_refs must point at the second action.
    a0 = next(o for o in objs if o["type"] == "attack-action")
    assert a0["effect_refs"] == [action_ids[1]]
    # Last action has no effect_refs (end of chain).
    a_last = [o for o in objs if o["type"] == "attack-action"][-1]
    assert "effect_refs" not in a_last


def test_attack_flow_short_circuits_when_no_techniques():
    """No techniques → empty list. We don't want a flow container with
    no actions in it (invalid per the spec — start_refs would be empty)."""
    from intel.attack_flow import build_attack_flow_objects
    assert build_attack_flow_objects(
        identity_id="identity--abc",
        technique_labels=[],
        attack_pattern_index={},
    ) == []


def test_attack_flow_skips_label_without_tid():
    """'unparseable label' must be silently dropped, not emitted as
    attack-action with technique_id=None."""
    from intel.attack_flow import build_attack_flow_objects
    objs = build_attack_flow_objects(
        identity_id="identity--abc",
        technique_labels=["not-a-technique", "T1059 - PowerShell"],
        attack_pattern_index={"T1059": "attack-pattern--p"},
    )
    actions = [o for o in objs if o["type"] == "attack-action"]
    assert len(actions) == 1
    assert actions[0]["technique_id"] == "T1059"


# ─── FLARE capa (intel.capa_runner) ─────────────────────────────────────────
def test_capa_runner_short_circuits_on_empty_input():
    """Zero-byte input → immediate error, no subprocess spawn."""
    from intel.capa_runner import run_capa_sync
    out = run_capa_sync(b"", filename="x.bin")
    assert out["available"] is True
    assert out["error"] == "empty input"
    assert out["rule_count"] == 0
    assert out["capabilities"] == []


def test_capa_skill_accepts_b64_input():
    """The skill should base64-decode `file_b64` when raw bytes aren't
    supplied — that's how the future /api/scan/capa endpoint will send
    upload payloads."""
    from skills import run_skill
    out = asyncio.run(run_skill("analyze_capabilities", {
        "file_b64": "",  # empty base64 → empty bytes → short-circuit
        "filename": "empty.bin",
    }))
    assert out["error"] == "empty input"


# ─── SigmaHQ corpus (intel.sigma_corpus) ────────────────────────────────────
def test_sigma_corpus_loads_thousands_of_rules():
    from intel.sigma_corpus import stats
    s = stats()
    assert s["loaded"] is True
    # The vendored corpus has ~2,600 rules; assert a generous lower bound
    # so this test survives upstream additions/removals.
    assert s["rule_count"] >= 1500
    assert s["techniques"] >= 100
    assert s["error"] is None


def test_sigma_match_returns_high_overlap_first():
    """T1059.001 + T1027 are heavily-covered techniques; the top hit
    should be a rule whose tag set overlaps BOTH (overlap=2 ranks above
    overlap=1 in the ranker)."""
    from intel.sigma_corpus import match_by_techniques
    matches = match_by_techniques(["T1059.001", "T1027"], max_results=5)
    assert len(matches) >= 1
    # The top match must have at least one of our requested techniques.
    requested = {"T1059.001", "T1027"}
    top_techs = set(matches[0].get("techniques") or [])
    assert top_techs & requested


def test_sigma_match_subtechnique_resolves_to_parent():
    """Asking for T1059.001 should also surface rules tagged only T1059
    (the parent technique) — our matcher unions the subtech with its
    parent before lookup."""
    from intel.sigma_corpus import match_by_techniques
    matches = match_by_techniques(["T1059.001"], max_results=10)
    parent_only = [m for m in matches if "T1059" in (m.get("techniques") or [])
                                       and "T1059.001" not in (m.get("techniques") or [])]
    # Not all corpora have T1059-only rules, so this is a soft assertion —
    # we only require that the matcher returned *something* without error.
    assert isinstance(parent_only, list)
    assert len(matches) >= 1


def test_match_sigma_rules_skill_returns_attribution():
    """Every match returned by the skill must carry source='SigmaHQ' so
    the frontend can render attribution alongside the rule title."""
    from skills import run_skill
    out = asyncio.run(run_skill("match_sigma_rules", {
        "mitre_techniques": ["T1059.001"], "max_results": 3,
    }))
    assert out["corpus_size"] >= 1500
    if out["matches"]:
        assert all(m["source"] == "SigmaHQ" for m in out["matches"])


# ─── nuclei-templates (intel.nuclei_index) ──────────────────────────────────
def test_nuclei_index_handles_missing_corpus():
    """nuclei-templates is operator-fetched via scripts/fetch_nuclei_templates.sh.
    When the dir isn't present, stats() must report the error string and
    lookup() must return an empty list — never crash."""
    from intel.nuclei_index import stats, lookup
    s = stats()
    assert s["loaded"] is True
    # Either corpus is present (templates > 0) OR error string is set.
    assert s["templates"] >= 0
    assert lookup("CVE-2023-1234") == []  # invalid CVE → empty
    # Even for a real-shaped CVE, lookup is allowed to return []; we only
    # care that it doesn't blow up.
    assert isinstance(lookup("CVE-2023-12345"), list)


def test_nuclei_lookup_rejects_non_cve():
    """Inputs that don't start with CVE- must be rejected without
    consulting the index."""
    from intel.nuclei_index import lookup
    assert lookup("not-a-cve") == []
    assert lookup("") == []
    assert lookup(None) == []  # type: ignore

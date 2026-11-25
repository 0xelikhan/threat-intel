"""Regression tests for the vendored cti-skills playbook library.

Covers:
  - loader walks the vendored tree and parses every SKILL.md
  - get_playbook returns the full body for a known slug
  - search_playbooks ranks the right skill at the top for a clear query
  - /api/cti-skills + /api/cti-skills/{name} endpoints wire correctly
  - the investigation-agent tool schema + dispatch include cti_skill_search
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


# ─── Loader ────────────────────────────────────────────────────────────────

def test_loader_discovers_all_playbooks():
    """Floor at 50 - the vendored library has 77 skills + LICENSE +
    README. If the walker ever drops below this, something in the
    frontmatter parser broke and the loader is silently skipping skills."""
    from skills.cti_skills import list_playbooks
    pbs = list_playbooks()
    assert len(pbs) >= 50, (
        f"loader found only {len(pbs)} playbooks; expected ≥50. "
        "Possible frontmatter regression."
    )


def test_get_playbook_returns_full_body():
    """Known slug - the campaign-tracking playbook was one of the
    longest at vendor time (~10 KB). If the body shrinks dramatically
    or vanishes, the file write / loader is broken."""
    from skills.cti_skills import get_playbook
    p = get_playbook("campaign-tracking")
    assert p is not None
    assert p["name"] == "campaign-tracking"
    assert len(p["body"]) > 2000, (
        f"campaign-tracking body is only {len(p['body'])} bytes; "
        "expected several KB of workflow content"
    )
    assert p["description"], "description field didn't parse out of frontmatter"


def test_get_playbook_unknown_returns_none():
    from skills.cti_skills import get_playbook
    assert get_playbook("does-not-exist-anywhere") is None


def test_search_playbooks_ranks_mitre_at_top_for_mitre_query():
    """The `mitre-attack` playbook is the canonical MITRE methodology.
    If the search ranker doesn't surface it in the top-3 for a tight
    MITRE query, the scoring weights need a look.

    Not asserting #1 slot - 'mitre-attack' and 'control-coverage-
    mapping' both legitimately match MITRE-adjacent queries; the ranker
    picks between them based on which has more term overlap. Top-3 is
    the useful floor."""
    from skills.cti_skills import search_playbooks
    hits = search_playbooks("mitre enterprise attack dataset", limit=5)
    assert hits, "zero matches for a MITRE query"
    top3 = [h["name"] for h in hits[:3]]
    assert "mitre-attack" in top3, (
        f"expected mitre-attack in top-3; got {top3}. "
        f"full ranking: {[h['name'] for h in hits]}"
    )


def test_search_playbooks_returns_snippet():
    from skills.cti_skills import search_playbooks
    hits = search_playbooks("ransomware", limit=3)
    assert hits
    for h in hits:
        assert h["snippet"], f"empty snippet for {h['name']!r}"
        assert h["score"] > 0


def test_search_playbooks_empty_query_returns_empty_list():
    from skills.cti_skills import search_playbooks
    assert search_playbooks("") == []
    # Short queries (< 3 chars per term) have no terms to match on.
    assert search_playbooks("ab cd") == []


# ─── HTTP endpoints ────────────────────────────────────────────────────────

@pytest.fixture
def client():
    from main import app
    return TestClient(app)


def test_api_list_cti_skills(client):
    resp = client.get("/api/cti-skills")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["count"] >= 50
    assert isinstance(body["playbooks"], list)
    # Every entry has the fields the frontend expects.
    for pb in body["playbooks"][:5]:
        for field in ("name", "description", "user_invocable", "tags", "version"):
            assert field in pb, f"missing {field!r} on {pb}"


def test_api_search_cti_skills(client):
    resp = client.get("/api/cti-skills?q=ransomware&limit=3")
    assert resp.status_code == 200
    body = resp.json()
    assert body["query"] == "ransomware"
    assert isinstance(body["matches"], list)
    assert len(body["matches"]) <= 3


def test_api_get_cti_skill(client):
    resp = client.get("/api/cti-skills/campaign-tracking")
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "campaign-tracking"
    assert len(body["body"]) > 2000


def test_api_get_cti_skill_404(client):
    resp = client.get("/api/cti-skills/this-playbook-does-not-exist")
    assert resp.status_code == 404


def test_cti_skills_endpoint_is_public(client):
    """The cti-skills list is auth-free - the investigation agent
    shouldn't need to authenticate against its own backend just to
    retrieve its vendored playbook library."""
    # A GET with no cookie should succeed. TestClient doesn't carry
    # session state unless we set it, so this is effectively anonymous.
    resp = client.get("/api/cti-skills")
    assert resp.status_code != 401, (
        "cti-skills listing is behind auth wall - add to _PUBLIC_PREFIXES"
    )


# ─── Investigation agent tool wiring ───────────────────────────────────────

def test_cti_skill_search_tool_registered():
    """The tool schema list must include cti_skill_search so the model
    knows to call it. Without the schema entry the model can't invoke
    the dispatch function."""
    from agents.investigation_tools import TOOL_SCHEMAS
    names = {t["function"]["name"] for t in TOOL_SCHEMAS}
    assert "cti_skill_search" in names, (
        f"cti_skill_search not in tool schemas: {sorted(names)}"
    )


def test_cti_skill_search_dispatches_correctly():
    """The dispatcher must route the tool name to its handler. Without
    this wiring the model's tool calls return {'error': 'unknown tool'}
    and the whole feature is silently dead."""
    import asyncio
    from agents.investigation_tools import execute_tool
    result = asyncio.run(execute_tool(
        "cti_skill_search", {"query": "mitre attack"}, config={},
    ))
    assert isinstance(result, dict)
    assert "matches" in result, f"expected matches key in {result}"
    assert len(result["matches"]) > 0, (
        "cti_skill_search returned zero matches for 'mitre attack'; "
        "loader or search is broken"
    )

"""Loader + search over the vendored cti-skills playbook library.

The playbooks live under ./cti/<name>/SKILL.md and come from the
0xelikhan/cti-skills repo (see cti/README.md for provenance and
cti/LICENSE for terms). Each is a Claude Code skill: YAML frontmatter
(name, description, user-invocable, metadata) followed by a markdown
body that documents the analyst workflow.

Three public functions:
    list_playbooks()       -> list of {name, description, body_preview}
    get_playbook(name)     -> {name, description, body, metadata}
    search_playbooks(q)    -> ranked matches with context snippets

The search is a plain keyword-score over the frontmatter description +
first 2 KB of the body. Good enough for the investigation agent to
pick the right methodology to cite without pulling in a vector DB.
"""

from __future__ import annotations

import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

_log = logging.getLogger("recon.skills.cti_skills")


_CTI_DIR = Path(__file__).resolve().parent / "cti"

# Frontmatter is `---\n<yaml>\n---\n<body>` - split on the sentinel
# lines rather than pulling in PyYAML for a parser we only use once.
_FRONTMATTER_RE = re.compile(
    r"^---\s*\n(?P<yaml>.*?)\n---\s*\n(?P<body>.*)$", re.DOTALL,
)


def _parse_frontmatter(text: str) -> Dict[str, Any]:
    """Extract name/description/user_invocable + metadata from the YAML
    frontmatter. Hand-rolled - the skills use a tiny subset of YAML
    (string scalars + `metadata: {key: value}` dict) so the parse is a
    few regex matches rather than a full YAML dependency."""
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {"body": text, "frontmatter_raw": ""}

    yaml_block = m.group("yaml")
    body = m.group("body").strip()
    out: Dict[str, Any] = {"body": body, "frontmatter_raw": yaml_block}

    # Top-level scalar fields.
    for key in ("name", "description", "user-invocable"):
        rx = re.compile(rf"^{re.escape(key)}:\s*(.+?)$", re.MULTILINE)
        hit = rx.search(yaml_block)
        if hit:
            val = hit.group(1).strip().strip('"\'')
            if key == "user-invocable":
                out["user_invocable"] = val.lower() in ("true", "yes", "1")
            else:
                out[key.replace("-", "_")] = val

    # metadata.version / metadata.tags - both are useful filters.
    version = re.search(r"^\s{2}version:\s*(.+?)$", yaml_block, re.MULTILINE)
    if version:
        out["version"] = version.group(1).strip().strip('"\'')
    tags = re.search(r"^\s{2}tags:\s*\[(.+?)\]", yaml_block, re.MULTILINE)
    if tags:
        out["tags"] = [t.strip().strip('"\'') for t in tags.group(1).split(",")]
    return out


@lru_cache(maxsize=1)
def _all_playbooks() -> Dict[str, Dict[str, Any]]:
    """Walk ./cti/*/SKILL.md once and cache the parsed result. Cache
    key is empty - safe because the vendored library is read-only at
    runtime; a code change forces a process restart which clears it."""
    out: Dict[str, Dict[str, Any]] = {}
    if not _CTI_DIR.is_dir():
        _log.warning("cti skills dir missing: %s", _CTI_DIR)
        return out
    for skill_dir in sorted(_CTI_DIR.iterdir()):
        if not skill_dir.is_dir():
            continue
        skill_file = skill_dir / "SKILL.md"
        if not skill_file.is_file():
            continue
        try:
            text = skill_file.read_text(encoding="utf-8")
        except Exception as e:
            _log.warning("failed to read %s: %s", skill_file, e)
            continue
        parsed = _parse_frontmatter(text)
        # Fallback: directory name is authoritative for the slug if
        # the frontmatter omits `name:`.
        slug = parsed.get("name") or skill_dir.name
        parsed["slug"] = slug
        out[slug] = parsed
    return out


def list_playbooks() -> List[Dict[str, Any]]:
    """Light index - every playbook's slug + description. Used by the
    /api/cti-skills endpoint and the investigation agent's tool
    schema."""
    return [
        {
            "name":           p["slug"],
            "description":    p.get("description", ""),
            "user_invocable": p.get("user_invocable", False),
            "tags":           p.get("tags", []),
            "version":        p.get("version", ""),
        }
        for p in _all_playbooks().values()
    ]


def get_playbook(name: str) -> Optional[Dict[str, Any]]:
    """Return a playbook's full body + metadata. None when the slug
    doesn't exist (callers should surface a 404 rather than guess)."""
    p = _all_playbooks().get(name)
    if not p:
        return None
    return {
        "name":           p["slug"],
        "description":    p.get("description", ""),
        "body":           p.get("body", ""),
        "user_invocable": p.get("user_invocable", False),
        "tags":           p.get("tags", []),
        "version":        p.get("version", ""),
    }


def _score(query_terms: List[str], text: str) -> int:
    """Count how many query terms appear in text (case-insensitive).
    Each distinct term that lands is worth +1; repeated hits don't
    stack, so a playbook can't game the score by mentioning the same
    word many times. Returns the score."""
    low = text.lower()
    return sum(1 for t in query_terms if t and t in low)


def search_playbooks(query: str, limit: int = 5) -> List[Dict[str, Any]]:
    """Rank playbooks by keyword overlap with the query. Hits in the
    description count double (the description is the authored summary
    of when to use the skill - a very high-signal field). Returns up
    to `limit` matches with a context snippet from the body for each.

    No vector search - keyword overlap is sufficient for a 77-skill
    corpus and adds zero dependencies. If the corpus grows past a few
    hundred entries, swap this for a proper retriever."""
    terms = [t.lower() for t in re.findall(r"[A-Za-z0-9]+", query) if len(t) >= 3]
    if not terms:
        return []
    scored: List[Dict[str, Any]] = []
    for p in _all_playbooks().values():
        desc  = p.get("description", "")
        body  = p.get("body", "")[:2000]   # body is long - cap for scoring
        score = _score(terms, desc) * 2 + _score(terms, body)
        if score <= 0:
            continue
        scored.append({
            "name":           p["slug"],
            "description":    desc,
            "score":          score,
            "snippet":        _snippet_for(terms, body),
            "user_invocable": p.get("user_invocable", False),
            "tags":           p.get("tags", []),
        })
    scored.sort(key=lambda r: (-r["score"], r["name"]))
    return scored[:limit]


def _snippet_for(terms: List[str], body: str, radius: int = 120) -> str:
    """Pull a ~240-char window around the first term-hit in the body
    so the search result shows WHY it matched, not just that it did.
    Falls back to the body's leading sentence when no term hits."""
    low = body.lower()
    first = min(
        (low.find(t) for t in terms if low.find(t) >= 0),
        default=-1,
    )
    if first < 0:
        # No hit - this only runs for the description-only matches,
        # which score ≥ 2. Show the opening lines so the caller still
        # has context.
        return body[:240].strip() + ("…" if len(body) > 240 else "")
    start = max(0, first - radius)
    end   = min(len(body), first + radius)
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(body) else ""
    return prefix + body[start:end].strip() + suffix

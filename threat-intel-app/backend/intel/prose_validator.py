"""
Server-side prose validators for LLM-emitted investigation results.

Mechanical enforcement of the rules the prompt asks the model to follow.
The prompt is the first line of defence; this module is the second so
that bugs which slip past the prompt don't reach the analyst:

  1. Cross-field prose overlap — if `analysis_assessment` sentences
     paraphrase content already in `summary` / `confirmed_facts`, drop
     them. Replaces a frontend-only de-dup that ran AFTER the data left
     the server, so non-frontend consumers (MCP, email composer, API
     callers) didn't get the benefit.

  2. Schema-shape sanity — strip keys the prompt forbids the model
     from emitting (`log_correlation`, etc.) and coerce wrong-typed
     fields into the contract the rest of the platform reads. Same
     spirit as the em-dash strip that's been server-side for a while.

  3. Sentence-cap enforcement — `summary` is documented as MAX 2
     sentences; LLM ignores this when "feeling chatty". A regex-based
     cap brings it back to spec before the analyst sees a 5-sentence
     restatement of the log.

Never raises. Bad input -> input passed through unchanged.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, Iterable, List, Optional

_log = logging.getLogger("recon.prose_validator")


# Same token regex the frontend dropOverlapping uses — keeps the two
# implementations in semantic lock-step.
_TOKEN_RE = re.compile(r"[a-z0-9@.-]{4,}")


def _tokens(s: Optional[str]) -> set:
    if not s or not isinstance(s, str):
        return set()
    return set(_TOKEN_RE.findall(s.lower()))


def token_overlap(a: Optional[str], b: Optional[str]) -> float:
    """Jaccard-ish overlap on 4+ char tokens. 0..1. Mirrors the
    frontend `tokenOverlap` helper exactly."""
    sa = _tokens(a)
    sb = _tokens(b)
    if not sa or not sb:
        return 0.0
    inter = sum(1 for t in sa if t in sb)
    return inter / max(1, min(len(sa), len(sb)))


def drop_overlapping(candidates: Iterable[Any],
                      against: Any,
                      threshold: float = 0.5) -> List[Any]:
    """Drop entries from `candidates` whose token overlap with the
    `against` corpus is >= threshold. Falsy / non-string candidates are
    also dropped so the returned list is render-safe."""
    if not candidates:
        return []
    if isinstance(against, list):
        corpus = " ".join(s for s in against if isinstance(s, str))
    elif isinstance(against, str):
        corpus = against
    else:
        corpus = ""
    if not corpus:
        return [c for c in candidates if c]
    return [c for c in candidates
            if c and isinstance(c, str) and token_overlap(c, corpus) < threshold]


# ─── Sentence-cap enforcement ────────────────────────────────────────────
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z\"'(])")


def cap_sentences(text: Optional[str], max_sentences: int) -> str:
    """Trim text to at most `max_sentences` sentences. Splitter is the
    same conservative regex the email composer uses (only splits after
    .!? followed by whitespace + a capital / quote / paren) so we don't
    chop mid-abbreviation. Returns '' on empty input."""
    if not text or not isinstance(text, str):
        return ""
    sentences = _SENTENCE_SPLIT_RE.split(text.strip())
    if len(sentences) <= max_sentences:
        return text.strip()
    return " ".join(sentences[:max_sentences]).strip()


# ─── Schema-shape sanity ────────────────────────────────────────────────
# Keys the prompt explicitly forbids the model from emitting. If they
# show up anyway, strip them silently so downstream renderers don't get
# confused by data they were told to ignore.
_FORBIDDEN_KEYS = {
    "log_correlation",       # multi-log retired; alert is single-log
    "_raw_ai_response",      # leak from earlier debugging
}


def strip_forbidden_keys(result: Dict[str, Any]) -> Dict[str, Any]:
    """Remove keys the model isn't supposed to emit. Returns the same
    dict object (mutated in place + returned for chaining)."""
    if not isinstance(result, dict):
        return result
    for k in list(result.keys()):
        if k in _FORBIDDEN_KEYS:
            _log.debug("stripping forbidden key from AI result: %s", k)
            del result[k]
    return result


# ─── Public API: validate_investigation_result ──────────────────────────
def validate_investigation_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """Run every server-side validator over an investigation-stage AI
    result. Returns the same dict (mutated in place for performance —
    the agent already passes it through the em-dash strip which mutates
    too). Idempotent: running this twice produces the same output as
    once.

    Validators run in order:
      1. strip_forbidden_keys   - drop keys the prompt forbids
      2. cap summary at 2 sentences - the prompt asks for MAX 2 but the
         model often emits 4-5; cap it mechanically
      3. drop analysis_assessment sentences that overlap with summary
         or confirmed_facts (>= 50%% token overlap)
      4. drop key_findings entries that paraphrase confirmed_facts
      5. drop analyst_notes paragraphs that overlap with the summary

    Side note: this used to run only in the frontend. Promoting it to
    the server means the same de-dup applies to the MCP server, email
    composer, and any future API consumer - the prose is clean before
    it leaves this process.
    """
    if not isinstance(result, dict):
        return result

    strip_forbidden_keys(result)

    # 1. Hard cap summary at 2 sentences.
    summary = result.get("summary")
    if summary:
        capped = cap_sentences(summary, max_sentences=2)
        if capped != summary:
            _log.debug("capped summary from %d -> %d chars",
                       len(summary), len(capped))
        result["summary"] = capped

    # 2. Build the "already said" corpus to dedup downstream fields
    # against. summary + confirmed_facts is the ground truth.
    summary_text = result.get("summary") or ""
    confirmed    = result.get("confirmed_facts") or []
    corpus_a     = " ".join([summary_text] +
                            [s for s in confirmed if isinstance(s, str)])

    # 3. analysis_assessment must not paraphrase summary / confirmed_facts.
    aa = result.get("analysis_assessment")
    if isinstance(aa, list):
        kept = drop_overlapping(aa, corpus_a, threshold=0.5)
        if len(kept) != len(aa):
            _log.debug("dropped %d duplicate analysis_assessment sentences",
                       len(aa) - len(kept))
        result["analysis_assessment"] = kept

    # 4. key_findings must not restate confirmed_facts. Lower threshold
    # here (0.6) because key_findings are SHORT and naturally share more
    # tokens with confirmed_facts even when distinct.
    kf = result.get("key_findings")
    if isinstance(kf, list):
        confirmed_corpus = " ".join(s for s in confirmed if isinstance(s, str))
        if confirmed_corpus:
            kept = drop_overlapping(kf, confirmed_corpus, threshold=0.6)
            if len(kept) != len(kf):
                _log.debug("dropped %d duplicate key_findings",
                           len(kf) - len(kept))
            result["key_findings"] = kept

    # 5. analyst_notes is a string field; drop entirely if it overlaps
    # summary + analysis_assessment too much. The prompt says "emit
    # empty when nothing distinct to add".
    notes = result.get("analyst_notes")
    if notes and isinstance(notes, str):
        analysis_text = " ".join(result.get("analysis_assessment") or [])
        combined_corpus = summary_text + " " + analysis_text
        if token_overlap(notes, combined_corpus) >= 0.6:
            _log.debug("dropping analyst_notes (overlap >= 0.6 with summary+analysis)")
            result["analyst_notes"] = ""

    return result

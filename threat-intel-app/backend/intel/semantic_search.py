"""
Semantic search over RECON's 11 bundled detection corpora.

Lets analysts pull detection rules by natural-language description
("PowerShell encoded command launch from Office macro") instead of by
MITRE technique ID. Same corpora that match_detections consumes:

  Sigma, panther-analysis, Splunk security_content, MITRE CAR,
  OTRF ThreatHunter-Playbook, Sublime, Chronicle YARA-L, olafhartong,
  falco-rules, Stratus Red Team, ET Open + Snort.

Implementation notes:

  * Two-tier embedder. If sentence-transformers + a local MiniLM model
    are present, we use that (better quality). Otherwise we fall back
    to sklearn TfidfVectorizer with char-ngrams — strictly lexical
    semantic-LITE but useful when the operator hasn't downloaded the
    model. The query interface is identical.

  * Single FAISS-equivalent: a numpy ndarray of L2-normalised
    embeddings + a single matmul on query. The 11 corpora yield at most
    ~12-15k rule descriptions, so a dense matmul is faster than a
    FAISS index in this regime AND avoids the faiss-cpu dependency.

  * Index built lazily on first query; threading.Lock guards the build.
    Persisted in process memory only (no-persistence policy).

Public API:

  search(query: str, top_k=10, sources=None, min_score=0.0) ->
    list[dict] with shape:
      { source, title, id, description, techniques, score, ... }

  stats() -> dict (loaded flag, vector count, embedder backend, ...)
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, Iterable, List, Optional, Tuple

_log = logging.getLogger("recon.intel.semantic_search")


# Which corpus modules feed the index. Each entry is
# (source_label, module_path, list-attr-on-state).
# The corpus modules already expose a `_state["rules"]` (or equivalent)
# after their _ensure_loaded() runs — we re-use that to avoid re-parsing.
_CORPUS_SOURCES: List[Tuple[str, str]] = [
    ("sigma",           "intel.sigma_corpus"),
    ("panther",         "intel.panther_rules"),
    ("splunk",          "intel.splunk_content"),
    ("mitre_car",       "intel.mitre_car"),
    ("hunter_playbook", "intel.hunter_playbook"),
    ("sublime",         "intel.sublime_rules"),
    ("chronicle",       "intel.chronicle_rules"),
    ("olafhartong",     "intel.olafhartong_th"),
    ("falco",           "intel.falco_rules"),
    ("stratus",         "intel.stratus_techniques"),
    ("ids_rules",       "intel.ids_rules"),
]


_lock = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":       False,
    "items":        [],     # list[dict] — rule metadata
    "texts":        [],     # list[str]  — embedding inputs
    "embeddings":   None,   # numpy.ndarray [N x dim]
    "backend":      None,   # "sentence_transformers" | "tfidf" | None
    "model":        None,   # the embedder/vectorizer instance
    "dim":          0,
    "error":        None,
    "source_counts": {},
}


def _collect_rules() -> List[Dict[str, Any]]:
    """Pull a flat list of (source, rule_meta) across all 11 corpora.
    Each rule_meta is the same dict shape the corpus modules already
    return from match_by_techniques."""
    import importlib

    items: List[Dict[str, Any]] = []
    source_counts: Dict[str, int] = {}

    for source_label, module_path in _CORPUS_SOURCES:
        try:
            mod = importlib.import_module(module_path)
        except Exception as e:
            _log.debug("semantic_search: corpus %s not importable: %s",
                       source_label, e)
            source_counts[source_label] = 0
            continue
        # Trigger lazy load via the corpus's match_by_techniques (or
        # stats()) — either populates the _state dict.
        try:
            if hasattr(mod, "stats"):
                mod.stats()
            elif hasattr(mod, "_ensure_loaded"):
                mod._ensure_loaded()
        except Exception as e:
            _log.debug("semantic_search: corpus %s load failed: %s",
                       source_label, e)

        rules = []
        st = getattr(mod, "_state", None)
        if isinstance(st, dict):
            rules = st.get("rules") or st.get("items") or []
        if not isinstance(rules, list):
            rules = []

        added = 0
        for r in rules:
            if not isinstance(r, dict):
                continue
            title = (r.get("title") or r.get("name")
                     or r.get("id") or "").strip()
            if not title:
                continue
            desc       = (r.get("description") or r.get("summary") or "").strip()
            techniques = r.get("techniques") or r.get("attack_techniques") or []
            if not isinstance(techniques, list):
                techniques = []
            rule_id    = (r.get("id") or r.get("rule_id") or r.get("path") or "").strip()
            items.append({
                "source":      source_label,
                "title":       title,
                "id":          rule_id,
                "description": desc[:400],
                "techniques":  techniques[:20],
                "level":       r.get("level") or "",
                "path":        r.get("path") or "",
            })
            added += 1
        source_counts[source_label] = added

    _state["source_counts"] = source_counts
    return items


def _build_text_for(item: Dict[str, Any]) -> str:
    """Compose the embedding input for a rule. Title is the highest-
    signal field; description gives semantic context; technique IDs
    give a lexical bridge for the analyst who DOES know the ID."""
    parts = [
        item.get("title") or "",
        item.get("description") or "",
        " ".join(item.get("techniques") or []),
    ]
    return " | ".join(p for p in parts if p)[:512]


def _try_sentence_transformers(texts: List[str]) -> Optional[Tuple[Any, Any, str]]:
    """Try to embed with sentence-transformers. Returns (model, ndarray,
    backend_name) or None if unavailable or the model isn't cached."""
    try:
        from sentence_transformers import SentenceTransformer  # type: ignore
        import numpy as np  # noqa: F401
    except Exception as e:
        _log.info("sentence_transformers not installed (%s) — TF-IDF fallback", e)
        return None

    import os
    # Default model — small, fast, ~80MB. Operator can override via env.
    model_name = os.environ.get("RECON_EMBED_MODEL", "all-MiniLM-L6-v2")
    try:
        model = SentenceTransformer(model_name)
    except Exception as e:
        # Common case: no network / no cached model. Fall back gracefully.
        _log.info("SentenceTransformer load failed for %s (%s) — TF-IDF fallback",
                   model_name, e)
        return None
    try:
        emb = model.encode(texts, normalize_embeddings=True,
                            batch_size=64, show_progress_bar=False)
    except Exception as e:
        _log.warning("embedding failed: %s — TF-IDF fallback", e)
        return None
    return model, emb, "sentence_transformers"


def _try_tfidf(texts: List[str]) -> Optional[Tuple[Any, Any, str]]:
    """Fallback embedder: sklearn TfidfVectorizer (char + word n-grams).
    Lexical but useful — and dependency-free given sklearn is already
    in the round-14 baseline for the DGA/phish classifiers."""
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        import numpy as np
    except Exception as e:
        _log.warning("sklearn unavailable for TF-IDF fallback: %s", e)
        return None
    vec = TfidfVectorizer(
        analyzer="char_wb", ngram_range=(3, 5),
        max_features=20_000, sublinear_tf=True,
        lowercase=True,
    )
    X = vec.fit_transform(texts)
    # L2-normalise rows for cosine-via-dot.
    from sklearn.preprocessing import normalize
    Xn = normalize(X, norm="l2", axis=1, copy=False)
    return vec, Xn, "tfidf"


def _build_index() -> None:
    """Collect rules, build the embedding matrix, store in _state."""
    try:
        items = _collect_rules()
    except Exception as e:
        _state["error"] = f"collect_rules failed: {e}"
        _state["loaded"] = True
        return

    if not items:
        _state["loaded"] = True
        _state["items"]  = []
        _state["backend"] = None
        _state["error"]   = "no rules across all corpora"
        return

    texts = [_build_text_for(x) for x in items]

    built = _try_sentence_transformers(texts) or _try_tfidf(texts)
    if not built:
        _state["loaded"] = True
        _state["items"]  = items
        _state["error"]  = "no embedder available (install sentence-transformers or sklearn)"
        return

    model, embeddings, backend = built
    # For the sentence-transformers path embeddings is a dense ndarray;
    # for the sklearn path it's a sparse csr matrix. Both support .dot
    # and .shape, so downstream code stays unified.
    _state["items"]       = items
    _state["texts"]       = texts
    _state["embeddings"]  = embeddings
    _state["model"]       = model
    _state["backend"]     = backend
    _state["dim"]         = embeddings.shape[1] if hasattr(embeddings, "shape") else 0
    _state["loaded"]      = True
    _state["error"]       = None
    _log.info("semantic_search index built: %d rules, backend=%s, dim=%d",
              len(items), backend, _state["dim"])


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def _encode_query(query: str) -> Any:
    """Encode a query under the active backend. Returns a 1xD vector
    compatible with the stored embeddings (dense ndarray or csr sparse)."""
    backend = _state["backend"]
    model   = _state["model"]
    if backend == "sentence_transformers":
        return model.encode([query], normalize_embeddings=True,
                            show_progress_bar=False)
    # TF-IDF path
    from sklearn.preprocessing import normalize
    Xq = model.transform([query])
    return normalize(Xq, norm="l2", axis=1, copy=False)


def search(query: str,
           top_k: int = 10,
           sources: Optional[Iterable[str]] = None,
           min_score: float = 0.0) -> List[Dict[str, Any]]:
    """Return the top_k rules whose embedding is closest to `query`."""
    if not isinstance(query, str) or not query.strip():
        return []
    _ensure_loaded()
    if not _state["embeddings"] is not None and not _state["items"]:
        return []
    if _state["embeddings"] is None:
        return []

    items = _state["items"]
    embs  = _state["embeddings"]

    import numpy as np
    qvec = _encode_query(query.strip())

    # Cosine == dot product because we L2-normalised both sides.
    if hasattr(embs, "toarray"):
        # sparse @ sparse-transposed
        scores = (embs @ qvec.T).toarray().ravel()
    else:
        scores = (embs @ qvec.T).ravel()
    scores = np.asarray(scores, dtype=float)

    # Optional source filter (re-rank within the subset)
    if sources:
        wanted = {s.lower() for s in sources if isinstance(s, str)}
        mask = np.array([item["source"] in wanted for item in items])
        idxs = np.where(mask)[0]
    else:
        idxs = np.arange(len(items))

    if idxs.size == 0:
        return []

    # Score subset, find top-k.
    sub_scores = scores[idxs]
    order = np.argsort(-sub_scores)[: max(1, top_k)]
    out: List[Dict[str, Any]] = []
    for rank, j in enumerate(order, 1):
        idx   = int(idxs[j])
        score = float(sub_scores[j])
        if score < min_score:
            continue
        item = dict(items[idx])
        item["score"] = round(score, 4)
        item["rank"]  = rank
        out.append(item)
    return out


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":        bool(_state["loaded"]),
        "backend":       _state["backend"],
        "rule_count":    len(_state.get("items") or []),
        "dim":           _state.get("dim", 0),
        "source_counts": dict(_state.get("source_counts") or {}),
        "error":         _state.get("error"),
    }

"""
Unified threat-intel feed aggregator — spec §8.

Polls (1) public TAXII 2.1 servers and (2) a self-hosted FreshRSS instance via
the GReader API and keeps everything in an IN-MEMORY cache keyed by IOC
value.

Cadence (started by main.py at startup):
  TAXII feeds      — every 6 hours
  FreshRSS articles — every 30 minutes

The cache is NOT persisted to disk — analyst-derived correlations are
out of scope for the no-persistence policy. On restart the cache is
empty and refills on the next poll cycle.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

# Spec §8 TAXII 2.x feed configuration
TAXII_FEEDS = [
    {"name": "MITRE ATT&CK",   "url": "https://cti-taxii.mitre.org/taxii/",
     "collection_id": "95ecc380-afe9-11e4-9b6c-751b66dd541e",  "extract": False},
    {"name": "URLhaus",        "url": "https://urlhaus-api.abuse.ch/v1/taxii2/",
     "collection_id": None, "extract": True},
    {"name": "ThreatFox",      "url": "https://threatfox-api.abuse.ch/taxii2/",
     "collection_id": None, "extract": True},
    {"name": "Feodo Tracker",  "url": "https://feodotracker.abuse.ch/taxii2/",
     "collection_id": None, "extract": True},
]


# ─── In-memory cache (never persisted) ────────────────────────────────
_cache_state = {
    "iocs":   {},                    # ioc_value -> entry dict
    "articles": [],                  # last 100 FreshRSS articles
    "last_taxii_poll":   None,
    "last_freshrss_poll": None,
}


def _load_cache():
    # Kept as a no-op for the existing call sites — there is no disk
    # cache to lazy-load any more; everything lives in _cache_state.
    return


def _save_cache():
    # Persistence is intentionally disabled — see module docstring.
    # Trim articles to the last 100 here since the writer used to do it
    # and the rest of the code assumes the bound.
    _cache_state["articles"] = _cache_state["articles"][-100:]


# ─── Public lookup APIs ────────────────────────────────────────────────────────
def check_ioc(value: str) -> Optional[Dict]:
    """Fast O(1) lookup — returns the cached entry if this IOC was seen in any feed."""
    _load_cache()
    return _cache_state["iocs"].get(value)


def stats() -> Dict:
    _load_cache()
    by_source: Dict[str, int] = {}
    by_type: Dict[str, int]   = {}
    for entry in _cache_state["iocs"].values():
        s = entry.get("source", "unknown")
        by_source[s] = by_source.get(s, 0) + 1
        t = entry.get("type", "unknown")
        by_type[t]   = by_type.get(t, 0) + 1
    return {
        "total_iocs": len(_cache_state["iocs"]),
        "by_source":  by_source,
        "by_type":    by_type,
        "articles":   len(_cache_state["articles"]),
        "last_taxii_poll":    _cache_state["last_taxii_poll"],
        "last_freshrss_poll": _cache_state["last_freshrss_poll"],
    }


def list_iocs(source: Optional[str] = None, type_: Optional[str] = None,
              since_hours: Optional[int] = None, limit: int = 500) -> List[Dict]:
    _load_cache()
    out = []
    cutoff = None
    if since_hours:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    for entry in _cache_state["iocs"].values():
        if source and entry.get("source") != source:
            continue
        if type_ and entry.get("type") != type_:
            continue
        if cutoff:
            ts = entry.get("seen_at")
            try:
                if ts and datetime.fromisoformat(ts.replace("Z", "+00:00")) < cutoff:
                    continue
            except Exception:
                pass
        out.append(entry)
        if len(out) >= limit:
            break
    return out


def list_articles(limit: int = 50) -> List[Dict]:
    _load_cache()
    return _cache_state["articles"][-limit:][::-1]


# ─── TAXII polling ─────────────────────────────────────────────────────────────
async def _poll_taxii_feed(feed: Dict) -> List[Dict]:
    """Best-effort polling of one TAXII server. Returns parsed IOC entries."""
    out: List[Dict] = []
    try:
        from taxii2client.v21 import Server
    except ImportError:
        return out
    try:
        server = Server(feed["url"])
        api_root = server.api_roots[0]
        collections = api_root.collections
        target_id = feed.get("collection_id")
        coll = (next((c for c in collections if c.id == target_id), None)
                if target_id else (collections[0] if collections else None))
        if not coll:
            return out
        # Pull objects added in the last 7 days to keep payload manageable
        since = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
        objects = coll.get_objects(added_after=since, limit=2000).get("objects", [])
        for obj in objects:
            if obj.get("type") != "indicator":
                continue
            parsed = _parse_stix_indicator(obj)
            if not parsed:
                continue
            parsed["source"] = feed["name"]
            parsed["seen_at"] = datetime.now(timezone.utc).isoformat()
            out.append(parsed)
    except Exception as e:
        logger.warning("TAXII poll failed for %s: %s", feed["name"], e)
    return out


def _parse_stix_indicator(obj: Dict) -> Optional[Dict]:
    pattern = obj.get("pattern", "")
    if not pattern:
        return None
    rules = [
        (r"ipv4-addr:value\s*=\s*'([^']+)'",  "ip"),
        (r"ipv6-addr:value\s*=\s*'([^']+)'",  "ip"),
        (r"domain-name:value\s*=\s*'([^']+)'", "domain"),
        (r"url:value\s*=\s*'([^']+)'",         "url"),
        (r"file:hashes\.['\"]?(?:SHA-256|SHA-1|MD5)['\"]?\s*=\s*'([^']+)'", "hash"),
        (r"email-addr:value\s*=\s*'([^']+)'",  "email"),
    ]
    for rex, t in rules:
        m = re.search(rex, pattern, re.IGNORECASE)
        if m:
            value = m.group(1).lower() if t == "hash" else m.group(1)
            return {
                "value":     value,
                "type":      t,
                "stix_id":   obj.get("id"),
                "labels":    obj.get("labels") or [],
                "name":      obj.get("name"),
                "confidence": obj.get("confidence"),
                "valid_from": obj.get("valid_from"),
                "tags":      obj.get("indicator_types") or [],
            }
    return None


async def poll_taxii(force: bool = False) -> Dict:
    """Poll every TAXII feed in parallel, merge into cache, persist."""
    _load_cache()
    tasks = [_poll_taxii_feed(f) for f in TAXII_FEEDS]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    added = 0
    by_feed: Dict[str, int] = {}
    for feed, res in zip(TAXII_FEEDS, results):
        if isinstance(res, Exception):
            by_feed[feed["name"]] = f"error: {res}"
            continue
        by_feed[feed["name"]] = len(res)
        for entry in res:
            v = entry["value"]
            if v not in _cache_state["iocs"]:
                added += 1
            _cache_state["iocs"][v] = entry
    _cache_state["last_taxii_poll"] = datetime.now(timezone.utc).isoformat()
    _save_cache()
    return {"added": added, "by_feed": by_feed,
            "polled_at": _cache_state["last_taxii_poll"]}


# ─── FreshRSS polling ──────────────────────────────────────────────────────────
async def poll_freshrss(url: str, api_key: str) -> Dict:
    """Poll FreshRSS via the GReader API. Extracts IOCs from article titles +
    summaries, marks read after processing."""
    import aiohttp
    _load_cache()
    if not (url and api_key):
        return {"skipped": "FRESHRSS_URL/KEY not configured"}
    timeout = aiohttp.ClientTimeout(total=15)
    headers = {"Authorization": f"GoogleLogin auth={api_key}"}
    base = url.rstrip("/")
    unread_url = f"{base}/api/greader.php/reader/api/0/stream/contents/reading-list"
    mark_url   = f"{base}/api/greader.php/reader/api/0/edit-tag"
    added = 0
    articles_added = 0
    try:
        async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
            async with session.get(unread_url, params={"n": 50}) as r:
                if r.status != 200:
                    return {"error": f"HTTP {r.status}"}
                d = await r.json()
            items = d.get("items") or []
            ids_to_mark = []
            for item in items:
                title = (item.get("title") or "")[:200]
                body = (((item.get("summary") or {}).get("content") or
                         item.get("content", {}).get("content") or "")[:5000])
                source = ((item.get("origin") or {}).get("title") or "FreshRSS")
                published = item.get("published")
                # Look for AI-summary block convention: "AI summary: …"
                summary_match = re.search(r"AI summary:\s*([^\n]{0,500})", title + "\n" + body, re.IGNORECASE)
                ai_summary = summary_match.group(1).strip() if summary_match else None
                iocs = _extract_iocs_from_text(title + " " + body)
                article = {
                    "title":      title,
                    "source":     source,
                    "published":  published,
                    "url":        (item.get("canonical") or [{}])[0].get("href"),
                    "ai_summary": ai_summary,
                    "iocs":       iocs,
                }
                _cache_state["articles"].append(article)
                articles_added += 1
                for ioc in iocs:
                    v = ioc["value"]
                    if v not in _cache_state["iocs"]:
                        added += 1
                    _cache_state["iocs"][v] = {
                        **ioc,
                        "source":     f"FreshRSS · {source}",
                        "seen_at":    datetime.now(timezone.utc).isoformat(),
                        "from_article": title,
                    }
                if item.get("id"):
                    ids_to_mark.append(item["id"])
            # Mark as read (best effort)
            for iid in ids_to_mark:
                try:
                    async with session.post(mark_url, data={
                        "i": iid,
                        "a": "user/-/state/com.google/read",
                    }):
                        pass
                except Exception:
                    pass
    except Exception as e:
        return {"error": str(e)}

    _cache_state["last_freshrss_poll"] = datetime.now(timezone.utc).isoformat()
    _save_cache()
    return {"articles": articles_added, "iocs_added": added,
            "polled_at": _cache_state["last_freshrss_poll"]}


_IOC_PATTERNS = [
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "ip"),
    (re.compile(r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b", re.IGNORECASE), "domain"),
    (re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE), "hash"),  # sha256
    (re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE), "hash"),  # sha1
    (re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE), "hash"),  # md5
]
_NOISE_DOMAINS = {"twitter.com", "github.com", "google.com", "microsoft.com",
                  "example.com", "youtube.com", "facebook.com"}


def _extract_iocs_from_text(text: str) -> List[Dict]:
    out, seen = [], set()
    for rex, t in _IOC_PATTERNS:
        for m in rex.findall(text):
            v = m if isinstance(m, str) else m[0]
            v_l = v.lower()
            if v_l in seen:
                continue
            # skip obvious noise
            if t == "domain" and v_l in _NOISE_DOMAINS:
                continue
            seen.add(v_l)
            out.append({"value": v if t != "hash" else v_l, "type": t})
    return out


# ─── Background scheduler (started by main.py) ─────────────────────────────────
async def run_polling_loop(get_config):
    """asyncio task: poll TAXII every 6h, FreshRSS every 30min. get_config is a
    callable returning the current config dict so key rotations are picked up."""
    while True:
        cfg = get_config() or {}
        last_t = _cache_state.get("last_taxii_poll")
        last_r = _cache_state.get("last_freshrss_poll")
        now    = datetime.now(timezone.utc)

        def _hours_since(ts):
            if not ts:
                return float("inf")
            try:
                return (now - datetime.fromisoformat(ts.replace("Z", "+00:00"))).total_seconds() / 3600
            except Exception:
                return float("inf")

        if _hours_since(last_t) >= 6:
            try:
                r = await poll_taxii()
                logger.info("[feeds] TAXII poll: %s", r)
            except Exception as e:
                logger.warning("TAXII poll error: %s", e)

        if _hours_since(last_r) * 60 >= 30:
            url = cfg.get("FRESHRSS_URL", "")
            key = cfg.get("FRESHRSS_API_KEY", "")
            if url and key:
                try:
                    r = await poll_freshrss(url, key)
                    logger.info("[feeds] FreshRSS poll: %s", r)
                except Exception as e:
                    logger.warning("FreshRSS poll error: %s", e)

        # Sleep 5 minutes between scheduler checks
        await asyncio.sleep(300)

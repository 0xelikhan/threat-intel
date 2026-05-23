"""
Azure Cosmos DB Cache — Lean Edition
TTLs: enrichment cache 24h, history 7 days.
Max 25 stored runs to keep Cosmos costs low for a shared team account.
Falls back to in-memory when Cosmos is not configured.
"""

import json
import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

_mem_cache:   dict = {}
_history:     list = []
_results:     dict = {}
_cache_container   = None
_history_container = None
_cosmos_ready      = False


def _init():
    global _cache_container, _history_container, _cosmos_ready
    if _cosmos_ready:
        return True
    from config import config
    conn = config.get("COSMOS_CONNECTION")
    if not conn:
        return False
    try:
        from azure.cosmos import CosmosClient
        client = CosmosClient.from_connection_string(conn)
        db = client.get_database_client("ThreatIntel")
        _cache_container   = db.get_container_client("EnrichmentCache")
        _history_container = db.get_container_client("AnalysisHistory")
        _cosmos_ready = True
        logger.info("Cosmos DB connected")
        return True
    except Exception as e:
        logger.warning(f"Cosmos unavailable, using in-memory: {e}")
        return False


def _ck(ioc_type: str, value: str) -> str:
    return f"{ioc_type}:{hashlib.md5(value.encode()).hexdigest()}"


# ─── ENRICHMENT CACHE (24h TTL) ───────────────────────────────────────
def cache_get(key: str) -> Optional[dict]:
    if key in _mem_cache:
        return _mem_cache[key]
    if not _init():
        return None
    try:
        item = _cache_container.read_item(item=key, partition_key=key.split(":")[0])
        data = item.get("data")
        if data:
            _mem_cache[key] = data
        return data
    except Exception:
        return None


def cache_set(key: str, data: dict):
    _mem_cache[key] = data
    if not _init():
        return
    try:
        _cache_container.upsert_item({
            "id":      key,
            "iocType": key.split(":")[0],
            "data":    data,
            "ttl":     86400,   # 24 hours
        })
    except Exception as e:
        logger.debug(f"cache_set: {e}")


# ─── ANALYSIS HISTORY (7-day TTL, max 25 runs) ────────────────────────
MAX_HISTORY = 25


def history_add(run_id: str, summary: dict, full_result: dict):
    """Store run. Evicts oldest when over MAX_HISTORY."""
    _results[run_id] = full_result
    _history.append(summary)

    # Keep in-memory list bounded
    if len(_history) > MAX_HISTORY:
        evicted = _history.pop(0)
        _results.pop(evicted.get("runId", ""), None)

    if not _init():
        return
    try:
        # Enforce cap in Cosmos too — delete oldest if over limit
        existing = list(_history_container.query_items(
            query="SELECT c.id FROM c ORDER BY c._ts ASC OFFSET 0 LIMIT 100",
            partition_key="default"
        ))
        if len(existing) >= MAX_HISTORY:
            for old in existing[:len(existing) - MAX_HISTORY + 1]:
                try:
                    _history_container.delete_item(item=old["id"], partition_key="default")
                except Exception:
                    pass

        _history_container.upsert_item({
            "id":        run_id,
            "tenantId":  "default",
            "summary":   summary,
            "result":    {k: v for k, v in full_result.items() if k != "stix_bundle"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ttl":       604800,   # 7 days
        })
    except Exception as e:
        logger.debug(f"history_add: {e}")


def history_list(limit: int = MAX_HISTORY) -> list:
    if _init():
        try:
            items = list(_history_container.query_items(
                query=f"SELECT c.id, c.summary, c.timestamp FROM c ORDER BY c._ts DESC OFFSET 0 LIMIT {limit}",
                partition_key="default"
            ))
            return [i.get("summary", {}) | {"runId": i["id"]} for i in items]
        except Exception as e:
            logger.debug(f"history_list: {e}")
    return list(reversed(_history[-limit:]))


def results_get(run_id: str) -> Optional[dict]:
    if run_id in _results:
        return _results[run_id]
    if not _init():
        return None
    try:
        item = _history_container.read_item(item=run_id, partition_key="default")
        result = item.get("result")
        if result:
            _results[run_id] = result
        return result
    except Exception:
        return None

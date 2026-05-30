"""
TAXII Poller — pulls STIX 2.1 IOC bundles from public TAXII feeds.
Designed to run as a scheduled job (cron or Azure Function timer trigger).
Free public feeds included. Add credentials for commercial feeds.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone, timedelta
from taxii2client.v21 import Server

logger = logging.getLogger(__name__)

# ─── FREE PUBLIC TAXII FEEDS ─────────────────────────────────────────────────────
FEEDS = [
    {
        "name": "MITRE ATT&CK",
        "url": "https://cti-taxii.mitre.org/taxii/",
        "collection_id": "95ecc380-afe9-11e4-9b6c-751b66dd541e",
        "auth": None,
        "description": "MITRE ATT&CK enterprise techniques and groups"
    },
    {
        "name": "Anomali Limo (community)",
        "url": "https://limo.anomali.com/api/v1/taxii2/feeds/",
        "collection_id": "107",
        "auth": ("guest", "guest"),
        "description": "Community threat intelligence feed"
    },
    {
        "name": "CISA AIS",
        "url": "https://ais2.cisa.dhs.gov/taxii2/",
        "collection_id": None,  # Enumerate on connect
        "auth": None,           # Requires CISA AIS enrollment
        "description": "CISA Automated Indicator Sharing — requires free enrollment"
    },
]

# IOC types we care about extracting from STIX objects
EXTRACTABLE_TYPES = {
    "indicator",
    "malware",
    "threat-actor",
    "attack-pattern",
    "campaign",
}


# ─── STIX OBJECT PARSER ──────────────────────────────────────────────────────────
def parse_stix_indicator(obj: dict) -> dict | None:
    """Extract IOC data from a STIX 2.1 indicator object."""
    pattern = obj.get("pattern", "")
    ioc_value = None
    ioc_type = None

    if "ipv4-addr:value" in pattern:
        import re
        m = re.search(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern)
        if m:
            ioc_value = m.group(1)
            ioc_type = "ip"
    elif "domain-name:value" in pattern:
        import re
        m = re.search(r"domain-name:value\s*=\s*'([^']+)'", pattern)
        if m:
            ioc_value = m.group(1)
            ioc_type = "domain"
    elif "url:value" in pattern:
        import re
        m = re.search(r"url:value\s*=\s*'([^']+)'", pattern)
        if m:
            ioc_value = m.group(1)
            ioc_type = "url"
    elif "file:hashes" in pattern:
        import re
        m = re.search(r"file:hashes\.['\"]?(?:SHA-256|SHA-1|MD5)['\"]?\s*=\s*'([^']+)'", pattern, re.IGNORECASE)
        if m:
            ioc_value = m.group(1).lower()
            ioc_type = "hash"
    elif "email-message:from_ref.value" in pattern or "email-addr:value" in pattern:
        import re
        m = re.search(r"email-addr:value\s*=\s*'([^']+)'", pattern)
        if m:
            ioc_value = m.group(1).lower()
            ioc_type = "email"

    if not ioc_value:
        return None

    return {
        "value": ioc_value,
        "type": ioc_type,
        "stix_id": obj.get("id"),
        "name": obj.get("name", ""),
        "description": obj.get("description", ""),
        "labels": obj.get("labels", []),
        "confidence": obj.get("confidence"),
        "valid_from": obj.get("valid_from"),
        "created": obj.get("created"),
        "source": obj.get("created_by_ref", "unknown"),
    }


# ─── FEED POLLER ─────────────────────────────────────────────────────────────────
async def poll_feed(feed: dict, since: datetime | None = None) -> list[dict]:
    """Poll a single TAXII feed and return parsed IOCs."""
    iocs = []

    try:
        if feed.get("auth"):
            server = Server(feed["url"], user=feed["auth"][0], password=feed["auth"][1])
        else:
            server = Server(feed["url"])

        # Get API root and collection
        api_root = server.api_roots[0]
        collections = api_root.collections

        target_id = feed.get("collection_id")
        if target_id:
            collection = next((c for c in collections if c.id == target_id), None)
        else:
            collection = collections[0] if collections else None

        if not collection:
            logger.warning(f"No collection found for feed: {feed['name']}")
            return []

        # Build filter kwargs
        kwargs = {"limit": 1000}
        if since:
            kwargs["added_after"] = since.strftime("%Y-%m-%dT%H:%M:%SZ")

        objects = collection.get_objects(**kwargs).get("objects", [])

        for obj in objects:
            if obj.get("type") == "indicator":
                parsed = parse_stix_indicator(obj)
                if parsed:
                    parsed["feed"] = feed["name"]
                    iocs.append(parsed)

        logger.info(f"Polled {feed['name']}: {len(objects)} objects, {len(iocs)} IOCs extracted")

    except Exception as e:
        logger.error(f"Failed to poll {feed['name']}: {e}")

    return iocs


async def poll_all_feeds(since_hours: int = 24) -> dict:
    """Poll all configured feeds and return aggregated results."""
    since = datetime.now(timezone.utc) - timedelta(hours=since_hours)

    tasks = [poll_feed(feed, since) for feed in FEEDS if feed.get("url")]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_iocs = []
    feed_stats = {}
    for feed, result in zip(FEEDS, results):
        if isinstance(result, list):
            all_iocs.extend(result)
            feed_stats[feed["name"]] = len(result)
        else:
            feed_stats[feed["name"]] = f"error: {result}"

    # Deduplicate by value
    seen = set()
    unique_iocs = []
    for ioc in all_iocs:
        if ioc["value"] not in seen:
            seen.add(ioc["value"])
            unique_iocs.append(ioc)

    return {
        "iocs": unique_iocs,
        "total": len(unique_iocs),
        "by_type": {
            t: len([i for i in unique_iocs if i["type"] == t])
            for t in ["ip", "domain", "url", "hash", "email"]
        },
        "by_feed": feed_stats,
        "polled_at": datetime.now(timezone.utc).isoformat(),
        "since": since.isoformat()
    }


# ─── MISP CSV PARSER ─────────────────────────────────────────────────────────────
def parse_misp_csv(filepath: str) -> list[dict]:
    """
    Parse a MISP attribute CSV export.
    MISP CSV columns: uuid, event_id, category, type, value, comment, to_ids, date, object_relation
    """
    import csv

    MISP_TYPE_MAP = {
        "ip-src": "ip", "ip-dst": "ip", "ip-src|port": "ip",
        "domain": "domain", "hostname": "domain", "domain|ip": "domain",
        "url": "url", "link": "url",
        "md5": "hash", "sha1": "hash", "sha256": "hash",
        "sha512": "hash", "malware-sample": "hash",
        "email-src": "email", "email-dst": "email"
    }

    iocs = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                misp_type = row.get("type", "").lower()
                ioc_type = MISP_TYPE_MAP.get(misp_type)
                if not ioc_type:
                    continue

                value = row.get("value", "").strip()
                if not value:
                    continue

                # Handle compound types like domain|ip
                if "|" in value and "|" in misp_type:
                    value = value.split("|")[0]

                iocs.append({
                    "value": value,
                    "type": ioc_type,
                    "source": "MISP",
                    "event_id": row.get("event_id"),
                    "category": row.get("category"),
                    "comment": row.get("comment", ""),
                    "to_ids": row.get("to_ids", "").lower() == "1",
                    "date": row.get("date"),
                    "uuid": row.get("uuid")
                })
    except Exception as e:
        logger.error(f"MISP CSV parse error: {e}")

    return iocs


def parse_misp_json(filepath: str) -> list[dict]:
    """Parse a MISP JSON export (full event export format)."""
    MISP_TYPE_MAP = {
        "ip-src": "ip", "ip-dst": "ip",
        "domain": "domain", "hostname": "domain",
        "url": "url",
        "md5": "hash", "sha1": "hash", "sha256": "hash", "sha512": "hash",
        "email-src": "email", "email-dst": "email"
    }

    iocs = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        events = data if isinstance(data, list) else [data]
        for event in events:
            event_data = event.get("Event", event)
            attributes = event_data.get("Attribute", [])
            for attr in attributes:
                ioc_type = MISP_TYPE_MAP.get(attr.get("type", "").lower())
                if not ioc_type:
                    continue
                value = attr.get("value", "").strip()
                if not value:
                    continue
                iocs.append({
                    "value": value,
                    "type": ioc_type,
                    "source": "MISP",
                    "event_id": event_data.get("id"),
                    "event_info": event_data.get("info"),
                    "category": attr.get("category"),
                    "comment": attr.get("comment", ""),
                    "to_ids": attr.get("to_ids", False),
                    "date": attr.get("timestamp"),
                    "uuid": attr.get("uuid")
                })
    except Exception as e:
        logger.error(f"MISP JSON parse error: {e}")

    return iocs


# ─── STANDALONE RUN ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    async def main():
        logger.info("Polling TAXII feeds (last 24h)...")
        result = await poll_all_feeds(since_hours=24)
        logger.info("Total unique IOCs: %d", result['total'])
        logger.info("By type: %s", result['by_type'])
        logger.info("By feed: %s", result['by_feed'])

        # Save to JSON for inspection
        with open("taxii_results.json", "w") as f:
            json.dump(result, f, indent=2)
        logger.info("Results saved to taxii_results.json")

    asyncio.run(main())

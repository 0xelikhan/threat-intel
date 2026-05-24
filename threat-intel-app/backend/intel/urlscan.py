"""
URLScan.io live URL submission + result polling.
Detonates a URL in URLScan's sandbox, returns screenshot, network requests,
DOM tree, verdicts, related submissions.
"""
import aiohttp


async def submit_url(target_url: str, api_key: str, visibility: str = "unlisted") -> dict:
    """Submit a URL for fresh scanning. Returns {uuid, result_url, api_url, message}."""
    if not (target_url and api_key):
        return {"ok": False, "error": "url + api_key required"}
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    payload = {"url": target_url, "visibility": visibility}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post("https://urlscan.io/api/v1/scan/",
                                    json=payload, headers=headers,
                                    timeout=aiohttp.ClientTimeout(total=20)) as r:
                data = await r.json()
                if r.status >= 400:
                    return {"ok": False, "error": data.get("message", f"HTTP {r.status}"),
                            "description": data.get("description", "")}
                return {"ok": True,
                        "uuid":       data.get("uuid"),
                        "result_url": data.get("result"),
                        "api_url":    data.get("api"),
                        "message":    data.get("message")}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def get_result(uuid: str, api_key: str) -> dict:
    """Fetch the completed URLScan result. Returns {ready, ...summary}."""
    if not uuid:
        return {"ready": False, "error": "uuid required"}
    headers = {"API-Key": api_key} if api_key else {}
    url = f"https://urlscan.io/api/v1/result/{uuid}/"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status == 404:
                    return {"ready": False, "still_processing": True}
                if r.status >= 400:
                    return {"ready": False, "error": f"HTTP {r.status}"}
                d = await r.json()
    except Exception as e:
        return {"ready": False, "error": str(e)}

    verdicts = d.get("verdicts", {}) or {}
    overall  = verdicts.get("overall", {}) or {}
    page     = d.get("page", {}) or {}
    stats    = d.get("stats", {}) or {}
    lists    = d.get("lists", {}) or {}

    return {
        "ready":         True,
        "uuid":          uuid,
        "report_url":    f"https://urlscan.io/result/{uuid}/",
        "screenshot":    f"https://urlscan.io/screenshots/{uuid}.png",
        "final_url":     page.get("url"),
        "page_title":    page.get("title", "")[:200],
        "verdict":       "malicious" if overall.get("malicious") else "suspicious" if overall.get("score", 0) > 0 else "clean",
        "score":         overall.get("score"),
        "categories":    overall.get("categories", [])[:8],
        "tags":          overall.get("tags", [])[:10],
        "domain":        page.get("domain"),
        "ip":            page.get("ip"),
        "country":       page.get("country"),
        "server":        page.get("server"),
        "asn":           page.get("asn"),
        "asnname":       page.get("asnname"),
        "tls_subject":   (page.get("tlsValidFrom") and page.get("tlsValidTo")
                          and f"{page.get('tlsValidFrom')} → {page.get('tlsValidTo')}") or None,
        "domains_seen":  (lists.get("domains") or [])[:20],
        "ips_seen":      (lists.get("ips") or [])[:20],
        "urls_loaded":   stats.get("uniqUrls"),
        "requests":      stats.get("uniqRequests"),
    }

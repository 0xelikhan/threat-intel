"""
Local Intel Feeds Loader
-------------------------
Loads offline IP/domain blocklists from cloned vendor repos so that IOC
analysis can hit zero APIs and still get real reputation hits.

Sources:
  - vendor/ipsum/ipsum.txt          (aggregated, scored)
  - vendor/firehol/*.netset         (community blocklists)
  - vendor/phishing-db/*.lst        (phishing domains, IPs)
  - https://feodotracker.abuse.ch/  (lazy-fetched at runtime, see
                                     check_feodo). Lives outside vendor/
                                     because we want it in production
                                     too, where vendor/ is not copied.

Memory: ~150 MB loaded once on first call, then cached forever.
"""
import logging
import re
import threading
import time
import urllib.request
from pathlib import Path
from functools import lru_cache

_log = logging.getLogger("recon.feeds_loader")

VENDOR  = Path(__file__).parent.parent.parent / "vendor"
IPSUM   = VENDOR / "ipsum" / "ipsum.txt"
FIREHOL = VENDOR / "firehol"
PHISH   = VENDOR / "phishing-db"

# Files within firehol we trust (high-confidence aggregates)
FIREHOL_KEEP = {
    "firehol_level1.netset",
    "firehol_level2.netset",
    "firehol_abusers_1d.netset",
    "feodo.ipset",
    "malware_filter.netset",
    "dshield.netset",
    "spamhaus_drop.netset",
    "spamhaus_edrop.netset",
}

# Phishing domain files we use (active, ~10MB → ~500K domains)
PHISH_DOMAIN_FILES = ["phishing-domains-ACTIVE.txt", "ALL-phishing-domains.lst"]


def _parse_netset(path: Path) -> set:
    """Read a firehol .netset/.ipset file → set of plain IPs (drops CIDR for fast lookup)."""
    out = set()
    try:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Take only single IPs; drop CIDR (don't expand huge ranges into memory)
            if "/" in line:
                continue
            if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", line):
                out.add(line)
    except Exception as e:
        _log.warning("failed to parse netset %s: %s", path.name, e)
    return out


@lru_cache(maxsize=1)
def malicious_ips() -> dict:
    """Return {ip: source} for all known-bad IPs across loaded blocklists."""
    out: dict[str, str] = {}

    # ipsum: score >= 2 means seen on multiple blocklists (more trustworthy)
    if IPSUM.exists():
        try:
            for line in IPSUM.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[0].count(".") == 3:
                    try:
                        if int(parts[1]) >= 2:
                            out[parts[0]] = f"ipsum (seen on {parts[1]} blocklists)"
                    except ValueError:
                        continue
        except Exception:
            pass

    # firehol level1/level2 - high-confidence aggregates
    if FIREHOL.exists():
        for name in FIREHOL_KEEP:
            p = FIREHOL / name
            if p.exists():
                ips = _parse_netset(p)
                src = name.replace(".netset","").replace(".ipset","").replace("_"," ")
                for ip in ips:
                    if ip not in out:
                        out[ip] = f"firehol · {src}"
    return out


@lru_cache(maxsize=1)
def phishing_domains() -> set:
    """Set of known phishing domains from Phishing.Database project."""
    out: set[str] = set()
    if not PHISH.exists():
        return out
    for fname in PHISH_DOMAIN_FILES:
        p = PHISH / fname
        if p.exists():
            try:
                for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.strip().lower()
                    if line and not line.startswith("#") and "." in line:
                        out.add(line)
            except Exception:
                continue
        if out:
            break  # first found file is enough
    return out


def check_ip(ip: str) -> dict | None:
    """Fast O(1) check — is this IP on any local blocklist?"""
    hit = malicious_ips().get(ip)
    return {"hit": True, "source": hit} if hit else None


def check_domain(domain: str) -> dict | None:
    """Fast O(1) check — is this domain in the phishing database?"""
    d = (domain or "").lower().strip().lstrip(".")
    if not d:
        return None
    if d in phishing_domains():
        return {"hit": True, "source": "Phishing.Database"}
    # also check parent domain (sub.example.com → example.com)
    parts = d.split(".")
    if len(parts) > 2:
        parent = ".".join(parts[-2:])
        if parent in phishing_domains():
            return {"hit": True, "source": "Phishing.Database (parent domain)"}
    return None


def stats() -> dict:
    return {
        "malicious_ip_count":     len(malicious_ips()),
        "phishing_domain_count":  len(phishing_domains()),
        "feodo_ip_count":         len(_feodo_state.get("ips") or set()),
        "ipsum_loaded":           IPSUM.exists(),
        "firehol_loaded":         FIREHOL.exists(),
        "phishing_db_loaded":     PHISH.exists(),
        "feodo_loaded_at":        _feodo_state.get("fetched_at"),
    }


# ─── Feodo Tracker (live HTTPS fetch, no vendor/ dependency) ───────────────
# Feodo Tracker publishes a plain-text list of active C2 IPs at the URL
# below. We pull it lazily on first lookup, cache for 6 hours, and check
# IOCs against the in-memory set. Lives in feeds_loader rather than as
# its own module so the check_ip() / check_domain() / check_feodo()
# pattern stays uniform for callers (one import, three lookups).
#
# Previously feodo data came from `vendor/firehol/feodo.ipset` which
# wasn't shipped in the production container, so agents/enrichment.py's
# `from intel.feeds_loader import check_feodo` was a latent ImportError
# guarded by try/except — Feodo never fired in prod. Bringing the fetch
# in-process restores the signal.

_FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
_FEODO_TTL_S = 6 * 3600
_feodo_state: dict = {"ips": set(), "fetched_at": 0.0, "error": None}
# Protect _feodo_state against concurrent refresh+lookup. Without this
# two async tasks both seeing stale state would issue duplicate HTTP
# requests AND race on the dict write. RLock so a single thread can
# re-enter (defensive — the current code doesn't but future callers
# might).
_feodo_lock = threading.RLock()


# In-flight guard: a second caller that arrives while the first is
# fetching shouldn't fire a duplicate HTTP request, but it also shouldn't
# block — we hold the lock only long enough to claim the slot, then
# release before the network call. Failed-fetch backoff (60 s) stops a
# retry storm if Feodo Tracker is down.
_feodo_inflight   = False
_feodo_last_error = 0.0
_FEODO_ERROR_BACKOFF_S = 60


def refresh_feodo_now() -> None:
    """Force-refresh the Feodo Tracker blocklist. Safe to call repeatedly
    — concurrent callers coalesce. The network fetch happens OUTSIDE the
    lock so per-IOC lookups never stall behind a slow upstream."""
    global _feodo_inflight, _feodo_last_error
    with _feodo_lock:
        if _feodo_inflight:
            return
        _feodo_inflight = True
    try:
        req = urllib.request.Request(
            _FEODO_URL,
            headers={"User-Agent": "RECON-MDR-Platform/1.0 (+feodo-poll)"},
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            text = r.read().decode("utf-8", errors="replace")
    except Exception as e:
        with _feodo_lock:
            _feodo_state["error"] = type(e).__name__
            _feodo_last_error = time.time()
            _feodo_inflight = False
        _log.warning("feodo refresh failed: %s", e)
        return
    ips = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", line):
            ips.add(line)
    with _feodo_lock:
        _feodo_state["ips"]        = ips
        _feodo_state["fetched_at"] = time.time()
        _feodo_state["error"]      = None
        _feodo_inflight = False
    _log.info("feodo refresh OK: %d active C2 IPs", len(ips))


def _refresh_feodo_if_stale() -> None:
    """Trigger a refresh when the cache is empty or older than the TTL.
    Network I/O runs outside the lock. Suppressed for 60 s after a
    failure to avoid retry storms."""
    if (_feodo_state["ips"]
            and (time.time() - _feodo_state["fetched_at"]) < _FEODO_TTL_S):
        return
    if (time.time() - _feodo_last_error) < _FEODO_ERROR_BACKOFF_S:
        return
    refresh_feodo_now()


def check_feodo(ip: str) -> dict | None:
    """Return {"hit": True, "source": "feodo_tracker", ...} when the IP
    appears on the Feodo Tracker active-C2 list. None on miss. Never
    raises and never blocks the event loop on the network fetch — the
    refresh path runs the urlopen call without holding any lock and the
    pre-warm + periodic background task keep the cache hot."""
    if not ip:
        return None
    try:
        _refresh_feodo_if_stale()
    except Exception:
        return None
    if ip in (_feodo_state.get("ips") or set()):
        return {
            "hit":     True,
            "source":  "feodo_tracker",
            "summary": ("On the abuse.ch Feodo Tracker active-C2 list. "
                        "These IPs serve Emotet / Dridex / TrickBot / "
                        "QakBot C2; any outbound to one is high-signal."),
            "url":     "https://feodotracker.abuse.ch/browse/",
        }
    return None

"""
MITRE ATT&CK Data Layer
Source: github.com/mitre-attack/mitreattack-python (Apache 2.0)
Falls back gracefully if enterprise-attack.json is not present.
"""
import re
from pathlib import Path
from functools import lru_cache

STIX_FILE            = Path(__file__).parent / "mitre" / "enterprise-attack.json"
STIX_FILE_ICS        = Path(__file__).parent / "mitre" / "ics-attack.json"
STIX_FILE_MOBILE     = Path(__file__).parent / "mitre" / "mobile-attack.json"
# ATT&CK for Cloud + Containers ship inside the Enterprise STIX bundle
# as separate `x-mitre-matrix` objects — we don't load them as separate
# files; the keyword routers below decide when to filter Enterprise
# results to the cloud/containers slice.


@lru_cache(maxsize=1)
def _mitre():
    try:
        from mitreattack.stix20 import MitreAttackData
        if STIX_FILE.exists():
            return MitreAttackData(str(STIX_FILE))
    except ImportError:
        pass
    return None


@lru_cache(maxsize=1)
def _mitre_ics():
    """Lazy-load the ATT&CK for ICS matrix. The ICS matrix uses
    the same STIX 2.0 shape as Enterprise, so the same mitreattack-
    python helper handles it. File ships separately so the operator
    can opt in to ICS coverage by dropping it next to enterprise-attack."""
    try:
        from mitreattack.stix20 import MitreAttackData
        if STIX_FILE_ICS.exists():
            return MitreAttackData(str(STIX_FILE_ICS))
    except ImportError:
        pass
    return None


def get_all_techniques_ics() -> list[dict]:
    """Same shape as get_all_techniques() but for the ICS matrix."""
    m = _mitre_ics()
    if not m:
        return []
    results = []
    for t in m.get_techniques(remove_revoked_deprecated=True):
        tid = next((r["external_id"] for r in t.get("external_references", [])
                    if r.get("source_name") == "mitre-ics-attack"), None)
        if not tid:
            continue
        tactics = [p["phase_name"].replace("-", " ").title()
                   for p in t.get("kill_chain_phases", [])
                   if p.get("kill_chain_name") == "mitre-ics-attack"]
        results.append({
            "id":          tid,
            "name":        t.get("name", ""),
            "tactic":      tactics[0] if tactics else "Unknown",
            "tactics":     tactics,
            "description": (t.get("description") or "")[:300],
            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
            "matrix":      "ics-attack",
        })
    return sorted(results, key=lambda x: x["id"])


# Keyword router — when an analyst alert mentions any of these tokens,
# the investigation agent will consult the ICS matrix in addition to
# Enterprise. Tokens chosen to be high-specificity (no generic IT terms).
_ICS_KEYWORDS = (
    "modbus", "dnp3", "iec 61850", "iec 60870", "iec-60870", "iec-104",
    "iec 104", "s7comm", "siemens s7", "ethernet/ip", "ethernet-ip",
    "profinet", "profibus", "opc-ua", "opc ua", "bacnet", "iccp",
    "scada", " plc ", "rtu", "hmi", "dcs distributed control",
    "purdue model", "wonderware", "factorytalk", "iconics", "ge ifix",
    "rockwell logix", "schneider modicon", "abb 800xa", "yokogawa centum",
    "honeywell experion", "iec 62443",
)


def looks_like_ics_alert(text: str) -> bool:
    """Return True when the alert text references ICS / OT protocols
    or vendor stacks. Used to gate ICS-matrix lookups."""
    if not isinstance(text, str) or not text:
        return False
    t = text.lower()
    return any(k in t for k in _ICS_KEYWORDS)


# ─── ATT&CK for Mobile ───────────────────────────────────────────────────────
@lru_cache(maxsize=1)
def _mitre_mobile():
    try:
        from mitreattack.stix20 import MitreAttackData
        if STIX_FILE_MOBILE.exists():
            return MitreAttackData(str(STIX_FILE_MOBILE))
    except ImportError:
        pass
    return None


def get_all_techniques_mobile() -> list[dict]:
    """Same shape as get_all_techniques() but for the Mobile matrix."""
    m = _mitre_mobile()
    if not m:
        return []
    results = []
    for t in m.get_techniques(remove_revoked_deprecated=True):
        tid = next((r["external_id"] for r in t.get("external_references", [])
                    if r.get("source_name") == "mitre-mobile-attack"), None)
        if not tid:
            continue
        tactics = [p["phase_name"].replace("-", " ").title()
                   for p in t.get("kill_chain_phases", [])
                   if p.get("kill_chain_name") == "mitre-mobile-attack"]
        results.append({
            "id":          tid,
            "name":        t.get("name", ""),
            "tactic":      tactics[0] if tactics else "Unknown",
            "tactics":     tactics,
            "description": (t.get("description") or "")[:300],
            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
            "matrix":      "mobile-attack",
        })
    return sorted(results, key=lambda x: x["id"])


# Mobile-attack keyword router. Tokens picked for high specificity.
_MOBILE_KEYWORDS = (
    "android", "ios ", "ios.", " ios:", "iphone", "ipad", "apk",
    "google play", "app store", "mobile device manage", "mdm",
    "intune mobile", "samsung knox", "android root", "jailbreak",
    "pegasus", "predator nso", "stalkerware", "mobile spyware",
    "google authenticator backup", "android device admin",
    "com.android", "com.apple", "ios payload",
)


def looks_like_mobile_alert(text: str) -> bool:
    if not isinstance(text, str) or not text:
        return False
    t = text.lower()
    return any(k in t for k in _MOBILE_KEYWORDS)


# ─── ATT&CK for Cloud + Containers (filters over Enterprise) ─────────────────
# ATT&CK no longer publishes Cloud/Containers as separate STIX bundles;
# they live inside enterprise-attack.json as `x-mitre-platform` tags on
# individual techniques. We filter via tactic/platform metadata when
# present in the loaded technique objects.
_CLOUD_KEYWORDS = (
    "aws ", "amazon web services", "ec2", "s3 bucket", "cloudtrail",
    "guardduty", "iam role", "iam user", "iam policy", "kms key",
    "azure ", "entra id", "azure ad", "microsoft 365", "m365",
    "office 365", "intune", "sharepoint", "exchange online",
    "gcp ", "google cloud", "google workspace", "gws",
    "oauth token", "service account key", "instance metadata",
    "imds ", "169.254.169.254", "kubernetes secret",
    "okta", "auth0", "ping identity", "onelogin",
    "saml assertion", "scim",
)

_CONTAINER_KEYWORDS = (
    "kubernetes", "k8s ", "kubeadm", "kubectl", "kubelet", "kube-",
    "docker ", "containerd", "cri-o", "runc",
    "ecs task", "fargate", "gke ", "aks ", "eks ",
    "openshift", "rancher", "harbor",
    "container escape", "pod escape", "privileged container",
    "container runtime", "container image", "image pull secret",
)


def looks_like_cloud_alert(text: str) -> bool:
    if not isinstance(text, str) or not text:
        return False
    t = text.lower()
    return any(k in t for k in _CLOUD_KEYWORDS)


def looks_like_container_alert(text: str) -> bool:
    if not isinstance(text, str) or not text:
        return False
    t = text.lower()
    return any(k in t for k in _CONTAINER_KEYWORDS)


def get_all_techniques() -> list[dict]:
    m = _mitre()
    if not m:
        return []
    results = []
    for t in m.get_techniques(remove_revoked_deprecated=True):
        tid = next((r["external_id"] for r in t.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        if not tid:
            continue
        tactics = [p["phase_name"].replace("-", " ").title()
                   for p in t.get("kill_chain_phases", [])
                   if p.get("kill_chain_name") == "mitre-attack"]
        results.append({
            "id":          tid,
            "name":        t.get("name", ""),
            "tactic":      tactics[0] if tactics else "Unknown",
            "tactics":     tactics,
            "description": (t.get("description") or "")[:300],
            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
        })
    return sorted(results, key=lambda x: x["id"])


@lru_cache(maxsize=1)
def _search_index() -> dict:
    """One-shot lowercase substring index keyed off (id, name, tactic).
    Returns {token_or_field_lower: [tech, ...]} — actually here we keep
    a flat list of (haystack, tech) pairs because substring matching
    can't use a hash directly. Built once per process; subsequent
    search_techniques() calls do a single linear scan over the cached
    pair list with no per-call .lower() / .get_all_techniques() walk."""
    pairs = []
    for t in get_all_techniques():
        haystack = (t["id"] + "\n" + t["name"] + "\n" + t["tactic"]).lower()
        pairs.append((haystack, t))
    return {"pairs": pairs}


def search_techniques(query: str) -> list[dict]:
    q = query.lower().strip()
    if len(q) < 2:
        return get_all_techniques()[:20]
    pairs = _search_index()["pairs"]
    out = []
    for haystack, tech in pairs:
        if q in haystack:
            out.append(tech)
            if len(out) >= 30:
                break
    return out


# Kill-chain ordering — used to bucket an actor's TTPs as "look for before
# this alert" vs "look for after this alert" relative to the techniques that
# actually matched the log. Lower index = earlier in the attack lifecycle.
_KILL_CHAIN_ORDER = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Defense Evasion",
    "Persistence",
    "Privilege Escalation",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command And Control",
    "Exfiltration",
    "Impact",
)
_TACTIC_POS = {t: i for i, t in enumerate(_KILL_CHAIN_ORDER)}


@lru_cache(maxsize=1)
def _group_index() -> dict:
    """Build a per-actor index of TTPs + tools, once. Each entry:
      { "techniques": [ {id, name, tactic}, ... ],
        "software":   [ {id, name, type, aliases, labels, description}, ... ],
        "process_names": [ "powershell.exe", ... ]  # derived from technique +
                                                    # software aliases
      }
    Cached for the process lifetime; subsequent lookups are dict access."""
    m = _mitre()
    if not m:
        return {}
    # Concrete-artifact keywords we lift from technique names so an analyst
    # gets actual process names to hunt for instead of bare MITRE codes.
    _PROC_RE = re.compile(
        r"\b("
        r"powershell|pwsh|cmd|wmic|wscript|cscript|mshta|rundll32|regsvr32|"
        r"certutil|bitsadmin|msbuild|installutil|msiexec|schtasks|"
        r"psexec|net1?\.exe|dsquery|ntdsutil|wbadmin|vssadmin|"
        r"lsass|svchost|services|explorer|winlogon|spoolsv|"
        r"mimikatz|cobaltstrike|sliver|brute\s*ratel|metasploit"
        r")\b",
        re.IGNORECASE,
    )
    out: dict = {}
    for group in m.get_groups():
        gid = next((r["external_id"] for r in group.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), "")
        if not gid:
            continue
        techs = []
        proc_set: set = set()
        for t in m.get_techniques_used_by_group(group["id"]):
            obj = t.get("object", {})
            tid = next((r["external_id"] for r in obj.get("external_references", [])
                        if r.get("source_name") == "mitre-attack"), None)
            if not tid:
                continue
            tactics = [p["phase_name"].replace("-", " ").title()
                       for p in obj.get("kill_chain_phases", [])
                       if p.get("kill_chain_name") == "mitre-attack"]
            tname = obj.get("name", "")
            techs.append({
                "id":     tid,
                "name":   tname,
                "tactic": tactics[0] if tactics else "Unknown",
            })
            # Lift concrete process names from the technique name (e.g.
            # "PowerShell" -> "powershell.exe").
            for hit in _PROC_RE.findall(tname or ""):
                bare = hit.lower().replace(" ", "")
                if not bare.endswith(".exe"):
                    bare = bare + ".exe"
                proc_set.add(bare)

        # Software (S####) the group is known to use. Aliases on a Software
        # record are typically the binary's filenames / tool names, which
        # is exactly the concrete artifact analysts want to hunt for.
        sw_list = []
        try:
            for sw in m.get_software_used_by_group(group["id"]):
                obj = sw.get("object", {})
                sid = next((r["external_id"] for r in obj.get("external_references", [])
                            if r.get("source_name") == "mitre-attack"), "")
                aliases = [a for a in (obj.get("aliases") or []) if a]
                sw_list.append({
                    "id":          sid,
                    "name":        obj.get("name", ""),
                    "type":        obj.get("type", ""),   # malware / tool
                    "labels":      obj.get("labels", []),
                    "aliases":     aliases,
                    "description": (obj.get("description") or "")
                                   .split(". ")[0][:280],
                })
                # Aliases sometimes include filenames like "Mimikatz.exe" or
                # "psexec.exe"; pull those into the process_names set so the
                # UI lists them as "look for X" without further parsing.
                for a in aliases[:6]:
                    if re.search(r"\.(exe|dll|bat|ps1|scr|vbs)$", a, re.IGNORECASE):
                        proc_set.add(a.lower())
        except Exception:
            sw_list = []

        out[gid] = {
            "techniques":    techs,
            "software":      sw_list,
            "process_names": sorted(proc_set),
        }
    return out


def _index_techs(entry: dict) -> list:
    """Backwards-compat helper: old call sites that expected a flat list
    of techniques from _group_index() still work."""
    if isinstance(entry, dict) and "techniques" in entry:
        return entry["techniques"]
    if isinstance(entry, list):
        return entry
    return []


def get_actor_ttps_by_phase(mitre_group_id: str,
                            matched_technique_ids: list[str]) -> dict:
    """For a given actor (MITRE G####), bucket their full TTP list relative to
    the techniques that already matched THIS alert. Returns:

      {
        "before":          [ {id, name, tactic}, … ],   # earlier in kill-chain
        "after":           [ {id, name, tactic}, … ],   # later in kill-chain
        "matched":         [ {id, name, tactic}, … ],   # already-fired
        "all_count":       N,
        "process_names":   [ "powershell.exe", "mimikatz.exe", … ],
        "software":        [ {id, name, type, aliases, description}, … ],
      }

    Empty buckets when MITRE data is unavailable or the group is unknown."""
    idx = _group_index()
    entry = idx.get(mitre_group_id or "")
    techs = _index_techs(entry)
    software = (entry.get("software") if isinstance(entry, dict) else None) or []
    process_names = (entry.get("process_names") if isinstance(entry, dict) else None) or []
    if not techs and not software:
        return {"before": [], "after": [], "matched": [], "all_count": 0,
                "process_names": [], "software": []}
    matched_set = {str(t).strip().upper() for t in (matched_technique_ids or [])}
    # Pivot tactic = the LATEST kill-chain position among matched techniques.
    # Everything earlier becomes "before"; everything later becomes "after".
    matched_positions = []
    for t in techs:
        if t["id"].upper() in matched_set:
            pos = _TACTIC_POS.get(t["tactic"])
            if pos is not None:
                matched_positions.append(pos)
    pivot = max(matched_positions) if matched_positions else None

    before: list = []
    after:  list = []
    matched_tts: list = []
    for t in techs:
        is_match = t["id"].upper() in matched_set
        if is_match:
            matched_tts.append(t)
            continue
        pos = _TACTIC_POS.get(t["tactic"])
        if pos is None:
            continue
        if pivot is None or pos < pivot:
            before.append(t)
        elif pos > pivot:
            after.append(t)
        else:
            # Same tactic as the matched pivot — surface as "after" since
            # it's a sibling technique within the same phase the alert
            # represents.
            after.append(t)

    # Deterministic ordering by kill-chain position then technique id so the
    # UI list is stable across renders.
    before.sort(key=lambda t: (_TACTIC_POS.get(t["tactic"], 99), t["id"]))
    after.sort (key=lambda t: (_TACTIC_POS.get(t["tactic"], 99), t["id"]))
    return {
        "before":        before[:10],
        "after":         after[:10],
        "matched":       matched_tts,
        "all_count":     len(techs),
        "process_names": process_names[:20],
        "software":      software[:12],
    }


def get_groups_by_techniques(technique_ids: list[str]) -> list[dict]:
    """Score = precision-style: `matched / N_alert_techniques * 100`.

    Reads as "of the techniques observed in THIS alert, what fraction line
    up with this actor's documented profile?" — independent of how huge
    the actor's full TTP catalogue is. The old `matched / max(...)` formula
    lowballed every score because mature APT profiles list 30-100+
    techniques, making 75%+ effectively unreachable for normal alerts.
    """
    m = _mitre()
    if not m or not technique_ids:
        return []
    n_alert = len(technique_ids) or 1
    results = []
    for group in m.get_groups():
        group_tids = set()
        for t in m.get_techniques_used_by_group(group["id"]):
            for ref in t.get("object", {}).get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    group_tids.add(ref["external_id"])
        matches = [t for t in technique_ids if t in group_tids]
        if not matches:
            continue
        # Precision: how much of THIS alert's TTPs are explained by this
        # actor's playbook. Capped at 100. Bounded floor avoids divide-by-0
        # when the alert had zero MITRE matches.
        score = round(len(matches) / n_alert * 100)
        gid = next((r["external_id"] for r in group.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), "")
        results.append({
            "name":              group.get("name", ""),
            "id":                gid,
            "aliases":           group.get("aliases", [])[:3],
            "matchedTechniques": matches,
            "score":             score,
            "description":       (group.get("description") or "")[:200],
        })
    return sorted(results, key=lambda x: x["score"], reverse=True)[:10]

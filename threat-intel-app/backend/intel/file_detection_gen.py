"""
Detection-content generation — spec §6 of the all-in-one scanner plan.

Given a file_analyzer result dict, synthesizes:
  - Sigma rule (hash-based endpoint detection)
  - KQL hunting query (Microsoft Sentinel / Defender XDR)
  - SPL hunting query (Splunk)
  - Snort / Suricata network rule (when hardcoded IOCs found)
  - Volatility/Rekall string search (unique memory-resident strings)

The Sigma rule is run through pysigma validation when available.
"""

from __future__ import annotations
import uuid
from datetime import datetime
from typing import Dict, List


def generate_all_detections(result: Dict) -> Dict:
    sha256 = (result.get("hashes") or {}).get("sha256")
    sha1   = (result.get("hashes") or {}).get("sha1")
    md5    = (result.get("hashes") or {}).get("md5")
    iocs   = result.get("iocs") or {}
    ips    = iocs.get("ips")    or []
    domains = iocs.get("domains") or []
    urls   = iocs.get("urls")   or []
    imphash = ((result.get("format_specific") or {}).get("pe") or {}).get("imphash")
    mutexes = _extract_mutex_strings(result)
    unique_strings = _unique_strings_for_memory(result, limit=10)

    sigma = _gen_sigma(sha256, sha1, md5, mutexes)
    kql   = _gen_kql_hunt(sha256, ips, domains, urls, imphash, mutexes)
    spl   = _gen_spl_hunt(sha256, ips, domains, imphash)
    suri  = _gen_suricata(ips, domains, urls) if (ips or domains or urls) else None
    vol   = _gen_volatility(unique_strings, mutexes) if (unique_strings or mutexes) else None

    out = {
        "sigma":     sigma,
        "kql":       kql,
        "spl":       spl,
        "suricata":  suri,
        "volatility": vol,
    }

    # Validate Sigma via pysigma (best-effort)
    try:
        from intel.detection_engineering import validate_sigma
        ok, errs = validate_sigma(sigma["rule"])
        sigma["valid"]  = ok
        sigma["errors"] = errs
    except Exception:
        sigma.setdefault("valid", None)

    return out


# ─── helpers ───────────────────────────────────────────────────────────────────
def _extract_mutex_strings(result: Dict) -> List[str]:
    """Look for `Global\\…` or `Local\\…` mutex-shaped strings in the extracted set."""
    out: List[str] = []
    samples = (result.get("strings") or {}).get("ascii_sample") or []
    for s in samples:
        if isinstance(s, str) and (s.startswith(("Global\\", "Local\\")) or "Mutex" in s):
            if 6 <= len(s) <= 80:
                out.append(s)
    return out[:8]


def _unique_strings_for_memory(result: Dict, limit: int = 10) -> List[str]:
    """Strings that look unique enough to survive in a memory dump — long,
    non-common, not just printable garbage from the import table."""
    samples = (result.get("strings") or {}).get("ascii_sample") or []
    candidates = []
    common = {"kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
              "ws2_32.dll", "wininet.dll", "shell32.dll"}
    for s in samples:
        if not isinstance(s, str) or len(s) < 12 or len(s) > 80:
            continue
        if s.lower() in common:
            continue
        # Require some non-alnum diversity or a noteworthy character
        if any(c in s for c in (":", "\\", "{", "/", "@", ".")):
            candidates.append(s)
    return candidates[:limit]


# ─── Sigma ────────────────────────────────────────────────────────────────────
def _gen_sigma(sha256, sha1, md5, mutexes) -> Dict:
    today = datetime.now().strftime("%Y/%m/%d")
    rid = str(uuid.uuid4())
    hash_block = []
    if sha256: hash_block.append(f"      - {sha256}")
    if sha1:   hash_block.append(f"      - {sha1}")
    if md5:    hash_block.append(f"      - {md5}")
    hash_yaml = "\n".join(hash_block) if hash_block else "      - 0"

    if mutexes:
        # Combined: file-hash OR known mutex creation
        mutex_yaml = "\n".join(f"      - '{m}'" for m in mutexes[:5])
        rule = f"""title: Suspicious file execution or mutex creation (RECON-generated)
id: {rid}
status: experimental
description: Detect execution of file by hash or creation of mutex observed in
  static analysis of the sample.
references:
  - https://attack.mitre.org/techniques/T1204/
author: RECON Platform
date: {today}
tags:
  - attack.execution
  - attack.t1204
logsource:
  product: windows
  category: process_creation
detection:
  selection_hash:
    Hashes|contains:
{hash_yaml}
  selection_mutex:
    MutantName|contains:
{mutex_yaml}
  condition: selection_hash or selection_mutex
falsepositives:
  - Unlikely — both indicators are file-specific.
level: high
"""
    else:
        rule = f"""title: Suspicious file execution by hash (RECON-generated)
id: {rid}
status: experimental
description: Detect process creation matching the hash of the analyzed sample.
references:
  - https://attack.mitre.org/techniques/T1204/
author: RECON Platform
date: {today}
tags:
  - attack.execution
  - attack.t1204
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Hashes|contains:
{hash_yaml}
  condition: selection
falsepositives:
  - Unlikely — hash is file-specific.
level: high
"""
    return {"rule": rule, "id": rid}


# ─── KQL (Microsoft Sentinel / Defender XDR Advanced Hunting) ─────────────────
def _gen_kql_hunt(sha256, ips, domains, urls, imphash, mutexes) -> Dict:
    """Multi-table union — DeviceProcessEvents + DeviceFileEvents + DeviceNetworkEvents."""
    parts = ["// RECON-generated hunting query — file + network indicators",
             "// Run in Microsoft Sentinel / Defender XDR Advanced Hunting"]
    union_blocks = []

    if sha256:
        union_blocks.append(
            f"DeviceProcessEvents\n"
            f"| where SHA256 == '{sha256}'\n"
            f"| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, "
            f"InitiatingProcessFileName, SHA256"
        )
        union_blocks.append(
            f"DeviceFileEvents\n"
            f"| where SHA256 == '{sha256}'\n"
            f"| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256"
        )

    if imphash:
        union_blocks.append(
            f"// Other PE files sharing this imphash (functionally similar)\n"
            f"DeviceFileEvents\n"
            f"| where AdditionalFields has '{imphash}'\n"
            f"| project Timestamp, DeviceName, FileName, FolderPath"
        )

    if ips:
        ip_list = ", ".join(f"'{i}'" for i in ips[:10])
        union_blocks.append(
            f"DeviceNetworkEvents\n"
            f"| where RemoteIP in~ ({ip_list})\n"
            f"| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName"
        )
    if domains:
        dom_list = ", ".join(f"'{d}'" for d in domains[:10])
        union_blocks.append(
            f"DeviceNetworkEvents\n"
            f"| where RemoteUrl has_any ({dom_list})\n"
            f"| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName"
        )

    if mutexes:
        mlist = ", ".join(f"'{m}'" for m in mutexes[:5])
        union_blocks.append(
            f"DeviceEvents\n"
            f"| where ActionType == 'MutantCreated' and AdditionalFields has_any ({mlist})\n"
            f"| project Timestamp, DeviceName, InitiatingProcessFileName, AdditionalFields"
        )

    if not union_blocks:
        return {"query": None, "note": "no IOCs available for KQL hunt"}

    query = "\n\n".join(parts + [f"union withsource=SourceTable\n(\n  {b}\n)" if i == 0 else f"({b})"
                                  for i, b in enumerate(union_blocks)])
    # Simpler form — concatenate blocks separated by union
    query = "\n".join(parts) + "\n\n" + "\n\n| union\n".join(union_blocks) + \
            "\n\n| sort by Timestamp desc"
    return {"query": query}


# ─── SPL (Splunk) ─────────────────────────────────────────────────────────────
def _gen_spl_hunt(sha256, ips, domains, imphash) -> Dict:
    parts = []
    if sha256:
        parts.append(f"index=* (SHA256={sha256} OR file_hash={sha256})")
    if imphash:
        parts.append(f"index=* imphash={imphash}")
    if ips:
        ip_or = " OR ".join(f"dest_ip={i}" for i in ips[:10])
        parts.append(f"index=* ({ip_or})")
    if domains:
        dom_or = " OR ".join(f"dest_host={d}" for d in domains[:10])
        parts.append(f"index=* ({dom_or})")
    if not parts:
        return {"query": None, "note": "no IOCs available for SPL hunt"}
    query = ("`# RECON-generated Splunk hunt`\n"
             "search " + " OR ".join(f"({p[6:]})" for p in parts) +
             "\n| stats count by host, sourcetype, _time"
             "\n| sort -count")
    return {"query": query}


# ─── Snort / Suricata ─────────────────────────────────────────────────────────
def _gen_suricata(ips, domains, urls) -> Dict:
    rules = []
    sid_base = 9_000_001
    for i, ip in enumerate(ips[:5]):
        rules.append(
            f'alert ip $HOME_NET any -> {ip} any '
            f'(msg:"RECON: connection to hardcoded malware IP {ip}"; '
            f'classtype:trojan-activity; sid:{sid_base + i}; rev:1;)'
        )
    for i, dom in enumerate(domains[:5]):
        rules.append(
            f'alert dns $HOME_NET any -> any any '
            f'(msg:"RECON: DNS query for malware domain {dom}"; '
            f'dns_query; content:"{dom}"; nocase; '
            f'classtype:trojan-activity; sid:{sid_base + 100 + i}; rev:1;)'
        )
    for i, url in enumerate(urls[:3]):
        # Extract just host + path for HTTP rule
        host = url.split("://", 1)[-1].split("/", 1)[0]
        path = "/" + url.split("://", 1)[-1].split("/", 1)[-1] if "/" in url.split("://", 1)[-1] else "/"
        rules.append(
            f'alert http $HOME_NET any -> any any '
            f'(msg:"RECON: HTTP request to malware URL {url[:80]}"; '
            f'flow:to_server,established; http.host; content:"{host}"; '
            f'http.uri; content:"{path[:80]}"; nocase; '
            f'classtype:trojan-activity; sid:{sid_base + 200 + i}; rev:1;)'
        )
    if not rules:
        return {"rules": None, "note": "no network IOCs found"}
    return {"rules": "\n".join(rules), "count": len(rules)}


# ─── Volatility / Rekall memory hunt ──────────────────────────────────────────
def _gen_volatility(unique_strings, mutexes) -> Dict:
    yarastr = []
    for i, s in enumerate(unique_strings[:8]):
        # Escape for YARA
        esc = s.replace("\\", "\\\\").replace('"', '\\"')
        yarastr.append(f'    $s{i+1} = "{esc}" ascii wide nocase')
    for i, m in enumerate(mutexes[:3]):
        esc = m.replace("\\", "\\\\").replace('"', '\\"')
        yarastr.append(f'    $m{i+1} = "{esc}" ascii wide')
    if not yarastr:
        return {"rule": None}
    rule = (
        "rule recon_memory_hunt\n"
        "{\n"
        "  meta:\n"
        "    description = \"RECON-generated memory hunt — unique strings + mutexes from sample\"\n"
        "    author = \"RECON Platform\"\n"
        f"    date = \"{datetime.now().strftime('%Y-%m-%d')}\"\n"
        "  strings:\n" + "\n".join(yarastr) + "\n"
        "  condition:\n"
        "    2 of them\n"
        "}\n"
    )
    cmd = ("vol.py -f <memory.dmp> windows.yarascan.YaraScan --yara-rules-file recon_memory_hunt.yar")
    return {"rule": rule, "volatility_cmd": cmd}

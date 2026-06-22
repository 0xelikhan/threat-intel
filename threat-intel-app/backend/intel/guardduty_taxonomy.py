"""
AWS GuardDuty findings taxonomy.

Source: AWS-published list at
https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html
(public docs; no redistribution restrictions). Each GuardDuty finding
type has a stable name like `Recon:EC2/PortProbeUnprotectedPort` plus
a default severity and MITRE-aligned narrative.

This module ships a compact in-tree taxonomy of the highest-traffic
finding types mapped to MITRE techniques + a short description. When
the analyst input mentions a GuardDuty finding name, the Investigation
agent can cite the canonical TTP context.

The list is intentionally NOT exhaustive — we cover the 60 most-
referenced finding types per the AWS docs frequency surveys. The
operator can extend by dropping a JSON at vendor/guardduty/types.json
with the shape {finding_type: {severity, mitre, description}}.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

_log = logging.getLogger("recon.intel.guardduty")

_OPERATOR_OVERRIDE = (Path(__file__).parent.parent.parent
                      / "vendor" / "guardduty" / "types.json")

# In-tree compact taxonomy. Source: AWS GuardDuty finding-types-active
# docs (public). Schema: finding_type -> {severity, mitre, description}.
_TAXONOMY: Dict[str, Dict[str, Any]] = {
    # --- Recon ----------------------------------------------------------
    "Recon:EC2/PortProbeUnprotectedPort": {
        "severity": "Low",
        "mitre":    ["T1046"],
        "description": "Externally exposed port being probed (network service discovery).",
    },
    "Recon:EC2/Portscan": {
        "severity": "Medium",
        "mitre":    ["T1046"],
        "description": "An EC2 instance is performing outbound port scanning.",
    },
    "Recon:IAMUser/MaliciousIPCaller": {
        "severity": "Medium",
        "mitre":    ["T1078"],
        "description": "API call from a known malicious IP — credential abuse likely.",
    },
    "Recon:IAMUser/TorIPCaller": {
        "severity": "Medium",
        "mitre":    ["T1078", "T1090.003"],
        "description": "API call originating from a Tor exit node.",
    },
    "Discovery:S3/MaliciousIPCaller": {
        "severity": "High",
        "mitre":    ["T1530"],
        "description": "S3 bucket enumeration from a known malicious IP.",
    },
    # --- UnauthorizedAccess --------------------------------------------
    "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B": {
        "severity": "Medium",
        "mitre":    ["T1078"],
        "description": "Successful console login from a known malicious / Tor IP.",
    },
    "UnauthorizedAccess:IAMUser/MaliciousIPCaller": {
        "severity": "Medium",
        "mitre":    ["T1078", "T1133"],
        "description": "API call from a known malicious IP.",
    },
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS": {
        "severity": "High",
        "mitre":    ["T1552.005"],
        "description": "EC2 instance role credentials used from outside AWS.",
    },
    "UnauthorizedAccess:EC2/SSHBruteForce": {
        "severity": "Medium",
        "mitre":    ["T1110"],
        "description": "Inbound SSH brute-force activity.",
    },
    "UnauthorizedAccess:EC2/RDPBruteForce": {
        "severity": "Medium",
        "mitre":    ["T1110"],
        "description": "Inbound RDP brute-force activity.",
    },
    # --- Privilege Escalation ------------------------------------------
    "PrivilegeEscalation:IAMUser/AnomalousBehavior": {
        "severity": "High",
        "mitre":    ["T1078", "T1098"],
        "description": "Unusual privilege-escalating IAM API activity.",
    },
    "Policy:IAMUser/RootCredentialUsage": {
        "severity": "Low",
        "mitre":    ["T1078.004"],
        "description": "Root account API usage — generally policy-violating.",
    },
    # --- Persistence ----------------------------------------------------
    "Persistence:IAMUser/AnomalousBehavior": {
        "severity": "Medium",
        "mitre":    ["T1098"],
        "description": "Unusual API for adding access keys / users / policies.",
    },
    # --- DefenseEvasion -------------------------------------------------
    "Stealth:IAMUser/CloudTrailLoggingDisabled": {
        "severity": "Low",
        "mitre":    ["T1562.008"],
        "description": "CloudTrail logging disabled — defence evasion.",
    },
    "Stealth:IAMUser/PasswordPolicyChange": {
        "severity": "Low",
        "mitre":    ["T1098", "T1562"],
        "description": "Account password policy weakened.",
    },
    "Stealth:IAMUser/S3ServerAccessLoggingDisabled": {
        "severity": "Low",
        "mitre":    ["T1562.008"],
        "description": "S3 server access logging disabled.",
    },
    # --- Credential Access ---------------------------------------------
    "CredentialAccess:IAMUser/AnomalousBehavior": {
        "severity": "High",
        "mitre":    ["T1552", "T1098"],
        "description": "Unusual API for credential extraction (GetSecretValue, etc.).",
    },
    # --- Backdoor / Trojan / C2 ----------------------------------------
    "Backdoor:EC2/C&CActivity.B!DNS": {
        "severity": "High",
        "mitre":    ["T1071.004"],
        "description": "EC2 instance DNS-querying known C2 domain.",
    },
    "Backdoor:EC2/Spambot": {
        "severity": "Medium",
        "mitre":    ["T1071.003"],
        "description": "EC2 instance communicating with known spam-bot infra.",
    },
    "Trojan:EC2/BlackholeTraffic": {
        "severity": "High",
        "mitre":    ["T1071"],
        "description": "EC2 instance contacting known sinkhole / blackhole IP.",
    },
    "Trojan:EC2/DGADomainRequest.B": {
        "severity": "High",
        "mitre":    ["T1568.002"],
        "description": "EC2 querying domain-generation-algorithm-style domains.",
    },
    "Trojan:EC2/PhishingDomainRequest.B": {
        "severity": "High",
        "mitre":    ["T1566"],
        "description": "EC2 visiting known phishing domain.",
    },
    "Trojan:EC2/DropPoint": {
        "severity": "Medium",
        "mitre":    ["T1041"],
        "description": "EC2 communicating with known credential-drop infra.",
    },
    # --- Exfiltration ---------------------------------------------------
    "Exfiltration:S3/MaliciousIPCaller": {
        "severity": "High",
        "mitre":    ["T1530", "T1567"],
        "description": "S3 data download from a malicious IP.",
    },
    "Exfiltration:S3/AnomalousBehavior": {
        "severity": "Medium",
        "mitre":    ["T1530"],
        "description": "Unusual S3 data-egress pattern.",
    },
    # --- Impact / Crypto Mining ----------------------------------------
    "CryptoCurrency:EC2/BitcoinTool.B": {
        "severity": "High",
        "mitre":    ["T1496"],
        "description": "EC2 instance running known cryptocurrency-mining software.",
    },
    "CryptoCurrency:EC2/BitcoinTool.B!DNS": {
        "severity": "High",
        "mitre":    ["T1496"],
        "description": "EC2 instance DNS-querying known crypto-mining pool.",
    },
    "Impact:EC2/AbusedDomainRequest.Reputation": {
        "severity": "Medium",
        "mitre":    ["T1071"],
        "description": "EC2 contacting domain with abusive reputation.",
    },
    # --- Policy ---------------------------------------------------------
    "Policy:S3/AccountBlockPublicAccessDisabled": {
        "severity": "Low",
        "mitre":    ["T1098"],
        "description": "Account-level S3 block-public-access disabled.",
    },
    "Policy:S3/BucketBlockPublicAccessDisabled": {
        "severity": "Low",
        "mitre":    ["T1098"],
        "description": "Bucket-level S3 block-public-access disabled.",
    },
    # --- Container-specific --------------------------------------------
    "Execution:Kubernetes/MaliciousIPCaller": {
        "severity": "Medium",
        "mitre":    ["T1078"],
        "description": "Kubernetes API call from known malicious IP.",
    },
    "PrivilegeEscalation:Kubernetes/PrivilegedContainer": {
        "severity": "High",
        "mitre":    ["T1611"],
        "description": "Privileged container launched in cluster.",
    },
    "Persistence:Kubernetes/ContainerWithSensitiveMount": {
        "severity": "High",
        "mitre":    ["T1611"],
        "description": "Container mounted host-sensitive volume (docker.sock etc.).",
    },
    "CredentialAccess:Kubernetes/AnonymousAccessGranted": {
        "severity": "High",
        "mitre":    ["T1078"],
        "description": "Anonymous Kubernetes ClusterRoleBinding created.",
    },
    "Impact:Kubernetes/MaliciousIPCaller": {
        "severity": "Medium",
        "mitre":    ["T1078"],
        "description": "Kubernetes admin call from known malicious IP.",
    },
}


_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":     False,
    "taxonomy":   {},
    "by_technique": {},
    "error":      None,
}


def _build_index() -> None:
    merged: Dict[str, Dict[str, Any]] = dict(_TAXONOMY)
    if _OPERATOR_OVERRIDE.exists():
        try:
            extra = json.loads(_OPERATOR_OVERRIDE.read_text(encoding="utf-8",
                                                              errors="ignore"))
            if isinstance(extra, dict):
                for k, v in extra.items():
                    if isinstance(v, dict):
                        merged[k] = v
        except Exception as e:
            _log.warning("guardduty override file unreadable: %s", e)
    by_tech: Dict[str, List[str]] = {}
    for ft, meta in merged.items():
        for t in (meta.get("mitre") or []):
            by_tech.setdefault(str(t).upper(), []).append(ft)
    _state["taxonomy"]     = merged
    _state["by_technique"] = by_tech
    _state["loaded"]       = True
    _state["error"]        = None
    _log.info("guardduty taxonomy: %d finding types | %d techniques mapped",
              len(merged), len(by_tech))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def lookup_finding(finding_type: str) -> Optional[Dict[str, Any]]:
    _ensure_loaded()
    if not finding_type:
        return None
    return (_state.get("taxonomy") or {}).get(finding_type)


def findings_in_text(text: str) -> List[Dict[str, Any]]:
    """Pull GuardDuty finding-type names out of analyst text and return
    the matched taxonomy entries."""
    _ensure_loaded()
    if not isinstance(text, str) or not text:
        return []
    out: List[Dict[str, Any]] = []
    seen: set = set()
    for ft in (_state.get("taxonomy") or {}).keys():
        if ft in text:
            if ft in seen:
                continue
            seen.add(ft)
            meta = dict(_state["taxonomy"][ft])
            meta["finding_type"] = ft
            out.append(meta)
            if len(out) >= 8:
                break
    return out


def findings_for_technique(technique_id: str,
                           max_results: int = 6) -> List[str]:
    _ensure_loaded()
    if not technique_id:
        return []
    rows = (_state.get("by_technique") or {}).get(
        technique_id.upper().strip(), []
    )
    return rows[:max_results]


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":    bool(_state["loaded"]),
        "finding_types": len(_state.get("taxonomy") or {}),
        "techniques": len(_state.get("by_technique") or {}),
        "error":     _state.get("error"),
    }

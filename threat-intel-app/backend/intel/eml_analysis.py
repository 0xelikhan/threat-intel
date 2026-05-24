"""
EML (RFC 5322 email) analyzer for SOC phishing triage.
Extracts headers, authentication results (SPF/DKIM/DMARC), attachments
with hashes, URLs, and surfaces classic phishing signals.
"""
import hashlib
import re
from typing import Any


_EML_HINTS = ("Received:", "From:", "To:", "Subject:", "Message-ID:", "Return-Path:",
              "DKIM-Signature:", "Authentication-Results:", "MIME-Version:")


def looks_like_eml(text: str) -> bool:
    """Cheap test: does this look like raw EML/RFC822 source?"""
    if not text or len(text) < 80:
        return False
    head = text[:1500]
    return sum(1 for h in _EML_HINTS if h in head) >= 3


def _hash_attachment(content: bytes) -> dict:
    return {
        "md5":    hashlib.md5(content).hexdigest(),
        "sha1":   hashlib.sha1(content).hexdigest(),
        "sha256": hashlib.sha256(content).hexdigest(),
        "size":   len(content),
    }


def _parse_auth_results(value: str) -> dict:
    """Pull spf / dkim / dmarc results from Authentication-Results header."""
    out: dict = {}
    for key in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{key}=([a-z]+)", value or "", re.IGNORECASE)
        if m:
            out[key] = m.group(1).lower()
    return out


def _received_chain_ips(received_headers: list[str]) -> list[str]:
    """Pull sender IPs from each Received: header (most recent → oldest)."""
    ips = []
    for h in received_headers:
        for ip in re.findall(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", h or ""):
            if ip not in ips:
                ips.append(ip)
    return ips


def analyze(raw_text: str) -> dict | None:
    """Parse EML text → structured analysis. Returns None if eml-parser unavailable."""
    try:
        import eml_parser
    except ImportError:
        return None

    try:
        parser = eml_parser.EmlParser(include_raw_body=True, include_attachment_data=True)
        parsed = parser.decode_email_bytes(raw_text.encode("utf-8", errors="ignore"))
    except Exception:
        return None

    header = parsed.get("header", {})
    body   = parsed.get("body", [])

    auth_value = header.get("header", {}).get("authentication-results", [""])[0] if isinstance(header.get("header", {}).get("authentication-results"), list) else (header.get("header", {}).get("authentication-results") or "")
    auth_results = _parse_auth_results(auth_value if isinstance(auth_value, str) else "")

    received = header.get("header", {}).get("received", [])
    if isinstance(received, str):
        received = [received]
    sender_ips = _received_chain_ips(received)

    # Authentication failure signals → strong phishing tell
    phishing_signals = []
    if auth_results.get("spf")   in ("fail", "softfail"): phishing_signals.append(f"SPF {auth_results['spf']}")
    if auth_results.get("dkim")  in ("fail", "none"):     phishing_signals.append(f"DKIM {auth_results['dkim']}")
    if auth_results.get("dmarc") in ("fail",):            phishing_signals.append(f"DMARC {auth_results['dmarc']}")

    # Display-name vs From mismatch (classic phishing trick)
    from_field = (header.get("from") or "").strip()
    return_path = (header.get("header", {}).get("return-path") or [""])
    if isinstance(return_path, list):
        return_path = return_path[0] if return_path else ""
    return_path = (return_path or "").strip("<>")
    if from_field and return_path and "@" in from_field and "@" in return_path:
        from_dom   = from_field.rsplit("@", 1)[-1].rstrip(">").lower()
        return_dom = return_path.rsplit("@", 1)[-1].lower()
        if from_dom and return_dom and from_dom != return_dom:
            phishing_signals.append(f"From/Return-Path mismatch ({from_dom} vs {return_dom})")

    # Reply-To mismatch (another classic)
    reply_to = header.get("header", {}).get("reply-to")
    if isinstance(reply_to, list):
        reply_to = reply_to[0] if reply_to else ""
    if reply_to and from_field and "@" in (reply_to or "") and "@" in from_field:
        if reply_to.rsplit("@", 1)[-1].lower() != from_field.rsplit("@", 1)[-1].rstrip(">").lower():
            phishing_signals.append(f"Reply-To differs from From")

    # Collect all URLs from body parts
    urls: list[str] = []
    for part in body:
        for u in (part.get("uri") or []):
            if u not in urls:
                urls.append(u)

    # Attachments
    atts = []
    for a in (parsed.get("attachment") or []):
        raw_b = a.get("raw")
        # eml_parser may give a base64 string or bytes
        if isinstance(raw_b, str):
            try:
                import base64
                raw_b = base64.b64decode(raw_b)
            except Exception:
                raw_b = b""
        elif not isinstance(raw_b, (bytes, bytearray)):
            raw_b = b""
        hashes = _hash_attachment(bytes(raw_b)) if raw_b else {}
        atts.append({
            "filename":     a.get("filename", ""),
            "content_type": a.get("content_header", {}).get("content-type", [""])[0] if isinstance(a.get("content_header", {}).get("content-type"), list) else a.get("content_header", {}).get("content-type", ""),
            **hashes,
        })

    return {
        "subject":      header.get("subject", ""),
        "from":         from_field,
        "to":           header.get("to", []),
        "date":         str(header.get("date", "")),
        "return_path":  return_path,
        "reply_to":     reply_to,
        "message_id":   header.get("header", {}).get("message-id", [""])[0] if isinstance(header.get("header", {}).get("message-id"), list) else header.get("header", {}).get("message-id", ""),
        "auth_results": auth_results,
        "sender_ips":   sender_ips,
        "urls":         urls,
        "attachments":  atts,
        "phishing_signals": phishing_signals,
    }

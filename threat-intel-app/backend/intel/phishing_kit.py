"""
Phishing-kit fingerprinting.
Covers the 2024-2025 AiTM / credential-theft kit landscape SOC analysts see daily.

Detection is layered:
  1. URL path / parameter signatures (fast, catches most kits)
  2. Hostname pattern matches (subdomain reuse, lookalike formats)
  3. HTML / response-body signatures (if a body snippet is provided)
  4. Tactic / category tagging
"""
import re


# (kit name, patterns[], category, mitre, description)
# Patterns are regex strings, matched case-insensitive against the URL string.
KIT_DEFINITIONS = [

    # ─── 2024-2025 AiTM / MFA-bypass kits ──────────────────────────────
    ("Tycoon 2FA", [
        r"/tycoon",
        r"\?token=[A-Z0-9]{32,}",
        r"/auth/realms/.*?/protocol/openid-connect/auth\?.*tycoon",
        r"tycoongroup\.com",
    ], "AiTM", "T1557", "MFA-bypass kit; reverse-proxies Microsoft 365 sign-in to harvest session cookies."),

    ("Sneaky 2FA (Sneaky Log)", [
        r"sneaky2fa",
        r"sneakylog",
        r"/lgn\.aspx\?session=",
        r"/cdn/[a-z0-9]{6,}/login\.html",
    ], "AiTM", "T1557.003", "AiTM kit specifically targeting Microsoft 365 with Cloudflare evasion."),

    ("Rockstar 2FA", [
        r"rockstar2fa",
        r"/rockstar/",
        r"/auth\?step=[12]&sid=",
    ], "AiTM", "T1557", "AiTM kit; uses Cloudflare workers as relays."),

    ("Mamba 2FA", [
        r"/mamba",
        r"otp\.php",
        r"/mb/[a-z]{4,}/auth",
    ], "AiTM", "T1557", "Microsoft 365 AiTM that captures OTP codes."),

    ("EvilProxy", [
        r"\?proxy=",
        r"/evilproxy",
        r"login\.microsoftonline\.com\..*?\.[a-z]{2,4}/",
        r"login\.microsoft\.com\.[a-z0-9-]+\.(top|xyz|icu|pw|cc)",
    ], "AiTM", "T1557.003", "Reverse-proxy phishing-as-a-service; harvests session tokens."),

    ("Storm-1167 (Phoenix)", [
        r"/aitm/",
        r"/adfsproxy/",
        r"/phoenix-?[a-z]{4,}\.",
    ], "AiTM", "T1557.003", "AiTM kit attributed to Microsoft's Storm-1167; long-running O365 phishing operator."),

    ("W3LL Panel", [
        r"/w3ll/",
        r"/w3ll-?[a-z]{4,}",
        r"/panel\.php\?action=login",
        r"/api/checker\.php",
    ], "AiTM", "T1557", "Sold-as-service panel for Microsoft 365 account takeovers."),

    ("ONNX / HookHand", [
        r"/onnx/",
        r"hookhand",
        r"/api/captcha-?check",
    ], "AiTM", "T1557.003", "AiTM kit, target: Microsoft 365, observed Q4 2024."),

    ("Greatness", [
        r"/greatness",
        r"/static/page\.html\?email=",
        r"/main\.aspx\?action=login&user=",
    ], "Credential Theft", "T1566.002", "Microsoft 365 phishing kit, often distributed via SVG attachments."),

    ("Caffeine", [
        r"caffeine-?[a-z0-9]{4,}\.",
        r"/lgn\.php\?",
        r"/csi/[a-z]{4,}/auth",
    ], "Credential Theft", "T1566", "Phishing-as-a-Service targeting Microsoft and Apple credentials."),

    # ─── Brand-specific kits ─────────────────────────────────────────
    ("16shop", [
        r"/16shop",
        r"/apple_login/",
        r"\?aktiv=",
        r"/amazon/customer-?services",
        r"/paypal/account-?login\?session",
    ], "Credential Theft", "T1566.002", "Multi-target kit (Apple, Amazon, PayPal). Indonesian-origin, SaaS model."),

    ("LogoKit", [
        r"/logo/[a-z0-9]{4,}",
        r"/api/login\?logo=https?://",
        r"/auth\?redirect=https?://[^/]+\.com.*&logo=",
    ], "Credential Theft", "T1566", "Self-customizing phishing page; renders target's logo dynamically."),

    # ─── Naked Pages / generic O365 phishing ────────────────────────
    ("Naked Pages", [
        r"/onedrive\.live\.com\?",
        r"sharepoint\.com\.[a-z0-9-]+\.(top|xyz|icu)",
        r"login\.live\.com\.[a-z0-9-]+\.",
    ], "Credential Theft", "T1566", "Bulk O365 phishing kit using lookalike hostnames."),

    # ─── Browser-in-Browser / BitB ──────────────────────────────────
    ("Browser-in-Browser (BitB)", [
        r"data:text/html;base64,.*Pop-up",
        r"/bitb-?[a-z]{4,}",
        r"/fake-?browser",
    ], "Social Engineering", "T1566", "Renders a fake browser window inside the page to mimic real OAuth popups."),

    # ─── QR phishing (Quishing) ─────────────────────────────────────
    ("Quishing (QR phishing)", [
        r"/qr\?token=[A-Z0-9]{16,}",
        r"\.svg\?qr=",
        r"/qrcode-?login",
    ], "Quishing", "T1566", "QR-code phishing that hides the malicious URL in an image, bypassing URL filters."),

    # ─── ClickFix / fake CAPTCHA ────────────────────────────────────
    ("ClickFix / Fake CAPTCHA", [
        r"/captcha-?(verify|check)\?",
        r"/verify-?you-?are-?human",
        r"/cloudflare-?check\?cf=",
        r"clickfix",
    ], "Social Engineering", "T1204.002", "Tricks user into pasting a command into Run dialog under the guise of CAPTCHA."),

    # ─── SocGholish-style fake-update ──────────────────────────────
    ("SocGholish fake-update", [
        r"/browser-update",
        r"/update-?(chrome|edge|firefox)\.(html?|js)\?",
        r"/yourbrowser-?update",
    ], "Drive-by Download", "T1189", "Fake browser-update lures delivering NetSupport RAT / payloads via JS."),

    # ─── Strox / DarkPanel / common generic kits ───────────────────
    ("Strox / DarkPanel", [
        r"/strox/",
        r"/dpanel/",
        r"/admin/results\.php\?id=",
        r"/results\.php\?session=",
    ], "Credential Theft", "T1566", "Generic credential-stealer panels reused across many campaigns."),

    # ─── Misc credential harvesters ────────────────────────────────
    ("Generic AiTM lookalike", [
        r"microsoftonline\.com\.[a-z0-9-]+\.(com|net|org|xyz|top|pw|live|cc|info)",
        r"login\.live\.com\.[a-z0-9-]+\.",
        r"office365\.com\.[a-z0-9-]+\.",
        r"accounts\.google\.com\.[a-z0-9-]+\.",
    ], "AiTM", "T1557.003", "Generic AiTM hostname pattern — legit-brand domain inserted as subdomain prefix."),

    ("Generic OAuth abuse", [
        r"/oauth/authorize\?.*&redirect_uri=https?://[^/]+\.tk/",
        r"/oauth/authorize\?.*&redirect_uri=https?://[^/]+\.(top|xyz|pw)/",
        r"/oauth2/v2\.0/authorize\?.*scope=offline_access.*&state=[A-Z0-9]{8,}.*&redirect_uri=https?://[^/]+\.[a-z]{2,4}/",
    ], "OAuth Phishing", "T1528", "OAuth consent phishing — abuses real Microsoft/Google login flows."),

    ("Credential POST harvester", [
        r"/(login|signin|auth)/post\.php",
        r"/result\.php\?email=",
        r"/save\.php\?u=&p=",
        r"/log\.php\?username=",
    ], "Credential Theft", "T1056.003", "Crude credential-POST endpoints often found in pre-built phishing pages."),

    # ─── HTML-body fingerprints (require body snippet) ─────────────
    # Matched by separate function; URL patterns are empty here.
]


# Additional HTML body signatures — matched against a page body snippet if available.
HTML_BODY_SIGS = [
    ("Tycoon 2FA body",     r'"app":\s*"tycoon"|tycoon-?[a-z0-9]+\.css'),
    ("Sneaky 2FA body",     r"window\.sneaky|sneakyclient"),
    ("EvilProxy body",      r"evilproxy|proxy_session_id"),
    ("Greatness body",      r"greatness-?[a-z]{4,}\.js|/static/page\.html\?email="),
    ("16shop body",         r"sxteenshop|/loader/16shop"),
    ("BitB body",           r"data:text/html;base64,.*<title>Sign in"),
    ("ClickFix body",       r"navigator\.clipboard\.writeText\([\"'](?:powershell|cmd|mshta)"),
    ("Cloned MS sign-in",   r'fmHF|i0116|idA_PWD_ForgotPassword|"loginFmt"|loginfmt'),
    ("Cloned Google",       r'/_/IdentitierSignin/|identifier\?ifkv='),
]


def fingerprint(url: str, html: str | None = None) -> dict | None:
    """Return matched kit metadata or None."""
    if not url and not html:
        return None
    target = (url or "").lower()
    hits = []

    # URL-pattern scan
    for kit, patterns, category, mitre, desc in KIT_DEFINITIONS:
        matched = [p for p in patterns if re.search(p, target, re.IGNORECASE)]
        if matched:
            hits.append({
                "kit": kit,
                "category": category,
                "mitre": mitre,
                "description": desc,
                "patterns_matched": len(matched),
            })

    # HTML-body scan (if a snippet was provided)
    if html:
        body = html[:50000]  # first 50K chars is plenty
        for sig_name, pattern in HTML_BODY_SIGS:
            if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
                hits.append({
                    "kit": sig_name,
                    "category": "Page-content match",
                    "mitre": "T1566",
                    "description": "HTML body matched a known phishing-page signature.",
                    "patterns_matched": 1,
                })

    if not hits:
        return None
    # Most specific (highest match count) first
    hits.sort(key=lambda h: -h["patterns_matched"])
    return {"kit":   hits[0]["kit"],
            "all_hits": hits,
            "patterns_matched": hits[0]["patterns_matched"],
            "url_snippet": target[:160]}


def scan_urls(urls: list[str], html_bodies: dict | None = None) -> list[dict]:
    """Fingerprint a batch of URLs. html_bodies maps URL → body snippet (optional)."""
    out = []
    for u in urls or []:
        body = (html_bodies or {}).get(u)
        fp = fingerprint(u, body)
        if fp:
            fp["url"] = u
            out.append(fp)
    return out


def stats() -> dict:
    return {
        "phishing_kit_count": len(KIT_DEFINITIONS),
        "phishing_body_sig_count": len(HTML_BODY_SIGS),
    }

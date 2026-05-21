import re
import json
import time
import requests
from datetime import datetime

# --- Configuration ---
FRESHRSS_URL = "http://YOUR_FRESHRSS_IP"
FRESHRSS_USER = "YOUR_FRESHRSS_USERNAME"
FRESHRSS_API_PASS = "YOUR_FRESHRSS_API_PASSWORD"

SENTINEL_WORKSPACE_ID = "YOUR_LOG_ANALYTICS_WORKSPACE_ID"
SENTINEL_TENANT_ID = "YOUR_AZURE_TENANT_ID"
SENTINEL_CLIENT_ID = "YOUR_SERVICE_PRINCIPAL_CLIENT_ID"
SENTINEL_CLIENT_SECRET = "YOUR_SERVICE_PRINCIPAL_CLIENT_SECRET"

SLACK_WEBHOOK = None  # set to webhook URL to enable Slack alerts

HOURS_BACK = 24
MAX_ARTICLES = 50


# --- IOC Extraction ---
def extract_iocs(text):
    iocs = {
        "ips": [],
        "domains": [],
        "hashes_md5": [],
        "hashes_sha256": [],
        "cves": [],
    }

    ip_pattern = re.findall(
        r'\b(?!10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.)(?:\d{1,3}\.){3}\d{1,3}\b',
        text
    )
    iocs["ips"] = list(set(ip_pattern))

    domain_pattern = re.findall(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|tk|pw|top|xyz|info|biz|cc)\b',
        text
    )
    exclude_domains = {"github.com", "microsoft.com", "google.com", "twitter.com", "linkedin.com"}
    iocs["domains"] = list(set(d.lower() for d in domain_pattern if d.lower() not in exclude_domains))

    iocs["hashes_md5"] = list(set(re.findall(r'\b[a-fA-F0-9]{32}\b', text)))
    iocs["hashes_sha256"] = list(set(re.findall(r'\b[a-fA-F0-9]{64}\b', text)))
    iocs["cves"] = list(set(re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)))

    return iocs


# --- FreshRSS API ---
def freshrss_auth():
    resp = requests.post(
        f"{FRESHRSS_URL}/api/greader.php/accounts/ClientLogin",
        data={"Email": FRESHRSS_USER, "Passwd": FRESHRSS_API_PASS},
        timeout=10
    )
    for line in resp.text.split("\n"):
        if line.startswith("Auth="):
            return line.split("=")[1].strip()
    raise Exception("FreshRSS authentication failed")


def get_recent_articles(token, hours=24, max_results=50):
    headers = {"Authorization": f"GoogleLogin auth={token}"}
    since = int(time.time()) - (hours * 3600)
    resp = requests.get(
        f"{FRESHRSS_URL}/api/greader.php/reader/api/0/stream/contents/user/-/state/com.google/reading-list",
        headers=headers,
        params={"n": max_results, "ot": since},
        timeout=15
    )
    return resp.json().get("items", [])


# --- Azure Sentinel ---
def get_sentinel_token():
    url = f"https://login.microsoftonline.com/{SENTINEL_TENANT_ID}/oauth2/token"
    resp = requests.post(url, data={
        "grant_type": "client_credentials",
        "client_id": SENTINEL_CLIENT_ID,
        "client_secret": SENTINEL_CLIENT_SECRET,
        "resource": "https://api.loganalytics.io"
    }, timeout=10)
    return resp.json().get("access_token")


def query_sentinel(token, kql_query):
    url = f"https://api.loganalytics.io/v1/workspaces/{SENTINEL_WORKSPACE_ID}/query"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    resp = requests.post(url, headers=headers, json={"query": kql_query}, timeout=30)
    if resp.status_code == 200:
        tables = resp.json().get("tables", [])
        if tables and tables[0].get("rows"):
            return tables[0]["rows"]
    return []


def check_iocs_in_sentinel(sentinel_token, iocs):
    hits = []

    if iocs["ips"]:
        ip_list = '", "'.join(iocs["ips"])
        kql = f'''
let ips = dynamic(["{ip_list}"]);
union isfuzzy=true
    (CommonSecurityLog | where SourceIP in (ips) or DestinationIP in (ips) | project TimeGenerated, Type="CommonSecurityLog", IOC=coalesce(SourceIP, DestinationIP), Details=Activity),
    (SigninLogs | where IPAddress in (ips) | project TimeGenerated, Type="SigninLogs", IOC=IPAddress, Details=ResultDescription),
    (DeviceNetworkEvents | where RemoteIP in (ips) | project TimeGenerated, Type="DeviceNetworkEvents", IOC=RemoteIP, Details=ActionType)
| where TimeGenerated > ago(7d)
| limit 50
'''
        for row in query_sentinel(sentinel_token, kql):
            hits.append({"type": "IP", "ioc": row[2] if len(row) > 2 else "unknown", "source": row[1], "time": row[0]})

    if iocs["domains"]:
        domain_list = '", "'.join(iocs["domains"])
        kql = f'''
let domains = dynamic(["{domain_list}"]);
union isfuzzy=true
    (DnsEvents | where Name has_any (domains) | project TimeGenerated, Type="DnsEvents", IOC=Name, Details=ClientIP),
    (DeviceNetworkEvents | where RemoteUrl has_any (domains) | project TimeGenerated, Type="DeviceNetworkEvents", IOC=RemoteUrl, Details=ActionType)
| where TimeGenerated > ago(7d)
| limit 50
'''
        for row in query_sentinel(sentinel_token, kql):
            hits.append({"type": "Domain", "ioc": row[2] if len(row) > 2 else "unknown", "source": row[1], "time": row[0]})

    if iocs["hashes_sha256"] or iocs["hashes_md5"]:
        all_hashes = iocs["hashes_sha256"] + iocs["hashes_md5"]
        hash_list = '", "'.join(all_hashes)
        kql = f'''
let hashes = dynamic(["{hash_list}"]);
union isfuzzy=true
    (DeviceFileEvents | where SHA256 in (hashes) or MD5 in (hashes) | project TimeGenerated, Type="DeviceFileEvents", IOC=coalesce(SHA256, MD5), Details=ActionType),
    (SecurityAlert | where ExtendedProperties has_any (hashes) | project TimeGenerated, Type="SecurityAlert", IOC="hash matched", Details=AlertName)
| where TimeGenerated > ago(7d)
| limit 50
'''
        for row in query_sentinel(sentinel_token, kql):
            hits.append({"type": "Hash", "ioc": row[2] if len(row) > 2 else "unknown", "source": row[1], "time": row[0]})

    if iocs["cves"]:
        cve_list = '", "'.join(iocs["cves"])
        kql = f'''
let cves = dynamic(["{cve_list}"]);
SecurityAlert
| where AlertName has_any (cves) or Description has_any (cves)
| where TimeGenerated > ago(7d)
| project TimeGenerated, Type="SecurityAlert", IOC=AlertName, Details=Description
| limit 50
'''
        for row in query_sentinel(sentinel_token, kql):
            hits.append({"type": "CVE", "ioc": row[2] if len(row) > 2 else "unknown", "source": row[1], "time": row[0]})

    return hits


# --- Slack Notification ---
def post_to_slack(article_title, article_url, iocs, hits):
    if not SLACK_WEBHOOK:
        return

    ioc_summary = []
    if iocs["ips"]:
        ioc_summary.append(f"IPs: {', '.join(iocs['ips'][:5])}")
    if iocs["domains"]:
        ioc_summary.append(f"Domains: {', '.join(iocs['domains'][:5])}")
    if iocs["hashes_sha256"] or iocs["hashes_md5"]:
        ioc_summary.append(f"Hashes: {len(iocs['hashes_sha256'] + iocs['hashes_md5'])}")
    if iocs["cves"]:
        ioc_summary.append(f"CVEs: {', '.join(iocs['cves'])}")

    hit_details = "\n".join([
        f"- {h['type']} `{h['ioc']}` seen in {h['source']} at {h['time']}"
        for h in hits[:5]
    ])

    requests.post(SLACK_WEBHOOK, json={
        "text": f":rotating_light: *IOC Match in Sentinel*\n*Article:* <{article_url}|{article_title}>\n*IOCs:* {', '.join(ioc_summary)}\n*Matches:*\n{hit_details}"
    }, timeout=10)


# --- Main ---
def main():
    print(f"[{datetime.now()}] Starting IOC check...")

    freshrss_token = freshrss_auth()
    articles = get_recent_articles(freshrss_token, hours=HOURS_BACK, max_results=MAX_ARTICLES)
    print(f"Found {len(articles)} articles")

    sentinel_token = get_sentinel_token()
    results = []

    for article in articles:
        title = article.get("title", "")
        url = article.get("alternate", [{}])[0].get("href", "")
        content = article.get("summary", {}).get("content", "")
        full_text = f"{title} {content}"

        iocs = extract_iocs(full_text)
        total_iocs = sum(len(v) for v in iocs.values())

        if total_iocs == 0:
            continue

        print(f"Checking: {title[:60]} ({total_iocs} IOCs)")
        hits = check_iocs_in_sentinel(sentinel_token, iocs)

        if hits:
            print(f"  MATCH: {len(hits)} hit(s)")
            post_to_slack(title, url, iocs, hits)
            results.append({
                "article": title,
                "url": url,
                "iocs": iocs,
                "sentinel_hits": hits
            })
        else:
            print(f"  No matches")

    print(f"\n[{datetime.now()}] Done. {len(results)} article(s) with IOC matches.")

    if results:
        with open("ioc_matches.json", "w") as f:
            json.dump(results, f, indent=2)
        print("Results saved to ioc_matches.json")


if __name__ == "__main__":
    main()

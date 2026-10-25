# Sources and API keys

Generated from `backend/config.py` (`API_KEY_DEFINITIONS`). Keys load from `data/config.json`, and any of these names set as an environment variable overrides the file. `POST /api/settings` writes the file; `GET /api/settings` only returns masked values.

Environment only (ignored in `config.json`): `LLM_PROVIDER`, `OPENCTI_INSECURE_TLS`, `RECON_TAXII_FEEDS`, `RECON_TAXII_<SLUG>_COLLECTION`, `RECON_TAXII_<SLUG>_AUTH`, sidecar URLs `RECON_<SERVICE>_URL`, `MOBSF_KEY`, `AUTH_*`, `RECON_SECRET`, `RECON_EMBED_MODEL`.

## LLM Settings

| Key | Source | Required | Get it |
|---|---|---|---|
| `LLM_PROVIDER` | LLM Provider | no |  |
| `OPENAI_API_KEY` | OpenAI / Azure OpenAI Key | yes | https://platform.openai.com/api-keys |
| `OPENAI_BASE_URL` | OpenAI Base URL | no |  |
| `OPENAI_API_VERSION` | OpenAI · API Version (Azure only) | no |  |
| `AI_MODEL` | AI Model (deep reasoning) | no |  |
| `FAST_AI_MODEL` | Fast AI Model (light tasks) | no |  |
| `OLLAMA_BASE_URL` | Ollama Base URL | no |  |
| `OLLAMA_MODEL` | Ollama Model | no |  |

## API Keys

| Key | Source | Required | Get it |
|---|---|---|---|
| `VIRUSTOTAL_KEY` | VirusTotal API Key | no | https://virustotal.com |
| `ABUSEIPDB_KEY` | AbuseIPDB API Key | no | https://abuseipdb.com |
| `MALWAREBAZAAR_API_KEY` | MalwareBazaar Auth-Key | no | https://auth.abuse.ch |
| `IPINFO_TOKEN` | ipinfo.io Token | no | https://ipinfo.io |
| `OTX_KEY` | AlienVault OTX Key | no | https://otx.alienvault.com |
| `URLSCAN_KEY` | URLScan.io API Key | no | https://urlscan.io |
| `PULSEDIVE_KEY` | Pulsedive API Key | no | https://pulsedive.com |
| `CRIMINAL_IP_KEY` | Criminal IP API Key | no | https://www.criminalip.io |
| `ABUSECH_AUTH_KEY` | abuse.ch API Key | no | https://auth.abuse.ch |
| `WHOISXML_KEY` | Whois XML API Key | no | https://whoisxmlapi.com |
| `VULNERS_KEY` | Vulners API Key | no | https://vulners.com/userinfo |
| `PHISHTANK_KEY` | PhishTank Application Key (see known issue) | no | https://www.phishtank.com/api_register.php |
| `STALKPHISH_KEY` | Stalkphish API Key (see known issue) | no | https://www.stalkphish.io/ |
| `URLDNA_KEY` | URLdna API Key (see known issue) | no | https://urldna.io/ |
| `SECURITYTRAILS_KEY` | SecurityTrails API Key (see known issue) | no | https://securitytrails.com/corp/api |
| `LEAKIX_KEY` | LeakIX API Key (see known issue) | no | https://leakix.net/ |
| `NETLAS_KEY` | Netlas API Key (see known issue) | no | https://netlas.io/ |
| `ONYPHE_KEY` | Onyphe API Key (see known issue) | no | https://www.onyphe.io/ |
| `HUNTER_HOW_KEY` | Hunter.how API Key (see known issue) | no | https://hunter.how/ |
| `BINARYEDGE_KEY` | BinaryEdge API Key (see known issue) | no | https://www.binaryedge.io/ |
| `ZOOMEYE_KEY` | ZoomEye API Key (see known issue) | no | https://www.zoomeye.org/ |
| `VALIDIN_KEY` | Validin API Key (see known issue) | no | https://app.validin.com/ |
| `EMAILREP_KEY` | EmailRep API Key (see known issue) | no | https://emailrep.io/key |
| `HUDSONROCK_KEY` | Hudson Rock Cavalier API Key (see known issue) | no | https://www.hudsonrock.com/cavalier-api |
| `HUNTER_IO_KEY` | Hunter.io API Key (see known issue) | no | https://hunter.io/api_keys |
| `POLYSWARM_KEY` | Polyswarm API Key (see known issue) | no | https://polyswarm.io/ |
| `INTEZER_KEY` | Intezer Analyze API Key (see known issue) | no | https://analyze.intezer.com/account-details |
| `HYBRID_ANALYSIS_KEY` | Hybrid Analysis API Key (see known issue) | no | https://www.hybrid-analysis.com/apikeys/info |
| `TRIAGE_KEY` | Hatching Triage API Key (see known issue) | no | https://tria.ge/account/api |
| `KOODOUS_KEY` | Koodous API Key (see known issue) | no | https://koodous.com/settings/profile |
| `FILESCAN_KEY` | FileScan.io API Key (see known issue) | no | https://www.filescan.io/api |
| `MWDB_KEY` | MWDB (CERT.pl) API Key (see known issue) | no | https://mwdb.cert.pl/profile/user |
| `JOESANDBOX_KEY` | Joe Sandbox Cloud API Key (see known issue) | no | https://jbxcloud.joesecurity.org/ |
| `NUMVERIFY_KEY` | NumVerify API Key (see known issue) | no | https://numverify.com/ |
| `GITHUB_TOKEN` | GitHub Personal Access Token (see known issue) | no | https://github.com/settings/tokens |
| `GITLAB_TOKEN` | GitLab Personal Access Token (see known issue) | no | https://gitlab.com/-/user_settings/personal_access_tokens |
| `SOURCEGRAPH_TOKEN` | Sourcegraph Access Token (see known issue) | no | https://sourcegraph.com/user/settings/tokens |
| `CENSYS_API_KEY` | Censys API Key (Personal Access Token) | no | https://search.censys.io/account/api |
| `CENSYS_ID` | Censys API ID (legacy v2) | no | https://search.censys.io/account/api |
| `CENSYS_SECRET` | Censys API Secret (legacy v2) | no | https://search.censys.io/account/api |
| `GOOGLE_API_KEY` | Google Safe Browsing API Key | no | https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com |
| `HONEYPOT_KEY` | Project Honeypot HTTP:BL Key | no | https://www.projecthoneypot.org/httpbl_configure.php |
| `PROXYCHECK_KEY` | Proxycheck API Key | no | https://proxycheck.io |
| `MALTIVERSE_KEY` | Maltiverse API Key | no | https://maltiverse.com |
| `API_TOKEN` | API · X-API-Key shared secret | no |  |

## Email Composer

| Key | Source | Required | Get it |
|---|---|---|---|
| `EMAIL_FROM_NAME` | Email · Analyst Display Name | no |  |
| `EMAIL_FROM_ADDRESS` | Email · From Address | no |  |
| `EMAIL_SIGNATURE` | Email · Custom Signature | no |  |
| `EMAIL_TEAM_NAME` | Email · Team Name | no |  |
| `EMAIL_SMTP_HOST` | Email · SMTP Host | no |  |
| `EMAIL_SMTP_PORT` | Email · SMTP Port | no |  |
| `EMAIL_SMTP_USER` | Email · SMTP Username | no |  |
| `EMAIL_SMTP_PASSWORD` | Email · SMTP Password / App Password | no |  |
| `EMAIL_COPY_TO` | Email · Default CC | no |  |

## Outbound Integrations

| Key | Source | Required | Get it |
|---|---|---|---|
| `MISP_URL` | MISP · Base URL | no | https://www.misp-project.org |
| `MISP_KEY` | MISP · API Key | no |  |
| `MISP_VERIFYCERT` | MISP · Verify TLS Certificate | no |  |
| `THEHIVE_URL` | TheHive · Base URL | no | https://thehive-project.org |
| `THEHIVE_KEY` | TheHive · API Key | no |  |
| `THEHIVE_ORG` | TheHive · Organisation | no |  |
| `THEHIVE_TLP` | TheHive · Default TLP | no |  |
| `RECON_TAXII_FEEDS` | TAXII Feeds · Enabled Slugs | no |  |
| `RECON_TAXII_CISA_AIS_COLLECTION` | TAXII · CISA AIS Collection Override | no | https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/automated-indicator-sharing-ais |
| `FRESHRSS_URL` | FreshRSS · Base URL | no | https://www.freshrss.org |
| `FRESHRSS_API_KEY` | FreshRSS · API Key | no |  |
| `OPENCTI_URL` | OpenCTI · Base URL | no | https://www.opencti.io |
| `OPENCTI_TOKEN` | OpenCTI · API Token | no |  |
| `OPENCTI_INSECURE_TLS` | OpenCTI · Skip TLS Verification | no |  |

## Enricher Toggles

| Key | Source | Required | Get it |
|---|---|---|---|
| `RECON_ENABLE_MSRC` | Enrichers · Microsoft MSRC (slow) | no |  |
| `RECON_ENABLE_MOZILLA_OBSERVATORY` | Enrichers · Mozilla Observatory (slow) | no |  |
| `RECON_ENABLE_CAPA` | Enrichers · FLARE capa file capabilities (slow) | no |  |
| `RECON_ENABLE_OSV` | Enrichers · OSV.dev ecosystem CVEs | no |  |
| `RECON_ENABLE_RHSA` | Enrichers · Red Hat Security Data | no |  |
| `RECON_ENABLE_SHODAN_INTERNETDB` | Enrichers · Shodan InternetDB | no |  |

## Keyless sources

| Area | Sources |
|---|---|
| IP | Shodan InternetDB, Tor exit lists, Robtex, HackerTarget, CIRCL BGP Ranking, DShield, dataplane.org, Spamhaus DROP/EDROP, Feodo Tracker, ThreatView, ViriBack, StopForumSpam, ET compromised IPs, PhishStats, cloud IP ranges (AWS, GCP, Cloudflare, Fastly, GitHub), Team Cymru |
| Domain | who-dat WHOIS, Spamhaus DBL, crt.sh, crt.name, RapidDNS, subdomain.center, Common Crawl, Wayback Machine, dnstwister, M365 tenant recon, Mozilla Observatory (off by default), Tranco, Phishing.Database, OpenPhish |
| Hash | CIRCL hashlookup, MISP OSINT feeds (CIRCL, DigitalSide, Botvrij) |
| CVE | NVD, FIRST EPSS, CISA KEV, MSRC (off by default), OSV, Red Hat, CIRCL vulnerability-lookup, CISA Vulnrichment, vendor RSS (Adobe, Apple, Oracle), endoflife.date |
| Other | HIBP breach list, Pwned Passwords, OpenSanctions, Ransomwhere, ransomware.live, OpenSSF Scorecards, Wiz cloud threats, DFIQ |
| TAXII | CISA AIS (needs enrollment), MITRE ATT&CK TAXII, hailataxii and Anomali Limo (public guest logins) |

## Known issue

`run_enrichment()` (the `/api/analyze` path, `agents/enrichment.py`) only passes 13 keys to the `enrich_*` functions: VirusTotal, AbuseIPDB, IPinfo, urlscan, OTX, Pulsedive, Censys, Google, Project Honeypot, Criminal IP, abuse.ch. Sources marked "see known issue" check `keys.get(...)` for a key that is never passed, so they are skipped on that path even when the key is set. They still work through the investigation, MCP and skills paths where those build their own key dict.

# scripts

Custom Python tools built on top of the SOC lab stack. Writing your own tooling to extend a SIEM's capability is the difference between a detection analyst and a detection engineer.

## Tools

| Tool | What it does |
|------|-------------|
| [alert-enricher](alert-enricher/) | Takes a Wazuh alert, queries VirusTotal and GeoIP, outputs a formatted incident report |
| [ioc-extractor](ioc-extractor/) | Parses any text input and pulls out IPs, domains, hashes, URLs, CVEs |
| [coverage-reporter](coverage-reporter/) | Reads all Sigma rules, generates a MITRE ATT&CK coverage matrix showing gaps |
| [lab-health](lab-health/) | Checks every lab service and VM — returns up/down status in seconds |

## Usage

Each tool has its own README with full usage, requirements, and sample output. All tools require Python 3.9+.

```bash
pip install -r requirements.txt
```

## Lab context

These tools run against the live lab environment documented in [homelab](https://github.com/YOUR-USERNAME/homelab). The coverage reporter reads Sigma rules from [detection-rules](https://github.com/YOUR-USERNAME/detection-rules).

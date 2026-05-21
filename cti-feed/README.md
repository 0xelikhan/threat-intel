# cti-feed

FreshRSS deployment on Azure that aggregates 160 curated security RSS feeds with AI Threat Intel Summary. 

https://github.com/user-attachments/assets/0ef38a66-2d6e-4db1-9720-cedf2d4e11a4

## Overview

Pulls from 160 security RSS feeds covering threat research, vulnerability advisories, malware analysis, offensive security, and news. Every incoming article is automatically classified into CTI categories using Azure OpenAI. Articles can be summarized on demand using the AI Summary extension with a prompt tuned for SOC daily briefs.

I also built a custom FreshRSS extension ([xExtension-CTISummarizer](./xExtension-CTISummarizer)) that scores articles 1-10 on fetch using Azure OpenAI, auto-hides low-relevance content, and injects severity cards directly into article content.

## Architecture

```
160 RSS sources
    |
    v
FreshRSS (Docker, ARM64)             polls every 30 min
    |
    +-- EntryBeforeInsert hook
    |       |
    |       v
    |   xExtension-LlmClassification
    |       |
    |       v
    |   Azure OpenAI (gpt-4o)        classifies article into CTI categories
    |       |
    |       v
    |   applies cti/ tags to article
    |
    +-- entry_before_display hook
    |       |
    |       v
    |   xExtension-AiSummary
    |       |
    |       v
    |   Anthropic Claude              on-demand summarization per article
    |
    +-- SQLite (Docker volume)        persists feeds, articles, user state
```

```
Azure
+-- Resource group: freshrss-rg
+-- VM: Standard_B2pls_v2 (ARM64, Ubuntu 22.04, East US)
|   +-- Docker: FreshRSS container
|   +-- NSG: inbound 22 (SSH), 80 (HTTP)
+-- Public IP: static
+-- Azure OpenAI: cti-freshrss (Standard S0, East US)
    +-- Deployment: gpt-4o (2024-11-20)
```

## Stack

| Component | Detail |
|---|---|
| Application | FreshRSS 1.29.x |
| Runtime | Docker Engine 29.x on Ubuntu 22.04 (aarch64) |
| VM | Azure Standard_B2pls_v2 (2 vCPU ARM64, 4GB RAM) |
| Database | SQLite (embedded, Docker volume) |
| Classification | Azure OpenAI gpt-4o via REST |
| Summarization | Anthropic Claude via API |
| Feed format | RSS/Atom, OPML |

## Setup

### Prerequisites

- Azure subscription
- Azure OpenAI resource with a `gpt-4o` deployment
- Anthropic API key from console.anthropic.com
- SSH key added to the VM via `az vm user update`

### Deploy the VM

```powershell
az group create --name freshrss-rg --location eastus

az vm create \
  --resource-group freshrss-rg \
  --name freshrss-vm \
  --image Canonical:0001-com-ubuntu-server-jammy:22_04-lts-arm64:latest \
  --size Standard_B2pls_v2 \
  --admin-username azureuser \
  --generate-ssh-keys \
  --location eastus

az vm open-port --resource-group freshrss-rg --name freshrss-vm --port 80

az network public-ip update \
  --resource-group freshrss-rg \
  --name freshrss-vmPublicIP \
  --allocation-method Static
```

### Run FreshRSS

```bash
sudo docker run -d \
  --name freshrss \
  --restart unless-stopped \
  -p 80:80 \
  -v freshrss_data:/var/www/FreshRSS/data \
  -v freshrss_extensions:/var/www/FreshRSS/extensions \
  -e TZ=America/New_York \
  -e CRON_MIN='2,32' \
  freshrss/freshrss
```

### Install extensions

**LLM Classification** ships with FreshRSS 1.29 but may need to be installed manually:

```bash
cd /tmp
curl -L https://github.com/FreshRSS/Extensions/archive/refs/heads/master.zip -o extensions.zip
sudo apt install unzip -y
unzip extensions.zip
sudo docker cp /tmp/Extensions-main/xExtension-LlmClassification \
  freshrss:/var/www/FreshRSS/extensions/xExtension-LlmClassification
sudo docker restart freshrss
```

**AI Summary:**

```bash
cd /tmp
git clone https://github.com/deimosfr/xExtension-AiSummary.git
sudo docker cp /tmp/xExtension-AiSummary \
  freshrss:/var/www/FreshRSS/extensions/xExtension-AiSummary
sudo docker restart freshrss
```

### Configure LLM Classification

In FreshRSS: Settings > Extensions > LLM Classification > gear icon

| Field | Value |
|---|---|
| API URL | `https://YOUR-RESOURCE.openai.azure.com/openai/deployments/gpt-4o/chat/completions?api-version=2024-10-21` |
| API Key | Azure OpenAI Key 1 |
| Model | `gpt-4o` |
| Tag prefix | `cti/` |
| Enable tag classification | On |

Allowed tags (one per line):
```
ransomware
apt
vulnerability
malware
phishing
cloud
supply-chain
identity
ics-ot
```

User prompt:
```
You are a cyber threat intelligence analyst. Classify this article into one or more of the following categories based on its technical content. Only assign a category if the article contains specific, actionable threat intelligence related to that category.

Categories:
- ransomware: ransomware groups, campaigns, victims, TTPs, encryption, extortion
- apt: nation-state actors, APT groups, espionage, state-sponsored intrusions
- vulnerability: CVEs, zero-days, PoC exploits, patch advisories, active exploitation
- malware: malware families, RATs, stealers, loaders, botnets, C2 infrastructure
- phishing: phishing campaigns, BEC, AiTM, HTML smuggling, credential harvesting
- cloud: AWS/Azure/GCP attacks, IAM abuse, container escapes, cloud misconfigurations
- supply-chain: dependency confusion, malicious packages, build pipeline compromise
- identity: credential stuffing, password spray, MFA bypass, Kerberoasting, AD attacks
- ics-ot: ICS/SCADA/OT attacks, PLC vulnerabilities, critical infrastructure

Article title: {title}
Article content: {content}

If the article is marketing, vendor news, or opinion with no threat intelligence value, return {"tags": []}.
```

### Configure AI Summary

In FreshRSS: Settings > Extensions > AI Summary > gear icon

| Field | Value |
|---|---|
| AI Provider | Anthropic (Claude) |
| API Key | Your Anthropic API key |
| Model | `claude-haiku-4-5` |

Custom prompt:
```
You are a senior cyber threat intelligence analyst. Summarize this article in 3-5 sentences for a security operations team daily brief.

Focus only on:
- What happened (the specific threat, attack, vulnerability, or campaign)
- Who is affected or targeted
- What TTPs, IOCs, CVEs, or malware families are involved
- What action the team should be aware of

Do not include background context, vendor history, or general advice. Write in plain technical language. If the article contains no specific threat intelligence value, state that in one sentence.

Title: {title}
Content: {content}
```

## Usage

Import `cti-feed.opml` via Subscription management > Import/Export. 

Click the **AI Summarize** button inside any article to get an on-demand summary.

### User queries

Pre-configured filters in the left sidebar, each scoped to unread articles sorted by publication date.

| Query | Expression |
|---|---|
| Ransomware | `intitle:ransomware OR intitle:ransom OR intext:lockbit OR intext:blackcat OR intext:alphv OR intext:clop OR intext:akira OR intext:play OR intext:royal OR intext:medusa OR intext:blackbasta OR intext:"double extortion" OR intext:"ransom note" OR intext:conti OR intext:revil` |
| APT | `intitle:APT OR intext:"threat actor" OR intext:"nation-state" OR intext:lazarus OR intext:kimsuky OR intext:sandworm OR intext:"volt typhoon" OR intext:"salt typhoon" OR intext:turla OR intext:fin7 OR intext:"midnight blizzard" OR intext:"state-sponsored"` |
| Vulnerabilities | `intitle:CVE OR intitle:vulnerability OR intitle:"zero-day" OR intitle:RCE OR intitle:"proof of concept" OR intext:"actively exploited" OR intext:"patch tuesday" OR intext:CVSS OR intext:"authentication bypass" OR intext:"buffer overflow"` |
| Malware | `intitle:malware OR intitle:trojan OR intitle:backdoor OR intext:infostealer OR intext:stealer OR intext:botnet OR intext:RAT OR intext:loader OR intext:"cobalt strike" OR intext:mimikatz OR intext:emotet OR intext:redline OR intext:asyncrat` |
| Phishing | `intitle:phishing OR intext:phishing OR intext:"spear phishing" OR intext:"business email compromise" OR intext:BEC OR intext:AiTM OR intext:"QR code phishing" OR intext:"HTML smuggling"` |
| Cloud | `intitle:AWS OR intitle:Azure OR intitle:GCP OR intext:"cloud security" OR intext:"S3 bucket" OR intext:kubernetes OR intext:"service principal" OR intext:"managed identity" OR intext:IMDS` |
| Supply Chain | `intitle:"supply chain" OR intext:"supply chain attack" OR intext:"dependency confusion" OR intext:typosquatting OR intext:npm OR intext:PyPI OR intext:"malicious package"` |
| Identity | `intitle:OAuth OR intext:"credential stuffing" OR intext:"password spray" OR intext:"MFA bypass" OR intext:"golden ticket" OR intext:kerberoasting OR intext:"pass the hash" OR intext:DCSync OR intext:"active directory"` |
| ICS/OT | `intitle:ICS OR intitle:SCADA OR intitle:OT OR intitle:PLC OR intext:"operational technology" OR intext:"industrial control" OR intext:"critical infrastructure" OR intext:TRITON` |

CTI Summarizer

`xExtension-CTISummarizer` is a custom extension I built that scores articles 1-10 using Azure OpenAI on fetch rather than on demand. Articles below the threshold are silently marked as read before they surface. Articles above get a severity card (CRITICAL/HIGH/MEDIUM/LOW) with a two-sentence summary injected at the top of the content. See the `xExtension-CTISummarizer` folder for setup and configuration.




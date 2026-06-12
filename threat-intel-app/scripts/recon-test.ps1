# RECON one-shot test helper. Authenticates against a local backend,
# posts a paste through /api/analyze/sync, and prints a per-IOC source
# breakdown so backend fixes can be verified without driving the UI.
#
# Credentials are read from env vars so they never appear on argv or
# in shell history:
#   $env:RECON_USERNAME = "admin"
#   $env:RECON_PASSWORD = "..."
#   $env:RECON_URL      = "http://localhost:8000"   # optional, this is the default
#
# Usage:
#   ./recon-test.ps1 -Text "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
#   ./recon-test.ps1 -File ./paste.txt
#   ./recon-test.ps1 -Text "..." -Raw                # dump full result JSON
#   ./recon-test.ps1 -Text "..." -OutFile ./out.json # write JSON to file
[CmdletBinding()]
param(
    [string]$Text,
    [string]$File,
    [string]$Label = "",
    [string]$InputType = "log",
    [switch]$Raw,
    [string]$OutFile,
    [int]$TimeoutSec = 300
)

$ErrorActionPreference = "Stop"

$baseUrl = if ($env:RECON_URL) { $env:RECON_URL.TrimEnd('/') } else { "http://localhost:8000" }
$user    = $env:RECON_USERNAME
$pass    = $env:RECON_PASSWORD

if (-not $user -or -not $pass) {
    Write-Error "Set RECON_USERNAME and RECON_PASSWORD env vars before running."
}
if (-not $Text -and -not $File) {
    Write-Error "Provide -Text '<paste>' or -File <path>."
}
if ($File) {
    if (-not (Test-Path $File)) { Write-Error "File not found: $File" }
    $Text = Get-Content -Raw -Path $File
}

# ── 1. Authenticate ─────────────────────────────────────────────────────────
$session = $null
$loginBody = @{ username = $user; password = $pass } | ConvertTo-Json -Compress
try {
    $null = Invoke-RestMethod -Uri "$baseUrl/api/auth/login" `
        -Method POST -Body $loginBody -ContentType "application/json" `
        -SessionVariable session -TimeoutSec 30
} catch {
    Write-Error "Login failed against $baseUrl - $($_.Exception.Message)"
}

# ── 2. Submit paste ─────────────────────────────────────────────────────────
$body = @{ logText = $Text; inputType = $InputType; label = $Label } |
    ConvertTo-Json -Compress -Depth 5
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$r  = Invoke-RestMethod -Uri "$baseUrl/api/analyze/sync" `
    -Method POST -Body $body -ContentType "application/json" `
    -WebSession $session -TimeoutSec $TimeoutSec
$sw.Stop()

# ── 3. Persist / dump ───────────────────────────────────────────────────────
if ($OutFile) {
    $r | ConvertTo-Json -Depth 100 | Set-Content -Path $OutFile -Encoding utf8
    Write-Host "Wrote full result JSON to $OutFile"
}
if ($Raw) {
    $r | ConvertTo-Json -Depth 100
    return
}

# ── 4. Compact summary ──────────────────────────────────────────────────────
$rs = $r.response_summary
Write-Host ""
Write-Host ("=== RECON run · {0:N1}s total ===" -f $sw.Elapsed.TotalSeconds) -ForegroundColor Cyan
# response_summary doesn't carry a top-level `verdict` or `disposition` —
# threat_level is the canonical verdict and disposition lives nested at
# analyst_summary.disposition. The original strings were placeholder
# field paths from an earlier API draft; correcting so the summary
# header actually shows something.
$dispText = if ($rs.analyst_summary -and $rs.analyst_summary.disposition) {
    $rs.analyst_summary.disposition
} else { '(none)' }
$confText = if ($rs.confidence -ne $null) {
    "{0:P0}" -f [double]$rs.confidence
} else { 'n/a' }
Write-Host ("threat_level: {0}    confidence: {1}    disposition: {2}" -f `
    $rs.threat_level, $confText, $dispText)

# Stage timings. agent_trace mixes top-level stage completion events
# (status=complete with elapsed_ms set) AND tool-call sub-events the
# investigation agent emits (no status, no elapsed_ms — only `summary`
# describing the tool result). The earlier code summed every entry's
# elapsed_ms which printed "investigation=0ms" twice before the real
# completion. Filter to status=complete to get one row per stage.
if ($r.agent_trace) {
    $stages = $r.agent_trace |
        Where-Object { $_.status -eq 'complete' -and $_.elapsed_ms } |
        ForEach-Object { "{0}={1}ms" -f $_.agent, [int]$_.elapsed_ms }
    Write-Host ("stages: {0}" -f ($stages -join '  '))
    $tool_events = ($r.agent_trace | Where-Object { -not $_.status }).Count
    if ($tool_events -gt 0) {
        Write-Host ("        + {0} AI tool call{1}" -f $tool_events, $(if ($tool_events -eq 1) {''} else {'s'}))
    }
}

# Attribution — exactly what the frontend gate sees (≥75 score, ≥5 matched)
if ($rs.matched_actors) {
    Write-Host ""
    Write-Host "matched_actors (raw, ungated):" -ForegroundColor Yellow
    $rs.matched_actors | Select-Object -First 5 | ForEach-Object {
        $mt = if ($_.matchedTechniques) { $_.matchedTechniques.Count } else { 0 }
        Write-Host ("  {0,-25} score={1}%  matched={2}  total={3}" -f `
            $_.name, $_.score, $mt, $_.total_techniques)
    }
}

# Per-IOC source breakdown — surfaces which keys the backend populated
# so I can tell whether (e.g.) hybrid_analysis is missing because no
# hit or because the parser dropped it.
$buckets = @{
    'ip'     = $r.enrichments.ips
    'domain' = $r.enrichments.domains
    'url'    = $r.enrichments.urls
    'hash'   = $r.enrichments.hashes
    'email'  = $r.enrichments.emails
    'cve'    = $r.enrichments.cves
}
foreach ($kind in 'hash','ip','domain','url','cve','email') {
    $bucket = $buckets[$kind]
    if (-not $bucket) { continue }
    $bucket.PSObject.Properties | ForEach-Object {
        $ioc = $_.Name
        $d   = $_.Value
        Write-Host ""
        Write-Host ("--- {0} [{1}] ---" -f $ioc, $kind) -ForegroundColor Green
        # Per-IOC verdict from the GTI scorer (if scored). Backend stores
        # it under gti_scores (not scores) — the dict is keyed by IOC value.
        $score = $r.gti_scores.$ioc
        if ($score) {
            Write-Host ("  score={0}  verdict={1}" -f $score.score, $score.verdict)
            if ($score.contributing_factors) {
                foreach ($f in $score.contributing_factors) {
                    Write-Host ("    · {0}" -f $f) -ForegroundColor DarkGray
                }
            }
        }
        # Every populated source key — quick way to see what the per-IOC
        # card *would* surface (or wouldn't) given the current data.
        $d.PSObject.Properties | ForEach-Object {
            $k = $_.Name
            $v = $_.Value
            if ($null -eq $v) { return }
            if ($v -is [string] -and $v.Length -eq 0) { return }
            $marker = "ok"
            if ($v.PSObject.Properties.Name -contains 'error' -and $v.error) {
                $marker = "ERR: " + ($v.error | Out-String).Trim()
            } elseif ($v.PSObject.Properties.Name -contains 'verdict' -and $v.verdict) {
                $marker = "verdict=$($v.verdict)"
            } elseif ($v.PSObject.Properties.Name -contains 'found') {
                $marker = if ($v.found) { "found" } else { "not_found" }
            }
            Write-Host ("    {0,-22} {1}" -f $k, $marker)
        }
    }
}

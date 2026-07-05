<#
.SYNOPSIS
  Runs a sample-log smoke test against synthetic logs in .\samples.

.DESCRIPTION
  Gives users a realistic local dry-run and scrub workflow before using the tool
  with sensitive data. The samples are synthetic, but generated maps and local
  reports are still treated as local-only artifacts.
#>
[CmdletBinding()]
param(
    [string]$Salt = 'sample-only-do-not-use-in-production',
    [string]$WorkDir = (Join-Path $PSScriptRoot '..\samples\out\smoke-test'),
    [switch]$SkipRealScrub
)

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$modulePath = Join-Path $repoRoot 'UniversalLogScrubber\UniversalLogScrubber.psd1'
Import-Module $modulePath -Force

$env:SCRUB_SAMPLE_SALT = $Salt
$sampleRoot = Join-Path $repoRoot 'samples\logs'
$profileRoot = Join-Path $repoRoot 'docs\profiles\examples'
$seedFile = Join-Path $repoRoot 'samples\sample-seeds.txt'
$allowFile = Join-Path $repoRoot 'samples\sample-allowlist.txt'
$outRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($WorkDir)
New-Item -ItemType Directory -Path $outRoot -Force | Out-Null

$cases = @(
    @{ Name='Application NDJSON'; Path='app-auth.ndjson'; Profile='AppJson' },
    @{ Name='Cloud audit JSONL'; Path='cloud-audit.jsonl'; Profile='CloudAudit' },
    @{ Name='Gateway key/value'; Path='gateway-kv.log'; Profile='Logfmt' },
    @{ Name='VPN/firewall text'; Path='vpn-firewall.log'; Profile='Firewall' },
    @{ Name='Web access text'; Path='web-access.log'; Profile='WebAccess' },
    @{ Name='Windows Event XML text'; Path='sysmon-event-xml.txt'; Profile='WindowsEventXml' },
    @{ Name='ServiceNow incidents CSV'; Path='servicenow_incidents.csv'; Profile='ServiceNow' },
    @{ Name='Nexthink devices/executions CSV'; Path='nexthink_devices_executions.csv'; Profile='Nexthink' },
    @{ Name='M365 unified audit CSV'; Path='m365_unified_audit_log.csv'; Profile='IdentityProvider' },
    @{ Name='Sentinel incidents/alerts JSONL'; Path='sentinel_incidents_alerts.jsonl'; Profile='CloudAudit' },
    @{ Name='Firewall/VPN syslog text'; Path='firewall_vpn_syslog.log'; Profile='Firewall' },
    @{ Name='EDR alerts JSONL'; Path='edr_alerts.jsonl'; Profile='Edr' },
    @{ Name='Intune managed devices CSV'; Path='intune_managed_devices.csv'; Profile='Intune' },
    @{ Name='SCCM CMTrace client log'; Path='sccm_cmtrace_client.log'; Profile='SccmText' },
    @{ Name='Intune registry export'; Path='intune_registry_export.reg'; Profile='IntuneDiagnostics' },
    @{ Name='Intune MDM HTML report'; Path='intune_mdm_report.html'; Profile='IntuneDiagnostics' },
    @{ Name='Intune policy XML report'; Path='intune_policy_report.xml'; Profile='IntuneDiagnostics' },

    # Additional realistic synthetic samples and BYOP/profile-extension coverage.
    @{ Name='AWS CloudTrail management JSONL'; Path='aws-cloudtrail-management.jsonl'; Profile='CloudAudit'; ProfileExtensionFile='aws-cloudtrail-extension.json'; RawAbsent=@('ASIA0D270E0D7729C1D9','naomi.rivera@northstar.example') },
    @{ Name='Microsoft Entra sign-in CSV'; Path='entra-signin-logs.csv'; Profile='IdentityProvider'; ProfileExtensionFile='entra-signin-extension.json'; RawAbsent=@('naomi.rivera@northstar.example','LT-RIVER-7742') },
    @{ Name='Okta system log JSONL'; Path='okta-system-log.jsonl'; Profile='IdentityProvider'; ProfileExtensionFile='okta-system-log-extension.json'; RawAbsent=@('naomi.rivera@northstar.example','/api/v1/users/naomi.rivera') },
    @{ Name='Kubernetes audit JSONL'; Path='kubernetes-audit.jsonl'; ProfileFile='kubernetes-audit-profile.json'; RawAbsent=@('naomi.rivera@northstar.example','sk-test-') },
    @{ Name='Nginx reverse proxy access'; Path='nginx-reverse-proxy-access.log'; Profile='WebAccess'; ProfileExtensionFile='webaccess-query-token-extension.json'; RawAbsent=@('SESS-8K4T-2291-55bb44e4','naomi.rivera%40northstar.example') },
    @{ Name='Palo Alto traffic CSV'; Path='paloalto-traffic.csv'; ProfileFile='paloalto-traffic-csv-profile.json'; RawAbsent=@('CORP\naomi.rivera','LT-RIVER-7742') },
    @{ Name='Sysmon event XML text with strict extension'; Path='sysmon-event-xml.txt'; Profile='WindowsEventXml'; ProfileExtensionFile='strict-workstation-paths-extension.json'; RawAbsent=@('C:\Users\naomi.rivera','CORP\naomi.rivera') },
    @{ Name='PostgreSQL audit CSV'; Path='postgresql-audit.csv'; ProfileFile='database-audit-profile.json'; RawAbsent=@('naomi.rivera@northstar.example','sk-test-') },
    @{ Name='EDR process alerts JSONL'; Path='edr-process-alerts.jsonl'; Profile='Edr'; RawAbsent=@('C:\Users\naomi.rivera','naomi.rivera@northstar.example') }
)

$failures = New-Object System.Collections.Generic.List[string]
foreach ($case in $cases) {
    $inputPath = Join-Path $sampleRoot $case.Path
    if (-not (Test-Path -LiteralPath $inputPath)) {
        Write-Host "[SKIP] Sample missing: $($case.Path)" -ForegroundColor DarkYellow
        continue
    }
    $caseOut = Join-Path $outRoot (($case.Name -replace '[^A-Za-z0-9_.-]', '-').ToLowerInvariant())
    New-Item -ItemType Directory -Path $caseOut -Force | Out-Null

    $baseArgs = @{
        Path = $inputPath
        WorkDir = (Join-Path $caseOut 'dryrun')
        SaltFromEnv = 'SCRUB_SAMPLE_SALT'
        SeedFile = $seedFile
        AllowlistFile = $allowFile
        DryRun = $true
        ExplainDetections = $true
        NonInteractive = $true
        PassThru = $true
    }
    if ($case.Profile) { $baseArgs.Profile = $case.Profile }
    if ($case.ProfileFile) { $baseArgs.ProfileFile = Join-Path $profileRoot $case.ProfileFile }
    if ($case.ProfileExtensionFile) { $baseArgs.ProfileExtensionFile = Join-Path $profileRoot $case.ProfileExtensionFile }

    Write-Host ""
    Write-Host "=== $($case.Name) dry run ===" -ForegroundColor Cyan
    $dry = Invoke-UniversalScrubber @baseArgs
    $dryChanges = (@($dry | ForEach-Object { $_.ChangeCount }) | Measure-Object -Sum).Sum
    if ($dryChanges -le 0) { [void]$failures.Add("Dry run found no changes for $($case.Name)") }

    if (-not $SkipRealScrub) {
        Write-Host ""
        Write-Host "=== $($case.Name) real scrub ===" -ForegroundColor Cyan
        $realArgs = $baseArgs.Clone()
        $realArgs.Remove('DryRun')
        $realArgs.Remove('ExplainDetections')
        $realArgs.WorkDir = Join-Path $caseOut 'scrubbed'
        $realArgs.TokenMapMode = 'Replace'
        $realArgs.SafeBundleOut = Join-Path $caseOut 'scrubbed\safe-upload.zip'
        $realArgs.Force = $true
        $real = Invoke-UniversalScrubber @realArgs

        foreach ($r in @($real)) {
            if (-not $r.Clean) { [void]$failures.Add("Scrub failed for $($case.Name): $($r.Input)") }
            if ($case.RawAbsent -and $r.Output -and (Test-Path -LiteralPath $r.Output)) {
                $scrubbedText = Get-Content -Path $r.Output -Raw
                foreach ($raw in @($case.RawAbsent)) {
                    if ($scrubbedText -match [regex]::Escape([string]$raw)) {
                        [void]$failures.Add("Raw value remained for $($case.Name): $raw")
                    }
                }
            }
        }
    }
}

# Exercise the public profile builder on a realistic synthetic sample.
$builderOut = Join-Path $outRoot 'profile-builder'
New-Item -ItemType Directory -Path $builderOut -Force | Out-Null
$built = Invoke-UniversalScrubber `
    -BuildProfileFromSample `
    -Path (Join-Path $sampleRoot 'nginx-reverse-proxy-access.log') `
    -WorkDir $builderOut `
    -BaseProfile WebAccess `
    -ProfileOut (Join-Path $builderOut 'generated-webaccess-profile.json') `
    -ProfileReportOut (Join-Path $builderOut 'generated-webaccess-profile-report_DO_NOT_UPLOAD.md') `
    -Force `
    -NonInteractive `
    -PassThru

if (-not (Test-Path -LiteralPath $built.ProfilePath)) { [void]$failures.Add('Profile builder did not write a profile.') }
if (-not (Test-UniversalScrubberProfile -ProfileFile $built.ProfilePath -Quiet)) { [void]$failures.Add('Generated sample profile did not validate.') }

if ($failures.Count -gt 0) {
    Write-Host ""
    Write-Host "Sample log smoke test failed:" -ForegroundColor Red
    foreach ($f in $failures) { Write-Host " - $f" -ForegroundColor Red }
    exit 1
}

Write-Host ""
Write-Host "Sample log smoke test passed." -ForegroundColor Green

<#
.SYNOPSIS
  Universal, deterministic log scrubber. Builds a token map first, then scrubs
  one or many log files so they can leave a secure environment for analysis.

.DESCRIPTION
  This module generalizes the proven scrubbing engine from the AD CS ESC-audit
  pipeline into a log-type-agnostic tool. The engine is unchanged in spirit:

    * Every sensitive value is replaced by  PREFIX_<hmac>  where the HMAC is
      HMAC-SHA256(salt, normalized-value), truncated to a fixed length. The same
      real value ALWAYS collapses to the same token, in every file and every run
      that shares the salt -- that is what lets you correlate across files while
      never exposing the real value.

    * A private "token map" CSV records  realValue -> token  so YOU can re-identify
      findings later. It is secret and must never leave your environment.

    * Scrub success means every selected file produced a scrubbed output without
      a scrub or conversion failure. The run manifest records skipped and failed
      files for review.

  CAPABILITIES
  ------------
    * Pluggable token-map sources:
         - Discover   : build a map from the supplied logs.
         - ExistingMap: reuse a map already built for the same job/salt.
         - AD         : build an optional identity map from Active Directory.
    * Profile-driven field semantics for CSV, TSV, PSV, JSON/JSONL, key=value,
      syslog-style text, IIS/W3C, Windows Event exports, registry exports,
      Office/workbook text extraction, and broad diagnostic bundles.
    * A C# processing engine handles the fast path for text-like discovery,
      map-driven scrub, and event-log conversion. PowerShell remains
      the command surface, profile loader, converter host, AD adapter, and
      workflow orchestrator.
    * Intune diagnostics get field-aware event XML/report handling so AppLocker
      hashes, FQBN publisher strings, RuleIds, provider GUIDs, Microsoft
      publisher strings, and Windows system paths stay readable while real
      user/device/network identifiers are scrubbed.
    * Folder jobs use one shared token map, worker-based file parallelism,
      compact in-memory progress, and a compact manifest.
    * Safe bundles include successful scrub outputs and exclude private maps,
      salts, detailed reports, manifests, and intermediate files.

  CONSISTENCY GUARANTEE
  ---------------------
  Map-build, scrub and leak-harden all share ONE salt, ONE HMAC length and ONE
  normalizer for the session. The token map is authoritative: during scrubbing a
  value found in the map always resolves to its mapped token regardless of which
  code path encounters it, so tokens never diverge.

  SECURITY
  --------
    * The *_token_map_DO_NOT_UPLOAD.csv file is SECRET. Never upload it.
    * Upload only the *_scrubbed.* files.
    * Reuse the SAME salt for every run that must correlate.

  QUICK START
  -----------
    Import-Module .\UniversalLogScrubber\UniversalLogScrubber.psd1
    Invoke-UniversalScrubber              # fully interactive, hand-held
    Invoke-UniversalScrubber -Path C:\logs -Profile Generic -MapSource Discover

.NOTES
  PowerShell 5.1+ (Windows PowerShell and PowerShell 7 both fine). The AD map
  source additionally needs a domain-joined session with read rights; every other
  capability works anywhere, fully offline.
#>

# We deliberately do NOT enable Set-StrictMode globally -- the AD/LDAP path was
# written without it and forcing strict mode there could surface spurious errors.
# The helpers below are written to be strict-safe regardless.

# =====================================================================
# REGION: Session state (shared by every stage)
# =====================================================================
$script:ModuleName       = 'UniversalLogScrubber'
$script:ModuleVersion    = '1.0.0'
$script:Salt             = $null
$script:HmacLength       = 24
$script:TokenByNorm      = @{}     # normalized-value -> token (the loaded map)
$script:TokenMapLiteralRows = @()   # sorted InputValue -> Token rows used to harden derived output paths
$script:TokenMapCacheKey = $null   # "<path>|<lastwrite>" of the map in memory
$script:AdditionalBroadLabels = @()
$script:ScrubPolicy = 'Balanced'
$script:ExplainDetections = $false
$script:DetectionTrace = $null
$script:DetectionTraceSeen = @{}
$script:FalsePositiveReport = $null
$script:DetectionCounts = @{}
$script:DetectionSummaryReport = $null
$script:CurrentTokenMapCsv = $null
$script:TokenMapPathRows = @()
$script:TokenMapPathRules = @()
$script:DerivedPathProtectionCache = @{}

function Reset-UlsCSharpMapOnlyScrubberCache {
    # The CSharp scrubber embeds the token map in memory. Clear it whenever a
    # map is rebuilt, re-imported, or a new scrub phase starts so a long-lived
    # PowerShell session cannot reuse a stale map for the same output path.
    $script:CSharpMapOnlyScrubber = $null
    $script:CSharpMapOnlyScrubberCacheKey = $null
    $script:CSharpMapOnlyScrubberEntryCount = 0
}

function Get-UlsTokenMapFileCacheKey {
    param([Parameter(Mandatory)][string]$Path)
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $item = Get-Item -LiteralPath $resolved
    $base = "{0}|{1}|{2}" -f $resolved, [int64]$item.Length, [int64]$item.LastWriteTimeUtc.Ticks
    try {
        $hash = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256 -ErrorAction Stop).Hash
        return ("{0}|sha256:{1}" -f $base, $hash)
    }
    catch {
        return $base
    }
}
$script:TokenMapMode = 'Merge'
$script:CSharpAvailable = $false
$script:CSharpEngineVersion = ''
$script:CSharpFallbackReason = ''
$script:CSharpMapOnlyScrubber = $null
$script:CSharpMapOnlyScrubberCacheKey = $null
$script:CSharpMapOnlyScrubberEntryCount = 0
$script:RegexTimeout = [TimeSpan]::FromMilliseconds(250)
$script:CurrentProfile = $null
$script:RuntimeLabelRules = @()
$script:RuntimeCustomRegexRules = @()
$script:RuntimeAllowExact = @{}
$script:RuntimeAllowRegex = @()
$script:KnownTokenPrefixes = @(
    'PRINCIPAL','UNMAPPED_PRINCIPAL','UNMAPPED_UPN','COMPUTER','GROUP',
    'OBJECT','SID','DNS','UPN','EMAIL','CERT','TEMPLATE','CA','X500',
    'GUID','IP','IP6','HOST','URL','URI','MAC','JWT','ARN','AWSKEY',
    'INSTANCE','BLOB','SECRET','APIKEY','CONNSTR','PEM','FIELD','LABEL'
)

# =====================================================================
# REGION: Hot-path caches and regex settings
#   1. Per-file (column,value)->scrubbed memoization cache. Populated per file
#      in Invoke-ScrubFile; $null disables it so direct callers/discovery are
#      unaffected. See Scrub-Field.
#   2. Larger static regex cache. The free-text / secret / common / leak
#      hardening passes use static [regex]::Replace/Matches(string, pattern, ...)
#      calls that share the process-wide cache (default size 15). The per-cell
#      battery cycles through more than 15 distinct patterns, so they were being
#      evicted and recompiled on essentially every cell. Raising the cache keeps
#      them compiled. Pure speed; no behavior change.
# =====================================================================
$script:__cellCache = $null
$script:__hmacTokenCache = $null
[System.Text.RegularExpressions.Regex]::CacheSize = 256

# Low-risk perf patch: precompiled Windows user-profile path regexes. These are used
# only behind a cheap substring gate in Invoke-WindowsPathUserHardening. Behavior is
# intended to match the prior dynamic [regex]::Replace calls while avoiding repeated
# regex lookup/compile overhead on hot Windows Event Message/EventDataJson paths.
$script:__rxWinUserPathOptions = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
$script:__rxWinUserPathNormal = [System.Text.RegularExpressions.Regex]::new('((?:\\\?\\)?[A-Za-z]:\\Users\\)([^\\/"'',;:\r\n]+)', $script:__rxWinUserPathOptions, $script:RegexTimeout)
$script:__rxWinUserPathEscaped = [System.Text.RegularExpressions.Regex]::new('([A-Za-z]:\\\\Users\\\\)([^\\/"'',;:\r\n]+)', $script:__rxWinUserPathOptions, $script:RegexTimeout)


# Optional phase timing report (-PerfReport). Behavior-neutral: timings are collected only
# when enabled and are written at the end of Invoke-UniversalScrubber.
$script:PerfReportEnabled = $false
$script:PerfReportDetailedEnabled = $false
$script:PerfReportRows = $null
$script:PerfReportPath = $null
$script:PerfReportTextPath = $null

# Progress calls render only in-process console progress.
$script:UlsProgressState = @{}
$script:UlsProgressCursorWasVisible = $null
function Write-UlsProgress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Activity,
        [string]$Phase,
        [string]$File,
        [long]$RowsDone = -1,
        [long]$RowsTotal = -1,
        [long]$BytesDone = -1,
        [long]$BytesTotal = -1,
        [int]$Workers = -1,
        [int]$Pending = -1,
        [int]$Ready = -1,
        [int]$CompletedBatches = -1,
        [switch]$Completed,
        [switch]$Reset,
        [switch]$Force,
        [int]$MinIntervalMs = 1000
    )

    if ($Reset) {
        [void]$script:UlsProgressState.Remove($Activity)
        return
    }
    if ($Completed) {
        try { Write-Progress -Activity $Activity -Completed } catch { }

        try {
            if ($null -ne $script:UlsProgressCursorWasVisible) {
                [Console]::CursorVisible = [bool]$script:UlsProgressCursorWasVisible
                $script:UlsProgressCursorWasVisible = $null
            }
        }
        catch { }

        [void]$script:UlsProgressState.Remove($Activity)
        return
    }

    $now = [DateTime]::UtcNow
    $state = $null
    if ($script:UlsProgressState.ContainsKey($Activity)) { $state = $script:UlsProgressState[$Activity] }
    if ($null -eq $state) {
        $state = [pscustomobject]@{ LastUtc = [DateTime]::UtcNow.AddMilliseconds(-1 * [Math]::Max($MinIntervalMs, 1)); StartedUtc = [DateTime]::UtcNow; LastPercent = -2; LastStatus = '' }
        $script:UlsProgressState[$Activity] = $state
    }

    $pct = -1
    if ($BytesTotal -gt 0 -and $BytesDone -ge 0) {
        $pct = [Math]::Min(100, [Math]::Max(0, [int](($BytesDone / [double]$BytesTotal) * 100)))
    }
    elseif ($RowsTotal -gt 0 -and $RowsDone -ge 0) {
        $pct = [Math]::Min(100, [Math]::Max(0, [int](($RowsDone / [double]$RowsTotal) * 100)))
    }

    $bits = New-Object System.Collections.Generic.List[string]
    if ($RowsDone -ge 0 -and $RowsTotal -gt 0) {
        [void]$bits.Add(("files {0}/{1}" -f $RowsDone, $RowsTotal))
    }
    elseif ($RowsDone -ge 0) { [void]$bits.Add(("files {0}" -f $RowsDone)) }
    if ($BytesDone -ge 0 -and $BytesTotal -gt 0) {
        [void]$bits.Add(("{0:N1}/{1:N1} MB" -f ($BytesDone / 1MB), ($BytesTotal / 1MB)))
    }
    try {
        $elapsedSpan = $now - ([DateTime]$state.StartedUtc)
        [void]$bits.Add(("elapsed {0:hh\:mm\:ss}" -f $elapsedSpan))
    } catch { }
    $status = (($bits.ToArray()) -join ' | ')
    if ([string]::IsNullOrWhiteSpace($status)) { $status = 'Running' }

    $elapsedMs = ($now - ([DateTime]$state.LastUtc)).TotalMilliseconds
    if (-not $Force -and $elapsedMs -lt $MinIntervalMs -and $pct -eq [int]$state.LastPercent -and [string]$state.LastStatus -eq $status) { return }

    try {
        if ($pct -ge 0) {
            Write-Progress -Activity $Activity -Status $status -PercentComplete $pct
        }
        else {
            Write-Progress -Activity $Activity -Status $status
        }
    }
    catch { }
    $state.LastUtc = $now
    $state.LastPercent = $pct
    $state.LastStatus = $status
}

function New-UlsPerfStopwatch {
    if (-not $script:PerfReportEnabled) { return $null }
    return [System.Diagnostics.Stopwatch]::StartNew()
}

function Add-UlsPerfPhase {
    param(
        [Parameter(Mandatory)][string]$Phase,
        [System.Diagnostics.Stopwatch]$Stopwatch,
        [double]$Seconds = -1,
        [string]$File = '',
        [int]$Rows = -1,
        [int]$Cells = -1,
        [string]$Notes = ''
    )
    if (-not $script:PerfReportEnabled) { return }
    if ($null -eq $script:PerfReportRows) { $script:PerfReportRows = New-Object System.Collections.Generic.List[object] }
    if ($Stopwatch) {
        if ($Stopwatch.IsRunning) { $Stopwatch.Stop() }
        $Seconds = $Stopwatch.Elapsed.TotalSeconds
    }
    [void]$script:PerfReportRows.Add([pscustomobject]@{
        Phase   = $Phase
        File    = $File
        Seconds = [Math]::Round([double]$Seconds, 3)
        Rows    = $Rows
        Cells   = $Cells
        Notes   = $Notes
    })
}

function Write-UlsPerfReport {
    param([Parameter(Mandatory)][string]$WorkDir)
    if (-not $script:PerfReportEnabled) { return $null }
    if ($null -eq $script:PerfReportRows) { $script:PerfReportRows = New-Object System.Collections.Generic.List[object] }

    $csvPath = Resolve-OutPath -Path (Join-Path $WorkDir 'scrub_perf_report.csv')
    $txtPath = Resolve-OutPath -Path (Join-Path $WorkDir 'scrub_perf_report.txt')

    # Materialize the generic List[object] as a real object array.  Do not use
    # @($script:PerfReportRows): in some PowerShell/.NET combinations that wraps
    # the List object itself instead of enumerating its rows, which can produce
    # noisy post-run Export-Csv / type conversion errors even after scrubbing has
    # completed successfully.
    $rows = @(
        foreach ($r in $script:PerfReportRows) {
            if ($null -ne $r) { $r }
        }
    )

    if ($rows.Count -gt 0) {
        $rows |
            Select-Object Phase, File, Seconds, Rows, Cells, Notes |
            Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    }
    else {
        '"Phase","File","Seconds","Rows","Cells","Notes"' | Set-Content -Path $csvPath -Encoding UTF8
    }

    $lines = New-Object System.Collections.Generic.List[string]
    [void]$lines.Add('Universal Log Scrubber performance report')
    [void]$lines.Add(('GeneratedUtc: {0}' -f ((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))))
    [void]$lines.Add('')

    $preferred = @('Read CSV','Discover identifiers','Build/correlate map','Scrub fields','Post hardening','Write output')
    $grouped = $rows | Group-Object Phase
    $byPhase = @{}
    foreach ($g in $grouped) { $byPhase[[string]$g.Name] = [double](($g.Group | Measure-Object -Property Seconds -Sum).Sum) }

    foreach ($p in $preferred) {
        if ($byPhase.ContainsKey($p)) { [void]$lines.Add(('{0}: {1:N3} sec' -f $p, [double]$byPhase[$p])) }
        else { [void]$lines.Add(('{0}: 0.000 sec' -f $p)) }
    }
    $detailOnlyPhases = @('Scrub column')
    foreach ($k in ($byPhase.Keys | Sort-Object)) {
        if ($preferred -contains $k) { continue }
        if ($detailOnlyPhases -contains $k) { continue }
        [void]$lines.Add(('{0}: {1:N3} sec' -f $k, [double]$byPhase[$k]))
    }

    [void]$lines.Add('')
    [void]$lines.Add('Details:')
    foreach ($r in $rows) {
        $detail = '{0} | {1:N3}s | file={2} | rows={3} | cells={4}' -f $r.Phase, [double]$r.Seconds, $r.File, $r.Rows, $r.Cells
        if ($r.Notes) { $detail += ' | ' + [string]$r.Notes }
        [void]$lines.Add($detail)
    }

    [string[]]$lineArray = $lines.ToArray()
    [System.IO.File]::WriteAllLines($txtPath, $lineArray, [System.Text.Encoding]::UTF8)
    $script:PerfReportPath = $csvPath
    $script:PerfReportTextPath = $txtPath
    Write-Ok "Performance report written: $csvPath"
    Write-Ok "Performance summary written: $txtPath"
    return $csvPath
}

# =====================================================================
# REGION: Pretty console UI
# =====================================================================
$script:UiWidth = 72

# Write the banner
function Write-BannerLine {
    param(
        [string]$Text,
        [ConsoleColor]$TextColor = 'Cyan',
        [int]$Indent = 2
    )

    $w = $script:UiWidth
    $side = [string]([char]0x2551)
    $innerWidth = $w - 2

    $inner = (' ' * $Indent) + $Text

    if ($inner.Length -gt $innerWidth) {
        $inner = $inner.Substring(0, $innerWidth)
    }

    $inner = $inner.PadRight($innerWidth)

    Write-Host $side -ForegroundColor DarkCyan -NoNewline
    Write-Host $inner -ForegroundColor $TextColor -NoNewline
    Write-Host $side -ForegroundColor DarkCyan
}

function Write-BannerSegmentsLine {
    param(
        [Parameter(Mandatory)]
        [object[]]$Segments,

        [int]$Indent = 2
    )

    $w = $script:UiWidth
    $side = [string]([char]0x2551)
    $innerWidth = $w - 2

    $used = $Indent

    Write-Host $side -ForegroundColor DarkCyan -NoNewline
    Write-Host (' ' * $Indent) -NoNewline

    foreach ($segment in $Segments) {
        $text = [string]$segment.Text
        $color = [ConsoleColor]$segment.Color

        $remaining = $innerWidth - $used
        if ($remaining -le 0) {
            break
        }

        if ($text.Length -gt $remaining) {
            $text = $text.Substring(0, $remaining)
        }

        Write-Host $text -ForegroundColor $color -NoNewline
        $used += $text.Length
    }

    if ($used -lt $innerWidth) {
        Write-Host (' ' * ($innerWidth - $used)) -NoNewline
    }

    Write-Host $side -ForegroundColor DarkCyan
}

function Write-BannerInfoLine {
    param(
        [string]$Label,
        [string]$Value
    )

    Write-BannerSegmentsLine -Indent 2 -Segments @(
        @{ Text = "> $($Label.PadRight(12))"; Color = 'Cyan'  }
        @{ Text = $Value;                 Color = 'White' }
    )
}

function Write-Banner {
    $w = $script:UiWidth

    $tl   = [string]([char]0x2554)
    $tr   = [string]([char]0x2557)
    $bl   = [string]([char]0x255A)
    $br   = [string]([char]0x255D)
    $hz   = [string]([char]0x2550)
    $sepL = [string]([char]0x2560)
    $sepR = [string]([char]0x2563)

    $top = $tl + ($hz * ($w - 2)) + $tr
    $sep = $sepL + ($hz * ($w - 2)) + $sepR
    $bot = $bl + ($hz * ($w - 2)) + $br

    Write-Host ''
    Write-Host $top -ForegroundColor DarkCyan

    Write-BannerLine -Text "[>_] Universal Log Scrubber" -TextColor Magenta -Indent 4
    Write-BannerLine -Text "Share the logs, not the exposure." -TextColor DarkGray -Indent 4

    Write-Host $sep -ForegroundColor DarkCyan

    Write-BannerInfoLine -Label "Version" -Value "v$script:ModuleVersion"
    Write-BannerInfoLine -Label "Author"  -Value "glid3s"
    Write-BannerInfoLine -Label "Repo"    -Value "github.com/glid3s/universal-log-scrubber"

    Write-Host $bot -ForegroundColor DarkCyan
    Write-Host ''
}

function Write-Rule {
    param([string]$Label)
    $w = $script:UiWidth
    if ($Label) {
        $dash = [string]([char]0x2500)
        $left = ($dash * 3) + " " + $Label + " "
        Write-Host ($left + ($dash * [Math]::Max(0, $w - $left.Length))) -ForegroundColor DarkCyan
    }
    else {
        Write-Host ([string]([char]0x2500) * $w) -ForegroundColor DarkCyan
    }
}

function Write-Status {
    param(
        [Parameter(Mandatory)][ValidateSet('OK','WARN','FAIL','STEP','INFO','WORK')][string]$Tag,
        [Parameter(Mandatory)][string]$Message
    )
    switch ($Tag) {
        'OK'   { $label = '[ OK ]'; $c = 'Green' }
        'WARN' { $label = '[WARN]'; $c = 'Yellow' }
        'FAIL' { $label = '[FAIL]'; $c = 'Red' }
        'STEP' { $label = '[STEP]'; $c = 'Cyan' }
        'INFO' { $label = '[INFO]'; $c = 'Gray' }
        'WORK' { $label = '[ .. ]'; $c = 'DarkCyan' }
    }
    $timestamp = (Get-Date).ToString('HH:mm:ss')
    Write-Host $label -ForegroundColor $c -NoNewline
    Write-Host (" $timestamp") -ForegroundColor DarkGray -NoNewline
    Write-Host (" " + $Message)
}

function Write-Ok    { param([string]$m) Write-Status -Tag OK   -Message $m }
function Write-Warn  { param([string]$m) Write-Status -Tag WARN -Message $m }
function Write-Fail  { param([string]$m) Write-Status -Tag FAIL -Message $m }
function Write-Step  { param([string]$m) Write-Status -Tag STEP -Message $m }
function Write-Info  { param([string]$m) Write-Status -Tag INFO -Message $m }
function Write-Work  { param([string]$m) Write-Status -Tag WORK -Message $m }
function Write-Detail { param([string]$m) Write-Host ("       " + $m) -ForegroundColor DarkGray }

# =====================================================================
# REGION: Interactive prompt helpers
# =====================================================================
function Read-DefaultString {
    param([Parameter(Mandatory)][string]$Prompt, [string]$Default)
    if ($PSBoundParameters.ContainsKey('Default')) {
        $promptText = if ([string]::IsNullOrEmpty($Default)) { $Prompt } else { "$Prompt [$Default]" }
        $answer = Read-Host $promptText
        if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
        return $answer.Trim()
    }
    while ($true) {
        $answer = Read-Host $Prompt
        if (-not [string]::IsNullOrWhiteSpace($answer)) { return $answer.Trim() }
        Write-Warn "A value is required."
    }
}

function Read-YesNo {
    param([Parameter(Mandatory)][string]$Prompt, [bool]$Default = $true)
    $suffix = if ($Default) { "[Y/n]" } else { "[y/N]" }
    $answer = Read-Host "$Prompt $suffix"
    if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
    return ($answer.Trim() -match '^(y|yes)$')
}

# Numbered chooser. $Options is an array of @{ Key=...; Label=...; Detail=... }.
# Returns the chosen Key.
function Read-Choice {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter(Mandatory)][array]$Options,
        [int]$DefaultIndex = 1
    )
    for ($i = 0; $i -lt $Options.Count; $i++) {
        $n = $i + 1
        Write-Host ("   {0}) " -f $n) -ForegroundColor Cyan -NoNewline
        Write-Host $Options[$i].Label -ForegroundColor White
        if ($Options[$i].Detail) { Write-Host ("        " + $Options[$i].Detail) -ForegroundColor DarkGray }
    }
    $sel = Read-DefaultString -Prompt $Prompt -Default ([string]$DefaultIndex)
    $idx = 0
    if ([int]::TryParse($sel, [ref]$idx) -and $idx -ge 1 -and $idx -le $Options.Count) {
        return $Options[$idx - 1].Key
    }
    # allow typing the key directly
    foreach ($o in $Options) { if ($o.Key -ieq $sel) { return $o.Key } }
    Write-Warn "Unrecognized choice; using default."
    return $Options[$DefaultIndex - 1].Key
}

# Prompt once for the salt; entry is masked; cached for the whole session.
function Get-SessionSalt {
    if (-not [string]::IsNullOrWhiteSpace($script:Salt)) { return $script:Salt }
    Write-Host ""
    Write-Warn "A salt is required to tokenize values."
    Write-Detail "Use the SAME salt every time you want tokens to line up across files / runs."
    Write-Detail "Treat it like a password: anyone with the salt + a token map can re-identify."
    while ($true) {
        $secure = Read-Host "Enter salt" -AsSecureString
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try { $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        if ([string]::IsNullOrWhiteSpace($plain)) { Write-Warn "Salt cannot be empty."; continue }
        $script:Salt = $plain
        return $script:Salt
    }
}

# =====================================================================
# REGION: Paths
# =====================================================================
function Resolve-OutPath {
    param([Parameter(Mandatory)][string]$Path)
    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $dir = Split-Path -Parent $full
    if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    return $full
}

function Get-PathFingerprint {
    param([Parameter(Mandatory)][string]$Path, [int]$Length = 12)
    $resolved = try { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path) } catch { [string]$Path }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($resolved.ToLowerInvariant()))
        return (ConvertTo-HexString -Bytes $bytes).Substring(0, [Math]::Min([Math]::Max($Length, 4), 64)).ToUpperInvariant()
    }
    finally { $sha.Dispose() }
}

function ConvertTo-UlsSafePathSegment {
    param([string]$Segment)
    if ([string]::IsNullOrWhiteSpace($Segment)) { return '_' }
    $s = $Segment -replace '[<>:"|?*]', '_'
    $s = $s -replace '[\x00-\x1F]', '_'
    $s = $s.Trim()
    if ([string]::IsNullOrWhiteSpace($s)) { $s = '_' }
    return $s
}

function Test-UlsPathUnderRoot {
    param([string]$Path, [string]$Root)
    if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($Root)) { return $false }
    try {
        $pathFull = [System.IO.Path]::GetFullPath($Path).TrimEnd([char[]]@('\','/'))
        $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd([char[]]@('\','/'))
        return ($pathFull.Equals($rootFull, [System.StringComparison]::OrdinalIgnoreCase) -or
            $pathFull.StartsWith($rootFull + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase) -or
            $pathFull.StartsWith($rootFull + [System.IO.Path]::AltDirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase))
    }
    catch { return $false }
}

function Get-UlsRelativeDirectory {
    param([string]$Path, [string]$BasePath)
    if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($BasePath)) { return '' }
    if (-not (Test-UlsPathUnderRoot -Path $Path -Root $BasePath)) { return '' }
    try {
        $baseFull = [System.IO.Path]::GetFullPath($BasePath).TrimEnd([char[]]@('\','/')) + [System.IO.Path]::DirectorySeparatorChar
        $pathFull = [System.IO.Path]::GetFullPath($Path)
        $baseUri = [Uri]::new($baseFull)
        $pathUri = [Uri]::new($pathFull)
        $relative = [Uri]::UnescapeDataString($baseUri.MakeRelativeUri($pathUri).ToString()) -replace '/', [System.IO.Path]::DirectorySeparatorChar
        if ($relative -match '^\.\.') { return '' }
        $dir = [System.IO.Path]::GetDirectoryName($relative)
        if ([string]::IsNullOrWhiteSpace($dir)) { return '' }
        $parts = @($dir -split '[\\/]+' | Where-Object { $_ -and $_ -ne '.' -and $_ -ne '..' } | ForEach-Object { ConvertTo-UlsSafePathSegment -Segment $_ })
        if ($parts.Count -eq 0) { return '' }
        return ($parts -join [System.IO.Path]::DirectorySeparatorChar)
    }
    catch { return '' }
}

function Get-UlsRelativePathForManifest {
    param([string]$Path, [string]$BasePath)
    if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($BasePath)) { return '' }
    if (-not (Test-UlsPathUnderRoot -Path $Path -Root $BasePath)) { return '' }
    try {
        $baseFull = [System.IO.Path]::GetFullPath($BasePath).TrimEnd([char[]]@('\','/')) + [System.IO.Path]::DirectorySeparatorChar
        $pathFull = [System.IO.Path]::GetFullPath($Path)
        $baseUri = [Uri]::new($baseFull)
        $pathUri = [Uri]::new($pathFull)
        return ([Uri]::UnescapeDataString($baseUri.MakeRelativeUri($pathUri).ToString()) -replace '/', [System.IO.Path]::DirectorySeparatorChar)
    }
    catch { return '' }
}

function Get-UlsOutputContext {
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$WorkDir,
        [string]$InputRoot = '',
        [string[]]$CabExtractionRoots = @()
    )
    foreach ($root in @($CabExtractionRoots | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })) {
        if (Test-UlsPathUnderRoot -Path $InputPath -Root $root) {
            $leaf = Split-Path -Leaf $root
            if ([string]::IsNullOrWhiteSpace($leaf)) { $leaf = 'cab' }
            return [pscustomobject]@{
                OutDir   = (Join-Path $WorkDir (Join-Path 'cab_scrubbed' (ConvertTo-UlsSafePathSegment -Segment $leaf)))
                BasePath = $root
            }
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($InputRoot) -and (Test-UlsPathUnderRoot -Path $InputPath -Root $InputRoot)) {
        return [pscustomobject]@{ OutDir = $WorkDir; BasePath = $InputRoot }
    }
    if (Test-UlsPathUnderRoot -Path $InputPath -Root $WorkDir) {
        return [pscustomobject]@{ OutDir = $WorkDir; BasePath = $WorkDir }
    }
    return [pscustomobject]@{ OutDir = $WorkDir; BasePath = '' }
}


function Protect-UlsDerivedPathText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }

    # Derived output paths only need identity/device/network-ish map entries.
    # Keep this hot path cheap: output path derivation runs before the first
    # scrub progress update and can be called several times per target during
    # Intune/CAB/ETL runs. Regex objects are compiled once when the map loads,
    # and repeated directory/stem segments are memoized for the current map.
    $rules = @($script:TokenMapPathRules)
    if ($rules.Count -eq 0) { return $Text }

    $cacheKey = [string]$Text
    try {
        if ($script:DerivedPathProtectionCache -and $script:DerivedPathProtectionCache.ContainsKey($cacheKey)) {
            return [string]$script:DerivedPathProtectionCache[$cacheKey]
        }
    }
    catch { }

    $out = [string]$Text
    foreach ($rule in $rules) {
        try {
            $raw = [string]$rule.Input
            if ([string]::IsNullOrWhiteSpace($raw) -or $raw.Length -lt 3) { continue }
            if ($out.IndexOf($raw, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
            $rx = $rule.Regex
            $tok = [string]$rule.Token
            if ($null -eq $rx -or [string]::IsNullOrWhiteSpace($tok)) { continue }
            $out = $rx.Replace($out, $tok.Replace('$', '$$'))
        }
        catch { }
    }

    try {
        if ($null -eq $script:DerivedPathProtectionCache) { $script:DerivedPathProtectionCache = @{} }
        if ($script:DerivedPathProtectionCache.Count -lt 10000) { $script:DerivedPathProtectionCache[$cacheKey] = $out }
    }
    catch { }
    return $out
}

function Protect-UlsDerivedRelativePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    $parts = @($Path -split '[\\/]+' | Where-Object { $_ -ne '' })
    if ($parts.Count -eq 0) { return $Path }
    $safe = foreach ($part in $parts) { Protect-UlsDerivedPathText -Text ([string]$part) }
    return ($safe -join [System.IO.Path]::DirectorySeparatorChar)
}

function Get-SafeDerivedPath {
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$OutDir,
        [Parameter(Mandatory)][string]$Suffix,
        [string]$BasePath = '',
        [switch]$UseHash
    )
    $stem = [System.IO.Path]::GetFileNameWithoutExtension($InputPath) -replace '(?i)_UNSCRUBBED$', ''
    if ($UseHash) { $stem = "{0}_{1}" -f $stem, (Get-PathFingerprint -Path $InputPath -Length 8) }
    $stem = Protect-UlsDerivedPathText -Text $stem
    $targetDir = $OutDir
    $relDir = Get-UlsRelativeDirectory -Path $InputPath -BasePath $BasePath
    if (-not [string]::IsNullOrWhiteSpace($relDir)) { $targetDir = Join-Path $OutDir (Protect-UlsDerivedRelativePath -Path $relDir) }
    return (Join-Path $targetDir ($stem + $Suffix))
}

function New-UlsSkippedFileRecord {
    param(
        [Parameter(Mandatory)]$File,
        [Parameter(Mandatory)][string]$Reason,
        [string]$ActionRequired = ''
    )
    $full = ''
    $name = ''
    $ext = ''
    $bytes = -1L
    try { $full = [string]$File.FullName } catch { $full = [string]$File }
    try { $name = [string]$File.Name } catch { $name = [System.IO.Path]::GetFileName($full) }
    try { $ext = [string]$File.Extension } catch { $ext = [System.IO.Path]::GetExtension($full) }
    try { $bytes = [int64]$File.Length } catch { }
    return [pscustomobject]@{
        path           = $full
        name           = $name
        extension      = $ext
        bytes          = $bytes
        reason         = $Reason
        actionRequired = $ActionRequired
    }
}

function Test-UlsIntuneDiagnosticsTextFile {
    param([Parameter(Mandatory)]$File)
    $ext = ''
    try { $ext = ([string]$File.Extension).ToLowerInvariant() } catch { $ext = [System.IO.Path]::GetExtension([string]$File).ToLowerInvariant() }
    return ($ext -in @('.log','.txt','.reg','.html','.htm','.xml','.log_'))
}

function Expand-UlsCabArchive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$File,
        [Parameter(Mandatory)][string]$WorkDir
    )
    $cabPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath([string]$File.FullName)
    $name = [System.IO.Path]::GetFileNameWithoutExtension($cabPath)
    $safeName = (($name -replace '[^A-Za-z0-9_.-]', '_').Trim('_'))
    if ([string]::IsNullOrWhiteSpace($safeName)) { $safeName = 'cab' }
    $extractRoot = Join-Path $WorkDir ("cab_extract_DO_NOT_UPLOAD\{0}_{1}" -f $safeName, (Get-PathFingerprint -Path $cabPath -Length 8))
    if (Test-Path -LiteralPath $extractRoot) { Remove-Item -LiteralPath $extractRoot -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $extractRoot -Force | Out-Null

    $expandExe = $null
    if ($env:SystemRoot) {
        $candidate = Join-Path $env:SystemRoot 'System32\expand.exe'
        if (Test-Path -LiteralPath $candidate) { $expandExe = $candidate }
    }
    if (-not $expandExe) {
        $cmd = Get-Command expand.exe -ErrorAction SilentlyContinue
        if ($cmd) { $expandExe = $cmd.Source }
    }
    if (-not $expandExe) { throw "expand.exe was not found; CAB extraction is unavailable on this host." }

    Write-Work ("Extracting CAB locally: {0}" -f ([System.IO.Path]::GetFileName($cabPath)))
    $output = & $expandExe '-R' '-F:*' $cabPath $extractRoot 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("CAB extraction failed with exit code {0}: {1}" -f $LASTEXITCODE, (($output | ForEach-Object { [string]$_ }) -join ' '))
    }
    $files = @(Get-ChildItem -LiteralPath $extractRoot -Recurse -File -ErrorAction SilentlyContinue | Sort-Object FullName)
    Write-Ok ("CAB extracted: {0} file(s) under {1}" -f $files.Count, $extractRoot)
    return [pscustomobject]@{ Root = $extractRoot; Files = $files }
}

# =====================================================================
# REGION: Crypto / normalization / token core (schema-agnostic)
# =====================================================================
function ConvertTo-UlsCanonicalMacKey {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = $Value.Trim()
    if ($v -notmatch '(?i)^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$') { return $null }
    return ('mac:' + (($v -replace '[:-]', '').ToLowerInvariant()))
}

function Get-UlsMacAddressVariants {
    param([string]$Value)
    $key = ConvertTo-UlsCanonicalMacKey -Value $Value
    if (-not $key) { return @() }
    $hex = $key.Substring(4)
    $pairs = @()
    for ($i = 0; $i -lt 12; $i += 2) { $pairs += $hex.Substring($i, 2) }
    return @(($pairs -join ':'), ($pairs -join '-'))
}

function Normalize-SANValue {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = $Value.Trim()
    if     ($v -match '(?i)principal name\s*=\s*(.+)$') { $v = $matches[1] }
    elseif ($v -match '(?i)rfc822 name\s*=\s*(.+)$')    { $v = $matches[1] }
    elseif ($v -match '(?i)upn\s*=\s*(.+)$')            { $v = $matches[1] }
    elseif ($v -match '(?i)email\s*=\s*(.+)$')          { $v = $matches[1] }
    $v = $v -replace '(?i)^smtp:', ''
    $v = $v -replace '(?i)^mailto:', ''
    return $v.Trim()
}

function Normalize-TokenKey {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = Normalize-SANValue -Value $Value
    if ([string]::IsNullOrWhiteSpace($v)) { return $null }
    $macKey = ConvertTo-UlsCanonicalMacKey -Value $v
    if ($macKey) { return $macKey }
    return ($v.Trim() -replace "`r|`n", " ").ToLowerInvariant()
}

function ConvertTo-HexString {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return "" }
    # PowerShell pipeline-per-byte conversion is expensive in hot HMAC fallback paths.
    # BitConverter preserves the same byte-to-hex content; callers already normalize case.
    return ([System.BitConverter]::ToString($Bytes).Replace('-', '').ToLowerInvariant())
}

# Returns "PREFIX_<hex>" or $null if the value cannot be normalized.
function Invoke-HmacToken {
    param([Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)][string]$Prefix)
    $normalized = Normalize-TokenKey -Value $Value
    if (-not $normalized) { return $null }
    $salt = Get-SessionSalt
    $len = [Math]::Min([Math]::Max($script:HmacLength, 4), 64)

    # Low/medium-risk perf patch: cache deterministic HMAC fallback tokens during a file scrub.
    # Token-map hits still win before this function is called. The cache key includes salt,
    # output length, prefix, and normalized value so changing any token parameter cannot reuse
    # an incompatible token. $null disables caching for direct/discovery callers.
    $cacheKey = $salt + ([char]0) + ([string]$len) + ([char]0) + $Prefix + ([char]0) + $normalized
    if ($null -ne $script:__hmacTokenCache -and $script:__hmacTokenCache.ContainsKey($cacheKey)) {
        return $script:__hmacTokenCache[$cacheKey]
    }

    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($salt)
    $msgBytes = [System.Text.Encoding]::UTF8.GetBytes($normalized)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($keyBytes)
    try { $hash = $hmac.ComputeHash($msgBytes) } finally { $hmac.Dispose() }
    $hex = (ConvertTo-HexString -Bytes $hash).Substring(0, $len).ToUpperInvariant()
    $token = "$Prefix`_$hex"
    if ($null -ne $script:__hmacTokenCache) { $script:__hmacTokenCache[$cacheKey] = $token }
    return $token
}

function Resolve-UlsSaltInput {
    param([string]$Salt, [string]$SaltFromEnv, [string]$SaltFile)
    if ($SaltFile) {
        if (-not (Test-Path -LiteralPath $SaltFile)) { throw "Salt file not found: $SaltFile" }
        return ([System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $SaltFile).Path)).Trim()
    }
    if ($SaltFromEnv) {
        $envSalt = [Environment]::GetEnvironmentVariable($SaltFromEnv)
        if ([string]::IsNullOrWhiteSpace($envSalt)) { throw "Environment variable '$SaltFromEnv' is empty or not set." }
        return $envSalt
    }
    return $Salt
}

function Test-UlsProtectedTokenMatch {
    param([string]$Value, [string]$ProtectedToken, [ValidateSet('FIELD','LABEL')][string]$Prefix)
    if ([string]::IsNullOrWhiteSpace($Value) -or [string]::IsNullOrWhiteSpace($ProtectedToken)) { return $false }
    $tok = Invoke-HmacToken -Value $Value -Prefix $Prefix
    return (-not [string]::IsNullOrWhiteSpace($tok) -and [string]::Equals($tok, $ProtectedToken, [System.StringComparison]::OrdinalIgnoreCase))
}

function Test-UlsProtectedLabelRuleMatch {
    param($Rule, [string]$Label)
    $protected = @()
    try { if ($Rule.ProtectedLabels) { $protected = @($Rule.ProtectedLabels) } } catch { }
    if ($protected.Count -eq 0) { return $true }
    foreach ($p in $protected) {
        if (Test-UlsProtectedTokenMatch -Value $Label -ProtectedToken ([string]$p) -Prefix LABEL) { return $true }
    }
    return $false
}

function Is-AlreadyToken {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return (
        $Value -match '^(HV_)?(PRINCIPAL|COMPUTER|GROUP|OBJECT|SID|DNS|UPN|EMAIL|CERT|TEMPLATE|CA|X500|GUID|IP|IP6|HOST|URL|URI|MAC|JWT|ARN|AWSKEY|INSTANCE|BLOB|SECRET|APIKEY|CONNSTR|PEM|FIELD|LABEL)_[A-F0-9]{4,}$' -or
        $Value -match '^UNMAPPED_(UPN|PRINCIPAL|DNS|OBJECT|IP)_[A-F0-9]{4,}$' -or
        $Value -match '^(BROAD|ADCS|HV_GROUP|BUILTIN)_[A-Z0-9_]+$'
    )
}

# Windows well-known SID / group resolver. Optional but broadly useful for any
# Windows-sourced log -- collapses well-known principals to readable, non-secret
# labels instead of opaque hashes. Returns $null for anything not well-known.
function Get-CanonicalKnownLabelByValue {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $trimmed = $Value.Trim()
    $simple = $trimmed
    if     ($trimmed -match '^CN=([^,]+),') { $simple = $matches[1] }
    elseif ($trimmed -match '\\')           { $simple = ($trimmed -split '\\')[-1] }
    $simple = $simple.Trim()
    $simpleLower = $simple.ToLowerInvariant()

    switch -Regex ($trimmed) {
        '^S-1-1-0$'      { return "BROAD_EVERYONE" }
        '^S-1-5-11$'     { return "BROAD_AUTHENTICATED_USERS" }
        '^S-1-5-18$'     { return "BUILTIN_SYSTEM" }
        '^S-1-5-32-545$' { return "BROAD_BUILTIN_USERS" }
        '^S-1-5-32-544$' { return "HV_GROUP_BUILTIN_ADMINISTRATORS" }
        '^S-1-5-32-548$' { return "HV_GROUP_ACCOUNT_OPERATORS" }
        '^S-1-5-32-549$' { return "HV_GROUP_SERVER_OPERATORS" }
        '^S-1-5-32-550$' { return "HV_GROUP_PRINT_OPERATORS" }
        '^S-1-5-32-551$' { return "HV_GROUP_BACKUP_OPERATORS" }
        '-512$'          { return "HV_GROUP_DOMAIN_ADMINS" }
        '-513$'          { return "BROAD_DOMAIN_USERS" }
        '-515$'          { return "BROAD_DOMAIN_COMPUTERS" }
        '-516$'          { return "HV_GROUP_DOMAIN_CONTROLLERS" }
        '-517$'          { return "ADCS_GROUP_CERT_PUBLISHERS" }
        '-518$'          { return "HV_GROUP_SCHEMA_ADMINS" }
        '-519$'          { return "HV_GROUP_ENTERPRISE_ADMINS" }
        '-520$'          { return "HV_GROUP_GROUP_POLICY_CREATOR_OWNERS" }
        '-526$'          { return "HV_GROUP_KEY_ADMINS" }
        '-527$'          { return "HV_GROUP_ENTERPRISE_KEY_ADMINS" }
    }
    switch ($simpleLower) {
        "everyone"                      { return "BROAD_EVERYONE" }
        "authenticated users"           { return "BROAD_AUTHENTICATED_USERS" }
        "system"                        { return "BUILTIN_SYSTEM" }
        "local system"                  { return "BUILTIN_SYSTEM" }
        "nt authority\system"           { return "BUILTIN_SYSTEM" }
        "domain users"                  { return "BROAD_DOMAIN_USERS" }
        "domain computers"              { return "BROAD_DOMAIN_COMPUTERS" }
        "users"                         { return "BROAD_BUILTIN_USERS" }
        "builtin\users"                 { return "BROAD_BUILTIN_USERS" }
        "administrators"                { return "HV_GROUP_BUILTIN_ADMINISTRATORS" }
        "builtin\administrators"        { return "HV_GROUP_BUILTIN_ADMINISTRATORS" }
        "domain admins"                 { return "HV_GROUP_DOMAIN_ADMINS" }
        "enterprise admins"             { return "HV_GROUP_ENTERPRISE_ADMINS" }
        "schema admins"                 { return "HV_GROUP_SCHEMA_ADMINS" }
        "account operators"             { return "HV_GROUP_ACCOUNT_OPERATORS" }
        "server operators"              { return "HV_GROUP_SERVER_OPERATORS" }
        "print operators"               { return "HV_GROUP_PRINT_OPERATORS" }
        "backup operators"              { return "HV_GROUP_BACKUP_OPERATORS" }
        "domain controllers"            { return "HV_GROUP_DOMAIN_CONTROLLERS" }
        "enterprise domain controllers" { return "HV_GROUP_ENTERPRISE_DOMAIN_CONTROLLERS" }
        "group policy creator owners"   { return "HV_GROUP_GROUP_POLICY_CREATOR_OWNERS" }
        "key admins"                    { return "HV_GROUP_KEY_ADMINS" }
        "enterprise key admins"         { return "HV_GROUP_ENTERPRISE_KEY_ADMINS" }
        "dnsadmins"                     { return "HV_GROUP_DNSADMINS" }
        "cert publishers"               { return "ADCS_GROUP_CERT_PUBLISHERS" }
    }
    foreach ($label in $script:AdditionalBroadLabels) {
        if (-not [string]::IsNullOrWhiteSpace($label) -and $trimmed -eq $label) { return "BROAD_DOMAIN_USERS" }
    }
    return $null
}

# True when a dotted-decimal string should be LEFT INTACT as an OID / version
# number rather than tokenized -- i.e. it is NOT a valid IPv4 address. A 4-octet
# value with every octet 0-255 is treated as an IP (and tokenized). This is the
# fix for IPv4 addresses being silently preserved -- and skipped by the leak
# check -- because they matched the old "dotted-decimal == OID" guard.
function Test-PreserveDottedDecimal {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim()
    if ($v -notmatch '^([0-9]+\.)+[0-9]+$') { return $false }                                                 # not dotted-decimal at all
    if ($v -match '^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$') { return $false }     # valid IPv4 -> tokenize it
    return $true
}

# Single token resolver. Order:
#   already-a-token -> token map -> canonical safe label -> keep OID -> fresh HMAC.
# The token map is consulted before the HMAC fallback, so a mapped value always
# wins -- guaranteeing identical tokens no matter which path reaches it.
function Get-Token {
    param([Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)][string]$Prefix)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    $clean = $Value.Trim()
    if (Is-AlreadyToken -Value $clean) { return $clean }
    $norm = Normalize-TokenKey -Value $clean
    if ($norm -and $script:TokenByNorm.ContainsKey($norm)) { return $script:TokenByNorm[$norm] }
    if ($script:ScrubPolicy -ne 'Strict' -and (Test-UlsWellKnownSid -Value $clean)) { return $clean }
    if ($script:ScrubPolicy -ne 'Strict' -and (Test-UlsWellKnownWindowsPrincipal -Value $clean)) { return $clean }
    $known = Get-CanonicalKnownLabelByValue -Value $clean
    if ($known) { return $known }
    if (Test-PreserveDottedDecimal -Value $clean) { return $clean }   # leave OIDs / versions (not IPs) intact
    # ULS perf patch 5 (FP fix): never tokenize loopback / localhost on ANY path. The universal-label
    # path otherwise reached the HMAC fallback without the shape path's loopback guard, so values like
    # ::1 ended up tokenized. Gated -- Strict still tokenizes everything.
    if ($script:ScrubPolicy -ne 'Strict' -and (Test-PreserveIpAddress -Value $clean)) { return $clean }
    if ($script:ScrubPolicy -ne 'Strict' -and $Prefix -eq 'IP6' -and -not (Test-UlsValidIpv6Address -Value $clean)) { return $clean }
    $token = Invoke-HmacToken -Value $clean -Prefix $Prefix
    if ($token) { return $token }
    return $clean
}

# =====================================================================
# REGION: Shape detectors (single source of truth)
#   Used BOTH by discovery (what to put in the map) and by hardening (what to
#   replace). Keeping one list guarantees the two agree.
# =====================================================================
# Each entry: Name, Prefix, Rx (single-quoted regex, no anchors so it can be
# scanned anywhere in a string).
$script:ShapeDetectors = @(
    @{ Name = 'SID';       Prefix = 'SID';  Common = $true; Sentinel = 'S-1-'; Rx = 'S-1-\d+(?:-\d+)+' },
    @{ Name = 'GUID';      Prefix = 'GUID'; Common = $true; Rx = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' },
    @{ Name = 'Email/UPN'; Prefix = 'UNMAPPED_UPN'; Sentinel = '@'; Rx = '[A-Za-z0-9._%+\-$]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}' },
    @{ Name = 'IPv4';      Prefix = 'IP';   Rx = '(?<!\d)(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)(?!\.\d)' },
    @{ Name = 'DOMAIN\user'; Prefix = 'PRINCIPAL'; Rx = '(?<![A-Za-z0-9_.\-])[A-Za-z0-9_.\-]+\\[A-Za-z0-9_.\-$]+' },
    @{ Name = 'FQDN';      Prefix = 'DNS';  Rx = '(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}' },
    @{ Name = 'LongHex';   Prefix = 'CERT'; Rx = '(?<![A-Za-z0-9_])[0-9a-fA-F]{20,}(?![A-Za-z0-9_])' },
    # --- Additional detectors also applied at scrub time by Invoke-CommonDetectors ---
    @{ Name = 'JWT';       Prefix = 'JWT';  Common = $true; Sentinel = 'eyJ'; Rx = 'eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}' },
    @{ Name = 'AWS_ARN';   Prefix = 'ARN';  Common = $true; Sentinel = 'arn:'; Rx = 'arn:aws[A-Za-z0-9\-]*:[A-Za-z0-9\-]*:[A-Za-z0-9\-]*:[0-9]*:[A-Za-z0-9_/.:\-]+' },
    @{ Name = 'AWS_Key';   Prefix = 'AWSKEY'; Common = $true; Rx = '(?:AKIA|ASIA)[0-9A-Z]{16,24}' },
    @{ Name = 'CloudInstance'; Prefix = 'INSTANCE'; Common = $true; Sentinel = 'i-'; Rx = '\bi-[0-9a-f]{8,17}\b' },
    @{ Name = 'MAC';       Prefix = 'MAC';  Common = $true; Rx = '(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}' },
    @{ Name = 'IPv6';      Prefix = 'IP6';  Common = $true; Skip = '^\d{1,5}(:\d{1,5}){1,7}$'; Rx = '(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}|::(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,7}:' },
    @{ Name = 'Base64Blob'; Prefix = 'BLOB'; Common = $true; Rx = '(?<![A-Za-z0-9+/=_])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])' }
)

# Public / well-known domains we deliberately KEEP unredacted so scrubbed logs stay
# readable (and so the FQDN detector does not over-tokenize them). Extended per-run
# from the chosen profile's AllowedDomains.
$script:AllowedDomainsDefault = @(
    'microsoft.com','windows.com','microsoftonline.com','office.com','office365.com','live.com',
    'azure.com','windowsupdate.com','msftncsi.com','msn.com','bing.com','outlook.com','msedge.net',
    'google.com','googleapis.com','gstatic.com',
    'apple.com','mozilla.org','amazonaws.com','cloudflare.com','digicert.com','verisign.com',
    'collector.cc','localhost','localdomain','example.com','example.org','example.net'
)
$script:AllowedDomains = @($script:AllowedDomainsDefault)

function Test-AllowedDomain {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim().ToLowerInvariant()
    if ($v -match '@([^@]+)$') { $v = $matches[1] }   # email -> domain part
    foreach ($d in $script:AllowedDomains) {
        $dd = ([string]$d).Trim().ToLowerInvariant()
        if ($dd -and ($v -eq $dd -or $v.EndsWith('.' + $dd))) { return $true }
    }
    return $false
}

function Get-DetectionContext {
    param([string]$Text, [int]$Index, [int]$Length, [int]$Radius = 48)
    # ULS perf patch 3: this context string is only consumed by Add-DetectionTrace's
    # detailed trace, which is discarded unless -ExplainDetections or -FalsePositiveReport
    # is active (same gate as Add-DetectionTrace). Skip the Substring + regex on the common
    # (non-reporting) path. Test-DiagnosticContext no longer routes through here (it computes
    # its own window), so this gate cannot affect any preserve / scrub decision.
    if (-not $script:ExplainDetections -and [string]::IsNullOrWhiteSpace($script:FalsePositiveReport)) { return "" }
    if ([string]::IsNullOrEmpty($Text) -or $Index -lt 0) { return "" }
    $start = [Math]::Max(0, $Index - $Radius)
    $end = [Math]::Min($Text.Length, $Index + $Length + $Radius)
    return (($Text.Substring($start, $end - $start)) -replace "`r|`n", " ")
}

function Add-DetectionTrace {
    param(
        [string]$Detector,
        [string]$Action,
        [string]$Value,
        [string]$Token,
        [string]$Reason,
        [string]$ColumnName,
        [string]$Context
    )
    $countKey = ("{0}|{1}" -f $Detector, $Action)
    if (-not $script:DetectionCounts) { $script:DetectionCounts = @{} }
    if (-not $script:DetectionCounts.ContainsKey($countKey)) { $script:DetectionCounts[$countKey] = 0 }
    $script:DetectionCounts[$countKey] = [int]$script:DetectionCounts[$countKey] + 1
    if (-not $script:ExplainDetections -and [string]::IsNullOrWhiteSpace($script:FalsePositiveReport)) { return }
    if (-not $script:DetectionTraceSeen) { $script:DetectionTraceSeen = @{} }
    $traceKey = (@($Detector,$Action,$Value,$Token,$Reason,$ColumnName) | ForEach-Object { if ($null -eq $_) { '' } else { [string]$_ } }) -join ([string]([char]31))
    if ($script:DetectionTraceSeen.ContainsKey($traceKey)) { return }
    $script:DetectionTraceSeen[$traceKey] = $true
    if (-not $script:DetectionTrace) { $script:DetectionTrace = New-Object System.Collections.Generic.List[object] }
    [void]$script:DetectionTrace.Add([pscustomobject]@{
        Detector = $Detector
        Action   = $Action
        Value    = $Value
        Token    = $Token
        Reason   = $Reason
        Column   = $ColumnName
        Context  = $Context
    })
}

function Test-KnownFileOrDiagnosticName {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim().Trim('"', "'", '.', ',', ';', ':')
    return (
        $v -match '(?i)\.(exe|dll|sys|log|dat|xml|csv|txt|dmp|mdmp|tmp|etl|evtx|edb|asar|unpacked|jar|sqm|mui|cat|inf|pnf|cpp|cxx|cc|h|hpp|werinternalmetadata|msi|mca|so|bin|sav|xaml|drv)$' -or
        $v -match '(?i)^WER[.-]' -or
        $v -match '(?i)^WER\.[0-9a-f-]{8,}\.tmp\.(?:csv|mdmp|dmp)$' -or
        $v -match '(?i)^oem\d+\.(?:inf|pnf)$' -or
        $v -match '(?i)^Data\.[A-Za-z0-9_.-]+$' -or
        $v -match '(?i)^(?:PackageMetadata|App)\.AppX[A-Za-z0-9_.-]+$' -or
        $v -match '(?i)^DSS\d*\.log$' -or
        $v -match '(?i)^0x[0-9a-f]+$'
    )
}

function Test-WindowsDiagnosticDottedName {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim().Trim('"', "'", ',', ';', ':')
    return (
        (Test-KnownFileOrDiagnosticName -Value $v) -or
        $v -match '(?i)^(Microsoft|MicrosoftWindows)\.' -or
        $v -match '(?i)^Microsoft[A-Za-z0-9]+\.' -or
        $v -match '(?i)^(MicrosoftCorporationII|Global)\.' -or
        $v -match '(?i)^(System|Windows|YourPhone|Language\.Fonts|Rsat|ServerCoreFonts|Office|Activity|Result|context|snapshot|graph|currentPolicy|AggregatedJob|PackageMetadata|App|ndis)\.' -or
        $v -match '(?i)\.(Addin|AddinLoader|FormRegionAddin|Connect|FastConnect)(\.|$)' -or
        $v -match '(?i)^(OneNote|Outlook|Teams|UmOutlook|OscAddin|ShellExperienceHost|StartMenuExperienceHost|MicrosoftOfficeHub)\.' -or
        $v -match '(?i)^\d+\.[A-Za-z][A-Za-z0-9_]+$' -or
        $v -match '^\d+\.\d+(?:\.\d+)*(?:Z)?$' -or
        $v -match '^\d+\.\d{6,}Z$' -or
        $v -match '^[A-Za-z][A-Za-z0-9_-]*\d+(?:\.\d+){2,}$'
    )
}

function Test-UlsDiagnosticPathOnlyUri {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = (($Value.Trim().Trim('"', "'", '.', ',', ';', ':')) -replace '\\','/')
    if ($v -match '(?i)^x-windowsupdate://') { return $true }
    if ($v -match '(?i)^https?://[+*](?::\d+)?(?:/|$)') { return $true }
    if ($v -match '(?i)^https?://(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?(?:/|$)') { return $true }
    if ($v -match '(?i)^https?://schemas\.microsoft\.com/') { return $true }
    if ($v -match '(?i)^https?://[^/?#]*(?:microsoft|windowsupdate|windows|office|msft|teams|azure|live|bing|msedge)\.[A-Za-z0-9.-]+/') {
        if ($v -notmatch '(?i)[?&](?:token|access_token|refresh_token|sig|signature|key|client_secret)=') { return $true }
    }
    if ($v -match '(?i)^file:///(?:[A-Za-z]:/)?(?:Program(?:%20| )Files|Windows|ProgramData)/') { return $true }
    if ($v -match '^(?i)[a-z][a-z0-9+.-]*://') { return $false }
    return (
        $v -match '(?i)^NodeCache/MS DM Server/Nodes/\d+/(?:NodeUri|ExpectedValue)$' -or
        $v -match '(?i)^EnterpriseModernAppManagement/AppManagement/(?:AppStore|nonStore)/' -or
        $v -match '(?i)^Policy/Config/' -or
        $v -match '(?i)^EnrollmentStatusTracking/' -or
        $v -match '(?i)^Device/(?:Vendor|MSFT|[A-Za-z0-9_.-]+)/' -or
        $v -match '(?i)^Vendor/MSFT/[A-Za-z0-9_./-]+$' -or
        $v -match '(?i)^[A-Za-z0-9_. -]+/[A-Za-z0-9_./~{}()-]+/(?:Name|Version|Publisher|NodeUri|ExpectedValue|Status|State|Config)$'
    )
}

function Test-UlsContainsEmbeddedSensitiveValue {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim()
    return (
        $v -match '(?i)[A-Za-z0-9._%+\-$]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}' -or
        $v -match 'S-1-\d+(?:-\d)+' -or
        $v -match '(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}' -or
        $v -match '(?<!\d)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\d)' -or
        $v -match '(?i)\b(secret|token|password|passwd|pwd|credential|authorization|bearer|client[_-]*secret|api[_-]*key|private[_-]*key)\b'
    )
}

function Test-UlsSensitiveMapContext {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    return ($Text -match '(?i)\b(user|upn|email|mail|account|principal|tenant|aad|azure\s*ad|entra|device\s*id|managed\s*device|enrollment|serial|imei|meid|sid|mac|ip|host|hostname|computer|workstation|secret|token|password|passwd|pwd|credential|authorization|bearer|client[_\s-]*secret|api[_\s-]*key|private[_\s-]*key)\b')
}

function Test-WindowsPathLikeDomainUser {
    param([string]$Value, [string]$Text, [int]$Index = -1, [int]$Length = 0)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }
    $v = $Value.Trim()
    if ($v -notmatch '\\') { return $false }
    if ($v -match '(?i)^ReportArchive\\') { return $true }
    if ($v -match '(?i)^(?:Reports|ReportQueue|MISC|Driver|Drivers|Services|Channels|setup|WinGet|nativeimages|SCRIPTING|ROOT_HUB\d*|onedrive|defender|SideCarPolicies|Files|Tools|shared|Operational|Status|DefaultPowerSchemeValues|BackgroundCapability|CBS|Inventories|Catalog_Entries\d*|params|appcompatflags|HealthScripts|DRIVERENUM|DOTNET|build)\\') { return $true }
    if ($v -match '(?i)^MoUpdateO_[^\\]+\\') { return $true }
    if ($v -match '(?i)^(?:Intc[A-Za-z0-9_]*|IrDeviceV2|L2CAP|MIC|ISH_[A-Za-z0-9_]*|PNP\d+|REV_[A-Za-z0-9_]*|Col\d+|Q)\\') { return $true }
    if ($v -match '(?i)^(?:USB\\VID_[0-9A-F]{4}|Devices\\UEFI)') { return $true }
    if ($v -match '(?i)^AUTHORITY\\(?:NetworkService|LocalService|System)$') { return $true }
    if ($v -match '(?i)\\[^\\]+\.(?:dll|exe|xml|etl|inf|pnf|sys|mui|cat|manifest|log|txt|json)$') { return $true }
    if ($v -match '(?i)^(?:Microsoft|MicrosoftWindows|MicrosoftCorporationII|Global|msteams|AppUp|Realtek)[A-Za-z0-9_.-]*\\') { return $true }
    if ($v -match '(?i)^[A-Za-z0-9_.-]+_[0-9]+\.[0-9][A-Za-z0-9_.-]*__[A-Za-z0-9]+\\') { return $true }
    $first = ($v -split '\\', 2)[0].Trim()
    $second = ($v -split '\\', 2)[1].Trim()
    if ($first -match '(?i)^(windows|winnt|system32|syswow64|sysnative|systemroot|drivers|users|public|default|programdata|appdata|microsoft|program files( \(x86\))?|inf|temp|tmp|config|fonts|assembly|servicing|winsxs|tasks|spool|wbem|registry|device|harddiskvolume\d*|office\d+|wer|reportqueue|reportarchive|livekernelreports|whea)$') { return $true }
    if ($second -match '(?i)^(windows|wer|temp|system32|syswow64|office\d+)$') { return $true }
    if (Test-KnownFileOrDiagnosticName -Value $second) { return $true }
    if (-not [string]::IsNullOrEmpty($Text) -and $Index -ge 0) {
        $before = if ($Index -gt 0) { [string]$Text[$Index - 1] } else { '' }
        $aft = $Index + [Math]::Max($Length, $v.Length)
        $after = if ($aft -lt $Text.Length) { [string]$Text[$aft] } else { '' }
        if ((@('\', '/', ':', '?') -contains $before) -or (@('\', '/') -contains $after)) { return $true }
        $cs = [Math]::Max(0, $Index - 32)
        $ctx = $Text.Substring($cs, $Index - $cs)
        if (($ctx -match '[A-Za-z]:\\') -or ($ctx -match '\\\\\?\\') -or ($ctx -match '\\[^\\"'',;]*$')) { return $true }
    }
    return $false
}

function Test-LooksLikeBase64Blob {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim()
    if ($v.Length -lt 40) { return $false }
    if ($v -match '[\\:]') { return $false }
    if ($v -match '(?i)[a-z]{3,}/[a-z]{3,}/') { return $false }
    $pad = $v
    while (($pad.Length % 4) -ne 0) { $pad += '=' }
    try {
        $bytes = [Convert]::FromBase64String($pad)
        return ($bytes.Length -ge 24)
    }
    catch { return $false }
}

function Test-DiagnosticContext {
    param([string]$Text, [int]$Index, [int]$Length)
    # Computes its own context window (was Get-DetectionContext -Radius 80) so the perf
    # gate added to Get-DetectionContext cannot change this preserve decision. The window
    # math and the cleanup regex are identical to the previous behavior.
    if ([string]::IsNullOrEmpty($Text) -or $Index -lt 0) { return $false }
    $start = [Math]::Max(0, $Index - 80)
    $end   = [Math]::Min($Text.Length, $Index + $Length + 80)
    $ctx   = (($Text.Substring($start, $end - $start)) -replace "`r|`n", " ")
    return ($ctx -match '(?i)\b(WER|Windows Error Reporting|Fault bucket|Report Id|ReportQueue|ReportArchive|AppHang|LiveKernelEvent|Hashed bucket|Cab Guid|Attached files)\b')
}

function Test-PreserveIpAddress {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim()
    return ($v -match '^(127)(?:\.\d{1,3}){3}$' -or $v -eq '::1' -or $v -ieq 'localhost')
}

function Test-PreserveGuid {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim().Trim('{','}')
    return ($v -eq '00000000-0000-0000-0000-000000000000')
}

function New-ScrubRegex {
    param(
        [Parameter(Mandatory)][string]$Pattern,
        [string]$Context = 'regex',
        [System.Text.RegularExpressions.RegexOptions]$Options = ([System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Multiline)
    )
    try {
        return [regex]::new($Pattern, $Options, $script:RegexTimeout)
    }
    catch {
        throw "Invalid $Context '$Pattern': $($_.Exception.Message)"
    }
}

function Resolve-ProfileTokenPrefix {
    param([Parameter(Mandatory)][string]$Prefix, [string]$Context = 'profile rule')
    $p = $Prefix.Trim().ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($p)) { throw "$Context has an empty Prefix." }
    if (@($script:KnownTokenPrefixes | Where-Object { $_ -ieq $p }).Count -eq 0) {
        throw "$Context has invalid Prefix '$Prefix'. Expected one of: $($script:KnownTokenPrefixes -join ', ')."
    }
    return $p
}

function Get-ShannonEntropy {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return 0.0 }
    $counts = @{}
    foreach ($ch in $Value.ToCharArray()) {
        $k = [string]$ch
        if (-not $counts.ContainsKey($k)) { $counts[$k] = 0 }
        $counts[$k] = [int]$counts[$k] + 1
    }
    $entropy = 0.0
    foreach ($k in $counts.Keys) {
        $p = [double]$counts[$k] / [double]$Value.Length
        if ($p -gt 0) { $entropy -= $p * ([Math]::Log($p, 2)) }
    }
    return $entropy
}

function ConvertTo-ColumnRuleRegex {
    param([string]$Exact, [string]$Wildcard, [string]$Regex, [string]$Context)
    if (-not [string]::IsNullOrWhiteSpace($Regex)) { return (New-ScrubRegex -Pattern $Regex -Context $Context) }
    if (-not [string]::IsNullOrWhiteSpace($Wildcard)) {
        $pat = '^' + ([regex]::Escape($Wildcard) -replace '\\\*', '.*' -replace '\\\?', '.') + '$'
        return (New-ScrubRegex -Pattern $pat -Context $Context)
    }
    if (-not [string]::IsNullOrWhiteSpace($Exact)) {
        return (New-ScrubRegex -Pattern ('^' + [regex]::Escape($Exact) + '$') -Context $Context)
    }
    throw "$Context requires Exact, Wildcard, or Regex."
}

function ConvertTo-ProfileColumnRules {
    param($Rules, [string]$DefaultAction = 'Scan', [string]$DefaultPrefix = 'OBJECT', [string]$Context = 'profile column rule')
    $out = New-Object System.Collections.Generic.List[object]
    $defaultPrefixResolved = Resolve-ProfileTokenPrefix -Prefix $DefaultPrefix -Context $Context
    foreach ($r in @($Rules)) {
        if ($null -eq $r) { continue }
        if ($r -is [string]) {
            $rx = ConvertTo-ColumnRuleRegex -Exact $r -Context $Context
            [void]$out.Add([pscustomobject]@{ RegexObject=$rx; ProtectedExact=@(); Action=$DefaultAction; Prefix=$defaultPrefixResolved; SplitOn=$null; Description='' })
            continue
        }
        $actionRaw = if ($r.Action) { [string]$r.Action } else { $DefaultAction }
        $actionMatch = @('Scrub','Scan','PassThrough') | Where-Object { $_ -ieq $actionRaw } | Select-Object -First 1
        if (-not $actionMatch) { throw "$Context has invalid Action '$actionRaw'. Expected Scrub, Scan, or PassThrough." }
        $action = [string]$actionMatch
        $prefixRaw = if ($r.Prefix) { [string]$r.Prefix } else { $defaultPrefixResolved }
        $prefix = Resolve-ProfileTokenPrefix -Prefix $prefixRaw -Context $Context
        $exactValues = @()
        if ($r.Exact) { $exactValues += @($r.Exact) }
        if ($r.Column) { $exactValues += @($r.Column) }
        if ($r.Columns) { $exactValues += @($r.Columns) }
        if ($r.Name) { $exactValues += @($r.Name) }
        $wildcards = @()
        if ($r.Wildcard) { $wildcards += @($r.Wildcard) }
        if ($r.Pattern -and -not $r.Regex) { $wildcards += @($r.Pattern) }
        $regexes = @()
        if ($r.Regex) { $regexes += @($r.Regex) }
        if ($r.Match -eq 'Regex' -and $r.Pattern) { $regexes += @($r.Pattern) }
        $protectedExact = @()
        if ($r.ProtectedExact) { $protectedExact += @($r.ProtectedExact) }
        foreach ($ex in $exactValues) {
            if ([string]::IsNullOrWhiteSpace([string]$ex)) { continue }
            $rx = ConvertTo-ColumnRuleRegex -Exact ([string]$ex) -Context $Context
            [void]$out.Add([pscustomobject]@{ RegexObject=$rx; ProtectedExact=@(); Action=$action; Prefix=$prefix; SplitOn=$r.SplitOn; Description=([string]$r.Description) })
        }
        foreach ($wc in $wildcards) {
            if ([string]::IsNullOrWhiteSpace([string]$wc)) { continue }
            $rx = ConvertTo-ColumnRuleRegex -Wildcard ([string]$wc) -Context $Context
            [void]$out.Add([pscustomobject]@{ RegexObject=$rx; ProtectedExact=@(); Action=$action; Prefix=$prefix; SplitOn=$r.SplitOn; Description=([string]$r.Description) })
        }
        foreach ($re in $regexes) {
            if ([string]::IsNullOrWhiteSpace([string]$re)) { continue }
            $rx = ConvertTo-ColumnRuleRegex -Regex ([string]$re) -Context $Context
            [void]$out.Add([pscustomobject]@{ RegexObject=$rx; ProtectedExact=@(); Action=$action; Prefix=$prefix; SplitOn=$r.SplitOn; Description=([string]$r.Description) })
        }
        $protectedClean = @($protectedExact | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
        if ($protectedClean.Count -gt 0) {
            [void]$out.Add([pscustomobject]@{ RegexObject=$null; ProtectedExact=@($protectedClean); Action=$action; Prefix=$prefix; SplitOn=$r.SplitOn; Description=([string]$r.Description) })
        }
    }
    return @($out.ToArray())
}

function Read-ScrubListFile {
    param([Parameter(Mandatory)][string]$Path, [string]$BasePath)
    $p = $Path
    if (-not [System.IO.Path]::IsPathRooted($p) -and $BasePath) { $p = Join-Path $BasePath $p }
    if (-not (Test-Path -LiteralPath $p)) { throw "List file not found: $Path" }
    $items = New-Object System.Collections.Generic.List[string]
    foreach ($line in [System.IO.File]::ReadLines((Resolve-Path -LiteralPath $p).Path)) {
        $t = ([string]$line).Trim()
        if ([string]::IsNullOrWhiteSpace($t) -or $t.StartsWith('#')) { continue }
        [void]$items.Add($t)
    }
    return @($items.ToArray())
}

function Merge-ScrubTerms {
    param([string[]]$Terms = @(), [string[]]$Files = @(), [string]$BasePath)
    $seen = @{}
    foreach ($term in @($Terms)) {
        $t = ([string]$term).Trim()
        if ($t.Length -lt 3) { continue }
        $k = $t.ToLowerInvariant()
        if (-not $seen.ContainsKey($k)) { $seen[$k] = $t }
    }
    foreach ($file in @($Files)) {
        if ([string]::IsNullOrWhiteSpace($file)) { continue }
        foreach ($term in (Read-ScrubListFile -Path $file -BasePath $BasePath)) {
            $t = ([string]$term).Trim()
            if ($t.Length -lt 3) { continue }
            $k = $t.ToLowerInvariant()
            if (-not $seen.ContainsKey($k)) { $seen[$k] = $t }
        }
    }
    return @($seen.Values | Sort-Object)
}

function Add-AllowlistEntry {
    param($Entry, [string]$BasePath)
    if ($null -eq $Entry) { return }
    if ($Entry -is [string]) {
        $t = $Entry.Trim()
        if ([string]::IsNullOrWhiteSpace($t)) { return }
        if ($t -match '(?i)^regex:(.+)$') {
            $script:RuntimeAllowRegex += (New-ScrubRegex -Pattern $matches[1].Trim() -Context 'allowlist regex')
        }
        elseif ($t -match '(?i)^domain:(.+)$') {
            $script:AllowedDomains += @($matches[1].Trim())
        }
        else {
            $script:RuntimeAllowExact[$t.ToLowerInvariant()] = $true
        }
        return
    }
    if ($Entry.Domain) { $script:AllowedDomains += @([string]$Entry.Domain) }
    if ($Entry.Regex) { $script:RuntimeAllowRegex += (New-ScrubRegex -Pattern ([string]$Entry.Regex) -Context 'allowlist regex') }
    if ($Entry.Value) { $script:RuntimeAllowExact[([string]$Entry.Value).Trim().ToLowerInvariant()] = $true }
    if ($Entry.Exact) { foreach ($v in @($Entry.Exact)) { if ($v) { $script:RuntimeAllowExact[([string]$v).Trim().ToLowerInvariant()] = $true } } }
}

function Test-ScrubAllowlist {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim().Trim('"', "'", '.', ',', ';', ':', '}', ']', ')')
    if ($script:RuntimeAllowExact -and $script:RuntimeAllowExact.ContainsKey($v.ToLowerInvariant())) { return $true }
    foreach ($rx in @($script:RuntimeAllowRegex)) {
        if ($rx.IsMatch($v)) { return $true }
    }
    if (Test-AllowedDomain -Value $v) { return $true }
    return $false
}

function Get-DefaultUniversalLabelRules {
    return @(
        [pscustomobject]@{ Name='SecretLabels'; Labels=@('api key','api_key','apikey','access token','access_token','refresh token','refresh_token','client secret','client_secret','secret','password','passwd','pwd','authorization','auth token','bearer token'); Prefix='SECRET'; SeparatorRegex='[:=]'; ValueRegex=$null; PreserveRegex='(?i)^(redacted|masked|null|none|\*+|x+)$' },
        [pscustomobject]@{ Name='PrincipalLabels'; Labels=@('account name','account','user name','username','user','principal','subject','actor','caller','login','identity','client user'); Prefix='PRINCIPAL'; SeparatorRegex='[:=]'; ValueRegex=$null; PreserveRegex=$null },
        [pscustomobject]@{ Name='DomainTenantLabels'; Labels=@('account domain','domain','tenant','tenant id','tenantid','organization','org','realm'); Prefix='X500'; SeparatorRegex='[:=]'; ValueRegex=$null; PreserveRegex=$null },
        [pscustomobject]@{ Name='HostLabels'; Labels=@('host','hostname','server','server name','machine','machine name','computer','computer name','device','workstation','workstation name','client name','target server name','pod','container','node','instance'); Prefix='DNS'; SeparatorRegex='[:=]'; ValueRegex=$null; PreserveRegex=$null },
        [pscustomobject]@{ Name='AddressLabels'; Labels=@('ip','ip address','src_ip','dst_ip','source ip','destination ip','source address','destination address','source network address','client address','remote addr','remote_addr','x-forwarded-for'); Prefix='IP'; SeparatorRegex='[:=]'; ValueRegex=$null; PreserveRegex=$null },
        [pscustomobject]@{ Name='UrlLabels'; Labels=@('url','uri','endpoint','callback','redirect_uri','redirect uri'); Prefix='URI'; SeparatorRegex='[:=]'; ValueRegex=$null; PreserveRegex=$null },
        [pscustomobject]@{ Name='ObjectIdLabels'; Labels=@('session','session id','sessionid','request id','requestid','correlation id','correlationid','trace id','traceid','span id','spanid','transaction id','transactionid'); Prefix='OBJECT'; SeparatorRegex='[:=]'; ValueRegex=$null; PreserveRegex=$null }
    )
}

function ConvertTo-UniversalLabelRule {
    param($Rule, [string]$Context = 'label rule')
    $name = if ($Rule.Name) { [string]$Rule.Name } else { $Context }
    $prefixRaw = if ($Rule.Prefix) { [string]$Rule.Prefix } else { 'OBJECT' }
    $prefix = Resolve-ProfileTokenPrefix -Prefix $prefixRaw -Context "$Context '$name'"
    $sep = if ($Rule.SeparatorRegex) { [string]$Rule.SeparatorRegex } else { '[:=]' }
    $valueRx = if ($Rule.ValueRegex) { [string]$Rule.ValueRegex } else { '(?:"[^"\r\n]{1,512}"|''[^''\r\n]{1,512}''|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|NT AUTHORITY|Window Manager|Font Driver Host|[^,\s;|]{1,512})' }
    $labelRx = $null
    $protectedLabels = @()
    if ($Rule.ProtectedLabels) { $protectedLabels += @($Rule.ProtectedLabels) }
    if ($Rule.LabelRegex) { $labelRx = [string]$Rule.LabelRegex }
    else {
        $labels = @()
        if ($Rule.Labels) { $labels += @($Rule.Labels) }
        if ($Rule.Label) { $labels += @($Rule.Label) }
        if ($labels.Count -gt 0) {
            $labelRx = (($labels | ForEach-Object { [regex]::Escape(([string]$_).Trim()) }) -join '|')
        }
        elseif ($protectedLabels.Count -gt 0) {
            $labelRx = '[A-Za-z][A-Za-z0-9_. -]{1,80}'
        }
        else {
            throw "$Context '$name' requires Labels, ProtectedLabels, or LabelRegex."
        }
    }
    $full = "(?im)((?<![A-Za-z0-9_])(?:$labelRx)(?![A-Za-z0-9_])\s*(?:$sep)\s*)($valueRx)"
    $preserve = if ($Rule.PreserveRegex) { New-ScrubRegex -Pattern ([string]$Rule.PreserveRegex) -Context "$Context preserve regex" } else { $null }
    $allow = @{}
    if ($Rule.Preserve) { foreach ($p in @($Rule.Preserve)) { if ($p) { $allow[([string]$p).Trim().ToLowerInvariant()] = $true } } }
    return [pscustomobject]@{
        Name = $name
        Prefix = $prefix
        RegexObject = (New-ScrubRegex -Pattern $full -Context "$Context '$name'")
        ProtectedLabels = @($protectedLabels | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
        PreserveRegex = $preserve
        PreserveExact = $allow
    }
}

function Get-UniversalLabeledValuePrefix {
    param([string]$Label, [string]$Value, [string]$DefaultPrefix)
    $v = ([string]$Value).Trim().Trim('"', "'")
    if ([string]::IsNullOrWhiteSpace($v)) { return $null }
    if ($DefaultPrefix -match '^(SECRET|APIKEY|CONNSTR|PEM)$') { return $DefaultPrefix }
    if ($Label -match '(?i)(key|secret|token|password|passwd|pwd|auth)') { return 'SECRET' }
    if ($Label -match '(?i)(address|addr|ip|x-forwarded)') {
        if ($v -match '^\d{1,3}(\.\d{1,3}){3}$') { return 'IP' }
        if ($v -match ':') { return 'IP6' }
        return 'DNS'
    }
    if ($Label -match '(?i)(url|uri|endpoint|callback|redirect)') { return 'URI' }
    if ($Label -match '(?i)(host|server|machine|computer|device|workstation|node|pod|container|instance|client name)') { return 'DNS' }
    if ($Label -match '(?i)(domain|tenant|organization|org|realm)') { return 'X500' }
    if ($v -match '\$$') { return 'COMPUTER' }
    if ($DefaultPrefix) { return $DefaultPrefix }
    return 'OBJECT'
}

function Test-PreserveUniversalLabeledValue {
    param($Rule, [string]$Label, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    $v = $Value.Trim().Trim('"', "'", '.', ',', ';', ':', '}', ']', ')')
    if ([string]::IsNullOrWhiteSpace($v)) { return $true }
    if (Is-AlreadyToken -Value $v) { return $true }
    if (Test-ScrubAllowlist -Value $v) { return $true }
    if ($Rule.PreserveExact -and $Rule.PreserveExact.ContainsKey($v.ToLowerInvariant())) { return $true }
    if ($Rule.PreserveRegex -and $Rule.PreserveRegex.IsMatch($v)) { return $true }
    if ($v -match '^(?:-|N/A|NULL|\(null\))$') { return $true }
    if ($v -match '(?i)^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|Guest|DefaultAccount|WDAGUtilityAccount|DWM-\d+|UMFD-\d+)$') { return $true }
    if ($v -match '(?i)^(WORKGROUP|NT AUTHORITY|BUILTIN|Window Manager|Font Driver Host)$') { return $true }
    if (($Label -match '(?i)(Address|IP|addr)') -and (Test-PreserveIpAddress -Value $v)) { return $true }
    if (($Label -match '(?i)(url|uri|endpoint|callback|redirect)') -and (Test-UlsDiagnosticPathOnlyUri -Value $v)) { return $true }
    if (($Label -match '(?i)(url|uri|endpoint|callback|redirect)') -and $v -notmatch '^(?i)[a-z][a-z0-9+.-]*://' -and -not (Test-UlsContainsEmbeddedSensitiveValue -Value $v)) { return $true }
    return $false
}

function Find-UlsUniversalLabeledIdentifiersCore {
    param([Parameter(Mandatory)][string]$Text)
    $found = @{}
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    foreach ($rule in @($script:RuntimeLabelRules)) {
        foreach ($m in $rule.RegexObject.Matches($Text)) {
            $label = ($m.Groups[1].Value -replace '\s*(?:[:=])\s*$', '').Trim()
            $raw = $m.Groups[2].Value.Trim().Trim('"', "'")
            if (-not (Test-UlsProtectedLabelRuleMatch -Rule $rule -Label $label)) { continue }
            if (Test-PreserveUniversalLabeledValue -Rule $rule -Label $label -Value $raw) { continue }
            $prefix = Get-UniversalLabeledValuePrefix -Label $label -Value $raw -DefaultPrefix $rule.Prefix
            if (-not $prefix) { continue }
            $norm = Normalize-TokenKey -Value $raw
            if ($norm -and -not $found.ContainsKey($norm)) {
                $found[$norm] = [pscustomobject]@{ Raw = $raw; Prefix = $prefix; Rule = $rule.Name }
            }
        }
    }
    return @($found.Values)
}

function Invoke-UniversalLabelHardening {
    param([Parameter(Mandatory)][string]$Text, [string]$ColumnName)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    $out = $Text
    foreach ($rule in @($script:RuntimeLabelRules)) {
        $out = $rule.RegexObject.Replace($out, {
            param($m)
            $prefixText = $m.Groups[1].Value
            $label = ($prefixText -replace '\s*(?:[:=])\s*$', '').Trim()
            $raw = $m.Groups[2].Value.Trim().Trim('"', "'")
            if (-not (Test-UlsProtectedLabelRuleMatch -Rule $rule -Label $label)) { return $m.Value }
            if (Test-PreserveUniversalLabeledValue -Rule $rule -Label $label -Value $raw) { return $m.Value }
            # Apply the same low-signal label filter the discovery and leak-check finders use,
            # so scrub behavior agrees with discovery and avoids junk words after labels.
            if (Test-UlsLowSignalUniversalLabelValue -Value $raw -Rule $rule.Name) { return $m.Value }
            $prefix = Get-UniversalLabeledValuePrefix -Label $label -Value $raw -DefaultPrefix $rule.Prefix
            if (-not $prefix) { return $m.Value }
            $tok = Get-Token -Value $raw -Prefix $prefix
            Add-DetectionTrace -Detector 'UniversalLabel' -Action 'Tokenized' -Value $raw -Token $tok -Reason $rule.Name -ColumnName $ColumnName -Context (Get-DetectionContext -Text $Text -Index $m.Index -Length $m.Length)
            return $prefixText + $tok
        })
    }
    return $out
}

function Test-RuleAllowlistedSecret {
    param($Rule, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    $v = $Value.Trim().Trim('"', "'")
    if (Test-ScrubAllowlist -Value $v) { return $true }
    if ($Rule.AllowExact -and $Rule.AllowExact.ContainsKey($v.ToLowerInvariant())) { return $true }
    foreach ($rx in @($Rule.AllowRegex)) { if ($rx.IsMatch($v)) { return $true } }
    if ($Rule.Entropy -and ((Get-ShannonEntropy -Value $v) -lt [double]$Rule.Entropy)) { return $true }
    return $false
}

function Find-CustomRegexIdentifiers {
    param([Parameter(Mandatory)][string]$Text)
    $found = @{}
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    foreach ($rule in @($script:RuntimeCustomRegexRules)) {
        if ($rule.Keywords -and $rule.Keywords.Count -gt 0) {
            $hasKeyword = $false
            foreach ($kw in @($rule.Keywords)) { if ($Text.IndexOf([string]$kw, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $hasKeyword = $true; break } }
            if (-not $hasKeyword) { continue }
        }
        foreach ($m in $rule.RegexObject.Matches($Text)) {
            $group = [int]$rule.CaptureGroup
            if ($group -ge $m.Groups.Count -or -not $m.Groups[$group].Success) { continue }
            $raw = $m.Groups[$group].Value.Trim().Trim('"', "'")
            if (Test-RuleAllowlistedSecret -Rule $rule -Value $raw) { continue }
            if (Is-AlreadyToken -Value $raw) { continue }
            $norm = Normalize-TokenKey -Value $raw
            if ($norm -and -not $found.ContainsKey($norm)) {
                $found[$norm] = [pscustomobject]@{ Raw = $raw; Prefix = $rule.Prefix; Rule = $rule.Name }
            }
        }
    }
    return @($found.Values)
}

function Invoke-CustomRegexHardening {
    param([Parameter(Mandatory)][string]$Text, [string]$ColumnName)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    $out = $Text
    foreach ($rule in @($script:RuntimeCustomRegexRules)) {
        if ($rule.Keywords -and $rule.Keywords.Count -gt 0) {
            $hasKeyword = $false
            foreach ($kw in @($rule.Keywords)) { if ($out.IndexOf([string]$kw, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $hasKeyword = $true; break } }
            if (-not $hasKeyword) { continue }
        }
        $out = $rule.RegexObject.Replace($out, {
            param($m)
            $group = [int]$rule.CaptureGroup
            if ($group -ge $m.Groups.Count -or -not $m.Groups[$group].Success) { return $m.Value }
            $raw = $m.Groups[$group].Value.Trim().Trim('"', "'")
            if (Test-RuleAllowlistedSecret -Rule $rule -Value $raw) { return $m.Value }
            if (Is-AlreadyToken -Value $raw) { return $m.Value }
            $tok = Get-Token -Value $raw -Prefix $rule.Prefix
            Add-DetectionTrace -Detector 'CustomRegex' -Action 'Tokenized' -Value $raw -Token $tok -Reason $rule.Name -ColumnName $ColumnName -Context (Get-DetectionContext -Text $Text -Index $m.Index -Length $m.Length)
            if ($group -eq 0) { return $tok }
            $rel = $m.Groups[$group].Index - $m.Index
            return $m.Value.Substring(0, $rel) + $tok + $m.Value.Substring($rel + $m.Groups[$group].Length)
        })
    }
    return $out
}

function Test-UlsWindowsUserPathHardeningNeeded {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    # One sentinel catches both normal paths (C:\Users\name) and JSON/CSV-escaped
    # paths (C:\\Users\\name), because the escaped form still contains "\Users\"
    # starting at its second slash. Avoids a second full-string IndexOf on hot fields.
    return ($Text.IndexOf('\Users\', [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
}

function Invoke-WindowsPathUserHardening {
    param([Parameter(Mandatory)][string]$Text)
    if (-not (Test-UlsWindowsUserPathHardeningNeeded -Text $Text)) { return $Text }

    $preserveProfileRegex = '^(Public|Default|Default User|All Users)$'
    $replaceProfile = {
        param($m)
        $profile = $m.Groups[2].Value
        if ([string]::IsNullOrWhiteSpace($profile) -or
            $profile -match $preserveProfileRegex -or
            (Is-AlreadyToken -Value $profile)) {
            return $m.Value
        }
        return $m.Groups[1].Value + (Get-Token -Value $profile -Prefix "PRINCIPAL")
    }

    # Normal Windows paths: C:\Users\alice\...
    $out = $script:__rxWinUserPathNormal.Replace($Text, $replaceProfile)

    # JSON/CSV-escaped Windows paths: C:\\Users\\alice\\...
    $out = $script:__rxWinUserPathEscaped.Replace($out, $replaceProfile)
    return $out
}

function Test-PreserveSecretCandidate {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    $v = $Value.Trim().Trim('"', "'")
    if ($v.Length -lt 8) { return $true }
    if (Is-AlreadyToken -Value $v) { return $true }
    if ($v -match '(?i)^(true|false|null|none|redacted|masked|password|\*+|x+)$') { return $true }
    if (Test-KnownFileOrDiagnosticName -Value $v) { return $true }
    return $false
}

function Find-UlsSecretIdentifiersCore {
    param([Parameter(Mandatory)][string]$Text)
    $found = @{}
    if ($Text -notmatch '(?i)(Authorization\s*[:=]|Bearer\s+|Basic\s+|password\s*[:=]|passwd\s*[:=]|pwd\s*[:=]|secret\s*[:=]|client_secret|api[_-]?key\s*[:=]|access[_-]?token\s*[:=]|refresh[_-]?token\s*[:=]|private[_-]?key\s*[:=]|PRIVATE KEY|connectionstring|connstr|Data Source=|Server=[^\r\n]{0,500}(?:Password|Pwd)=|gh[pousr]_|xox[baprs]-|sk_(?:live|test)_|sk-[A-Za-z0-9]|(?:AKIA|ASIA)[0-9A-Z]{16,24}|\b(?:token|secret|key|password)[A-Za-z0-9_. \-]{0,24}[:=])') { return @() }
    $add = {
        param([string]$Raw, [string]$Prefix)
        if (Test-PreserveSecretCandidate -Value $Raw) { return }
        $norm = Normalize-TokenKey -Value $Raw
        if ($norm -and -not $found.ContainsKey($norm)) {
            $found[$norm] = [pscustomobject]@{ Raw = $Raw.Trim(); Prefix = $Prefix }
        }
    }
    foreach ($m in [regex]::Matches($Text, '(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----')) {
        & $add $m.Value 'PEM'
    }
    foreach ($m in [regex]::Matches($Text, '(?i)\bAuthorization\s*[:=]\s*(?:Bearer|Basic)\s+([A-Za-z0-9+/_=.\-]{12,})')) {
        & $add $m.Groups[1].Value 'SECRET'
    }
    foreach ($m in [regex]::Matches($Text, '(?i)\b(?:password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?token|refresh[_-]?token|private[_-]?key)\s*[:=]\s*["'']?([^"''\s;,]{8,})')) {
        & $add $m.Groups[1].Value 'SECRET'
    }
    foreach ($m in [regex]::Matches($Text, '(?i)\b(?:Server|Data Source)=[^;\r\n]+;(?:[^;\r\n]+;){0,8}(?:Password|Pwd)=[^;\r\n]+')) {
        & $add $m.Value 'CONNSTR'
    }
    foreach ($m in [regex]::Matches($Text, '\b(?:gh[pousr]_[A-Za-z0-9_]{30,}|xox[baprs]-[A-Za-z0-9-]{20,}|sk_(?:live|test)_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9]{20,}|(?:AKIA|ASIA)[0-9A-Z]{16,24})\b')) {
        & $add $m.Value 'APIKEY'
    }
    foreach ($m in [regex]::Matches($Text, '(?i)\b(?:token|secret|key|password)[A-Za-z0-9_. \-]{0,24}[:=]\s*["'']?([A-Za-z0-9+/_=\-.]{24,})')) {
        & $add $m.Groups[1].Value 'SECRET'
    }
    return @($found.Values)
}

function Invoke-SecretHardening {
    param([Parameter(Mandatory)][string]$Text, [string]$ColumnName)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    if ($Text -notmatch '(?i)(Authorization\s*[:=]|Bearer\s+|Basic\s+|password\s*[:=]|passwd\s*[:=]|pwd\s*[:=]|secret\s*[:=]|client_secret|api[_-]?key\s*[:=]|access[_-]?token\s*[:=]|refresh[_-]?token\s*[:=]|private[_-]?key\s*[:=]|PRIVATE KEY|connectionstring|connstr|Data Source=|Server=[^\r\n]{0,500}(?:Password|Pwd)=|gh[pousr]_|xox[baprs]-|sk_(?:live|test)_|sk-[A-Za-z0-9]|(?:AKIA|ASIA)[0-9A-Z]{16,24}|\b(?:token|secret|key|password)[A-Za-z0-9_. \-]{0,24}[:=])') { return $Text }
    $out = $Text
    $out = [regex]::Replace($out, '(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----', {
        param($m)
        if (Test-PreserveSecretCandidate -Value $m.Value) { return $m.Value }
        $tok = Get-Token -Value $m.Value -Prefix 'PEM'
        Add-DetectionTrace -Detector 'PEM private key' -Action 'Tokenized' -Value '[PEM private key]' -Token $tok -Reason 'Private key block' -ColumnName $ColumnName -Context '[PEM private key]'
        return $tok
    })
    $out = [regex]::Replace($out, '(?i)(\bAuthorization\s*[:=]\s*(?:Bearer|Basic)\s+)([A-Za-z0-9+/_=.\-]{12,})', {
        param($m)
        $secret = $m.Groups[2].Value
        if (Test-PreserveSecretCandidate -Value $secret) { return $m.Value }
        $tok = Get-Token -Value $secret -Prefix 'SECRET'
        Add-DetectionTrace -Detector 'Authorization secret' -Action 'Tokenized' -Value $secret -Token $tok -Reason 'Authorization header' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
        return $m.Groups[1].Value + $tok
    })
    $out = [regex]::Replace($out, '(?i)(\b(?:password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?token|refresh[_-]?token|private[_-]?key)\s*[:=]\s*["'']?)([^"''\s;,]{8,})', {
        param($m)
        $secret = $m.Groups[2].Value
        if (Test-PreserveSecretCandidate -Value $secret) { return $m.Value }
        $prefix = if ($m.Groups[1].Value -match '(?i)api[_-]?key') { 'APIKEY' } else { 'SECRET' }
        $tok = Get-Token -Value $secret -Prefix $prefix
        Add-DetectionTrace -Detector 'Key/value secret' -Action 'Tokenized' -Value $secret -Token $tok -Reason 'Secret-like key name' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
        return $m.Groups[1].Value + $tok
    })
    $out = [regex]::Replace($out, '(?i)\b(?:Server|Data Source)=[^;\r\n]+;(?:[^;\r\n]+;){0,8}(?:Password|Pwd)=[^;\r\n]+', {
        param($m)
        if (Test-PreserveSecretCandidate -Value $m.Value) { return $m.Value }
        $tok = Get-Token -Value $m.Value -Prefix 'CONNSTR'
        Add-DetectionTrace -Detector 'Connection string' -Action 'Tokenized' -Value '[connection string]' -Token $tok -Reason 'Password-bearing connection string' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
        return $tok
    })
    $out = [regex]::Replace($out, '\b(?:gh[pousr]_[A-Za-z0-9_]{30,}|xox[baprs]-[A-Za-z0-9-]{20,}|sk_(?:live|test)_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9]{20,}|(?:AKIA|ASIA)[0-9A-Z]{16,24})\b', {
        param($m)
        if (Test-PreserveSecretCandidate -Value $m.Value) { return $m.Value }
        $tok = Get-Token -Value $m.Value -Prefix 'APIKEY'
        Add-DetectionTrace -Detector 'API key' -Action 'Tokenized' -Value $m.Value -Token $tok -Reason 'Known secret prefix' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
        return $tok
    })
    $out = [regex]::Replace($out, '(?i)(\b(?:token|secret|key|password)[A-Za-z0-9_. \-]{0,24}[:=]\s*["'']?)([A-Za-z0-9+/_=\-.]{24,})', {
        param($m)
        $secret = $m.Groups[2].Value
        if (Test-PreserveSecretCandidate -Value $secret) { return $m.Value }
        $tok = Get-Token -Value $secret -Prefix 'SECRET'
        Add-DetectionTrace -Detector 'High entropy secret' -Action 'Tokenized' -Value $secret -Token $tok -Reason 'Keyword + high-entropy-looking value' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
        return $m.Groups[1].Value + $tok
    })
    return $out
}

function Write-DetectionReport {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not $script:DetectionTrace -or $script:DetectionTrace.Count -eq 0) { return $null }
    try {
        $out = Resolve-OutPath -Path $Path
        $escape = {
            param($x)
            $s = [string]$x
            $s = $s -replace "`r|`n", " "
            return '"' + ($s -replace '"', '""') + '"'
        }
        $lines = New-Object System.Collections.Generic.List[string]
        [void]$lines.Add('"Detector","Action","Value","Token","Reason","Column","Context"')
        $traceItems = @()
        try { $traceItems = @($script:DetectionTrace.ToArray()) } catch { $traceItems = @($script:DetectionTrace) }
        foreach ($d in $traceItems) {
            $fields = @(
                (& $escape $d.Detector),
                (& $escape $d.Action),
                (& $escape $d.Value),
                (& $escape $d.Token),
                (& $escape $d.Reason),
                (& $escape $d.Column),
                (& $escape $d.Context)
            )
            [void]$lines.Add(($fields -join ','))
        }
        [System.IO.File]::WriteAllText([string]$out, (($lines.ToArray()) -join [Environment]::NewLine), [System.Text.Encoding]::UTF8)
        Write-Warn "Detection review report written: $out"
        Write-Warn "Treat this report like the token map if it contains original values or context."
        return $out
    }
    catch {
        Write-Warn "Could not write detection review report: line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        return $null
    }
}

function Write-DetectionSummaryReport {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not $script:DetectionCounts -or $script:DetectionCounts.Count -eq 0) { return $null }
    try {
        $out = Resolve-OutPath -Path $Path
        $rows = foreach ($k in ($script:DetectionCounts.Keys | Sort-Object)) {
            $parts = $k -split '\|', 2
            [pscustomobject]@{
                Detector = $parts[0]
                Action   = if ($parts.Count -gt 1) { $parts[1] } else { "" }
                Count    = [int]$script:DetectionCounts[$k]
            }
        }
        $rows | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8
        Write-Ok "Safe detection summary written: $out"
        return $out
    }
    catch {
        Write-Warn "Could not write detection summary: $($_.Exception.Message)"
        return $null
    }
}

# Additional detectors applied at scrub time in addition to the core passes.
# CSV-safe: every value class stops at quote / comma / whitespace. UNC and URL need
# group handling so they are bespoke; the rest iterate the Common-flagged list above.
function Invoke-CommonDetectors {
    param([Parameter(Mandatory)][string]$Text)
    $out = $Text
    # ULS perf patch 4: cheap literal pre-checks -- skip a pass when the required literal
    # substring is absent from the current text. Hardening replaces identifiers with tokens
    # (which never contain these sentinels) and never ADDS one, so skipping a pass that could
    # not have matched is byte-identical.
    $oic = [System.StringComparison]::OrdinalIgnoreCase
    if ($out.IndexOf('\Users\', $oic) -ge 0) { $out = Invoke-WindowsPathUserHardening -Text $out }

    # UNC path: tokenize the host in \\host\share (before any DOMAIN\user pass).
    if ($out.IndexOf('\\') -ge 0) {
        $out = [regex]::Replace($out, '\\\\([A-Za-z0-9._\-]+)((?:\\[^\s",;]*)?)', {
            param($m)
            $h = $m.Groups[1].Value
            if (Is-AlreadyToken -Value $h) { return $m.Value }
            if (Test-AllowedDomain -Value $h) { return $m.Value }
            if (Test-PreserveDetectedValue -Value $h -Detector 'UNC host' -Prefix 'DNS' -Text $out -Index $m.Groups[1].Index -Length $h.Length) { return $m.Value }
            $tok = Get-Token -Value $h -Prefix "DNS"
            Add-DetectionTrace -Detector 'UNC host' -Action 'Tokenized' -Value $h -Token $tok -Reason 'UNC host' -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
            return '\\' + $tok + $m.Groups[2].Value
        })
    }

    # URL / connection URI: tokenize optional userinfo and the host in scheme://[user@]host[:port]/...
    # Includes common database, cache, queue, Kafka, WebSocket, and JDBC schemes.
    if ($out.IndexOf('://') -ge 0) {
        $out = [regex]::Replace($out, '(?i)\b((?:jdbc:[a-z][a-z0-9+.-]*|https?|ftp|ldap|ldaps|smb|wss?|postgres(?:ql)?|mysql|mssql|sqlserver|redis|mongodb(?:\+srv)?|amqps?|kafka))://([^/\s"'',;]+)', {
            param($m)
            $scheme = $m.Groups[1].Value
            $auth = $m.Groups[2].Value
            $user = ''
            $hostport = $auth
            if ($auth -match '^([^@]+)@(.+)$') { $user = $matches[1]; $hostport = $matches[2] }
            $hp = $hostport; $port = ''
            if ($hostport -match '^(.+):(\d+)$') { $hp = $matches[1]; $port = ':' + $matches[2] }
            $userTok = if ($user) { (Get-Token -Value $user -Prefix "PRINCIPAL") + '@' } else { '' }
            $hostTok = $hp
            if (-not (Is-AlreadyToken -Value $hp) -and -not (Test-AllowedDomain -Value $hp) -and -not (Test-PreserveDetectedValue -Value $hp -Detector 'URL host' -Prefix 'DNS' -Text $out -Index $m.Groups[2].Index -Length $auth.Length)) {
                $hostTok = Get-Token -Value $hp -Prefix "DNS"
                Add-DetectionTrace -Detector 'URL host' -Action 'Tokenized' -Value $hp -Token $hostTok -Reason 'URL authority host' -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
            }
            return $scheme + '://' + $userTok + $hostTok + $port
        })
    }

    # The simple Common-flagged detectors (JWT, ARN, AWS key, instance id, MAC, IPv6, base64).
    foreach ($d in ($script:ShapeDetectors | Where-Object { $_.Common })) {
        if ($d.Sentinel -and ($out.IndexOf([string]$d.Sentinel, $oic) -lt 0)) { continue }
        $skip = $d.Skip
        $prefix = $d.Prefix
        $out = [regex]::Replace($out, $d.Rx, {
            param($m)
            $val = $m.Value
            if (Is-AlreadyToken -Value $val) { return $val }
            if ($skip -and ($val -match $skip)) { return $val }
            if (Test-PreserveDetectedValue -Value $val -Detector $d.Name -Prefix $prefix -Text $out -Index $m.Index -Length $m.Length) {
                Add-DetectionTrace -Detector $d.Name -Action 'Preserved' -Value $val -Token '' -Reason 'Balanced diagnostic preserve' -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
                return $val
            }
            $tok = Get-Token -Value $val -Prefix $prefix
            Add-DetectionTrace -Detector $d.Name -Action 'Tokenized' -Value $val -Token $tok -Reason 'Shape detector' -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
            return $tok
        })
    }
    return $out
}

# Value-only hardening for key=value text (logfmt, CEF/LEEF extensions). Keys are
# preserved; each value is run through the per-field hardener. A whole-text pass
# afterwards (by the caller) catches any identifiers outside key=value form.
function Invoke-KvValueOnlyText {
    param([Parameter(Mandatory)][string]$Text)
    return [regex]::Replace($Text, '([A-Za-z0-9_.\-]+)=("(?:[^"\\]|\\.)*"|[^\s]+)', {
        param($m)
        $key = $m.Groups[1].Value
        $val = $m.Groups[2].Value
        $q = ''
        $inner = $val
        if ($val.Length -ge 2 -and $val[0] -eq '"' -and $val[$val.Length - 1] -eq '"') { $q = '"'; $inner = $val.Substring(1, $val.Length - 2) }
        $scr = Invoke-FreeTextHardening -ColumnName $key -Value $inner
        return $key + '=' + $q + $scr + $q
    })
}

# Decide a token prefix from a value's SHAPE alone (no column context).
function Get-MapColumnName {
    param([Parameter(Mandatory)]$Row, [Parameter(Mandatory)][string[]]$Candidates)
    $props = @($Row.PSObject.Properties.Name)
    foreach ($candidate in $Candidates) { if ($props -contains $candidate) { return $candidate } }
    return $null
}

function New-ScrubTokenMapRow {
    param(
        [Parameter(Mandatory)][string]$InputValue,
        [Parameter(Mandatory)][string]$NormalizedValue,
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][string]$TokenType,
        [Parameter(Mandatory)][string]$Source,
        [string]$FirstSeenSource,
        [string]$LastSeenSource,
        [string]$SourcePathHash
    )
    if ([string]::IsNullOrWhiteSpace($FirstSeenSource)) { $FirstSeenSource = $Source }
    if ([string]::IsNullOrWhiteSpace($LastSeenSource)) { $LastSeenSource = $Source }
    [pscustomobject][ordered]@{
        InputValue      = $InputValue
        NormalizedValue = $NormalizedValue
        Token           = $Token
        TokenType       = $TokenType
        Source          = $Source
        SaltFingerprint = (Get-SaltFingerprint)
        HmacLength      = $script:HmacLength
        FirstSeenSource = $FirstSeenSource
        LastSeenSource  = $LastSeenSource
        SourcePathHash  = $SourcePathHash
    }
}


function Test-UlsStandaloneTimestampLikeValue {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = ([string]$Value).Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')
    if ([string]::IsNullOrWhiteSpace($v)) { return $false }

    # Standalone log/event timestamps are operational context, not identifiers.
    # Keep this intentionally anchored so embedded IDs, URLs, cert values, and
    # secret-looking payloads still flow through the normal detectors.
    return (
        $v -match '(?i)^(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2})[ T]\d{1,2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:\s?(?:AM|PM))?(?:Z|[+-]\d{2}:?\d{2})?$' -or
        $v -match '(?i)^\d{4}\d{2}\d{2}[T _-]?\d{2}\d{2}\d{2}(?:\.\d{1,9})?(?:Z)?$'
    )
}

function Test-UlsCompositeStatusPayload {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = ([string]$Value).Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')
    if ($v.Length -lt 32) { return $false }

    # Avoid mapping an entire diagnostic status payload as a computer/object when
    # a custom/profile regex sees too much. Embedded sensitive values are still
    # handled by the normal focused detectors.
    if ($v -match '^\s*[\{\[]' -and
        $v -match '(?i)"(?:categoryState|subcategoryState|state|status)"\s*:' -and
        $v -match '(?i)"(?:notStarted|succeeded|completed|disabled|enabled|unknown|error|failed)"' -and
        -not (Test-UlsContainsEmbeddedSensitiveValue -Value $v)) {
        return $true
    }

    return (
        $v -match '(?i)\b(?:Version|Result|MIResult|Output|Status|RetryCount|LastSyncDateTime|HRESULT|ErrorCode|ExpectedValue|NodeUri)\s*[:=]' -and
        $v -match '(?i)(?:^|\s)[A-Za-z][A-Za-z0-9_.-]{1,40}\s*='
    )
}

function Test-UlsLongNaturalLanguagePrincipalNoise {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = ([string]$Value).Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')
    if ($v.Length -lt 96 -or $v -notmatch '\s') { return $false }
    if ($v -match '[@\\/=:]' -or (Test-UlsContainsEmbeddedSensitiveValue -Value $v)) { return $false }
    return ($v -match '(?i)\b(?:this system|authorized use|unauthorized use|information contained|property of|criminal|disciplinary)\b')
}


function Test-UlsXmlStateFragmentValue {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim()
    return ($v -match '(?is)^<(?:enabled|disabled)\s*/>\s*(?:<data\b[^>]{0,256}\s*/>\s*)?$')
}

function Test-UlsLogonBannerTitleValue {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim().Trim('"', "'", '.', ',', ';', ':')
    return ($v -match '(?i)^(?:[A-Za-z0-9&().,'' -]{2,80}\s+)?Logon\s+Banner$')
}


function Test-UlsRelativeDiagnosticBackslashPathValue {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')
    if ($v -notmatch '\\') { return $false }
    return (
        $v -match '(?i)^(?:\d+\.\d+\.\d+_\d+|AUTHORITY|Google|Chrome|Store|Explorer|Launch|Service|Services|Extensions|Downloads|Sessions|Pinned|RemoteActions|EntityExtraction|Active_Projects|Center)\\' -or
        $v -match '(?i)\\(?:assets|assets\.db|Files|Scripts|TaskBar|Quick|Application|Account|User)$' -or
        $v -match '(?i)\\[^\\]+\.(?:db|js-?|crx|txt|log|xml|json|csv)$'
    )
}

function Test-UlsBenignPlaceholderValue {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')
    return (
        $v -match '(?i)^%[A-Z0-9_. -]{2,64}%$' -or
        $v -match '(?i)^AP-%SERIAL%$' -or
        $v -match '(?i)^(?:EMPTY|UNKNOWN|N/?A|NULL|NONE|Device)$'
    )
}

function Test-UlsEncodedGuidCnFragmentValue {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')
    return ($v -match '(?i)^CN%3d[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:&amp)?$')
}

function Test-UlsHighEntropyDotZeroPrincipalNoise {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')
    return (
        $v -match '^[A-Za-z0-9+/]{16,}\.0$' -and
        $v -match '[A-Z]' -and
        $v -match '[a-z]'
    )
}

function Test-UlsBenignUriPrincipalValue {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')
    if ($v -notmatch '(?i)^https?://') { return $false }
    if ($v -match '(?i)[?&](?:token|access_token|refresh_token|sig|signature|key|client_secret|password|pwd)=') { return $false }
    return ($v -match '(?i)^https?://(?:login\.windows\.net|login\.microsoftonline\.com|device\.login\.microsoftonline\.com|enterpriseregistration\.windows\.net)(?:/|$)')
}

function Test-UlsHashAsMacValue {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')
    return ($v -match '(?i)^[0-9a-f]{24,}$')
}

function Test-UlsFileNameLikeDnsValue {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')
    return ($v -match '(?i)^[A-Za-z0-9_.-]+\.(?:cer|crt|crl|pem|p7b|p7c)$')
}

function Test-UlsShouldMapDiscoveredIdentifier {
    param(
        [string]$Raw,
        [string]$Prefix,
        [ValidateSet('Strict','Balanced','Readable')][string]$ScrubPolicy = $script:ScrubPolicy
    )

    if ([string]::IsNullOrWhiteSpace($Raw) -or [string]::IsNullOrWhiteSpace($Prefix)) { return $false }
    $v = ([string]$Raw).Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')
    if ($v.Length -lt 3) { return $false }
    if ($ScrubPolicy -ne 'Strict') {
        if (Test-UlsStandaloneTimestampLikeValue -Value $v) { return $false }
        if (Test-UlsCompositeStatusPayload -Value $v) { return $false }
        if (Test-UlsXmlStateFragmentValue -Value $v) { return $false }
        if (Test-UlsBenignPlaceholderValue -Value $v) { return $false }
        if ($Prefix -eq 'MAC' -and (Test-UlsHashAsMacValue -Value $v)) { return $false }
        if ($Prefix -eq 'DNS' -and (Test-UlsFileNameLikeDnsValue -Value $v)) { return $false }
        if ($Prefix -eq 'PRINCIPAL' -and ((Test-UlsLongNaturalLanguagePrincipalNoise -Value $v) -or (Test-UlsLogonBannerTitleValue -Value $v) -or (Test-UlsRelativeDiagnosticBackslashPathValue -Value $v) -or (Test-UlsEncodedGuidCnFragmentValue -Value $v) -or (Test-UlsHighEntropyDotZeroPrincipalNoise -Value $v) -or (Test-UlsBenignUriPrincipalValue -Value $v))) { return $false }
        if (Test-UlsWellKnownSid -Value $v) { return $false }
        if (Test-UlsWellKnownWindowsPrincipal -Value $v) { return $false }
        if ($Prefix -eq 'DNS' -and (Test-WindowsDiagnosticDottedName -Value $v) -and $v -notmatch '(?i)\.(local|lan|corp|internal|intranet|home|test)$') { return $false }
        if ($Prefix -eq 'PRINCIPAL' -and (Test-WindowsPathLikeDomainUser -Value $v -Text '' -Index -1 -Length 0)) { return $false }
        if ($Prefix -eq 'URI' -and (Test-UlsDiagnosticPathOnlyUri -Value $v)) { return $false }
        if ($Prefix -eq 'X500' -and $v -match '(?i)^CN=\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$') { return $false }
        if ($Prefix -eq 'BLOB' -and $v.Length -gt 1024) { return $false }
    }
    return $true
}

function Export-ScrubTokenMapRows {
    param([Parameter(Mandatory)]$Rows, [Parameter(Mandatory)][string]$TokenMapCsv)
    $out = Resolve-OutPath -Path $TokenMapCsv
    $dir = Split-Path -Parent $out
    if (-not $dir) { $dir = (Get-Location).Path }
    $tmp = Join-Path $dir (".{0}.{1}.tmp" -f ([System.IO.Path]::GetFileName($out)), ([guid]::NewGuid().ToString("N")))
    $backup = $out + ".bak"
    $rowsForWrite = @($Rows)
    if ($rowsForWrite.Count -gt 0) {
        $rowsForWrite | Export-Csv -Path $tmp -NoTypeInformation -Encoding UTF8
    }
    else {
        [pscustomobject][ordered]@{
            InputValue=""; NormalizedValue=""; Token=""; TokenType=""; Source="";
            SaltFingerprint=""; HmacLength=""; FirstSeenSource=""; LastSeenSource=""; SourcePathHash=""
        } | Select-Object -First 0 | Export-Csv -Path $tmp -NoTypeInformation -Encoding UTF8
    }
    try {
        if (Test-Path -LiteralPath $out) {
            try { [System.IO.File]::Replace($tmp, $out, $backup, $true) }
            catch {
                Copy-Item -LiteralPath $out -Destination $backup -Force -ErrorAction SilentlyContinue
                Move-Item -LiteralPath $tmp -Destination $out -Force
            }
        }
        else {
            Move-Item -LiteralPath $tmp -Destination $out -Force
        }
    }
    finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
    Reset-UlsCSharpMapOnlyScrubberCache
    return $out
}

function Import-ScrubTokenMap {
    param([Parameter(Mandatory)][string]$TokenMapCsv)
    if (-not (Test-Path $TokenMapCsv)) { throw "Token map not found: $TokenMapCsv" }
    $resolved = (Resolve-Path -Path $TokenMapCsv).Path
    $cacheKey = Get-UlsTokenMapFileCacheKey -Path $resolved
    if ($script:TokenMapCacheKey -eq $cacheKey -and $script:TokenByNorm -and $script:TokenByNorm.Count -gt 0) {
        Write-Info "Reusing token map already in memory ($($script:TokenByNorm.Count) entries)."
        return $script:TokenByNorm
    }
    Write-Work "Loading token map: $([System.IO.Path]::GetFileName($TokenMapCsv))"
    $tokenRows = Import-Csv $TokenMapCsv
    $map = @{}
    $literalRows = New-Object System.Collections.Generic.List[object]
    $pathRows = New-Object System.Collections.Generic.List[object]
    $pathRules = New-Object System.Collections.Generic.List[object]
    $pathRowSeen = @{}
    $pathSensitiveTypes = @('PRINCIPAL','UNMAPPED_UPN','UPN','EMAIL','COMPUTER','GROUP','DNS','HOST','X500','IP','IP6','MAC','SID')
    function _AddPathProtectionLiteral {
        param([string]$Literal,[string]$Token,[string]$TokenType)
        if ([string]::IsNullOrWhiteSpace($Literal) -or [string]::IsNullOrWhiteSpace($Token)) { return }
        $lit = [string]$Literal
        if ($lit.Length -lt 3 -or $lit.Length -gt 160) { return }
        if (Is-AlreadyToken -Value $lit) { return }
        $typ = ([string]$TokenType).ToUpperInvariant()
        if ([string]::IsNullOrWhiteSpace($typ) -and $Token -match '^([A-Z0-9]+)_') { $typ = $matches[1] }
        if ($pathSensitiveTypes -notcontains $typ) { return }
        if ($lit -match '(?i)^(?:true|false|null|none|empty|enabled|disabled|success|failed|device)$') { return }
        if ($lit -match '(?i)^https?://') { return }
        $k = $lit.ToLowerInvariant()
        if ($pathRowSeen.ContainsKey($k)) { return }
        $pathRowSeen[$k] = $true
        [void]$pathRows.Add([pscustomobject]@{ Input = $lit; Token = $Token })
    }
    foreach ($row in $tokenRows) {
        $inputCol = Get-MapColumnName -Row $row -Candidates @("InputValue", "OriginalValue", "Value", "SourceValue")
        $normCol  = Get-MapColumnName -Row $row -Candidates @("NormalizedValue", "Normalized", "NormalizedKey")
        $tokenCol = Get-MapColumnName -Row $row -Candidates @("Token", "ScrubbedValue", "Replacement")
        $typeCol  = Get-MapColumnName -Row $row -Candidates @("TokenType", "Type", "Prefix")
        if (-not $tokenCol) { continue }
        $token = [string]$row.$tokenCol
        if ([string]::IsNullOrWhiteSpace($token)) { continue }
        $tokenType = ''
        if ($typeCol -and $row.$typeCol) { $tokenType = [string]$row.$typeCol }
        elseif ($token -match '^([A-Z0-9]+)_') { $tokenType = $matches[1] }
        $norm = $null
        if ($normCol -and $row.$normCol)       { $norm = Normalize-TokenKey -Value ([string]$row.$normCol) }
        elseif ($inputCol -and $row.$inputCol) { $norm = Normalize-TokenKey -Value ([string]$row.$inputCol) }
        if ($norm -and -not $map.ContainsKey($norm)) { $map[$norm] = $token }
        if ($inputCol -and -not [string]::IsNullOrWhiteSpace([string]$row.$inputCol)) {
            $literal = [string]$row.$inputCol
            if ($literal.Length -ge 3 -and -not (Is-AlreadyToken -Value $literal)) {
                [void]$literalRows.Add([pscustomobject]@{ Input = $literal; Token = $token })
                _AddPathProtectionLiteral -Literal $literal -Token $token -TokenType $tokenType
                if ($token -match '^MAC_') {
                    foreach ($macVariant in @(Get-UlsMacAddressVariants -Value $literal)) {
                        if ($macVariant.Length -ge 3) {
                            [void]$literalRows.Add([pscustomobject]@{ Input = $macVariant; Token = $token })
                            _AddPathProtectionLiteral -Literal $macVariant -Token $token -TokenType 'MAC'
                        }
                    }
                }
            }
        }
    }
    $script:TokenByNorm = $map
    $script:TokenMapLiteralRows = @($literalRows.ToArray() | Sort-Object @{ Expression = { $_.Input.Length }; Descending = $true })
    $script:TokenMapPathRows = @($pathRows.ToArray() | Sort-Object @{ Expression = { $_.Input.Length }; Descending = $true })
    $script:DerivedPathProtectionCache = @{}
    foreach ($pr in @($script:TokenMapPathRows)) {
        try {
            $raw = [string]$pr.Input
            $tok = [string]$pr.Token
            if ([string]::IsNullOrWhiteSpace($raw) -or [string]::IsNullOrWhiteSpace($tok) -or $raw.Length -lt 3) { continue }
            $rx = [System.Text.RegularExpressions.Regex]::new([regex]::Escape($raw), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant, $script:RegexTimeout)
            [void]$pathRules.Add([pscustomobject]@{ Input = $raw; Token = $tok; Regex = $rx })
        }
        catch { }
    }
    $script:TokenMapPathRules = @($pathRules.ToArray())
    $script:TokenMapCacheKey = $cacheKey
    $script:CurrentTokenMapCsv = $resolved
    Reset-UlsCSharpMapOnlyScrubberCache
    Write-Ok "Loaded $($script:TokenByNorm.Count) token map entries."
    return $map
}

function Test-TokenMapCollisions {
    param([Parameter(Mandatory)]$Rows)
    $byToken = @{}
    $bySource = @{}
    foreach ($r in @($Rows)) {
        $tok = [string]$r.Token
        $norm = [string]$r.NormalizedValue
        if ([string]::IsNullOrWhiteSpace($tok) -or [string]::IsNullOrWhiteSpace($norm)) { continue }
        if (-not $byToken.ContainsKey($tok)) { $byToken[$tok] = New-Object System.Collections.Generic.HashSet[string] }
        if (-not $bySource.ContainsKey($tok)) { $bySource[$tok] = New-Object System.Collections.Generic.List[string] }
        [void]$byToken[$tok].Add($norm)
        [void]$bySource[$tok].Add([string]$r.Source)
    }
    $collisions = @()
    foreach ($tok in $byToken.Keys) {
        if ($byToken[$tok].Count -le 1) { continue }
        $sources = @($bySource[$tok])
        $intentional = ($sources.Count -gt 0 -and @($sources | Where-Object { $_ -notmatch '(\+corr$|^AD:)' }).Count -eq 0)
        if (-not $intentional) { $collisions += $tok }
    }
    if ($collisions.Count -gt 0) {
        Write-Warn "Token collision warning: $($collisions.Count) token(s) map to multiple normalized values."
        Write-Warn "Increase -HmacLength and rebuild the map if these aliases were not intentionally correlated."
        foreach ($tok in ($collisions | Select-Object -First 5)) {
            Write-Detail ("{0}: {1}" -f $tok, ((@($byToken[$tok]) | Select-Object -First 4) -join ', '))
        }
    }
    return $collisions.Count
}

# =====================================================================
# REGION: Map source 1 -- DISCOVERY (build the map from the log itself)
# =====================================================================
function New-ScrubTokenMap {
    <#
      Scan one or more input files, detect identifier-shaped values, and mint a
      stable token for each distinct value. Writes a private token-map CSV and
      loads it into the session. No AD required.
    #>
    param(
        [Parameter(Mandatory)][string[]]$InputPath,
        [Parameter(Mandatory)][string]$TokenMapCsv,
        [string[]]$SeedTerms = @(),
        [switch]$NoCorrelate,
        [ValidateSet('Merge','Replace')][string]$TokenMapMode = 'Merge',
        [ValidateSet('Strict','Balanced','Readable')][string]$ScrubPolicy = $script:ScrubPolicy,
        [string]$ProfileName = '',
        [string]$WorkDir = '',
        [string[]]$AllowlistFile = @(),
        [int]$ThrottleLimit = 4,
        [int]$LargeFileThresholdMB = 100,
        [switch]$KeepIntermediate
    )
    $script:ScrubPolicy = $ScrubPolicy
    [void](Get-SessionSalt)
    if ([string]::IsNullOrWhiteSpace($ProfileName)) {
        try {
            if ($script:CurrentProfile -and -not [string]::IsNullOrWhiteSpace([string]$script:CurrentProfile.Name)) { $ProfileName = [string]$script:CurrentProfile.Name }
        } catch { }
        if ([string]::IsNullOrWhiteSpace($ProfileName)) { $ProfileName = 'Generic' }
    }
    Write-Rule "Building token map by discovery"

    $seen = @{}   # normKey -> [pscustomobject] map row
    $fileNo = 0
    $out = Resolve-OutPath -Path $TokenMapCsv
    if ($TokenMapMode -eq 'Merge' -and (Test-Path -LiteralPath $out)) {
        Write-Info "Merging with existing token map: $([System.IO.Path]::GetFileName($out))"
        foreach ($row in (Import-Csv $out)) {
            $inputCol = Get-MapColumnName -Row $row -Candidates @("InputValue", "OriginalValue", "Value", "SourceValue")
            $normCol  = Get-MapColumnName -Row $row -Candidates @("NormalizedValue", "Normalized", "NormalizedKey")
            $tokenCol = Get-MapColumnName -Row $row -Candidates @("Token", "ScrubbedValue", "Replacement")
            if (-not $tokenCol -or [string]::IsNullOrWhiteSpace([string]$row.$tokenCol)) { continue }
            $inputValue = if ($inputCol) { [string]$row.$inputCol } else { "" }
            $norm = if ($normCol -and $row.$normCol) { Normalize-TokenKey -Value ([string]$row.$normCol) } else { Normalize-TokenKey -Value $inputValue }
            if (-not $norm -or $seen.ContainsKey($norm)) { continue }
            $source = if ($row.Source) { [string]$row.Source } else { "ExistingMap" }
            $tokenType = if ($row.TokenType) { [string]$row.TokenType } else { "OBJECT" }
            $firstSeen = if ($row.FirstSeenSource) { [string]$row.FirstSeenSource } else { $source }
            $lastSeen = if ($row.LastSeenSource) { [string]$row.LastSeenSource } else { $source }
            $pathHash = if ($row.SourcePathHash) { [string]$row.SourcePathHash } else { "" }
            $seen[$norm] = New-ScrubTokenMapRow `
                -InputValue $inputValue `
                -NormalizedValue $norm `
                -Token ([string]$row.$tokenCol) `
                -TokenType $tokenType `
                -Source $source `
                -FirstSeenSource $firstSeen `
                -LastSeenSource $lastSeen `
                -SourcePathHash $pathHash
        }
        Write-Ok "Preserved $($seen.Count) existing token map entr$(if ($seen.Count -eq 1) { 'y' } else { 'ies' })."
    }

    function _AddCorrelatedAlias {
        param(
            [string]$AliasValue,
            [string]$Token,
            [string]$TokenType,
            [string]$SourceValue,
            [string]$PathHashValue,
            [switch]$AllowRetarget
        )
        if ($NoCorrelate) { return 0 }
        $a = ([string]$AliasValue).Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')
        if ([string]::IsNullOrWhiteSpace($a) -or $a.Length -lt 3 -or [string]::IsNullOrWhiteSpace($Token)) { return 0 }
        if (Is-AlreadyToken -Value $a) { return 0 }
        $aliasType = if ([string]::IsNullOrWhiteSpace($TokenType)) { 'PRINCIPAL' } else { [string]$TokenType }
        if (-not (Test-UlsShouldMapDiscoveredIdentifier -Raw $a -Prefix $aliasType -ScrubPolicy $ScrubPolicy)) { return 0 }
        $an = Normalize-TokenKey -Value $a
        if (-not $an) { return 0 }
        $corrSource = ("{0}+corr" -f $SourceValue)
        if ($seen.ContainsKey($an)) {
            if ($AllowRetarget) {
                try {
                    $existing = $seen[$an]
                    $oldToken = [string]$existing.Token
                    $oldType = [string]$existing.TokenType
                    $safeTypes = @('PRINCIPAL','UNMAPPED_UPN','COMPUTER')
                    # If a bare alias was discovered before its richer identity form
                    # (UPN, DOMAIN\user, machine account, AP-prefixed device name),
                    # retarget the existing row so equivalent identities collapse to
                    # one token. Do not retarget secrets, certs, blobs, URLs, etc.
                    if ($oldToken -and $oldToken -ne $Token -and ($safeTypes -contains $oldType) -and ($safeTypes -contains $aliasType)) {
                        $existing.Token = $Token
                        $existing.TokenType = $aliasType
                        if (-not ([string]$existing.Source -match '\+corr')) { $existing.Source = $corrSource }
                        $existing.LastSeenSource = $corrSource
                        if (-not $existing.SourcePathHash) { $existing.SourcePathHash = $PathHashValue }
                    }
                } catch { }
            }
            return 0
        }
        $seen[$an] = New-ScrubTokenMapRow -InputValue $a -NormalizedValue $an -Token $Token -TokenType $aliasType -Source $corrSource -FirstSeenSource $corrSource -LastSeenSource $corrSource -SourcePathHash $PathHashValue
        return 1
    }

    function _AddIdentityAliasesFromValue {
        param(
            [string]$InputValue,
            [string]$Token,
            [string]$TokenType,
            [string]$SourceValue,
            [string]$PathHashValue
        )
        if ($NoCorrelate -or [string]::IsNullOrWhiteSpace($InputValue) -or [string]::IsNullOrWhiteSpace($Token)) { return 0 }
        $n = 0
        $v = ([string]$InputValue).Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')

        if ($v -match '^(?<local>[^@\s]{3,80})@(?<domain>[^@\s]+\.[^@\s]+)$') {
            $n += _AddCorrelatedAlias -AliasValue $matches['local'] -Token $Token -TokenType 'PRINCIPAL' -SourceValue $SourceValue -PathHashValue $PathHashValue -AllowRetarget
        }

        if ($v -match '^(?<domain>[A-Za-z0-9_.-]{2,64})\\(?<user>[A-Za-z0-9_.\-$]{2,80})$') {
            $dom = $matches['domain']
            $usr = $matches['user']
            $looksLikeRealPrincipal = (
                ($dom -cmatch '^[A-Z0-9.-]{2,32}$' -and $usr -cmatch '[a-z]' -and $usr -notmatch '(?i)\.(?:db|js|crx|txt|log|xml|json|csv)$') -or
                ($usr.EndsWith('$') -and $dom -cmatch '^[A-Z0-9.-]{2,32}$')
            )
            if ($looksLikeRealPrincipal -and $dom -notmatch '(?i)^(?:NT AUTHORITY|AUTHORITY|BUILTIN|WORKGROUP|Google|Chrome|Store|Explorer|Launch|Service|Services|Extensions|Downloads|Sessions|Pinned|RemoteActions|EntityExtraction|Active_Projects|Center)$') {
                $n += _AddCorrelatedAlias -AliasValue $usr -Token $Token -TokenType 'PRINCIPAL' -SourceValue $SourceValue -PathHashValue $PathHashValue -AllowRetarget
                $n += _AddCorrelatedAlias -AliasValue ("{0}_{1}" -f $dom, $usr) -Token $Token -TokenType 'PRINCIPAL' -SourceValue $SourceValue -PathHashValue $PathHashValue -AllowRetarget
                $n += _AddCorrelatedAlias -AliasValue ("IntuneWindowsAgent_Proxy_{0}_{1}.txt" -f $dom, $usr) -Token $Token -TokenType 'PRINCIPAL' -SourceValue $SourceValue -PathHashValue $PathHashValue -AllowRetarget
            }
        }

        if ($v -match '^(?<user>[A-Za-z][A-Za-z0-9._''-]{2,80})_Windows_\d{1,2}/\d{1,2}/\d{4}_\d{1,2}:\d{2}(?:\s*[AP]M)?$') {
            $n += _AddCorrelatedAlias -AliasValue $matches['user'] -Token $Token -TokenType 'PRINCIPAL' -SourceValue $SourceValue -PathHashValue $PathHashValue -AllowRetarget
        }

        return $n
    }

    function _AddComputerAliasesFromValue {
        param(
            [string]$InputValue,
            [string]$Token,
            [string]$TokenType,
            [string]$SourceValue,
            [string]$PathHashValue
        )
        if ($NoCorrelate -or [string]::IsNullOrWhiteSpace($InputValue) -or [string]::IsNullOrWhiteSpace($Token)) { return 0 }
        if ($TokenType -notin @('COMPUTER','PRINCIPAL')) { return 0 }
        $v = ([string]$InputValue).Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')
        if ([string]::IsNullOrWhiteSpace($v)) { return 0 }

        $host = $null
        if ($v -match '^(?<h>[A-Za-z0-9][A-Za-z0-9-]{4,31})\$$') { $host = $matches['h'] }
        elseif ($v -match '(?i)^AP-(?<h>[A-Za-z0-9][A-Za-z0-9-]{4,31})(?:_defaultuser0)?$') { $host = $matches['h'] }
        elseif ($TokenType -eq 'COMPUTER' -and $v -match '^(?<h>[A-Za-z0-9][A-Za-z0-9-]{4,31})$') { $host = $matches['h'] }
        if ([string]::IsNullOrWhiteSpace($host)) { return 0 }

        # Avoid manufacturing aliases for generic labels such as PROD, 00927, or
        # underscore-delimited policy names. Target real endpoint-looking names.
        if ($host -notmatch '(?i)^(?:DESKTOP-|LAPTOP-|AP-)|(?=.*[A-Z])(?=.*\d)[A-Za-z0-9-]{5,32}$') { return 0 }

        $computerToken = Get-Token -Value $host -Prefix 'COMPUTER'
        $n = 0
        $n += _AddCorrelatedAlias -AliasValue $host -Token $computerToken -TokenType 'COMPUTER' -SourceValue $SourceValue -PathHashValue $PathHashValue -AllowRetarget
        $n += _AddCorrelatedAlias -AliasValue ("{0}$" -f $host) -Token $computerToken -TokenType 'COMPUTER' -SourceValue $SourceValue -PathHashValue $PathHashValue -AllowRetarget
        $n += _AddCorrelatedAlias -AliasValue ("AP-{0}" -f $host) -Token $computerToken -TokenType 'COMPUTER' -SourceValue $SourceValue -PathHashValue $PathHashValue -AllowRetarget
        $n += _AddCorrelatedAlias -AliasValue ("AP-{0}_defaultuser0" -f $host) -Token $computerToken -TokenType 'COMPUTER' -SourceValue $SourceValue -PathHashValue $PathHashValue -AllowRetarget
        $n += _AddCorrelatedAlias -AliasValue ("DeviceHash_{0}.csv" -f $host) -Token $computerToken -TokenType 'COMPUTER' -SourceValue $SourceValue -PathHashValue $PathHashValue -AllowRetarget
        return $n
    }

    function _MergeDiscoveredRows {
        param([object[]]$Rows, [string]$DefaultSource = '', [string]$DefaultPathHash = '')
        $added = 0
        foreach ($wr in $Rows) {
            $inputCol = Get-MapColumnName -Row $wr -Candidates @("InputValue", "OriginalValue", "Value", "SourceValue")
            $normCol  = Get-MapColumnName -Row $wr -Candidates @("NormalizedValue", "Normalized", "NormalizedKey")
            $tokenCol = Get-MapColumnName -Row $wr -Candidates @("Token", "ScrubbedValue", "Replacement")
            $inputValue = if ($inputCol) { [string]$wr.$inputCol } elseif ($wr.Raw) { [string]$wr.Raw } else { "" }
            if ([string]::IsNullOrWhiteSpace($inputValue)) { continue }
            $tokenType = if ($wr.TokenType) { [string]$wr.TokenType } elseif ($wr.Prefix) { [string]$wr.Prefix } else { "OBJECT" }
            if (-not (Test-UlsShouldMapDiscoveredIdentifier -Raw $inputValue -Prefix $tokenType -ScrubPolicy $ScrubPolicy)) { continue }
            $norm = if ($normCol -and $wr.$normCol) { Normalize-TokenKey -Value ([string]$wr.$normCol) } else { Normalize-TokenKey -Value $inputValue }
            if (-not $norm) { continue }
            $sourceValue = if ($wr.Source) { [string]$wr.Source } elseif ($DefaultSource) { $DefaultSource } else { 'Discovery' }
            $pathHashValue = if ($wr.SourcePathHash) { [string]$wr.SourcePathHash } else { $DefaultPathHash }
            if ($ScrubPolicy -ne 'Strict' -and $tokenType -eq 'COMPUTER' -and $sourceValue -match '(?i)certutil|certificate\s+store' -and $inputValue -match '(?i)^(?=.*[a-f])[0-9a-f]{6,}$') { continue }
            $effectiveToken = $null
            if (-not $seen.ContainsKey($norm)) {
                $tok = if ($tokenCol -and -not [string]::IsNullOrWhiteSpace([string]$wr.$tokenCol)) { [string]$wr.$tokenCol } else { Get-Token -Value $inputValue -Prefix $tokenType }
                $seen[$norm] = New-ScrubTokenMapRow -InputValue $inputValue -NormalizedValue $norm -Token $tok -TokenType $tokenType -Source $sourceValue -SourcePathHash $pathHashValue
                $effectiveToken = $tok
                $added++
            }
            else {
                $seen[$norm].LastSeenSource = $sourceValue
                if (-not $seen[$norm].SourcePathHash) { $seen[$norm].SourcePathHash = $pathHashValue }
                try { $effectiveToken = [string]$seen[$norm].Token } catch { $effectiveToken = $null }
            }
            $added += _AddIdentityAliasesFromValue -InputValue $inputValue -Token $effectiveToken -TokenType $tokenType -SourceValue $sourceValue -PathHashValue $pathHashValue
            $added += _AddComputerAliasesFromValue -InputValue $inputValue -Token $effectiveToken -TokenType $tokenType -SourceValue $sourceValue -PathHashValue $pathHashValue
        }
        return $added
    }

    $parallelDiscoveryCompletedPaths = @{}
    $profileIsBuiltIn = Test-UlsBuiltInProfileName -ProfileName $ProfileName
    if ($profileIsBuiltIn -and $ThrottleLimit -gt 1) {
        $fileLevelEligible = New-Object System.Collections.Generic.List[string]
        $csharpTextLikeExtensions = @('','.log','.txt','.reg','.html','.htm','.xml','.log_','.csv','.tsv','.psv','.json','.jsonl','.ndjson')
        foreach ($candidatePath in @($InputPath)) {
            if ([string]::IsNullOrWhiteSpace($candidatePath) -or -not (Test-Path -LiteralPath $candidatePath)) { continue }
            $extForBatch = [System.IO.Path]::GetExtension($candidatePath).ToLowerInvariant()
            if ($extForBatch -notin $csharpTextLikeExtensions) { continue }
            $lenForBatch = 0L
            try { $lenForBatch = [int64](Get-Item -LiteralPath $candidatePath).Length } catch { $lenForBatch = 0L }
            if ($lenForBatch -le 0) { continue }
            [void]$fileLevelEligible.Add($candidatePath)
        }
        if ($fileLevelEligible.Count -gt 1) {
            Write-Info ("Discovering token map with {0} CSharp worker(s)." -f ([Math]::Min([Math]::Max($ThrottleLimit, 1), $fileLevelEligible.Count)))
            $fileWorkerRows = @(Invoke-UlsCSharpDiscoverFilesProcessPool -InputPath ([string[]]$fileLevelEligible.ToArray()) -ProfileName $ProfileName -AllowlistFile $AllowlistFile -ScrubPolicy $ScrubPolicy -HmacLength $script:HmacLength -ThrottleLimit $ThrottleLimit)
            $fileWorkerAdded = _MergeDiscoveredRows -Rows $fileWorkerRows
            foreach ($donePath in @($fileLevelEligible.ToArray())) {
                try { $parallelDiscoveryCompletedPaths[[System.IO.Path]::GetFullPath($donePath).ToLowerInvariant()] = $true } catch { $parallelDiscoveryCompletedPaths[[string]$donePath] = $true }
            }
            Write-Detail ("CSharp process-pool discovery merged {0} worker row(s), {1} new map entr$(if ($fileWorkerAdded -eq 1) { 'y' } else { 'ies' })." -f $fileWorkerRows.Count, $fileWorkerAdded)
        }
    }
    foreach ($file in $InputPath) {
        $fileNo++
        if (-not (Test-Path $file)) { Write-Warn "Skipping (not found): $file"; continue }
        $fileFullKey = ''
        try { $fileFullKey = [System.IO.Path]::GetFullPath($file).ToLowerInvariant() } catch { $fileFullKey = [string]$file }
        if ($parallelDiscoveryCompletedPaths.ContainsKey($fileFullKey)) { continue }
        $name = [System.IO.Path]::GetFileName($file)
        $fileHash = Get-PathFingerprint -Path $file -Length 12
        $source = "Discovery:$name"
        Write-Work "Scanning ($fileNo/$($InputPath.Count)): $name"
        $hits = 0

        $extForCSharpDiscovery = [System.IO.Path]::GetExtension($file).ToLowerInvariant()
        $csharpDiscoveryExtensions = @('','.log','.txt','.reg','.html','.htm','.xml','.log_','.csv','.tsv','.psv','.json','.jsonl','.ndjson')
        if ($extForCSharpDiscovery -in $csharpDiscoveryExtensions) {
            $fileLengthForCSharp = 0L
            try { $fileLengthForCSharp = [int64](Get-Item -LiteralPath $file).Length } catch { $fileLengthForCSharp = 0L }
            $thresholdBytesForCSharp = [long]([Math]::Max($LargeFileThresholdMB, 1) * 1MB)
            $isConvertedEventXmlText = ([System.IO.Path]::GetFileName($file) -match '(?i)\.events\.txt$')
            if ($isConvertedEventXmlText) { $thresholdBytesForCSharp = [Math]::Min($thresholdBytesForCSharp, [int64](8MB)) }
            if ($profileIsBuiltIn -and $ThrottleLimit -gt 1 -and $fileLengthForCSharp -ge $thresholdBytesForCSharp) {
                if ($isConvertedEventXmlText) { Write-Detail "Detected Windows Event XML text; using field-aware CSharp discovery." }
                $csharpRows = @(Invoke-UlsCSharpDiscoverLargeFileParallel -InputPath $file -ProfileName $ProfileName -AllowlistFile $AllowlistFile -ScrubPolicy $ScrubPolicy -HmacLength $script:HmacLength -ThrottleLimit $ThrottleLimit)
            }
            else {
                if ($isConvertedEventXmlText) { Write-Detail "Detected Windows Event XML text; using field-aware CSharp discovery." }
                $csharpRows = @((Invoke-UlsCSharpDiscoverFileBatch -BatchIndex 0 -Files ([string[]]@($file)) -ProfileName $ProfileName -Salt (Get-SessionSalt) -HmacLength $script:HmacLength -ScrubPolicy $ScrubPolicy -AllowlistFile $AllowlistFile).Rows)
            }
            $hits += _MergeDiscoveredRows -Rows $csharpRows -DefaultSource $source -DefaultPathHash $fileHash
            Write-Detail ("CSharp discovery merged {0} map row(s)." -f $csharpRows.Count)
            continue
        }

        throw "CSharp discovery does not support '$name' (extension '$extForCSharpDiscovery')."
    }

    $ulsPerfBuildMap = New-UlsPerfStopwatch

    # Seed terms: shapeless secrets (org / host prefixes / project codenames) the
    # detectors cannot recognise. Mapped here so they tokenize consistently.
    foreach ($term in $SeedTerms) {
        $t = ([string]$term).Trim()
        if ($t.Length -lt 3) { continue }
        $norm = Normalize-TokenKey -Value $t
        if ($norm -and -not $seen.ContainsKey($norm)) {
            $prefix = if ($t -match '^(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$') { "DNS" } else { "X500" }
            $tok = Get-Token -Value $t -Prefix $prefix
            $seen[$norm] = New-ScrubTokenMapRow -InputValue $t -NormalizedValue $norm -Token $tok -TokenType $prefix -Source "SeedTerm" -SourcePathHash ""
        }
    }

    if ($seen.Count -gt 0) {
        $rowsOut = @($seen.Values) | Sort-Object Token, InputValue -Unique
        [void](Test-TokenMapCollisions -Rows $rowsOut)
        $out = Export-ScrubTokenMapRows -Rows $rowsOut -TokenMapCsv $out
    }
    else {
        $out = Export-ScrubTokenMapRows -Rows @() -TokenMapCsv $out
        Write-Warn "No identifiers were discovered. Output map is empty (check the input)."
    }
    Write-Ok "Token map written: $out  ($($seen.Count) entries)"
    Write-Warn "DO NOT upload this token map -- it re-identifies everything."
    [void](Import-ScrubTokenMap -TokenMapCsv $out)
    Add-UlsPerfPhase -Phase 'Build map' -Stopwatch $ulsPerfBuildMap -File ([System.IO.Path]::GetFileName($out)) -Rows $seen.Count -Notes ('NoCorrelate={0}; Mode={1}' -f [bool]$NoCorrelate, $TokenMapMode)
    return $out
}

# =====================================================================
# REGION: Map source 2 -- ACTIVE DIRECTORY (optional, authoritative)
#   Collapses every representation of one identity (SID, DOMAIN\sam, UPN, mail,
#   SPN, dNSHostName) onto a SINGLE token. Degrades gracefully off-domain.
# =====================================================================
function New-ScrubTokenMapFromAD {
    param(
        [Parameter(Mandatory)][string]$TokenMapCsv,
        [switch]$SkipComputers,
        [string[]]$SeedTerms = @()
    )
    [void](Get-SessionSalt)
    Write-Rule "Building token map from Active Directory"
    try { Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop } catch { }

    function Convert-ObjectSidToString {
        param([Parameter(Mandatory)]$ObjectSid)
        [byte[]]$bytes = @($ObjectSid | ForEach-Object { [byte]$_ })
        return ([System.Security.Principal.SecurityIdentifier]::new($bytes, 0)).Value
    }
    function Get-One { param($R,$N) if ($R.Properties.Contains($N) -and $R.Properties[$N].Count -gt 0) { return $R.Properties[$N][0] } return $null }
    function Get-Many { param($R,$N) if ($R.Properties.Contains($N) -and $R.Properties[$N].Count -gt 0) { return @($R.Properties[$N]) } return @() }

    $defaultNC = $null
    try {
        $rootDse = [ADSI]"LDAP://RootDSE"
        $defaultNC = [string]$rootDse.defaultNamingContext
    } catch { $defaultNC = $null }
    if ([string]::IsNullOrWhiteSpace($defaultNC)) {
        Write-Fail "Could not reach Active Directory (not domain-joined, or no rights)."
        return $null
    }
    $dnsName = (($defaultNC -split "," | Where-Object { $_ -like "DC=*" } | ForEach-Object { $_.Substring(3) }) -join ".")
    $netbios = ($dnsName -split "\.")[0].ToUpperInvariant()
    Write-Info "Domain: $dnsName  (NetBIOS $netbios)"

    $rows = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $count = 0
    try {
    $entry = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$defaultNC")
    $searcher = [System.DirectoryServices.DirectorySearcher]::new($entry)
    $parts = @("(&(objectCategory=person)(objectClass=user))", "(objectCategory=group)")
    if (-not $SkipComputers) { $parts += "(objectCategory=computer)" }
    $searcher.Filter = "(|$($parts -join ''))"
    $searcher.PageSize = 1000
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    foreach ($p in @("distinguishedName","objectSid","objectClass","sAMAccountName","cn","name","userPrincipalName","mail","proxyAddresses","dNSHostName","servicePrincipalName")) {
        [void]$searcher.PropertiesToLoad.Add($p)
    }

    Write-Work "Enumerating AD users, groups and computers..."
    foreach ($r in $searcher.FindAll()) {
        $count++
        if ($count % 500 -eq 0) { Write-UlsProgress -Activity "Read AD" -Phase ("aliases {0}" -f $seen.Count) -RowsDone $count }
        $sidBytes = Get-One $r "objectSid"
        if (-not $sidBytes) { continue }
        $sid = Convert-ObjectSidToString -ObjectSid $sidBytes
        $classes = @(Get-Many $r "objectClass" | ForEach-Object { "$_".ToLowerInvariant() })
        $type = if ($classes -contains "group") { "Group" } elseif ($classes -contains "computer") { "Computer" } elseif ($classes -contains "user") { "User" } else { "Object" }

        $sam = [string](Get-One $r "sAMAccountName")
        $cn  = [string](Get-One $r "cn")
        $name= [string](Get-One $r "name")
        $upn = [string](Get-One $r "userPrincipalName")
        $mail= [string](Get-One $r "mail")
        $dns = [string](Get-One $r "dNSHostName")
        $dn  = [string](Get-One $r "distinguishedName")

        $known = Get-CanonicalKnownLabelByValue -Value $sam
        if (-not $known) { $known = Get-CanonicalKnownLabelByValue -Value $cn }
        if ($known) {
            $token = $known
        }
        else {
            $prefix = switch ($type) { "Group" {"GROUP"} "Computer" {"COMPUTER"} "User" {"PRINCIPAL"} default {"OBJECT"} }
            $token = Invoke-HmacToken -Value $sid -Prefix $prefix
        }
        if (-not $token) { continue }

        $aliases = New-Object System.Collections.Generic.List[string]
        foreach ($v in @($sid,$dn,$sam,$cn,$name,$upn,$mail,$dns)) {
            if (-not [string]::IsNullOrWhiteSpace($v) -and -not $aliases.Contains($v)) { $aliases.Add($v) }
        }
        if ($sam) {
            foreach ($v in @("$netbios\$sam")) { if (-not $aliases.Contains($v)) { $aliases.Add($v) } }
            if ($type -eq "User" -or $type -eq "Computer") { $imp = "$sam@$dnsName"; if (-not $aliases.Contains($imp)) { $aliases.Add($imp) } }
            if ($sam.EndsWith("$")) {
                $nd = $sam.TrimEnd("$")
                foreach ($v in @($nd, "$netbios\$nd")) { if (-not $aliases.Contains($v)) { $aliases.Add($v) } }
                if ($type -eq "Computer") { $cu = "$nd@$dnsName"; if (-not $aliases.Contains($cu)) { $aliases.Add($cu) } }
            }
        }
        foreach ($pa in (Get-Many $r "proxyAddresses")) { if ("$pa" -match '^(?i)smtp:(.+)$') { $a = $matches[1]; if ($a -and -not $aliases.Contains($a)) { $aliases.Add($a) } } }
        foreach ($spn in (Get-Many $r "servicePrincipalName")) { if ($spn -and -not $aliases.Contains([string]$spn)) { $aliases.Add([string]$spn) } }
        foreach ($addr in @($upn,$mail)) {
            if (-not [string]::IsNullOrWhiteSpace($addr)) {
                foreach ($variant in @($addr, "Principal Name=$addr", "RFC822 Name=$addr", "UPN=$addr", "Email=$addr", "smtp:$addr", "mailto:$addr")) {
                    if (-not $aliases.Contains($variant)) { $aliases.Add($variant) }
                }
            }
        }
        if ($dns) { foreach ($v in @($dns, "DNS Name=$dns", "dNSHostName=$dns")) { if (-not $aliases.Contains($v)) { $aliases.Add($v) } } }

        foreach ($alias in $aliases) {
            $norm = Normalize-TokenKey -Value $alias
            if ($norm -and -not $seen.ContainsKey($norm)) {
                $seen[$norm] = $true
                $rowType = switch ($type) { "Group" {"GROUP"} "Computer" {"COMPUTER"} "User" {"PRINCIPAL"} default {"OBJECT"} }
                $rows.Add((New-ScrubTokenMapRow -InputValue $alias -NormalizedValue $norm -Token $token -TokenType $rowType -Source "AD" -SourcePathHash "AD"))
            }
        }
    }
    Write-UlsProgress -Activity "Read AD" -Completed
    }
    catch {
        Write-Warn "AD enumeration interrupted: $($_.Exception.Message)"
        if ($rows.Count -eq 0) { return $null }
    }

    foreach ($term in $SeedTerms) {
        $t = ([string]$term).Trim()
        if ($t.Length -lt 3) { continue }
        $norm = Normalize-TokenKey -Value $t
        if ($norm -and -not $seen.ContainsKey($norm)) {
            $seen[$norm] = $true
            $prefix = if ($t -match '^(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$') { "DNS" } else { "X500" }
            $rows.Add((New-ScrubTokenMapRow -InputValue $t -NormalizedValue $norm -Token (Get-Token -Value $t -Prefix $prefix) -TokenType $prefix -Source "SeedTerm" -SourcePathHash ""))
        }
    }

    $out = Resolve-OutPath -Path $TokenMapCsv
    $rowsOut = $rows | Sort-Object Token, InputValue -Unique
    [void](Test-TokenMapCollisions -Rows $rowsOut)
    $out = Export-ScrubTokenMapRows -Rows $rowsOut -TokenMapCsv $out
    Write-Ok "AD token map written: $out  ($($rows.Count) aliases)"
    Write-Warn "DO NOT upload this token map."
    [void](Import-ScrubTokenMap -TokenMapCsv $out)
    return $out
}

# =====================================================================
# REGION: Profiles (column / field semantics, per log type)
# =====================================================================
function Get-ScrubProfile {
    param([string]$Name)

    # Generic, deny-by-default: no column allow-list. Every cell is scanned for
    # identifier shapes; pure numbers / booleans / dates / OIDs / existing tokens
    # pass untouched. Shapeless secrets need SeedTerms.
    $generic = [pscustomobject]@{
        Name = 'Generic'
        Description = 'Any log. Deny-by-default: scans every field for identifier shapes.'
        Format = 'Auto'                 # Csv if .csv, else Text
        PassThroughRegex = $null
        ColumnPrefix = @()              # no column hints; rely on value shape
        FreeTextRegex = '.*'            # harden every column
        DenyByDefault = $true
    }

    # CA / AD CS exports -- mirrors the original pipeline's column rules so your
    # existing *_UNSCRUBBED.csv files scrub identically.
    $ca = [pscustomobject]@{
        Name = 'CA'
        Description = 'AD CS ESC-audit exports (issued certs, templates, CA/PKI security).'
        Format = 'Csv'
        PassThroughRegex = '^(RequestID|SubmittedWhen|ResolvedWhen|NotBefore|NotAfter|Disposition|ParseStatus|Published|SubjectSuppliedByRequester|SANSuppliedByRequester|SubjectOrSANSuppliedByRequester|ManagerApprovalRequired|AuthorizedSignaturesRequired|RequiredSignatureCount|NoSecurityExtension|NoEKU|AuthCapableOrAnyPurpose|ESC1Candidate_AnyEnroll|ESC1Candidate_BroadEnroll|ESC4Candidate|ESC5Candidate|ESC7Candidate|ESC11Candidate|ESC6_CAConfigFlag|EditF_AttributeSubjectAltName2|EditFlagsHex|InterfaceFlagsHex|IF_EnforceEncryptICertRequest|SecuritySource|IsDangerous|IsDefaultPrincipal|AccessType|PkiObjectType|Rights|SidMismatchLikelyBenign|StrongCertificateBindingEnforcement|EnforcementLevel|FullEnforcement|ReadStatus|ReadMethod|EndpointKind|Scheme|IsHttp|AuthFromMetadata|Probed|Reachable|HttpStatus|AuthSchemesOffered|NtlmOffered|EpaTokenChecking|EpaSource|Esc8RiskFromMetadata|ESC8Confirmed|ESC8NeedsEpaCheck|ESC8Mitigated|ESC8Candidate|HasSidSecurityExtension|RequestAttributesHasSAN|IsEnrollmentAgentCert|HasAnyPurposeOrNoEKU|OnBehalfOfCallerMismatch|NameFlag.*|EnrollmentFlag.*|EKU.*|OID.*|AuthEKUsMatched)$'
        ColumnPrefix = @(
            @{ Pattern = '^ca_|publishingca|certissuer'; Prefix = 'CA' },
            @{ Pattern = 'template'; Prefix = 'TEMPLATE'; NotOid = $true },
            @{ Pattern = 'hash|thumbprint|serial|certificatehash|rawcertificate'; Prefix = 'CERT' },
            @{ Pattern = 'dns|hostname|fqdn'; Prefix = 'DNS' },
            @{ Pattern = 'san_upn|subjectaltnameupn|upn|email'; Prefix = 'UNMAPPED_UPN' },
            @{ Pattern = 'requester|caller'; Prefix = 'UNMAPPED_PRINCIPAL'; DollarComputer = $true },
            @{ Pattern = 'principal|owner|user|account|enroll|permission|acl|allow|dangerouscontrol|group'; Prefix = 'PRINCIPAL'; DollarComputer = $true },
            @{ Pattern = 'issuer|subject|distinguished|x500|dn'; Prefix = 'X500' }
        )
        FreeTextRegex = 'Subject|Issuer|Distinguished|RequestAttributes|SAN|Principal|Enroll|Permission|ACL|Allow|Dangerous|Owner|Group|Name|Dns|DNS|Email|URI|Url|URL|Host'
        DenyByDefault = $false
    }

    # Generic Windows event log exported to CSV/XML/text.
    $win = [pscustomobject]@{
        Name = 'WindowsEventCsv'
        Description = 'Windows event logs exported to CSV.'
        Format = 'Csv'
        PassThroughRegex = '^(Id|EventID|Level|LevelDisplayName|TimeCreated|RecordId|LogName|ProviderName|ProviderId|ProviderGuid|Version|Qualifiers|Task|TaskDisplayName|Opcode|OpcodeDisplayName|Keywords|KeywordsDisplayNames|ProcessId|ThreadId|ActivityId|RelatedActivityId)$'
        ColumnPrefix = @(
            @{ Pattern = 'sid'; Prefix = 'SID' },
            @{ Pattern = 'address|ip'; Prefix = 'IP' },
            @{ Pattern = 'computer|host|workstation|machine'; Prefix = 'DNS' },
            @{ Pattern = 'account|user|subject|target|caller'; Prefix = 'PRINCIPAL'; DollarComputer = $true },
            @{ Pattern = 'domain'; Prefix = 'X500' }
        )
        FreeTextRegex = '^(Message|EventDataJson)$'
        DenyByDefault = $false
        SchemaColumns = ConvertTo-ProfileColumnRules -Rules @(
            [pscustomobject]@{ Regex = '^(Message|EventDataJson)$'; Action = 'Scan'; Prefix = 'OBJECT' },
            [pscustomobject]@{ Regex = '^(Id|EventID|Level|LevelDisplayName|TimeCreated|RecordId|LogName|ProviderName|ProviderId|ProviderGuid|Version|Qualifiers|Task|TaskDisplayName|Opcode|OpcodeDisplayName|Keywords|KeywordsDisplayNames|ProcessId|ThreadId|ActivityId|RelatedActivityId)$'; Action = 'PassThrough'; Prefix = 'OBJECT' }
        ) -DefaultAction 'Scan' -DefaultPrefix 'OBJECT' -Context 'WindowsEventCsv SchemaColumns'
        WholeColumnRules = ConvertTo-ProfileColumnRules -Rules @(
            [pscustomobject]@{ Regex = '^(MachineName|ComputerName)$'; Action = 'Scrub'; Prefix = 'COMPUTER' }
        ) -DefaultAction 'Scrub' -DefaultPrefix 'COMPUTER' -Context 'WindowsEventCsv WholeColumnRules'
    }

    # Free-form text logs (syslog, application logs, JSON lines, key=value).
    $text = [pscustomobject]@{
        Name = 'Text'
        Description = 'Free-form text logs (syslog, app logs, JSON lines, key=value).'
        Format = 'Text'
        PassThroughRegex = $null
        ColumnPrefix = @()
        FreeTextRegex = '.*'
        DenyByDefault = $true
    }

    # Tab- and pipe-delimited tables (treated like CSV with a different delimiter).
    $tsv = [pscustomobject]@{
        Name='Tsv'; Description='Tab-separated tables (.tsv).'; Format='Tsv'; Delimiter="`t"
        PassThroughRegex=$null; ColumnPrefix=@(); FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $psv = [pscustomobject]@{
        Name='Psv'; Description='Pipe-separated tables (col1|col2|...).'; Format='Psv'; Delimiter='|'
        PassThroughRegex=$null; ColumnPrefix=@(); FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }

    # IIS / W3C access logs (after the #Fields header is converted to CSV columns).
    $iis = [pscustomobject]@{
        Name='IIS'; Description='IIS / W3C access logs (.log with a #Fields header).'; Format='Csv'; Delimiter=','
        PassThroughRegex='^(date|time|time-taken|sc-status|sc-substatus|sc-win32-status|sc-bytes|cs-bytes|s-port|cs-method|cs-version)$'
        ColumnPrefix=@(
            @{ Pattern='(^|[_\-. ])(?:c-ip|s-ip|x-forwarded|x-forwarded-for|ip|ipaddr|ipaddress)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='username|cs-username|user'; Prefix='PRINCIPAL'; DollarComputer=$true },
            @{ Pattern='host|computername|s-computername|cs-host'; Prefix='DNS' }
        )
        FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }

    # Free-form text variants (detectors do the work).
    $syslog = [pscustomobject]@{
        Name='Syslog'; Description='Syslog (RFC 3164/5424) and similar line logs.'; Format='Text'; Delimiter=','
        PassThroughRegex=$null; ColumnPrefix=@(); FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $apache = [pscustomobject]@{
        Name='Apache'; Description='Apache / Nginx access logs (combined/common format).'; Format='Text'; Delimiter=','
        PassThroughRegex=$null; ColumnPrefix=@(); FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }

    # key=value text: tokenize VALUES, preserve keys.
    $cef = [pscustomobject]@{
        Name='Cef'; Description='CEF / LEEF SIEM events (key=value extensions).'; Format='Kv'; Delimiter=','
        PassThroughRegex=$null; ColumnPrefix=@(); FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $logfmt = [pscustomobject]@{
        Name='Logfmt'; Description='logfmt key=value application logs.'; Format='Kv'; Delimiter=','
        PassThroughRegex=$null; ColumnPrefix=@(); FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }

    $webAccess = [pscustomobject]@{
        Name='WebAccess'; Description='Web access logs from reverse proxies, Nginx, Apache, CDNs, and load balancers.'; Format='Text'; Delimiter=','
        PassThroughRegex=$null; ColumnPrefix=@(); FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $cloudAudit = [pscustomobject]@{
        Name='CloudAudit'; Description='Cloud audit/activity logs with principals, tenants, resources, source IPs, and request IDs.'; Format='Json'; Delimiter=','
        PassThroughRegex='^(eventTime|eventType|eventName|eventSource|awsRegion|status|result|severity|level|operation|category)$'
        ColumnPrefix=@(
            @{ Pattern='user|principal|actor|caller|identity|assumedrole|arn'; Prefix='PRINCIPAL'; DollarComputer=$true },
            @{ Pattern='tenant|account|subscription|project|organization|org'; Prefix='X500' },
            @{ Pattern='(^|[_\-. ])(?:source|client|remote|ip|ipaddr|ipaddress|address|addr)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='host|resource|instance|node|cluster'; Prefix='DNS' },
            @{ Pattern='request|correlation|trace|session|eventid'; Prefix='OBJECT' }
        )
        FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $firewallText = [pscustomobject]@{
        Name='Firewall'; Description='Firewall/VPN syslog and key=value text logs with source/destination addresses, users, devices, and rules.'; Format='Kv'; Delimiter=','
        PassThroughRegex=$null
        ColumnPrefix=@(
            @{ Pattern='(^|[_\-. ])(?:src|dst|source|destination|client|remote|ip|ipaddr|ipaddress|addr|address)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='user|account|principal|identity|login'; Prefix='PRINCIPAL'; DollarComputer=$true },
            @{ Pattern='host|device|gateway|server|clientname|fqdn|domain'; Prefix='DNS' },
            @{ Pattern='url|uri|endpoint'; Prefix='URI' },
            @{ Pattern='session|correlation|request|rule|policy'; Prefix='OBJECT' }
        )
        FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $firewallTextAlias = [pscustomobject]@{
        Name='FirewallText'; Description='Alias-style profile for firewall/VPN syslog and key=value text logs.'; Format='Kv'; Delimiter=','
        PassThroughRegex=$firewallText.PassThroughRegex; ColumnPrefix=$firewallText.ColumnPrefix; FreeTextRegex=$firewallText.FreeTextRegex; DenyByDefault=$firewallText.DenyByDefault; AllowedDomains=$firewallText.AllowedDomains
    }
    $firewallCsv = [pscustomobject]@{
        Name='FirewallCsv'; Description='Structured firewall/network security CSV exports with source/destination addresses, users, devices, and rules.'; Format='Csv'; Delimiter=','
        PassThroughRegex='^(action|allow|deny|protocol|proto|port|src_port|dst_port|bytes|packets|rule|policy|severity|time|date|timestamp)$'
        ColumnPrefix=@(
            @{ Pattern='(^|[_\-. ])(?:src|dst|source|destination|client|remote|ip|ipaddr|ipaddress|addr|address)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='user|account|principal|identity'; Prefix='PRINCIPAL'; DollarComputer=$true },
            @{ Pattern='host|device|gateway|server|clientname'; Prefix='DNS' }
        )
        FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $vpn = [pscustomobject]@{
        Name='Vpn'; Description='VPN, remote access, and authentication gateway logs.'; Format='Csv'; Delimiter=','
        PassThroughRegex='^(action|status|result|duration|bytes|port|protocol|time|date|timestamp|reason)$'
        ColumnPrefix=@(
            @{ Pattern='user|username|account|principal|identity|login'; Prefix='PRINCIPAL' },
            @{ Pattern='(^|[_\-. ])(?:client|remote|assigned|source|ip|ipaddr|ipaddress|address|addr)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='host|gateway|server|device'; Prefix='DNS' },
            @{ Pattern='session|correlation|request'; Prefix='OBJECT' }
        )
        FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $proxy = [pscustomobject]@{
        Name='Proxy'; Description='Proxy, SWG, and web filtering logs.'; Format='Csv'; Delimiter=','
        PassThroughRegex='^(action|status|category|method|http_method|response_code|bytes|time|date|timestamp|mime|user_agent)$'
        ColumnPrefix=@(
            @{ Pattern='user|username|account|principal'; Prefix='PRINCIPAL' },
            @{ Pattern='(^|[_\-. ])(?:client|source|remote|ip|ipaddr|ipaddress|address|addr)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='url|uri|referer|referrer|request'; Prefix='URI' },
            @{ Pattern='host|domain|fqdn|server'; Prefix='DNS' }
        )
        FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $appJson = [pscustomobject]@{
        Name='AppJson'; Description='Application JSON/NDJSON logs with user, host, tenant, request, trace, and secret fields.'; Format='Json'; Delimiter=','
        PassThroughRegex='^(timestamp|time|level|severity|messageTemplate|event|eventId|status|duration|elapsed|count)$'
        ColumnPrefix=@(
            @{ Pattern='user|username|account|principal|actor|subject'; Prefix='PRINCIPAL' },
            @{ Pattern='host|server|machine|node|pod|container|service'; Prefix='DNS' },
            @{ Pattern='(^|[_\-. ])(?:ip|ipaddr|ipaddress|address|addr|client|remote|source)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='tenant|org|organization|domain'; Prefix='X500' },
            @{ Pattern='request|correlation|trace|span|session|transaction'; Prefix='OBJECT' },
            @{ Pattern='token|secret|password|key|authorization'; Prefix='SECRET' }
        )
        FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $database = [pscustomobject]@{
        Name='Database'; Description='Database audit/query logs with users, clients, hosts, SQL text, and connection strings.'; Format='Text'; Delimiter=','
        PassThroughRegex=$null
        ColumnPrefix=@(
            @{ Pattern='user|login|principal|account|owner|schema'; Prefix='PRINCIPAL' },
            @{ Pattern='host|server|database|db|instance|client'; Prefix='DNS' },
            @{ Pattern='(^|[_\-. ])(?:ip|ipaddr|ipaddress|address|addr|client)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='password|secret|connection|string|conn'; Prefix='SECRET' }
        )
        FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $container = [pscustomobject]@{
        Name='Container'; Description='Container runtime, Docker, and orchestrator logs.'; Format='Json'; Delimiter=','
        PassThroughRegex='^(time|timestamp|level|severity|stream|exitCode|restartCount|status)$'
        ColumnPrefix=@(
            @{ Pattern='container|pod|node|host|image|service|namespace|cluster'; Prefix='DNS' },
            @{ Pattern='user|account|principal|serviceaccount'; Prefix='PRINCIPAL' },
            @{ Pattern='(^|[_\-. ])(?:ip|ipaddr|ipaddress|address|addr)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='secret|token|key|password'; Prefix='SECRET' }
        )
        FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $kubernetes = [pscustomobject]@{
        Name='Kubernetes'; Description='Kubernetes audit and workload logs.'; Format='Json'; Delimiter=','
        PassThroughRegex='^(kind|apiVersion|verb|stage|level|timestamp|code|reason|namespace)$'
        ColumnPrefix=@(
            @{ Pattern='user|username|groups|serviceaccount|impersonated'; Prefix='PRINCIPAL' },
            @{ Pattern='pod|node|container|host|cluster|object|resource|namespace'; Prefix='DNS' },
            @{ Pattern='(^|[_\-. ])(?:source|ip|ipaddr|ipaddress|address|addr)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='token|secret|authorization'; Prefix='SECRET' }
        )
        FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $identityProvider = [pscustomobject]@{
        Name='IdentityProvider'; Description='Identity provider, SSO, MFA, and directory sign-in logs.'; Format='Csv'; Delimiter=','
        PassThroughRegex='^(time|date|timestamp|result|status|success|failure|risk|mfa|method|app|application|event|eventid)$'
        ColumnPrefix=@(
            @{ Pattern='user|username|upn|email|account|principal|actor|target'; Prefix='UNMAPPED_UPN' },
            @{ Pattern='tenant|domain|realm|org|organization|directory'; Prefix='X500' },
            @{ Pattern='(^|[_\-. ])(?:ip|ipaddr|ipaddress|address|addr|client|source|remote)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='device|host|machine|computer'; Prefix='DNS' },
            @{ Pattern='session|correlation|request|token|jti'; Prefix='OBJECT' }
        )
        FreeTextRegex='.*'; DenyByDefault=$true; AllowedDomains=@()
    }
    $serviceNow = [pscustomobject]@{
        Name='ServiceNow'; Description='ServiceNow incident/change/task/CMDB exports with callers, assignees, CIs, notes, and URLs.'; Format='Csv'; Delimiter=','
        PassThroughRegex='^(number|sys_id|opened|opened_at|closed|closed_at|resolved|resolved_at|updated|sys_updated_on|created|sys_created_on|state|status|priority|impact|urgency|severity|category|subcategory|assignment_group|business_service|short_description|approval|active|made_sla|reassignment_count|calendar_duration|business_duration)$'
        ColumnPrefix=@(
            @{ Pattern='caller|opened_by|resolved_by|closed_by|assigned_to|requested_for|requested_by|watch_list|user|email|upn'; Prefix='PRINCIPAL'; DollarComputer=$true },
            @{ Pattern='cmdb_ci|configuration_item|computer|host|device|server|node|endpoint|asset'; Prefix='COMPUTER' },
            @{ Pattern='(^|[_\-. ])(?:ip|ipaddr|ipaddress|address|addr|source|destination)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='company|department|domain|tenant|account'; Prefix='X500' },
            @{ Pattern='url|uri|link|endpoint'; Prefix='URI' },
            @{ Pattern='work_notes|comments|description|close_notes|additional_comments'; Prefix='OBJECT' },
            @{ Pattern='token|secret|password|credential|key'; Prefix='SECRET' }
        )
        FreeTextRegex='work_notes|comments|description|notes|url|uri|link'
        DenyByDefault=$false; AllowedDomains=@('service-now.com','servicenow.com')
    }
    $intuneDiagnostics = [pscustomobject]@{
        Name='IntuneDiagnostics'; Description='Intune diagnostics bundle logs, MDM diagnostic reports, registry exports, XML/HTML reports, and command-output text.'; Format='Text'; Delimiter=','
        PassThroughRegex='^(timestamp|time|date|status|state|result|level|severity|eventid|event_id|errorcode|error_code|hresult|policy|policyname|provider|operation|phase|step|count)$'
        ColumnPrefix=@()
        FreeTextRegex='(?i)(intune|mdm|omadm|deviceenroller|deviceenrollment|enrollment|autopilot|windows update|windowsupdate|policy|compliance|tenant|upn|user|userid|device|serial|imei|meid|wifi|ethernet|mac|regedit|registry|html|xml|computer|security userid)'
        DenyByDefault=$false; AllowedDomains=@('microsoft.com','windows.net')
        LabelRules=@(
            @{ Name='IntuneUser'; Labels=@('UPN','User Principal Name','User','User Name','UserId','User ID','Security UserID','Subject User Name','Account Name','Primary User','Enrolled By','Enrollment UPN','Email','Email Address'); Prefix='UNMAPPED_UPN' },
            @{ Name='IntuneDevice'; Labels=@('Device Name','Managed Device Name','Computer Name','Computer','Hostname','Host Name','Machine Name','DeviceId','Device ID','Azure AD Device ID','AAD Device ID','AADDeviceId','Entra Device ID'); Prefix='COMPUTER' },
            @{ Name='IntuneSerial'; Labels=@('Serial Number','SerialNumber','IMEI','MEID'); Prefix='COMPUTER' },
            @{ Name='IntuneIpAddress'; Labels=@('IP Address','IPv4 Address','Client IP Address','Source Network Address'); Prefix='IP' },
            @{ Name='IntuneMacAddress'; Labels=@('WiFi MAC Address','Wi-Fi MAC Address','Ethernet MAC Address','MAC Address'); Prefix='MAC' },
            @{ Name='IntuneTenant'; Labels=@('Tenant ID','Tenant Name','Domain Name','Organization','Organization ID'); Prefix='X500' },
            @{ Name='IntuneSecrets'; Labels=@('Token','Refresh Token','Access Token','Authorization','Bearer','Password','Client Secret'); Prefix='SECRET' }
        )
        CustomRegexRules=@(
            @{
                Name='RegistryUserSid'
                Regex='(?i)(\\(?:Users|ProfileList)\\)(S-1-5-21-[0-9-]{10,})'
                CaptureGroup=2
                Prefix='SID'
                Keywords=@('ProfileList','Users','S-1-5-21')
                Entropy=0
            },
            @{
                Name='AzureAdUserSid'
                Regex='(?i)\buserSID\s*[:=]\s*(S-1-12-1-[0-9-]{10,})'
                CaptureGroup=1
                Prefix='SID'
                Keywords=@('userSID','S-1-12-1')
                Entropy=0
            },
            @{
                Name='IntuneUserGuidLabel'
                Regex='(?i)\buserId\s*[:=]\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
                CaptureGroup=1
                Prefix='OBJECT'
                Keywords=@('userId')
                Entropy=0
            },
            @{
                Name='IntunePolicyUserGuidPath'
                Regex='(?i)\\(?:Policies|Execution)\\([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\\|\]|$)'
                CaptureGroup=1
                Prefix='OBJECT'
                Keywords=@('IntuneManagementExtension','Policies','Execution')
                Entropy=0
            },
            @{
                Name='HtmlAttributeSensitiveValue'
                Regex='(?i)\b(?:data-user|data-upn|data-device|data-tenant)\s*=\s*["'']([^"'']{3,200})["'']'
                CaptureGroup=1
                Prefix='OBJECT'
                Keywords=@('data-user','data-upn','data-device','data-tenant')
                Entropy=0
            },
            @{
                Name='HtmlIntuneDeviceLabel'
                Regex='(?i)\b((?:Device\s+Name|Managed\s+Device\s+Name|Computer\s+Name|Computer|Hostname|Host\s+Name|Machine\s+Name)\s*[:=]\s*)([^<\r\n]{3,200})'
                CaptureGroup=2
                Prefix='COMPUTER'
                Keywords=@('Device Name','Computer','Hostname','Machine Name')
                Entropy=0
            },
            @{
                Name='HtmlIntuneUserLabel'
                Regex='(?i)\b((?:UPN|User\s+Principal\s+Name|Primary\s+User|Enrolled\s+By|Email(?:\s+Address)?)\s*[:=]\s*)([^<\r\n]{3,200})'
                CaptureGroup=2
                Prefix='UNMAPPED_UPN'
                Keywords=@('UPN','User Principal Name','Primary User','Email')
                Entropy=0
            },
            @{
                Name='HtmlIntuneSerialLabel'
                Regex='(?i)\b((?:Serial\s+Number|SerialNumber|IMEI|MEID)\s*[:=]\s*)([^<\r\n]{3,200})'
                CaptureGroup=2
                Prefix='COMPUTER'
                Keywords=@('Serial','IMEI','MEID')
                Entropy=0
            },
            @{
                Name='XmlComputerElement'
                Regex='(?i)<Computer>([^<]{3,200})</Computer>'
                CaptureGroup=1
                Prefix='COMPUTER'
                Keywords=@('<Computer>')
                Entropy=0
            },
            @{
                Name='XmlDataDevice'
                Regex='(?i)<Data\b[^>]*\bName\s*=\s*["''](?:DeviceName|Device\s+Name|Computer|ComputerName|DeviceId|Device\s+ID|AADDeviceID|AzureADDeviceID|Azure\s+AD\s+Device\s+ID)["''][^>]*>([^<]{3,256})</Data>'
                CaptureGroup=1
                Prefix='COMPUTER'
                Keywords=@('<Data','Device','Computer','AADDeviceID')
                Entropy=0
            },
            @{
                Name='XmlDataUser'
                Regex='(?i)<Data\b[^>]*\bName\s*=\s*["''](?:UPN|UserPrincipalName|User\s+Principal\s+Name|PrimaryUser|Primary\s+User|Email|EmailAddress)["''][^>]*>([^<]{3,256})</Data>'
                CaptureGroup=1
                Prefix='UNMAPPED_UPN'
                Keywords=@('<Data','UPN','UserPrincipalName','Email')
                Entropy=0
            },
            @{
                Name='XmlDataSerial'
                Regex='(?i)<Data\b[^>]*\bName\s*=\s*["''](?:SerialNumber|Serial\s+Number|IMEI|MEID)["''][^>]*>([^<]{3,256})</Data>'
                CaptureGroup=1
                Prefix='COMPUTER'
                Keywords=@('<Data','Serial','IMEI','MEID')
                Entropy=0
            },
            @{
                Name='XmlDataMac'
                Regex='(?i)<Data\b[^>]*\bName\s*=\s*["''](?:MACAddress|MAC\s+Address|WiFiMacAddress|EthernetMacAddress)["''][^>]*>((?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2})</Data>'
                CaptureGroup=1
                Prefix='MAC'
                Keywords=@('<Data','MAC')
                Entropy=0
            },
            @{
                Name='XmlUserSidAttribute'
                Regex='(?i)\bUserID\s*=\s*["''](S-1-5-21-[0-9-]{10,})["'']'
                CaptureGroup=1
                Prefix='SID'
                Keywords=@('UserID','S-1-5-21')
                Entropy=0
            },
            @{
                Name='IntuneDiagnosticSerialNumber'
                Regex='(?i)\b((?:Serial\s+Number|SerialNumber|IMEI|MEID)\s*[:=]\s*)([A-Z0-9][A-Z0-9._-]{5,})\b'
                CaptureGroup=2
                Prefix='COMPUTER'
                Keywords=@('Serial','IMEI','MEID')
                Entropy=0
            },
            @{
                Name='IntuneMacAddressLabel'
                Regex='(?i)\b((?:Wi-?Fi|Ethernet)?\s*MAC\s+Address\s*[:=]\s*)((?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2})\b'
                CaptureGroup=2
                Prefix='MAC'
                Keywords=@('MAC Address')
                Entropy=0
            }
        )
    }
    $nexthink = [pscustomobject]@{
        Name='Nexthink'; Description='Nexthink device, user, binary, destination, campaign, and experience exports.'; Format='Csv'; Delimiter=','
        PassThroughRegex='^(timestamp|time|date|event_time|collector|score|status|state|severity|platform|os|os_version|version|binary_version|package_version|count|duration|latency|size|bytes|cpu|memory|disk|battery|wifi|execution_status)$'
        ColumnPrefix=@(
            @{ Pattern='user|username|upn|email|account|employee|principal'; Prefix='PRINCIPAL'; DollarComputer=$true },
            @{ Pattern='device|host|hostname|machine|computer|endpoint|collector|serial|asset'; Prefix='COMPUTER' },
            @{ Pattern='(^|[_\-. ])(?:ip|ipaddr|ipaddress|address|addr|remote|destination|source)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='(?:^|[_\-. ])(?:binary|file|executable|process)[_\-. ]*(?:sha1|sha256|sha512|hash|checksum|thumbprint)(?:$|[_\-. ])'; Prefix='OBJECT' },
            @{ Pattern='domain|tenant|organization|department|entity'; Prefix='X500' },
            @{ Pattern='url|uri|web|destination|dns|fqdn'; Prefix='DNS' },
            @{ Pattern='campaign|survey|question|answer|comment|description'; Prefix='OBJECT' },
            @{ Pattern='token|secret|password|credential|key'; Prefix='SECRET' }
        )
        FreeTextRegex='comment|description|campaign|question|answer|url|uri|destination|execution\.output|output|message|details|path|file'
        CustomRegexRules=@(
            @{
                Name='NexthinkActionDevice'
                Regex='(?i)(\bAction\s+run\s+by\s+\S+\s+on\s+)([A-Za-z][A-Za-z0-9_-]{2,})'
                CaptureGroup=2
                Prefix='COMPUTER'
                Keywords=@('Action run by')
                Entropy=0
            }
        )
        DenyByDefault=$false; AllowedDomains=@('nexthink.com')
    }
    $sccm = [pscustomobject]@{
        Name='Sccm'; Description='SCCM/MECM inventory, deployment, client, and collection exports.'; Format='Csv'; Delimiter=','
        PassThroughRegex='^(timestamp|time|date|site|site_code|status|state|result|compliance|deployment_status|client_status|active|obsolete|version|build|os|os_version|collection|collection_id|deployment_id|assignment_id|article_id|ci_id|resourceid|resource_id|model|manufacturer|count)$'
        ColumnPrefix=@(
            @{ Pattern='user|username|last_logon|primary_user|upn|email|account'; Prefix='PRINCIPAL'; DollarComputer=$true },
            @{ Pattern='device|resource|computer|machine|hostname|netbios|client|endpoint|serial|smbios|bios|asset'; Prefix='COMPUTER' },
            @{ Pattern='(^|[_\-. ])(?:ip|ipaddr|ipaddress|address|addr|subnet|boundary)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='(^|_)(mac|macaddress|mac_address|mac_addresses0)($|_)'; Prefix='MAC' },
            @{ Pattern='domain|forest|tenant|department|org|organization'; Prefix='X500' },
            @{ Pattern='package|application|app|program|software|publisher|product'; Prefix='OBJECT' },
            @{ Pattern='url|uri|management_point|distribution_point|server'; Prefix='DNS' },
            @{ Pattern='token|secret|password|credential|key'; Prefix='SECRET' }
        )
        FreeTextRegex='description|error|message|comment|url|uri|server|management|distribution'
        DenyByDefault=$false; AllowedDomains=@()
    }
    $sccmText = [pscustomobject]@{
        Name='SccmText'; Description='SCCM/MECM/ConfigMgr client, CMTrace, deployment, and management-point text logs.'
        Format='Text'; Delimiter=','
        PassThroughRegex=$null
        ColumnPrefix=@()
        FreeTextRegex='.*'
        DenyByDefault=$true
        AllowedDomains=@('microsoft.com','windows.net')
        LabelRules=@(
            @{ Name='ConfigMgrUser'; Labels=@('user','username','account','context','caller','primary user'); Prefix='PRINCIPAL'; Preserve=@('SYSTEM','LOCAL SYSTEM','NT AUTHORITY\SYSTEM') },
            @{ Name='ConfigMgrDevice'; Labels=@('device','machine','computer','hostname','client','management point','distribution point','server'); Prefix='COMPUTER' },
            @{ Name='ConfigMgrAddress'; Labels=@('ip','ip address','client ip','remote address','source address'); Prefix='IP' },
            @{ Name='ConfigMgrUrl'; Labels=@('url','uri','mp','dp','endpoint'); Prefix='URI' }
        )
        CustomRegexRules=@(
            @{
                Name='CMTraceContext'
                Regex='(?i)\bcontext="([^"]{3,180})"'
                CaptureGroup=1
                Prefix='PRINCIPAL'
                Keywords=@('context=')
                Entropy=0
                Allowlist=@('SYSTEM','LOCAL SYSTEM','NT AUTHORITY\SYSTEM')
            }
        )
    }
    $intune = [pscustomobject]@{
        Name='Intune'; Description='Microsoft Intune / Endpoint Manager device, app, policy, enrollment, and compliance exports.'; Format='Csv'; Delimiter=','
        PassThroughRegex='^(timestamp|time|date|last_sync|enrolled_date|enrollment_date|compliance_state|compliant|managed|ownership|management_agent|platform|os|os_version|model|manufacturer|policy|policy_name|profile|assignment|state|status|result|risk|count|version)$'
        ColumnPrefix=@(
            @{ Pattern='user|username|upn|email|primary_user|enrolled_by|owner|principal|account'; Prefix='UNMAPPED_UPN'; DollarComputer=$true },
            @{ Pattern='device|device_name|managed_device|computer|host|machine|serial|imei|meid|azure_ad_device|aad_device|entra|endpoint'; Prefix='COMPUTER' },
            @{ Pattern='(^|[_\-. ])(?:ip|ipaddr|ipaddress|address|addr)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='(^|_)(mac|macaddress|mac_address|wifi|wi_?fi|ethernet)($|_)'; Prefix='MAC' },
            @{ Pattern='tenant|domain|organization|department|group'; Prefix='X500' },
            @{ Pattern='app|application|bundle|package|publisher|certificate|thumbprint'; Prefix='OBJECT' },
            @{ Pattern='url|uri|server|endpoint'; Prefix='DNS' },
            @{ Pattern='token|secret|password|credential|key'; Prefix='SECRET' }
        )
        FreeTextRegex='description|error|message|remediation|notes|url|uri'
        DenyByDefault=$false; AllowedDomains=@('microsoft.com','windows.net')
    }
    $edr = [pscustomobject]@{
        Name='Edr'; Description='EDR/XDR alert JSON or JSONL exports with devices, users, network destinations, commands, and evidence.'
        Format='Json'; Delimiter=','
        PassThroughRegex='^(timestamp|time|date|vendor|product|severity|level|status|state|action|verdict|process_name|parent_process|parent_process_name|file_name|sha1|sha256|md5|alert_id|event_id|rule|rule_name|tactic|technique)$'
        ColumnPrefix=@(
            @{ Pattern='user|username|user_email|upn|account|principal|identity'; Prefix='PRINCIPAL'; DollarComputer=$true },
            @{ Pattern='device|device_name|device_id|host|hostname|machine|computer|endpoint|asset|sensor'; Prefix='COMPUTER' },
            @{ Pattern='(^|[_\-. ])(?:ip|ipaddr|ipaddress|address|addr|remote_ip|local_ip|source|destination)(?:$|[_\-. ])'; Prefix='IP' },
            @{ Pattern='domain|remote_domain|dns|fqdn|url|uri|endpoint'; Prefix='DNS' },
            @{ Pattern='command|command_line|process_path|image_path|file_path|registry|evidence|description|message'; Prefix='OBJECT' },
            @{ Pattern='token|secret|password|credential|key|authorization'; Prefix='SECRET' }
        )
        FreeTextRegex='command|command_line|process_path|image_path|file_path|registry|evidence|description|message|url|uri|domain'
        DenyByDefault=$false; AllowedDomains=@('microsoft.com','windows.net')
    }

    $all = [ordered]@{ Generic=$generic; CA=$ca; WindowsEventCsv=$win; Text=$text;
                       Tsv=$tsv; Psv=$psv; IIS=$iis; Syslog=$syslog; Apache=$apache; Cef=$cef; Logfmt=$logfmt;
                       WebAccess=$webAccess; CloudAudit=$cloudAudit; Firewall=$firewallText; FirewallText=$firewallTextAlias; FirewallCsv=$firewallCsv; Vpn=$vpn; Proxy=$proxy;
                       AppJson=$appJson; Database=$database; Container=$container; Kubernetes=$kubernetes; IdentityProvider=$identityProvider;
                       ServiceNow=$serviceNow; IntuneDiagnostics=$intuneDiagnostics; Nexthink=$nexthink; Sccm=$sccm; SccmText=$sccmText; Intune=$intune; Edr=$edr }
    if ($Name) {
        foreach ($k in $all.Keys) { if ($k -ieq $Name) { return $all[$k] } }
        return $null
    }
    return @($all.Values)
}

# =====================================================================
# REGION: Local log format recommendations (no salt, no scrubbing)
# =====================================================================
function Get-ReadableFileSample {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$File,
        [int]$SampleLines = 50,
        [int]$MaxSampleBytes = 1048576
    )

    if ($SampleLines -lt 1) { $SampleLines = 1 }
    if ($MaxSampleBytes -lt 4096) { $MaxSampleBytes = 4096 }
    $warnings = @()
    $ext = ([string]$File.Extension).ToLowerInvariant()
    if ($ext -in @('.evtx','.xlsx','.docx','.pptx','.doc','.ppt','.cab','.etl','.zip')) {
        $warnings += "File type is not sampled as plain text."
        return [pscustomobject]@{ Lines = @(); Text = ''; Warnings = $warnings }
    }

    $lines = @()
    try {
        $maxChars = [Math]::Max(4096, [Math]::Min($MaxSampleBytes, 4MB))
        $sb = New-Object System.Text.StringBuilder
        $reader = New-Object System.IO.StreamReader($File.FullName, [System.Text.Encoding]::UTF8, $true, 4096)
        try {
            $buf = New-Object char[] 4096
            $lineBreaks = 0
            while ($sb.Length -lt $maxChars) {
                $want = [Math]::Min($buf.Length, $maxChars - $sb.Length)
                if ($want -le 0) { break }
                $read = $reader.Read($buf, 0, $want)
                if ($read -le 0) { break }
                [void]$sb.Append($buf, 0, $read)
                for ($i = 0; $i -lt $read; $i++) {
                    if ($buf[$i] -eq [char]"`n") { $lineBreaks++ }
                }
                if ($lineBreaks -ge $SampleLines) { break }
            }
            if (-not $reader.EndOfStream) { $warnings += "Sample truncated to a bounded local preview." }
        }
        finally { try { $reader.Close() } catch { } }
        $sampleText = $sb.ToString()
        $lines = @($sampleText -split "`r?`n" | Select-Object -First $SampleLines)
    }
    catch {
        $warnings += "Could not read sample: $($_.Exception.Message)"
    }

    $text = if ($lines.Count -gt 0) { [string]::Join("`n", @($lines | ForEach-Object { [string]$_ })) } else { '' }
    if ($text -match "`0") { $warnings += "Sample contains NUL bytes and may be binary." }
    return [pscustomobject]@{ Lines = $lines; Text = $text; Warnings = $warnings }
}

function Get-LogHeaderColumns {
    param([string]$Header, [string]$Delimiter)
    if ([string]::IsNullOrWhiteSpace($Header)) { return @() }
    $parts = @($Header -split [regex]::Escape($Delimiter))
    return @($parts | ForEach-Object {
        $c = ([string]$_).Trim()
        $c = $c.Trim([char]34).Trim([char]39)
        $c.Trim()
    } | Where-Object { $_ })
}

function Get-LogColumnHitCount {
    param([string[]]$Columns, [string[]]$Patterns)
    $hits = 0
    foreach ($pat in $Patterns) {
        foreach ($col in @($Columns)) {
            if ($col -match $pat) { $hits++; break }
        }
    }
    return $hits
}

function Test-JsonText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    try {
        [void]($Text | ConvertFrom-Json -ErrorAction Stop)
        return $true
    }
    catch { return $false }
}

function Test-JsonLines {
    param([string[]]$Lines)
    $checked = 0
    $ok = 0
    foreach ($line in @($Lines)) {
        $t = ([string]$line).Trim()
        if ([string]::IsNullOrWhiteSpace($t)) { continue }
        $checked++
        try {
            [void]($t | ConvertFrom-Json -ErrorAction Stop)
            $ok++
        }
        catch { }
        if ($checked -ge 10) { break }
    }
    if ($checked -le 1) { return $false }
    return ($ok -ge [Math]::Ceiling($checked * 0.8))
}

function Get-UlsEnterpriseProfileHint {
    param(
        [string[]]$Columns = @(),
        [string]$Text = ''
    )

    $columnsSafe = @($Columns | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $textSafe = [string]$Text

    $hints = @(
        [pscustomobject]@{
            Profile='ServiceNow'; Format='ServiceNow export'; Confidence=92
            Patterns=@('(?i)^sys_id$','(?i)^number$','(?i)^short_description$','(?i)^work_notes$','(?i)^additional_comments$','(?i)^caller_id$','(?i)^opened_by$','(?i)^assigned_to$','(?i)^cmdb_ci$','(?i)^assignment_group$','(?i)^sys_created_on$','(?i)^sys_updated_on$')
            TextPattern='(?i)\b(service[- ]?now|sys_id|work_notes|cmdb_ci|assignment_group|additional_comments)\b'
            Reason='Header/sample contains ServiceNow task, CMDB, caller, assignee, or work-note fields.'
            MinHits=3
        }
        [pscustomobject]@{
            Profile='Nexthink'; Format='Nexthink export'; Confidence=90
            Patterns=@('(?i)^device_uid$','(?i)^device_name$','(?i)^device\.name$','(?i)^device\.collector\.uid$','(?i)^user_name$','(?i)^user\.name$','(?i)^user\.email$','(?i)^user_sid$','(?i)^binary_name$','(?i)^binary\.name$','(?i)^remote_action$','(?i)^remote_action\.name$','(?i)^campaign$','(?i)^campaign\.name$','(?i)^execution_status$','(?i)^execution\.status$','(?i)^collector$','(?i)^experience_score$','(?i)^destination$','(?i)^destination\.name$','(?i)^destination\.ip$')
            TextPattern='(?i)\b(nexthink|device_uid|remote_action|experience_score|execution_status|binary_name)\b'
            Reason='Header/sample contains Nexthink device, user, binary, campaign, or remote-action fields.'
            MinHits=3
        }
        [pscustomobject]@{
            Profile='Sccm'; Format='SCCM/MECM export'; Confidence=91
            Patterns=@('(?i)^ResourceID$','(?i)^SMSUniqueIdentifier$','(?i)^Name0$','(?i)^User_Name0$','(?i)^CollectionID$','(?i)^DeploymentID$','(?i)^SiteCode$','(?i)^PackageID$','(?i)^ApplicationName$','(?i)^ClientVersion$','(?i)^LastLogonUserName$','(?i)^MAC_Addresses0$','(?i)^SerialNumber0$')
            TextPattern='(?i)\b(SMSUniqueIdentifier|ResourceID|CollectionID|DeploymentID|SiteCode|ClientVersion|MECM|SCCM)\b'
            Reason='Header/sample contains SCCM/MECM inventory, client, collection, or deployment fields.'
            MinHits=3
        }
        [pscustomobject]@{
            Profile='Intune'; Format='Intune export'; Confidence=91
            Patterns=@('(?i)^managedDeviceName$','(?i)^managed device id$','(?i)^deviceName$','(?i)^device name$','(?i)^userPrincipalName$','(?i)^user principal name$','(?i)^primary user$','(?i)^email address$','(?i)^azureADDeviceId$','(?i)^azure ad device id$','(?i)^complianceState$','(?i)^compliance$','(?i)^managementAgent$','(?i)^enrolledDateTime$','(?i)^deviceEnrollmentType$','(?i)^serialNumber$','(?i)^serial number$','(?i)^imei$','(?i)^wiFiMacAddress$','(?i)^wi-fi mac$','(?i)^ethernetMacAddress$','(?i)^ownerType$','(?i)^operatingSystem$','(?i)^os$','(?i)^osVersion$','(?i)^os version$','(?i)^last check-in$')
            TextPattern='(?i)\b(Intune|Endpoint Manager|managedDeviceName|azureADDeviceId|complianceState|managementAgent|deviceEnrollmentType)\b'
            Reason='Header/sample contains Intune device, enrollment, compliance, or management-agent fields.'
            MinHits=3
        }
        [pscustomobject]@{
            Profile='IdentityProvider'; Format='M365/identity audit export'; Confidence=89
            Patterns=@('(?i)^CreationDate$','(?i)^UserIds?$','(?i)^Operations?$','(?i)^AuditData$','(?i)^Workload$','(?i)^RecordType$','(?i)^ResultStatus$','(?i)^ClientIP$','(?i)^UserId$','(?i)^ObjectId$','(?i)^Actor$','(?i)^Target$')
            TextPattern='(?i)\b(OfficeActivity|AzureActiveDirectory|Exchange|SharePoint|Unified Audit|AuditData|ResultStatus|ClientIP)\b'
            Reason='Header/sample contains Microsoft 365, Entra ID, or unified audit export fields.'
            MinHits=3
        }
        [pscustomobject]@{
            Profile='FirewallCsv'; Format='Firewall CSV export'; Confidence=88
            Patterns=@('(?i)^(src|src_ip|srcip|source|source_ip|sourceip|source_address|sourceaddress)$','(?i)^(dst|dst_ip|dstip|destination|destination_ip|destinationip|destination_address|destinationaddress)$','(?i)^(action|rule|policy|protocol|proto)$','(?i)^(src_port|srcport|dst_port|dstport|bytes|packets)$','(?i)^(user|username|identity|src_user|srcuser|source_user|sourceuser|destination_user|destinationuser)$','(?i)^(src_host|srchost|source_host|sourcehost|dst_host|dsthost|destination_host|destinationhost)$')
            TextPattern='(?i)\b(src_ip|dst_ip|source_ip|destination_ip|firewall|vpn|policy|rule|deny|allow)\b'
            Reason='Header/sample contains firewall/VPN source, destination, action, rule, or user fields.'
            MinHits=3
        }
    )

    foreach ($hint in $hints) {
        $hits = Get-LogColumnHitCount -Columns $columnsSafe -Patterns $hint.Patterns
        if ($hits -ge [int]$hint.MinHits) {
            return [pscustomobject]@{ Profile=$hint.Profile; Format=$hint.Format; Confidence=$hint.Confidence; Reason=$hint.Reason }
        }
        if ($hits -ge 2 -and -not [string]::IsNullOrWhiteSpace($textSafe) -and $textSafe -match $hint.TextPattern) {
            return [pscustomobject]@{ Profile=$hint.Profile; Format=$hint.Format; Confidence=$hint.Confidence; Reason=$hint.Reason }
        }
    }
    return $null
}

function Test-UlsIntuneDiagnosticsText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    $patterns = @(
        '(?i)\b(Intune|IntuneManagementExtension|Endpoint Manager)\b',
        '(?i)\b(MDM|OMADM|OMA-DM|DeviceManagement-Enterprise-Diagnostics-Provider)\b',
        '(?i)\b(DeviceEnroller|DeviceEnrollment|EnterpriseMgmt|EnrollmentStatusTracking|Autopilot)\b',
        '(?i)\b(Windows Update|WindowsUpdate|UsoSvc|UpdateSessionOrchestration)\b',
        '(?i)\b(PolicyManager|./Vendor/MSFT|Diagnostic Report|MDMDiagReport)\b',
        '(?i)\\(SOFTWARE\\Microsoft\\Enrollments|SOFTWARE\\Microsoft\\Provisioning|ProfileList\\S-1-5-21-)',
        '(?i)<(?:Computer|Security\s+UserID|UserID|Event|System)\b',
        '(?i)\b(?:Azure AD Device ID|AAD Device ID|Tenant ID|Serial Number|IMEI|MEID|WiFi MAC Address|Ethernet MAC Address)\b',
        '(?i)\b(?:MDMDiag|DiagnosticLogCSP|WlanReport|battery-report|energy-report|DeviceInventory|DeclaredConfiguration)\b'
    )
    $hits = 0
    foreach ($pat in $patterns) {
        if ($Text -match $pat) { $hits++ }
    }
    return ($hits -ge 2)
}

function Test-UlsIntuneDiagnosticsPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    return ($Path -match '(?i)(\\|/|^)(DiagLogs-[^\\/]+|MDMDiagnostics|IntuneManagementExtension|DiagnosticLogCSP|DeviceEnrollment|DeviceEnroller|EnterpriseMgmt|Autopilot|WlanReport|WindowsUpdate|PolicyManager|DeviceInventory|DeclaredConfiguration)(\\|/|$|[_\-.])' -or
            $Path -match '(?i)(RegistryKey .*Microsoft_(?:Enrollments|IntuneManagementExtension|PolicyManager|DeviceInventory)|HKLM[_\\]Software[_\\]Microsoft[_\\]Enrollments)')
}

function Test-UlsFirewallVpnText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    $hasNetworkPair = ($Text -match '(?i)\b(src_ip|source_ip|src=|saddr=)\b' -and $Text -match '(?i)\b(dst_ip|destination_ip|dst=|daddr=)\b')
    $hasFirewallMarker = ($Text -match '(?i)\b(firewall|fw-|vpn|globalprotect|anyconnect|ipsec|wireguard|tunnel|policy=|rule=|proto=|protocol=|deny|allow|blocked|permitted)\b')
    if (-not ($hasNetworkPair -and $hasFirewallMarker)) { return $false }
    $hits = 0
    foreach ($pat in @(
        '(?i)\b(src_ip|source_ip|dst_ip|destination_ip|src=|dst=|saddr=|daddr=)\b',
        '(?i)\b(firewall|fw-|vpn|globalprotect|anyconnect|ipsec|wireguard|tunnel)\b',
        '(?i)\b(action|policy|rule|deny|allow|blocked|permitted|protocol|proto|src_port|dst_port)\s*=',
        '(?i)\b(user|username|account|identity)\s*='
    )) {
        if ($Text -match $pat) { $hits++ }
    }
    return ($hits -ge 2)
}

function New-RecommendedScrubCommand {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Profile,
        [switch]$UseAutoProfile,
        [string]$ExtraSwitches = ''
    )
    $quotedPath = "'" + ($Path -replace "'", "''") + "'"
    $profilePart = if ($UseAutoProfile) { "-AutoProfile" } else { "-Profile $Profile" }
    $extraPart = if ([string]::IsNullOrWhiteSpace($ExtraSwitches)) { '' } else { ' ' + $ExtraSwitches.Trim() }
    return "Invoke-UniversalScrubber -Path $quotedPath $profilePart$extraPart -DryRun -Salt `"preview-only`" -MapSource Discover -NonInteractive"
}

function New-LogFormatRecommendationObject {
    param(
        [Parameter(Mandatory)]$File,
        [Parameter(Mandatory)][string]$DetectedFormat,
        [Parameter(Mandatory)][string]$SuggestedProfile,
        [Parameter(Mandatory)][int]$Confidence,
        [string[]]$Reasons,
        [string[]]$Warnings,
        [string]$ExtraSwitches = ''
    )

    if (-not (Get-ScrubProfile -Name $SuggestedProfile)) {
        $Warnings += "Profile '$SuggestedProfile' is not built in; using Generic."
        $SuggestedProfile = 'Generic'
    }
    if ($Confidence -lt 0) { $Confidence = 0 }
    if ($Confidence -gt 100) { $Confidence = 100 }
    return [pscustomobject]@{
        Path               = $File.FullName
        Name               = $File.Name
        Extension          = $File.Extension
        DetectedFormat     = $DetectedFormat
        SuggestedProfile   = $SuggestedProfile
        Confidence         = $Confidence
        Reasons            = @($Reasons)
        Warnings           = @($Warnings)
        RecommendedCommand = (New-RecommendedScrubCommand -Path $File.FullName -Profile $SuggestedProfile -ExtraSwitches $ExtraSwitches)
    }
}

function Get-LogFormatRecommendation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$File,
        [int]$SampleLines = 50
    )

    $sample = Get-ReadableFileSample -File $File -SampleLines $SampleLines
    $warnings = @($sample.Warnings)
    $lines = @($sample.Lines)
    $text = [string]$sample.Text
    $ext = ([string]$File.Extension).ToLowerInvariant()
    $first = @($lines | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ } | Select-Object -First 1)
    $firstLine = if ($first.Count -gt 0) { [string]$first[0] } else { '' }

    if ($ext -eq '.evtx') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'EVTX' -SuggestedProfile 'WindowsEventCsv' -Confidence 95 `
            -Reasons @('The .evtx extension identifies a Windows Event Log file.') `
            -Warnings @('EVTX is binary; the scrubber converts it to CSV before scrubbing.')
    }
    if ($ext -eq '.etl') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'ETL trace' -SuggestedProfile 'Generic' -Confidence 45 `
            -Reasons @('The .etl extension identifies a Windows Event Trace Log.') `
            -Warnings @('ETL conversion is opt-in. Use -ConvertEtl to run local CSharp EventLogReader conversion, or convert ETL to CSV/XML/text with your diagnostic workflow before scrubbing.') `
            -ExtraSwitches '-ConvertEtl'
    }
    if ($ext -eq '.cab') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'CAB archive' -SuggestedProfile 'Text' -Confidence 20 `
            -Reasons @('The .cab extension identifies a cabinet archive, commonly used inside Intune diagnostic bundles.') `
            -Warnings @('CAB archives are skipped unless -ExtractCab is used. Extract approved contents first, or remove archives that are not needed for review.')
    }
    if ($ext -eq '.xlsx') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'XLSX' -SuggestedProfile 'Generic' -Confidence 90 `
            -Reasons @('The .xlsx extension identifies an Excel workbook.') `
            -Warnings @('Workbook conversion happens locally before scrubbing. Export specific sheets or use BYOP for complex workbooks.')
    }
    if ($ext -eq '.docx') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'DOCX' -SuggestedProfile 'Text' -Confidence 90 `
            -Reasons @('The .docx extension identifies an OpenXML Word document.') `
            -Warnings @('DOCX text extraction happens locally under the work directory before scrubbing. The intermediate text is UNSCRUBBED until the scrub step completes.')
    }
    if ($ext -eq '.pptx') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'PPTX' -SuggestedProfile 'Text' -Confidence 90 `
            -Reasons @('The .pptx extension identifies an OpenXML PowerPoint deck.') `
            -Warnings @('PPTX text extraction happens locally under the work directory before scrubbing. The intermediate text is UNSCRUBBED until the scrub step completes.')
    }
    if ($ext -in @('.doc','.ppt')) {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'Legacy Office document' -SuggestedProfile 'Text' -Confidence 25 `
            -Reasons @('The extension identifies a legacy binary Office format.') `
            -Warnings @('Legacy .doc/.ppt files are not parsed natively. Export to .docx/.pptx or plain text, then scrub the exported file.')
    }

    if (@($lines | Where-Object { ([string]$_) -match '^#Fields:' }).Count -gt 0) {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'W3C/IIS' -SuggestedProfile 'IIS' -Confidence 98 `
            -Reasons @('A #Fields: header was found.') -Warnings $warnings
    }
    if ($ext -in @('.log','.txt','.reg','.html','.htm','.xml','.log_') -and ((Test-UlsIntuneDiagnosticsText -Text $text) -or (Test-UlsIntuneDiagnosticsPath -Path ([string]$File.FullName)))) {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'Intune Diagnostics text/report' -SuggestedProfile 'IntuneDiagnostics' -Confidence 88 `
            -Reasons @('The sample contains Intune, MDM, enrollment, policy, Windows Update, or registry diagnostics markers.') `
            -Warnings $warnings
    }
    if ($text -match '(?m)^\s*CEF:\d+\|') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'CEF' -SuggestedProfile 'Cef' -Confidence 96 `
            -Reasons @('A CEF prefix was found.') -Warnings $warnings
    }
    if ($text -match '(?m)^\s*LEEF:\d+(?:\.\d+)?\|') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'LEEF' -SuggestedProfile 'Cef' -Confidence 94 `
            -Reasons @('A LEEF prefix was found; the built-in CEF profile handles key=value SIEM extensions.') -Warnings $warnings
    }
    if ($text -match '(?is)<!\[LOG\[.*?\]LOG\]!><time=' -or $text -match '(?i)\b(CCMExec|ConfigMgr|Configuration Manager|Software Center|Management Point|Distribution Point)\b') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'SCCM/ConfigMgr client text' -SuggestedProfile 'SccmText' -Confidence 88 `
            -Reasons @('The sample contains CMTrace or SCCM/ConfigMgr client-log markers.') -Warnings $warnings
    }

    $jsonLinesOk = Test-JsonLines -Lines $lines
    $jsonLineExtensionOk = $jsonLinesOk
    if (-not $jsonLineExtensionOk -and $ext -in @('.jsonl','.ndjson') -and -not [string]::IsNullOrWhiteSpace($firstLine)) {
        $jsonLineExtensionOk = Test-JsonText -Text $firstLine
    }
    if ($jsonLinesOk -or $jsonLineExtensionOk) {
        $profile = 'Generic'
        $enterpriseHint = Get-UlsEnterpriseProfileHint -Text $text
        if ($enterpriseHint) { $profile = [string]$enterpriseHint.Profile }
        elseif ($text -match '(?i)"(IncidentNumber|IncidentName|AlertIds|Tactics|Entities|TimeGenerated|ProviderName)"|Microsoft Sentinel|Sentinel') { $profile = 'CloudAudit' }
        elseif ((($text -match '(?i)"(alert_id|process_path|command_line|remote_domain|sha256)"') -and ($text -match '(?i)"(device_name|user_email|remote_ip|process_name)"')) -or ($text -match '(?i)\b(EDR|XDR|Defender for Endpoint)\b')) { $profile = 'Edr' }
        elseif ($text -match '(?i)"(eventSource|eventName|awsRegion|userIdentity|tenantId|operationName|operation|principal|resource|sourceIPAddress)"') { $profile = 'CloudAudit' }
        elseif ($text -match '(?i)"(message|level|trace|span|api_key|client_secret|username|host)"') { $profile = 'AppJson' }
        $reason = if ($enterpriseHint) { @('Multiple sampled lines parse as standalone JSON objects.', [string]$enterpriseHint.Reason) } else { @('Multiple sampled lines parse as standalone JSON objects.') }
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'JSON Lines / NDJSON' -SuggestedProfile $profile -Confidence 92 `
            -Reasons $reason -Warnings $warnings
    }
    if ((Test-JsonText -Text $text) -or ($ext -eq '.json' -and (Test-JsonText -Text $text))) {
        $profile = 'Generic'
        $enterpriseHint = Get-UlsEnterpriseProfileHint -Text $text
        if ($enterpriseHint) { $profile = [string]$enterpriseHint.Profile }
        elseif ($text -match '(?i)"(IncidentNumber|IncidentName|AlertIds|Tactics|Entities|TimeGenerated|ProviderName)"|Microsoft Sentinel|Sentinel') { $profile = 'CloudAudit' }
        elseif ((($text -match '(?i)"(alert_id|process_path|command_line|remote_domain|sha256)"') -and ($text -match '(?i)"(device_name|user_email|remote_ip|process_name)"')) -or ($text -match '(?i)\b(EDR|XDR|Defender for Endpoint)\b')) { $profile = 'Edr' }
        elseif ($text -match '(?i)"(eventSource|eventName|awsRegion|userIdentity|tenantId|operationName|operation|principal|resource|sourceIPAddress)"') { $profile = 'CloudAudit' }
        elseif ($text -match '(?i)"(message|level|trace|span|api_key|client_secret|username|host)"') { $profile = 'AppJson' }
        $reason = if ($enterpriseHint) { @('The sampled content parses as JSON.', [string]$enterpriseHint.Reason) } else { @('The sampled content parses as JSON.') }
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'JSON' -SuggestedProfile $profile -Confidence 90 `
            -Reasons $reason -Warnings $warnings
    }

    $jsonish = ($firstLine -match '^\s*[\{\[]')
    if (-not $jsonish -and ($ext -eq '.tsv' -or ($firstLine -match "`t" -and @($firstLine.ToCharArray() | Where-Object { $_ -eq "`t" }).Count -ge 1))) {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'TSV' -SuggestedProfile 'Tsv' -Confidence 88 `
            -Reasons @('The sample appears tab-delimited.') -Warnings $warnings
    }
    if (-not $jsonish -and ($ext -eq '.psv' -or (($firstLine -split '\|').Count -ge 3 -and $firstLine -notmatch '^\s*(CEF|LEEF):'))) {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'PSV' -SuggestedProfile 'Psv' -Confidence 86 `
            -Reasons @('The sample appears pipe-delimited.') -Warnings $warnings
    }

    if (-not $jsonish -and ($ext -eq '.csv' -or (($firstLine -split ',').Count -ge 3))) {
        $columns = Get-LogHeaderColumns -Header $firstLine -Delimiter ','
        $adHits = Get-LogColumnHitCount -Columns $columns -Patterns @('(?i)^RequestID$','(?i)^CertificateTemplate$','(?i)^CertSubject$','(?i)^CertIssuer$','(?i)^ESC\d*','(?i)^PkiObjectType$')
        $eventHits = Get-LogColumnHitCount -Columns $columns -Patterns @('(?i)^ProviderName$','(?i)^LevelDisplayName$','(?i)^RecordId$','(?i)^MachineName$','(?i)^TimeCreated$','(?i)^Message$')
        if ($adHits -ge 2) {
            return New-LogFormatRecommendationObject -File $File -DetectedFormat 'CSV' -SuggestedProfile 'CA' -Confidence 96 `
                -Reasons @('CSV header contains AD CS certificate/audit columns.') -Warnings $warnings
        }
        if ($eventHits -ge 3) {
            return New-LogFormatRecommendationObject -File $File -DetectedFormat 'Windows Event CSV' -SuggestedProfile 'WindowsEventCsv' -Confidence 96 `
                -Reasons @('CSV header contains Windows Event export columns.') -Warnings $warnings
        }
        $enterpriseHint = Get-UlsEnterpriseProfileHint -Columns $columns -Text $text
        if ($enterpriseHint) {
            return New-LogFormatRecommendationObject -File $File -DetectedFormat ([string]$enterpriseHint.Format) -SuggestedProfile ([string]$enterpriseHint.Profile) -Confidence ([int]$enterpriseHint.Confidence) `
                -Reasons @([string]$enterpriseHint.Reason) -Warnings $warnings
        }
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'CSV' -SuggestedProfile 'Generic' -Confidence 82 `
            -Reasons @('The sample appears comma-delimited.') -Warnings $warnings
    }

    if ($text -match '(?m)^\S+\s+\S+\s+\S+\s+\[[^\]]+\]\s+"[A-Z]+ [^"]+ HTTP/[0-9.]+"\s+\d{3}\s+') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'Apache/Nginx access log' -SuggestedProfile 'Apache' -Confidence 86 `
            -Reasons @('The sample matches common/combined web access log shape.') -Warnings $warnings
    }
    if (Test-UlsFirewallVpnText -Text $text) {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'Firewall/VPN text' -SuggestedProfile 'Firewall' -Confidence 88 `
            -Reasons @('The sample contains firewall/VPN source, destination, user, action, policy, or rule fields.') -Warnings $warnings
    }
    $kvMatches = [regex]::Matches($text, '(?<!\S)[A-Za-z_][A-Za-z0-9_.-]*=("[^"]*"|''[^'']*''|\S+)')
    if ($kvMatches.Count -ge 2) {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'logfmt / key=value' -SuggestedProfile 'Logfmt' -Confidence 88 `
            -Reasons @('Multiple key=value pairs were found in the sample.') -Warnings $warnings
    }
    if ($text -match '(?m)^(?:<\d+>)?(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+\S+\s+') {
        return New-LogFormatRecommendationObject -File $File -DetectedFormat 'Syslog-like text' -SuggestedProfile 'Syslog' -Confidence 82 `
            -Reasons @('The sample starts with a syslog-like timestamp and host prefix.') -Warnings $warnings
    }

    return New-LogFormatRecommendationObject -File $File -DetectedFormat 'Generic text' -SuggestedProfile 'Text' -Confidence 50 `
        -Reasons @('No stronger structured format was detected from the local sample.') -Warnings $warnings
}

function Write-LogFormatRecommendationSummary {
    [CmdletBinding()]
    param(
        [object[]]$Recommendations,
        [switch]$SafeFirstRun,
        [string]$Title = 'Log format recommendations'
    )

    $items = @($Recommendations)
    Write-Rule $Title
    Write-Info "Local-only sample analysis. No salt, token map, report, bundle or scrubbed output is created."
    if ($items.Count -eq 0) {
        Write-Warn "No candidate log files were found."
        return
    }
    foreach ($rec in $items) {
        Write-Ok ("{0}: {1} -> {2} ({3}% confidence)" -f $rec.Name, $rec.DetectedFormat, $rec.SuggestedProfile, $rec.Confidence)
        foreach ($reason in @($rec.Reasons | Select-Object -First 3)) { Write-Detail $reason }
        foreach ($warn in @($rec.Warnings)) { Write-Warn ("{0}: {1}" -f $rec.Name, $warn) }
        Write-Detail ("Suggested: {0}" -f $rec.RecommendedCommand)
    }
    if ($SafeFirstRun) {
        Write-Host ""
        Write-Step "Suggested dry-run command(s)"
        foreach ($cmd in @($items | ForEach-Object { $_.RecommendedCommand } | Select-Object -Unique)) { Write-Detail $cmd }
    }
}

function Test-LogFormat {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Recurse,
        [string[]]$Include,
        [string[]]$Exclude,
        [int]$SampleLines = 50,
        [switch]$Quiet
    )

    $targets = Resolve-LogRecommendationTargets -Path $Path -Recurse:$Recurse -Include $Include -Exclude $Exclude
    if ($targets.Count -eq 0) { throw "No candidate log files found: $Path" }
    $recs = @()
    foreach ($t in $targets) { $recs += Get-LogFormatRecommendation -File $t -SampleLines $SampleLines }
    if (-not $Quiet) { Write-LogFormatRecommendationSummary -Recommendations $recs }
    return $recs
}

# =====================================================================
# REGION: Field scrubbing (profile-aware)
# =====================================================================
function Get-FallbackPrefix {
    param([string]$ColumnName, [string]$Value, $Profile)
    $col = if ($ColumnName) { $ColumnName.ToLowerInvariant() } else { "" }
    # Defer multi-valued cells to the caller's list branch.
    if ($Value -match ';|\|') { return $null }
    # Universal pass-through shapes (never tokenize these).
    if ($col -notmatch 'serial|certificate|cert|hash|thumbprint' -and $col -match 'requestid|date|time|when|disposition|validity|count|number|status|flag|enabled|required|approval|candidate') { return $null }
    if ($col -match 'eku|oid|authcapable|published') { return $null }

    if ($Value -match '^S-1-\d+(?:-\d+)+$') { return 'SID' }

    foreach ($rule in $Profile.ColumnPrefix) {
        if ($col -match $rule.Pattern) {
            if ($rule.NotOid -and ($Value -match '^([0-9]+\.)+[0-9]+$')) { continue }
            if ($rule.DollarComputer -and ($Value -match '\$$')) { return "COMPUTER" }
            return $rule.Prefix
        }
    }
    # Fall back to value shape.
    return Get-ValueShapePrefix -Value $Value
}

function Get-TokenForAtomicValue {
    param([string]$ColumnName, [string]$Value, $Profile)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    $clean = if ($ColumnName -match 'SAN|UPN|Email') { Normalize-SANValue -Value $Value } else { $Value.Trim() }
    if ([string]::IsNullOrWhiteSpace($clean)) { return $Value }
    if (Is-AlreadyToken -Value $clean) { return $clean }
    if (Test-ScrubAllowlist -Value $clean) { return $clean }
    $norm = Normalize-TokenKey -Value $clean
    if ($norm -and $script:TokenByNorm.ContainsKey($norm)) { return $script:TokenByNorm[$norm] }
    if ($script:ScrubPolicy -ne 'Strict' -and (Test-UlsWellKnownSid -Value $clean)) { return $clean }
    if ($script:ScrubPolicy -ne 'Strict' -and (Test-UlsWellKnownWindowsPrincipal -Value $clean)) { return $clean }
    $known = Get-CanonicalKnownLabelByValue -Value $clean
    if ($known) { return $known }
    if (Test-PreserveDottedDecimal -Value $clean) { return $clean }   # OID / version (not an IP)
    if ($script:ScrubPolicy -ne 'Strict' -and (Test-WindowsDiagnosticDottedName -Value $clean)) { return $clean }
    if ($clean -match '^(true|false)$') { return $clean }        # boolean
    $date = [datetime]::MinValue
    if (($ColumnName -match 'date|time|when|notbefore|notafter') -and [datetime]::TryParse($clean, [ref]$date)) { return $clean }
    $prefix = Get-FallbackPrefix -ColumnName $ColumnName -Value $clean -Profile $Profile
    if ($prefix) {
        $atomicContext = ("{0}: {1}" -f $ColumnName, $clean)
        $atomicIndex = [Math]::Max(0, $atomicContext.Length - $clean.Length)
        if (Test-PreserveDetectedValue -Value $clean -Detector 'AtomicValue' -Prefix $prefix -Text $atomicContext -Index $atomicIndex -Length $clean.Length) { return $clean }
        $token = Invoke-HmacToken -Value $clean -Prefix $prefix
        if ($token) { return $token }
    }
    return $clean
}

function Get-MatchingProfileColumnRule {
    param($Profile, [string]$ColumnName, [string]$RuleSet)
    if (-not $Profile -or [string]::IsNullOrWhiteSpace($ColumnName)) { return $null }
    $rules = @()
    try { if ($Profile.$RuleSet) { $rules = @($Profile.$RuleSet) } } catch { }
    foreach ($rule in $rules) {
        if ($null -eq $rule) { continue }
        if ($null -ne $rule.RegexObject -and $rule.RegexObject.IsMatch($ColumnName)) { return $rule }
        foreach ($protected in @($rule.ProtectedExact)) {
            if (Test-UlsProtectedTokenMatch -Value $ColumnName -ProtectedToken ([string]$protected) -Prefix FIELD) { return $rule }
        }
    }
    return $null
}

function Invoke-TokenizeWholeValue {
    param([string]$ColumnName, [string]$Value, [string]$Prefix = 'OBJECT', [string]$SplitOn)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    $text = [string]$Value
    if (-not [string]::IsNullOrWhiteSpace($SplitOn) -and $text -match $SplitOn) {
        $parts = [regex]::Split($text, "($SplitOn)")
        $rebuilt = foreach ($part in $parts) {
            if ($part -match "^($SplitOn)$") { $part }
            else {
                $p = $part.Trim()
                if ([string]::IsNullOrWhiteSpace($p)) { $part }
                elseif (Is-AlreadyToken -Value $p) { $p }
                elseif (Test-ScrubAllowlist -Value $p) { $p }
                else { Get-Token -Value $p -Prefix $Prefix }
            }
        }
        return [string]::Concat($rebuilt)
    }
    $clean = $text.Trim()
    if (Is-AlreadyToken -Value $clean) { return $clean }
    if (Test-ScrubAllowlist -Value $clean) { return $clean }
    return (Get-Token -Value $clean -Prefix $Prefix)
}

function Test-UlsWindowsEventCsvProfile {
    param($Profile)
    try { return ($Profile -and ([string]$Profile.Name -ieq 'WindowsEventCsv')) } catch { return $false }
}

function Test-UlsValidIpv6Address {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $trimChars = [char[]]@('[',']','(',')','{','}','"',[char]39,',',';')
    $v = ([string]$Value).Trim().Trim($trimChars)
    if ($v -notmatch ':') { return $false }
    $addr = [System.Net.IPAddress]::None
    if (-not [System.Net.IPAddress]::TryParse($v, [ref]$addr)) { return $false }
    return ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6)
}

function Test-UlsWellKnownSid {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = ([string]$Value).Trim()
    return (
        $v -match '^S-1-0-0$' -or
        $v -match '^S-1-1-0$' -or
        $v -match '^S-1-[23]-' -or
        $v -match '^S-1-5-(18|19|20|113|114)$' -or
        $v -match '^S-1-5-(32|80|90|96)-' -or
        $v -match '^S-1-15-' -or
        $v -match '^S-1-16-'
    )
}

function Test-UlsWellKnownWindowsPrincipal {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = ([string]$Value).Trim().Trim('"', "'", '.', ',', ';', ':', '}', ']', ')')
    return (
        $v -match '(?i)^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|LocalSystem|LocalService|NetworkService|ANONYMOUS LOGON|Everyone|Authenticated Users|Users|Administrators|Administrator|Guest|Guests|DefaultAccount|WDAGUtilityAccount|DWM-\d+|UMFD-\d+|Registry|LOCAL|localhost|%%\d+)$' -or
        $v -match '(?i)^(NT AUTHORITY|BUILTIN|WORKGROUP|Window Manager|Font Driver Host)$' -or
        $v -match '(?i)^(NT AUTHORITY|BUILTIN|Window Manager|Font Driver Host)\\'
    )
}

function Get-UlsDetectorContext {
    param([string]$Text, [int]$Index = -1, [int]$Length = 0, [int]$Radius = 80)
    if ([string]::IsNullOrEmpty($Text) -or $Index -lt 0) { return '' }
    $start = [Math]::Max(0, $Index - $Radius)
    $end = [Math]::Min($Text.Length, $Index + [Math]::Max($Length, 1) + $Radius)
    return (($Text.Substring($start, $end - $start)) -replace "`r|`n", " ")
}

function Test-UlsGuidHasSensitiveContext {
    param([string]$Text, [int]$Index = -1, [int]$Length = 0)
    $ctx = Get-UlsDetectorContext -Text $Text -Index $Index -Length $Length
    return ($ctx -match '(?i)\b(logon\s*guid|logonguid|client\s*request\s*id|clientrequestid|request\s*id|requestid|correlation\s*id|correlationid|trace\s*id|traceid|session\s*id|sessionid|transaction\s*id|transactionid|operation\s*id|operationid|object\s*id|objectid|tenant\s*id|tenantid|application\s*id|applicationid)\b')
}

function Test-UlsLongHexHasSensitiveContext {
    param([string]$Text, [int]$Index = -1, [int]$Length = 0)
    $ctx = Get-UlsDetectorContext -Text $Text -Index $Index -Length $Length
    return ($ctx -match '(?i)\b(thumbprint|certificate|cert|serial|serialnumber|serial\s*number|signature|token|secret|key|password|credential)\b')
}

function Get-UlsConnectionHostPrefix {
    param([string]$HostValue)
    if ([string]::IsNullOrWhiteSpace($HostValue)) { return $null }
    $h = ([string]$HostValue).Trim().Trim('[',']')
    if ($h -match '(?i)^(yes|no|true|false|null|none|unknown|default|failed|success|succeeded|error|warning|info|localhost)$') { return $null }
    if ($h -match '^\d{1,3}(\.\d{1,3}){3}$') { return 'IP' }
    if ($h -match ':' -and (Test-UlsValidIpv6Address -Value $h)) { return 'IP6' }
    if ($h.Length -lt 3) { return $null }
    if ($h -match '^[A-Za-z0-9][A-Za-z0-9_.-]{0,252}$') { return 'DNS' }
    return $null
}

function Invoke-UlsConnectionHostHardening {
    param([Parameter(Mandatory)][string]$Text, [string]$ColumnName)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    if ($Text.IndexOf('://') -lt 0 -and $Text -notmatch '(?i)\b(server|host|address|bootstrap\.servers|broker\.list|data source)\s*=') { return $Text }

    $out = [regex]::Replace($Text, '(?i)(?<prefix>\b(?:jdbc:[a-z0-9+.-]+:)?(?:postgres(?:ql)?|mysql|mariadb|sqlserver|oracle|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|kafka|zookeeper|ws|wss|http|https)://(?:[^@\s/;,?]+@)?)(?<host>\[[^\]\s]+\]|[A-Za-z0-9][A-Za-z0-9_.-]{0,252}|\d{1,3}(?:\.\d{1,3}){3})(?<suffix>(?::\d{1,5})?)', {
        param($m)
        $rawHost = $m.Groups['host'].Value
        $host = $rawHost.Trim('[',']')
        if ((Is-AlreadyToken -Value $host) -or (Test-ScrubAllowlist -Value $host) -or (Test-AllowedDomain -Value $host)) { return $m.Value }
        $prefix = Get-UlsConnectionHostPrefix -HostValue $host
        if (-not $prefix) { return $m.Value }
        $tok = Get-Token -Value $host -Prefix $prefix
        if ($rawHost.StartsWith('[') -and $rawHost.EndsWith(']')) { $tok = "[$tok]" }
        Add-DetectionTrace -Detector 'ConnectionHost' -Action 'Tokenized' -Value $host -Token $tok -Reason 'URL/connection string host' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $Text -Index $m.Index -Length $m.Length)
        return $m.Groups['prefix'].Value + $tok + $m.Groups['suffix'].Value
    })

    $out = [regex]::Replace($out, '(?i)(?<prefix>\b(?:server|host|address|bootstrap\.servers|broker\.list|data source)\s*=\s*)(?<host>[A-Za-z0-9][A-Za-z0-9_.-]{1,252}|\d{1,3}(?:\.\d{1,3}){3})(?<suffix>(?::\d{1,5})?)', {
        param($m)
        $host = $m.Groups['host'].Value
        if ((Is-AlreadyToken -Value $host) -or (Test-ScrubAllowlist -Value $host) -or (Test-AllowedDomain -Value $host)) { return $m.Value }
        $prefix = Get-UlsConnectionHostPrefix -HostValue $host
        if (-not $prefix) { return $m.Value }
        $tok = Get-Token -Value $host -Prefix $prefix
        Add-DetectionTrace -Detector 'ConnectionHost' -Action 'Tokenized' -Value $host -Token $tok -Reason 'Connection string host key' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
        return $m.Groups['prefix'].Value + $tok + $m.Groups['suffix'].Value
    })

    return $out
}

function Get-UlsWindowsEventKeyPrefix {
    param([string]$KeyName, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($KeyName) -or [string]::IsNullOrWhiteSpace($Value)) { return $null }
    $k = ([string]$KeyName).Trim()
    $v = ([string]$Value).Trim().Trim('"', "'", '.', ',', ';', ':', '}', ']', ')')
    if ([string]::IsNullOrWhiteSpace($v)) { return $null }
    if (Test-UlsWellKnownSid -Value $v) { return $null }
    if (Test-UlsWellKnownWindowsPrincipal -Value $v) { return $null }
    if ($v -match '^(?:-|N/A|NULL|\(null\)|0x[0-9a-fA-F]+|\d+)$') { return $null }
    if ($k -match '(?i)(process\s*id|processid|thread\s*id|threadid|logon\s*id|logonid|record\s*id|recordid|event\s*id|eventid|provider\s*guid|providerguid|activity\s*id|activityid|opcode|keywords|level|time|date)') { return $null }
    if ($k -match '(?i)(path|process\s*name|processname|image|filename|file\s*name|commandline|command\s*line)$') { return $null }
    if ($k -match '(?i)(sid|security\s*id)$' -or $v -match '^S-1-\d+(?:-\d+)+$') { return 'SID' }
    if ($k -match '(?i)(ip|address|network\s*address|client\s*address|source\s*address|destination\s*address)') {
        if ($v -match ':' -and (Test-UlsValidIpv6Address -Value $v)) { return 'IP6' }
        return 'IP'
    }
    # line 3258 — allow the trailing " Name" / "Name" suffix that Windows event keys use
    if ($k -match '(?i)(computer|machine|workstation|hostname|host|server)(\s*name)?$') { return 'COMPUTER' }
    # if ($k -match '(?i)(computer|machine|workstation|hostname|host\s*name|host)$') { return 'COMPUTER' }
    if ($k -match '(?i)(domain|realm)$') { return 'COMPUTER' }
    if ($k -match '(?i)(user|account|subject|target|caller|member|identity|principal|service)') {
        if ($v -match '\$$') { return 'COMPUTER' }
        return 'PRINCIPAL'
    }
    if ($k -match '(?i)(logon\s*guid|logonguid|correlation\s*id|correlationid|request\s*id|requestid|trace\s*id|traceid|session\s*id|sessionid)$' -and $v -match '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$') { return 'GUID' }
    return $null
}

function Invoke-UlsWindowsEventKeyValueToken {
    param(
        [string]$KeyName,
        [string]$Value,
        [string]$Text,
        [int]$Index = -1,
        [int]$Length = 0
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    $raw = ([string]$Value).Trim()
    if ([string]::IsNullOrWhiteSpace($raw)) { return $Value }
    if ((Is-AlreadyToken -Value $raw) -or (Test-ScrubAllowlist -Value $raw)) { return $Value }
    $prefix = Get-UlsWindowsEventKeyPrefix -KeyName $KeyName -Value $raw
    if (-not $prefix) { return $Value }
    if (Test-PreserveDetectedValue -Value $raw -Detector 'WindowsEventKey' -Prefix $prefix -Text $Text -Index $Index -Length $Length) { return $Value }
    return (Get-Token -Value $raw -Prefix $prefix)
}

function Invoke-UlsWindowsEventLabeledHardening {
    param([Parameter(Mandatory)][string]$Text, [string]$ColumnName)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    $labelPattern = '(?i)(?<prefix>\b(?:Security ID|Account Name|Account Domain|Caller Workstation|Workstation Name|Source Network Address|Client Address|IP Address|Computer Name|Server Name|Target User Name|Target Domain Name|Subject User Name|Subject Domain Name|TargetSid|SubjectUserSid|TargetUserName|SubjectUserName|TargetDomainName|SubjectDomainName|WorkstationName|IpAddress)\s*:\s*)(?<value>[^\s,;]+)'
    return [regex]::Replace($Text, $labelPattern, {
        param($m)
        $labelText = $m.Groups['prefix'].Value
        $key = ($labelText -replace '[:\s]+$', '').Trim()
        $value = $m.Groups['value'].Value
        $tok = Invoke-UlsWindowsEventKeyValueToken -KeyName $key -Value $value -Text $Text -Index $m.Groups['value'].Index -Length $m.Groups['value'].Length
        if ($tok -eq $value) { return $m.Value }
        Add-DetectionTrace -Detector 'WindowsEventKey' -Action 'Tokenized' -Value $value -Token $tok -Reason $key -ColumnName $ColumnName -Context (Get-DetectionContext -Text $Text -Index $m.Index -Length $m.Length)
        return $labelText + $tok
    })
}

function Invoke-UlsWindowsEventFlatJsonScrub {
    param([Parameter(Mandatory)][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    if ($Text -notmatch '^\s*[\{\[]') { return $Text }
    $pattern = '(?<prefix>"(?<key>[^"\\]+)"\s*:\s*")(?<value>[^"\\]*(?:\\.[^"\\]*)*)(?<suffix>")'
    return [regex]::Replace($Text, $pattern, {
        param($m)
        $key = $m.Groups['key'].Value
        $value = $m.Groups['value'].Value
        $tok = Invoke-UlsWindowsEventKeyValueToken -KeyName $key -Value $value -Text $Text -Index $m.Groups['value'].Index -Length $m.Groups['value'].Length
        if ($tok -eq $value -and $key -match '(?i)(message|description|command\s*line|commandline|script\s*block|scriptblock|script|xml|payload|details|data|value)') {
            $tok = Invoke-UlsWindowsEventMessageHardening -Text $value -ColumnName ("EventDataJson." + $key)
        }
        if ($tok -eq $value) { return $m.Value }
        Add-DetectionTrace -Detector 'WindowsEventJsonKey' -Action 'Tokenized' -Value $value -Token $tok -Reason $key -ColumnName 'EventDataJson' -Context (Get-DetectionContext -Text $Text -Index $m.Index -Length $m.Length)
        return $m.Groups['prefix'].Value + $tok + $m.Groups['suffix'].Value
    })
}

function Invoke-UlsWindowsEventMessageHardening {
    param([Parameter(Mandatory)][string]$Text, [string]$ColumnName)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }

    $out = $Text
    $out = Invoke-SecretHardening -Text $out -ColumnName $ColumnName
    $out = Invoke-CustomRegexHardening -Text $out -ColumnName $ColumnName
    $out = Invoke-UlsConnectionHostHardening -Text $out -ColumnName $ColumnName
    $out = Invoke-UlsWindowsEventLabeledHardening -Text $out -ColumnName $ColumnName
    $out = Invoke-WindowsPathUserHardening -Text $out

    if ($out.IndexOf('S-1-', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        $out = [regex]::Replace($out, 'S-1-\d+(?:-\d+)+', {
            param($m)
            if (Test-PreserveDetectedValue -Value $m.Value -Detector 'SID' -Prefix 'SID' -Text $out -Index $m.Index -Length $m.Length) { return $m.Value }
            return (Get-Token -Value $m.Value -Prefix 'SID')
        })
    }
    if ($out.IndexOf('\') -ge 0) {
        $out = [regex]::Replace($out, '(?<![A-Za-z0-9_.\-:\\/?])[A-Za-z0-9_.-]+\\[A-Za-z0-9_.\-$]+', {
            param($m)
            if (Test-PreserveDetectedValue -Value $m.Value -Detector 'DOMAIN\user' -Prefix 'PRINCIPAL' -Text $out -Index $m.Index -Length $m.Length) { return $m.Value }
            return (Get-Token -Value $m.Value -Prefix 'PRINCIPAL')
        })
    }
    if ($out.IndexOf('@') -ge 0) {
        $out = [regex]::Replace($out, '\b[A-Za-z0-9._%+\-$]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', {
            param($m)
            if ((Is-AlreadyToken -Value $m.Value) -or (Test-AllowedDomain -Value $m.Value)) { return $m.Value }
            return (Get-Token -Value $m.Value -Prefix 'UNMAPPED_UPN')
        })
    }
    $out = [regex]::Replace($out, '(?<!\d)(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)(?!\.\d)', {
        param($m)
        if (Test-PreserveDetectedValue -Value $m.Value -Detector 'IPv4' -Prefix 'IP' -Text $out -Index $m.Index -Length $m.Length) { return $m.Value }
        return (Get-Token -Value $m.Value -Prefix 'IP')
    })
    if ($out.IndexOf(':') -ge 0) {
        $out = [regex]::Replace($out, '(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}|::(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,7}:', {
            param($m)
            if (-not (Test-UlsValidIpv6Address -Value $m.Value)) { return $m.Value }
            if (Test-PreserveDetectedValue -Value $m.Value -Detector 'IPv6' -Prefix 'IP6' -Text $out -Index $m.Index -Length $m.Length) { return $m.Value }
            return (Get-Token -Value $m.Value -Prefix 'IP6')
        })
    }
    if ($out.IndexOf('.') -ge 0) {
        $out = [regex]::Replace($out, '\b(?=[A-Za-z0-9.-]*[A-Za-z])[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b', {
            param($m)
            $value = $m.Value
            if ((Is-AlreadyToken -Value $value) -or (Test-AllowedDomain -Value $value) -or (Test-PreserveDetectedValue -Value $value -Detector 'FQDN' -Prefix 'DNS' -Text $out -Index $m.Index -Length $m.Length)) { return $value }
            return (Get-Token -Value $value -Prefix 'DNS')
        })
    }

    if ($script:ScrubPolicy -eq 'Strict') {
        $out = Invoke-CommonDetectors -Text $out
    }
    else {
        $out = [regex]::Replace($out, '(?i)\b(?:(?:logon\s*guid|client\s*request\s*id|correlation\s*id|trace\s*id|session\s*id|transaction\s*id|operation\s*id)\s*[:=]\s*)\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?', {
            param($m)
            $guid = [regex]::Match($m.Value, '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}').Value
            if ([string]::IsNullOrWhiteSpace($guid)) { return $m.Value }
            return ($m.Value -replace [regex]::Escape($guid), (Get-Token -Value $guid -Prefix 'GUID'))
        })
    }
    return $out
}

function Invoke-UlsWindowsEventDataJsonScrub {
    param([Parameter(Mandatory)][string]$Text, [Parameter(Mandatory)]$Profile)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    $trim = ([string]$Text).Trim().TrimStart([char]0xFEFF)
    if ($trim -match '^[\{\[]') {
        $fast = Invoke-UlsWindowsEventFlatJsonScrub -Text $Text
        $fast = Invoke-WindowsPathUserHardening -Text $fast
        if ($fast -ne $Text) { return $fast }
        if ([regex]::IsMatch($Text, '"[^"\\]+"\s*:\s*"')) { return $fast }
        try {
            $obj = $trim | ConvertFrom-Json -ErrorAction Stop
            $scrubbed = Invoke-JsonNodeScrub -Node $obj -Profile $Profile -KeyName '' -Changes $null -MaxDepth 40 -Seen @{}
            $jsonOut = $scrubbed | ConvertTo-Json -Depth 40 -Compress
            $jsonOut = Invoke-JsonSerializedKeyValueHardening -Text $jsonOut -Profile $Profile -Changes $null
            return (Invoke-WindowsPathUserHardening -Text $jsonOut)
        }
        catch { }
    }
    # Invoke-UlsWindowsEventMessageHardening already runs Invoke-WindowsPathUserHardening.
    # Avoid a duplicate scan on fallback EventDataJson values.
    return (Invoke-UlsWindowsEventMessageHardening -Text $Text -ColumnName 'EventDataJson')
}

function Test-UlsWindowsEventXmlText {
    param([AllowNull()][string]$Text, [string]$Path = '')
    $name = ''
    try { if (-not [string]::IsNullOrWhiteSpace($Path)) { $name = [System.IO.Path]::GetFileName($Path) } } catch { }
    $nameLooksRight = ($name -match '(?i)(^|\s)Events? .+ Events\.txt$' -or $name -match '(?i)Microsoft-Windows-.+Events\.txt$')
    if ([string]::IsNullOrWhiteSpace($Text)) { return $nameLooksRight }
    $hasEventShape = (
        $Text.IndexOf('<Event', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and
        $Text.IndexOf('<System>', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and
        $Text.IndexOf('<Provider', [System.StringComparison]::OrdinalIgnoreCase) -ge 0
    )
    if (-not $hasEventShape) { return $false }
    if ($Text.IndexOf('<Channel>', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or $nameLooksRight) { return $true }
    return ($Text.IndexOf('<EventID', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and $Text.IndexOf('</Event>', [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
}

function Test-UlsWindowsEventXmlTextFile {
    param([Parameter(Mandatory)][string]$Path, [int]$SampleBytes = 131072)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    if ($ext -notin @('.txt','.log','.log_','.xml')) { return $false }
    $sample = ''
    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($item.Length -le 0) { return $false }
        $sample = Get-ReadableFileSample -File $item -MaxBytes $SampleBytes
    }
    catch { $sample = '' }
    return (Test-UlsWindowsEventXmlText -Text $sample -Path $Path)
}

function ConvertFrom-UlsXmlText {
    param([AllowNull()][string]$Value)
    if ($null -eq $Value) { return '' }
    try { return [System.Net.WebUtility]::HtmlDecode([string]$Value) } catch { return [string]$Value }
}

function ConvertTo-UlsXmlText {
    param([AllowNull()][string]$Value)
    if ($null -eq $Value) { return '' }
    try { return [System.Net.WebUtility]::HtmlEncode([string]$Value) } catch { return [string]$Value }
}

function Test-UlsWindowsEventXmlLowRiskKey {
    param([string]$KeyName)
    if ([string]::IsNullOrWhiteSpace($KeyName)) { return $false }
    $k = ([string]$KeyName).Trim()
    return ($k -match '(?i)^(Provider|ProviderName|ProviderGuid|Guid|EventID|EventRecordID|RecordID|ProcessID|ThreadID|Version|Level|Task|Opcode|Keywords|Channel|RuleId|RuleID|FileHash|Fqbn|PolicyName|RuleName|FilePath|FullFilePath|TargetFilePath|SourceFilePath|ProcessName|Image|ImagePath|CommandLine|UtcTime|TimeCreated|Execution|Correlation|ActivityID|RelatedActivityID)$')
}

function Get-UlsWindowsEventXmlSensitivePrefix {
    param([string]$KeyName, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($KeyName) -or [string]::IsNullOrWhiteSpace($Value)) { return $null }
    $k = ([string]$KeyName).Trim()
    $v = (ConvertFrom-UlsXmlText -Value $Value).Trim().Trim('"', "'", '.', ',', ';', ':', '}', ']', ')')
    if ([string]::IsNullOrWhiteSpace($v)) { return $null }
    if (Test-UlsWindowsEventXmlLowRiskKey -KeyName $k) { return $null }
    if (Test-UlsWellKnownSid -Value $v) { return $null }
    if (Test-UlsWellKnownWindowsPrincipal -Value $v) { return $null }
    if ($v -match '^(?:-|N/A|NULL|\(null\)|0x[0-9a-fA-F]+|\d+)$') { return $null }
    if ($k -match '(?i)(sid|security\s*userid|user\s*id|userid)$' -or $v -match '^S-1-\d+(?:-\d+)+$') { return 'SID' }
    if ($k -match '(?i)(computer|machine|workstation|hostname|host|server|device)(\s*name)?$') { return 'COMPUTER' }
    if ($k -match '(?i)(ip|address|network\s*address|client\s*address|source\s*address|destination\s*address)') {
        if ($v -match ':' -and (Test-UlsValidIpv6Address -Value $v)) { return 'IP6' }
        return 'IP'
    }
    if ($k -match '(?i)(upn|email|mail|user|account|subject|target|caller|member|identity|principal|owner|enrolled)') {
        if ($v -match '\$$') { return 'COMPUTER' }
        if ($v -match '^S-1-\d+(?:-\d+)+$') { return 'SID' }
        return 'PRINCIPAL'
    }
    if ($k -match '(?i)(tenant|organization|domain|realm)$') { return 'X500' }
    if ($k -match '(?i)(serial|imei|meid)$') { return 'COMPUTER' }
    if ($k -match '(?i)(mac|wifi|ethernet)' -and $v -match '^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$') { return 'MAC' }
    if ($k -match '(?i)(url|uri|endpoint)$') { return 'URI' }
    return (Get-UlsWindowsEventKeyPrefix -KeyName $k -Value $v)
}

function Add-UlsWindowsEventXmlIdentifier {
    param(
        [Parameter(Mandatory)]$List,
        [Parameter(Mandatory)]$Seen,
        [string]$Raw,
        [string]$Prefix,
        [string]$Detector = 'WindowsEventXml',
        [string]$Reason = ''
    )
    if ([string]::IsNullOrWhiteSpace($Raw) -or [string]::IsNullOrWhiteSpace($Prefix)) { return }
    $v = (ConvertFrom-UlsXmlText -Value $Raw).Trim().Trim('"', "'", '.', ',', ';', ':', '}', ']', ')')
    if ([string]::IsNullOrWhiteSpace($v)) { return }
    if ((Is-AlreadyToken -Value $v) -or (Test-ScrubAllowlist -Value $v)) { return }
    if ($Prefix -eq 'SID' -and (Test-UlsWellKnownSid -Value $v)) { return }
    if ($Prefix -eq 'PRINCIPAL' -and (Test-UlsWellKnownWindowsPrincipal -Value $v)) { return }
    if (($Prefix -eq 'IP' -or $Prefix -eq 'IP6') -and (Test-PreserveIpAddress -Value $v)) { return }
    if ($Prefix -eq 'IP6' -and -not (Test-UlsValidIpv6Address -Value $v)) { return }
    if (Test-PreserveDetectedValue -Value $v -Detector $Detector -Prefix $Prefix -Text $Reason -Index 0 -Length $v.Length) { return }
    $norm = Normalize-TokenKey -Value $v
    if (-not $norm -or $Seen.ContainsKey($norm)) { return }
    $Seen[$norm] = $true
    [void]$List.Add([pscustomobject]@{ Raw=$v; Prefix=$Prefix; Detector=$Detector; Reason=$Reason })
}

function Add-UlsWindowsEventXmlMessageIdentifiers {
    param([Parameter(Mandatory)]$List, [Parameter(Mandatory)]$Seen, [string]$Text, [string]$Reason)
    if ([string]::IsNullOrWhiteSpace($Text)) { return }
    $decoded = ConvertFrom-UlsXmlText -Value $Text
    foreach ($m in [regex]::Matches($decoded, '(?i)(?:\\\?\\)?[A-Za-z]:\\Users\\([^\\/"'',;:<>\r\n]+)')) {
        Add-UlsWindowsEventXmlIdentifier -List $List -Seen $Seen -Raw $m.Groups[1].Value -Prefix 'PRINCIPAL' -Detector 'WindowsEventXmlUserPath' -Reason $Reason
    }
    foreach ($m in [regex]::Matches($decoded, 'S-1-\d+(?:-\d+)+')) {
        Add-UlsWindowsEventXmlIdentifier -List $List -Seen $Seen -Raw $m.Value -Prefix 'SID' -Detector 'WindowsEventXmlSid' -Reason $Reason
    }
    foreach ($m in [regex]::Matches($decoded, '\b[A-Za-z0-9._%+\-$]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')) {
        Add-UlsWindowsEventXmlIdentifier -List $List -Seen $Seen -Raw $m.Value -Prefix 'UNMAPPED_UPN' -Detector 'WindowsEventXmlUPN' -Reason $Reason
    }
    foreach ($m in [regex]::Matches($decoded, '(?<!\d)(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)(?!\.\d)')) {
        Add-UlsWindowsEventXmlIdentifier -List $List -Seen $Seen -Raw $m.Value -Prefix 'IP' -Detector 'WindowsEventXmlIPv4' -Reason $Reason
    }
    foreach ($id in (Find-UlsConnectionHostIdentifiers -Text $decoded)) {
        Add-UlsWindowsEventXmlIdentifier -List $List -Seen $Seen -Raw ([string]$id.Raw) -Prefix ([string]$id.Prefix) -Detector 'ConnectionHost' -Reason $Reason
    }
    foreach ($id in (Find-SecretIdentifiers -Text $decoded)) {
        Add-UlsWindowsEventXmlIdentifier -List $List -Seen $Seen -Raw ([string]$id.Raw) -Prefix ([string]$id.Prefix) -Detector 'Secret' -Reason $Reason
    }
}

function Find-UlsWindowsEventXmlTextIdentifiers {
    param([Parameter(Mandatory)][string]$Text, [string]$Path = '')
    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }

    foreach ($m in [regex]::Matches($Text, '(?is)<Computer>(?<value>[^<]{1,512})</Computer>')) {
        Add-UlsWindowsEventXmlIdentifier -List $out -Seen $seen -Raw $m.Groups['value'].Value -Prefix 'COMPUTER' -Reason 'Computer element'
    }
    foreach ($m in [regex]::Matches($Text, '(?is)\bUserID\s*=\s*["''](?<value>S-1-\d+(?:-\d+)+)["'']')) {
        Add-UlsWindowsEventXmlIdentifier -List $out -Seen $seen -Raw $m.Groups['value'].Value -Prefix 'SID' -Reason 'Security UserID attribute'
    }
    foreach ($m in [regex]::Matches($Text, '(?is)<Data\b(?<attrs>[^>]*)>(?<value>.*?)</Data>')) {
        $attrs = $m.Groups['attrs'].Value
        $key = ''
        if ($attrs -match '\bName\s*=\s*["''](?<name>[^"'']+)["'']') { $key = $matches['name'] }
        $value = $m.Groups['value'].Value
        if ([string]::IsNullOrWhiteSpace($key)) { continue }
        $prefix = Get-UlsWindowsEventXmlSensitivePrefix -KeyName $key -Value $value
        if ($prefix) {
            Add-UlsWindowsEventXmlIdentifier -List $out -Seen $seen -Raw $value -Prefix $prefix -Reason $key
        }
        if ($key -match '(?i)(message|description|details|data|payload|xml|json|script|command|url|uri|path)') {
            Add-UlsWindowsEventXmlMessageIdentifiers -List $out -Seen $seen -Text $value -Reason $key
        }
    }
    foreach ($m in [regex]::Matches($Text, '(?is)<(?<key>(?:Target|Subject|Caller|User|Account|Computer|Workstation|Client|Source|Destination|Ip|IP)[A-Za-z0-9_]{0,80})>(?<value>[^<]{1,512})</\k<key>>')) {
        $key = $m.Groups['key'].Value
        $value = $m.Groups['value'].Value
        $prefix = Get-UlsWindowsEventXmlSensitivePrefix -KeyName $key -Value $value
        if ($prefix) { Add-UlsWindowsEventXmlIdentifier -List $out -Seen $seen -Raw $value -Prefix $prefix -Reason $key }
    }
    return @($out.ToArray())
}

function Invoke-UlsWindowsEventXmlFragmentAction {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][scriptblock]$Action)
    $count = 0
    $settings = [System.Xml.XmlReaderSettings]::new()
    $settings.ConformanceLevel = [System.Xml.ConformanceLevel]::Fragment
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Ignore
    $settings.IgnoreWhitespace = $false
    $xr = $null
    try {
        $xr = [System.Xml.XmlReader]::Create($Path, $settings)
        while ($xr.Read()) {
            if ($xr.NodeType -eq [System.Xml.XmlNodeType]::Element -and [string]::Equals($xr.LocalName, 'Event', [System.StringComparison]::OrdinalIgnoreCase)) {
                $fragment = $xr.ReadOuterXml()
                if (-not [string]::IsNullOrWhiteSpace($fragment)) {
                    & $Action $fragment $count
                    $count++
                }
            }
        }
        return $count
    }
    finally {
        if ($xr) { try { $xr.Close() } catch { } }
    }
}

function Invoke-UlsWindowsEventXmlFragmentActionFallback {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][scriptblock]$Action)
    $reader = [System.IO.StreamReader]::new($Path)
    $chars = New-Object char[] 65536
    $carry = ''
    $count = 0
    try {
        while ($true) {
            $read = $reader.Read($chars, 0, $chars.Length)
            if ($read -le 0) { break }
            $buffer = $carry + ([string]::new($chars, 0, $read))
            while ($true) {
                $m = [regex]::Match($buffer, '(?is)<Event\b.*?</Event>')
                if (-not $m.Success) { break }
                & $Action $m.Value $count
                $count++
                $buffer = $buffer.Substring($m.Index + $m.Length)
            }
            if ($buffer.Length -gt 1048576) { $buffer = $buffer.Substring([Math]::Max(0, $buffer.Length - 1048576)) }
            $carry = $buffer
        }
        if ($count -eq 0 -and $carry.IndexOf('<Event', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            & $Action $carry $count
            $count++
        }
        return $count
    }
    finally {
        try { $reader.Close() } catch { }
    }
}

function Find-UlsWindowsEventXmlTextFileIdentifiers {
    param([Parameter(Mandatory)][string]$Path)
    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $action = {
        param([string]$Fragment, [int]$Index)
        foreach ($id in (Find-UlsWindowsEventXmlTextIdentifiers -Text $Fragment -Path $Path)) {
            $norm = Normalize-TokenKey -Value ([string]$id.Raw)
            if (-not $norm -or $seen.ContainsKey($norm)) { continue }
            $seen[$norm] = $true
            [void]$out.Add($id)
        }
    }
    try { [void](Invoke-UlsWindowsEventXmlFragmentActionFallback -Path $Path -Action $action) }
    catch { try { [void](Invoke-UlsWindowsEventXmlFragmentAction -Path $Path -Action $action) } catch { } }
    if ($out.Count -eq 0) {
        try {
            foreach ($line in [System.IO.File]::ReadLines($Path)) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                foreach ($id in (Find-UlsWindowsEventXmlTextIdentifiers -Text $line -Path $Path)) {
                    $norm = Normalize-TokenKey -Value ([string]$id.Raw)
                    if (-not $norm -or $seen.ContainsKey($norm)) { continue }
                    $seen[$norm] = $true
                    [void]$out.Add($id)
                }
            }
        } catch { }
    }
    return @($out.ToArray())
}

function Get-UlsWindowsEventXmlTokenForValue {
    param([string]$KeyName, [string]$Value, [string]$Text = '', [int]$Index = -1, [int]$Length = 0)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    $raw = (ConvertFrom-UlsXmlText -Value $Value).Trim()
    if ([string]::IsNullOrWhiteSpace($raw) -or (Is-AlreadyToken -Value $raw) -or (Test-ScrubAllowlist -Value $raw)) { return $Value }
    $prefix = Get-UlsWindowsEventXmlSensitivePrefix -KeyName $KeyName -Value $raw
    if (-not $prefix) { return $Value }
    if ($prefix -eq 'SID' -and (Test-UlsWellKnownSid -Value $raw)) { return $Value }
    if ($prefix -eq 'PRINCIPAL' -and (Test-UlsWellKnownWindowsPrincipal -Value $raw)) { return $Value }
    if (($prefix -eq 'IP' -or $prefix -eq 'IP6') -and (Test-PreserveIpAddress -Value $raw)) { return $Value }
    if ($prefix -eq 'IP6' -and -not (Test-UlsValidIpv6Address -Value $raw)) { return $Value }
    return (Get-Token -Value $raw -Prefix $prefix)
}

function Invoke-UlsWindowsEventXmlTextHardening {
    param([Parameter(Mandatory)][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    $out = $Text
    $out = [regex]::Replace($out, '(?is)(?<prefix><Computer>)(?<value>[^<]{1,512})(?<suffix></Computer>)', {
        param($m)
        $tok = Get-UlsWindowsEventXmlTokenForValue -KeyName 'Computer' -Value $m.Groups['value'].Value -Text $out -Index $m.Groups['value'].Index -Length $m.Groups['value'].Length
        return $m.Groups['prefix'].Value + (ConvertTo-UlsXmlText -Value $tok) + $m.Groups['suffix'].Value
    })
    $out = [regex]::Replace($out, '(?is)(?<prefix>\bUserID\s*=\s*["''])(?<value>S-1-\d+(?:-\d+)+)(?<suffix>["''])', {
        param($m)
        $tok = Get-UlsWindowsEventXmlTokenForValue -KeyName 'UserID' -Value $m.Groups['value'].Value -Text $out -Index $m.Groups['value'].Index -Length $m.Groups['value'].Length
        return $m.Groups['prefix'].Value + $tok + $m.Groups['suffix'].Value
    })
    $out = [regex]::Replace($out, '(?is)(?<prefix><Data\b(?<attrs>[^>]*)>)(?<value>.*?)(?<suffix></Data>)', {
        param($m)
        $attrs = $m.Groups['attrs'].Value
        $key = ''
        if ($attrs -match '\bName\s*=\s*["''](?<name>[^"'']+)["'']') { $key = $matches['name'] }
        if ([string]::IsNullOrWhiteSpace($key)) { return $m.Value }
        $value = $m.Groups['value'].Value
        $newValue = $value
        $tok = Get-UlsWindowsEventXmlTokenForValue -KeyName $key -Value $value -Text $out -Index $m.Groups['value'].Index -Length $m.Groups['value'].Length
        if ($tok -ne $value) { $newValue = ConvertTo-UlsXmlText -Value $tok }
        elseif ($key -match '(?i)(message|description|details|data|payload|xml|json|script|command|url|uri|path)') {
            $decoded = ConvertFrom-UlsXmlText -Value $value
            $h = Invoke-UlsWindowsEventMessageHardening -Text $decoded -ColumnName $key
            if ($h -ne $decoded) { $newValue = ConvertTo-UlsXmlText -Value $h }
        }
        return $m.Groups['prefix'].Value + $newValue + $m.Groups['suffix'].Value
    })
    $out = [regex]::Replace($out, '(?is)(?<prefix><(?<key>(?:Target|Subject|Caller|User|Account|Computer|Workstation|Client|Source|Destination|Ip|IP)[A-Za-z0-9_]{0,80})>)(?<value>[^<]{1,512})(?<suffix></\k<key>>)', {
        param($m)
        $tok = Get-UlsWindowsEventXmlTokenForValue -KeyName $m.Groups['key'].Value -Value $m.Groups['value'].Value -Text $out -Index $m.Groups['value'].Index -Length $m.Groups['value'].Length
        if ($tok -eq $m.Groups['value'].Value) { return $m.Value }
        return $m.Groups['prefix'].Value + (ConvertTo-UlsXmlText -Value $tok) + $m.Groups['suffix'].Value
    })
    $out = Invoke-WindowsPathUserHardening -Text $out
    $out = Invoke-UlsConnectionHostHardening -Text $out -ColumnName 'WindowsEventXml'
    return $out
}

function Invoke-UlsWindowsEventXmlTextFileScrub {
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$OutputPath,
        [string[]]$SensitiveTerms = @()
    )
    $name = [System.IO.Path]::GetFileName($InputPath)
    $outFull = Resolve-OutPath -Path $OutputPath
    Write-Work "Scrubbing (Windows Event XML text): $name"
    $tmp = "$outFull.eventxml.tmp"
    $rows = 0
    $success = $false
    $sw = New-UlsPerfStopwatch
    $writeAction = {
        param([string]$Fragment, [int]$Index)
        $h = Invoke-UlsWindowsEventXmlTextHardening -Text $Fragment
        $h = Protect-SensitiveTerms -Text $h -SensitiveTerms $SensitiveTerms
        $script:__ulsEventXmlWriter.Write($h)
        $script:__ulsEventXmlRows = [int]$script:__ulsEventXmlRows + 1
        if (($script:__ulsEventXmlRows % 1000) -eq 0) { Write-UlsProgress -Activity 'Scrub event XML' -File $name -RowsDone $script:__ulsEventXmlRows }
    }
    try {
        $script:__ulsEventXmlRows = 0
        $script:__ulsEventXmlWriter = [System.IO.StreamWriter]::new($tmp, $false, [System.Text.Encoding]::UTF8)
        try {
            try { [void](Invoke-UlsWindowsEventXmlFragmentActionFallback -Path $InputPath -Action $writeAction) }
            catch { [void](Invoke-UlsWindowsEventXmlFragmentAction -Path $InputPath -Action $writeAction) }
        }
        finally {
            try { $script:__ulsEventXmlWriter.Close() } catch { }
            $script:__ulsEventXmlWriter = $null
        }
        $rows = [int]$script:__ulsEventXmlRows
        if ($rows -gt 0) {
            Move-Item -LiteralPath $tmp -Destination $outFull -Force
            $success = $true
        }
    }
    finally {
        if (-not $success) { try { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } catch { } }
        Write-UlsProgress -Activity 'Scrub event XML' -File $name -Completed
        $script:__ulsEventXmlRows = 0
        $script:__ulsEventXmlWriter = $null
    }
    if (-not $success) {
        $reader = [System.IO.StreamReader]::new($InputPath)
        $writer = [System.IO.StreamWriter]::new($outFull, $false, [System.Text.Encoding]::UTF8)
        try {
            while (-not $reader.EndOfStream) {
                $line = $reader.ReadLine()
                if ($null -eq $line) { break }
                $h = Invoke-UlsWindowsEventXmlTextHardening -Text $line
                $h = Protect-SensitiveTerms -Text $h -SensitiveTerms $SensitiveTerms
                $writer.WriteLine($h)
                $rows++
            }
        }
        finally {
            try { $writer.Close() } catch { }
            try { $reader.Close() } catch { }
        }
    }
    Add-UlsPerfPhase -Phase 'Scrub fields' -Stopwatch $sw -File $name -Rows $rows -Notes 'Windows Event XML field-aware scrub'
    Write-Detail "Output: $([System.IO.Path]::GetFileName($outFull))"
    $outBytes = 0L
    try { $outBytes = [int64](Get-Item -LiteralPath $outFull).Length } catch { }
    return [pscustomobject]@{ Input=$InputPath; Output=$outFull; Clean=$true; Rows=$rows; Streamed=$true; WindowsEventXmlText=$true; Engine='PowerShell'; Format='Text'; OutputBytes=$outBytes }
}

function Test-UlsWindowsEventXmlPreserveDetectedValue {
    param([string]$Value, [string]$Detector, [string]$Prefix, [string]$Text, [int]$Index = -1, [int]$Length = 0)
    if ([string]::IsNullOrWhiteSpace($Value) -or [string]::IsNullOrWhiteSpace($Text)) { return $false }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }
    if ($Text.IndexOf('<Event', [System.StringComparison]::OrdinalIgnoreCase) -lt 0 -and $Text.IndexOf('<Data', [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { return $false }
    $start = if ($Index -ge 0) { [Math]::Max(0, $Index - 160) } else { 0 }
    $take = if ($Index -ge 0) { [Math]::Min($Text.Length - $start, [Math]::Max($Length, 1) + 320) } else { [Math]::Min($Text.Length, 512) }
    $ctx = $Text.Substring($start, $take)
    if ($ctx -match '(?i)(Provider\s+Name|Provider\b[^>]*\bGuid|EventID|EventRecordID|RecordID|ProcessID|ThreadID|RuleId|RuleID|FileHash|Fqbn|PolicyName|RuleName|FilePath|FullFilePath|TargetFilePath|SourceFilePath|ProcessName|ImagePath|CommandLine|Channel|Level|Task|Opcode|Keywords)') { return $true }
    $v = ([string]$Value).Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')
    if ($Prefix -eq 'SID' -and (Test-UlsWellKnownSid -Value $v)) { return $true }
    if ($Prefix -eq 'PRINCIPAL' -and (Test-UlsWellKnownWindowsPrincipal -Value $v)) { return $true }
    if ($v -match '(?i)^(MICROSOFT|MICROSOFT CORPORATION|Windows|System|Security|Application|Setup)$') { return $true }
    if ($v -match '(?i)^(%SYSTEM32%|%PROGRAMFILES%|C:\\Windows\\|C:\\Program Files\\)') { return $true }
    return $false
}

# Per-field free-text hardening (the fuller set; safe because it runs on ONE cell,
# not across the whole CSV). Every match routes through Get-Token.
function Invoke-UlsFreeTextHardeningCore {
    param([string]$ColumnName, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    $out = $Value
    $out = Invoke-SecretHardening -Text $out -ColumnName $ColumnName
    $out = Invoke-CustomRegexHardening -Text $out -ColumnName $ColumnName
    $out = Invoke-CommonDetectors -Text $out
    $out = Invoke-UniversalLabelHardening -Text $out -ColumnName $ColumnName
    # ULS perf patch 4: skip an inline pass when its regex's required literal substring is absent
    # from the current text. Byte-identical -- hardening replaces identifiers with tokens (which
    # contain none of these sentinels) and never adds one, so a skipped pass could not have matched.
    $oic = [System.StringComparison]::OrdinalIgnoreCase
    if ($out.IndexOf('S-1-', $oic) -ge 0) {
        $out = [regex]::Replace($out, 'S-1-\d+(?:-\d+)+', { param($m) Get-Token -Value $m.Value -Prefix "SID" })
    }
    if ($out.IndexOf('CertificateTemplate', $oic) -ge 0) {
        $out = [regex]::Replace($out, '(?im)(\bCertificateTemplate\s*:\s*)([A-Za-z0-9_.\-]+)', {
            param($m) if (Is-AlreadyToken -Value $m.Groups[2].Value) { return $m.Value } else { return $m.Groups[1].Value + (Get-Token -Value $m.Groups[2].Value -Prefix "TEMPLATE") } })
    }
    $out = [regex]::Replace($out, '(?im)(\b(?:cdc|rmd|ccm)\s*:\s*)([A-Za-z0-9_.\-]+)', {
        param($m) if (Is-AlreadyToken -Value $m.Groups[2].Value) { return $m.Value } else { return $m.Groups[1].Value + (Get-Token -Value $m.Groups[2].Value -Prefix "DNS") } })
    if ($out.IndexOf('=') -ge 0) {
        $out = [regex]::Replace($out, '(?im)(\b(?:DNS Name|Principal Name|RFC822 Name|URL|URI|IP Address)\s*=\s*)([^,;\r\n]+)', {
            param($m)
            $label = $m.Groups[1].Value
            $rawVal = $m.Groups[2].Value.Trim()
            if (Is-AlreadyToken -Value $rawVal) { return $label + $rawVal }
            if ($label -match '(?i)IP Address') { return $label + (Get-Token -Value $rawVal -Prefix "IP") }
            if ($label -match '(?i)Principal Name|RFC822 Name') { return $label + (Get-Token -Value $rawVal -Prefix "UNMAPPED_UPN") }
            if ($label -match '(?i)URL|URI') { return $label + (Get-Token -Value $rawVal -Prefix "URI") }
            return $label + (Get-Token -Value $rawVal -Prefix "DNS") })
    }
    if ($out.IndexOf('\') -ge 0) {
        $out = [regex]::Replace($out, '(?<![A-Za-z0-9_.\-:\\/?])[A-Za-z0-9_.-]+\\[A-Za-z0-9_.\-$]+', {
            param($m)
            if (Test-PreserveDetectedValue -Value $m.Value -Detector 'DOMAIN\user' -Prefix 'PRINCIPAL' -Text $out -Index $m.Index -Length $m.Length) {
                Add-DetectionTrace -Detector 'DOMAIN\user' -Action 'Preserved' -Value $m.Value -Token '' -Reason 'Windows path segment' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
                return $m.Value
            }
            $tok = Get-Token -Value $m.Value -Prefix "PRINCIPAL"
            Add-DetectionTrace -Detector 'DOMAIN\user' -Action 'Tokenized' -Value $m.Value -Token $tok -Reason 'Standalone DOMAIN\user' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
            return $tok
        })
    }
    if ($out.IndexOf('@') -ge 0) {
        $out = [regex]::Replace($out, '\b[A-Za-z0-9._%+\-$]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', {
            param($m) if ((Is-AlreadyToken -Value $m.Value) -or (Test-AllowedDomain -Value $m.Value)) { return $m.Value } else { return Get-Token -Value $m.Value -Prefix "UNMAPPED_UPN" } })
    }
    $out = [regex]::Replace($out, '(?<!\d)(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)(?!\.\d)', {
        param($m) if (Test-PreserveDetectedValue -Value $m.Value -Detector 'IPv4' -Prefix 'IP' -Text $out -Index $m.Index -Length $m.Length) { return $m.Value } else { return Get-Token -Value $m.Value -Prefix "IP" }
    })
    $out = [regex]::Replace($out, '\b(?=[A-Za-z0-9.-]*[A-Za-z])[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b', {
        param($m)
        $value = $m.Value
        if (Is-AlreadyToken -Value $value) { return $value }
        if ($value -match '^([0-9]+\.)+[0-9]+$') { return $value }
        if ($value -match '^\d+(?:\.\d+)+$') { return $value }
        if (Test-AllowedDomain -Value $value) { return $value }
        if (Test-PreserveDetectedValue -Value $value -Detector 'FQDN' -Prefix 'DNS' -Text $out -Index $m.Index -Length $m.Length) {
            Add-DetectionTrace -Detector 'FQDN' -Action 'Preserved' -Value $value -Token '' -Reason 'Diagnostic dotted name' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
            return $value
        }
        $tok = Get-Token -Value $value -Prefix "DNS"
        Add-DetectionTrace -Detector 'FQDN' -Action 'Tokenized' -Value $value -Token $tok -Reason 'Private or unknown dotted host' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
        return $tok })
    if ($out.IndexOf('=') -ge 0) {
        $out = [regex]::Replace($out, '(?i)\b(?:CN|OU|DC|O|L|ST|C)=[^;,\r\n]+', { param($m) Get-Token -Value $m.Value -Prefix "X500" })
    }
    $out = [regex]::Replace($out, '(?<![A-Za-z0-9_])[0-9a-fA-F]{20,}(?![A-Za-z0-9_])', {
        param($m)
        if (Test-PreserveDetectedValue -Value $m.Value -Detector 'LongHex' -Prefix 'CERT' -Text $out -Index $m.Index -Length $m.Length) {
            Add-DetectionTrace -Detector 'LongHex' -Action 'Preserved' -Value $m.Value -Token '' -Reason 'Diagnostic hash context' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
            return $m.Value
        }
        $tok = Get-Token -Value $m.Value -Prefix "CERT"
        Add-DetectionTrace -Detector 'LongHex' -Action 'Tokenized' -Value $m.Value -Token $tok -Reason 'Long hex value' -ColumnName $ColumnName -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
        return $tok
    })
    return $out
}

function Scrub-Field {
    # ULS perf patch 1: per-file memoization wrapper. Within a single file scrub the salt,
    # the loaded token map, the scrub policy, the profile, and the allowlist are all fixed,
    # and Get-Token never mutates the loaded map -- so an identical (column, value) cell
    # always scrubs to the same string. Caching that result is byte-identical to recomputing
    # it and removes the dominant cost on repetitive logs (e.g. Windows Security messages).
    # The cache is created fresh per file in Invoke-ScrubFile; when $script:__cellCache is
    # $null (direct callers, discovery) this wrapper simply forwards to Scrub-FieldCore.
    #
    # Disclosure: because duplicates are not recomputed, -DetectionSummaryReport counts and
    # the fail-closed fallback tally become per-DISTINCT-value rather than per-occurrence.
    # The scrubbed output file, the token map, and the leak-check verdict are UNCHANGED.
    param([string]$ColumnName, $Value, $Profile)
    if ($null -eq $Value) { return $null }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $text }
    if ($null -eq $script:__cellCache) {
        return (Scrub-FieldCore -ColumnName $ColumnName -Value $Value -Profile $Profile)
    }
    $cacheKey = ([string]$ColumnName) + ([char]0) + $text
    if ($script:__cellCache.ContainsKey($cacheKey)) { return $script:__cellCache[$cacheKey] }
    $result = Scrub-FieldCore -ColumnName $ColumnName -Value $Value -Profile $Profile
    $script:__cellCache[$cacheKey] = $result
    return $result
}

function Scrub-FieldCore {
    param([string]$ColumnName, $Value, $Profile)
    if ($null -eq $Value) { return $null }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $text }

    try {
        $exactNorm = Normalize-TokenKey -Value $text
        if ($exactNorm -and $script:TokenByNorm -and $script:TokenByNorm.ContainsKey($exactNorm)) {
            return [string]$script:TokenByNorm[$exactNorm]
        }

        $wholeRule = Get-MatchingProfileColumnRule -Profile $Profile -ColumnName $ColumnName -RuleSet 'WholeColumnRules'
        if ($wholeRule) {
            return [string](Invoke-TokenizeWholeValue -ColumnName $ColumnName -Value $text -Prefix $wholeRule.Prefix -SplitOn $wholeRule.SplitOn)
        }

        $schemaRule = Get-MatchingProfileColumnRule -Profile $Profile -ColumnName $ColumnName -RuleSet 'SchemaColumns'
        if ($schemaRule -and $schemaRule.Action -eq 'Scrub') {
            return [string](Invoke-TokenizeWholeValue -ColumnName $ColumnName -Value $text -Prefix $schemaRule.Prefix -SplitOn $schemaRule.SplitOn)
        }
        if ($schemaRule -and $schemaRule.Action -eq 'PassThrough') { return $text }

        # Profile pass-through columns (analytical / non-identifying). In Balanced/Readable these are
        # truly pass-through: provider names, event ids, timestamps, record ids, and similar metadata
        # are not identifiers by default. Strict keeps the older fail-closed hardening behavior.
        if ($Profile.PassThroughRegex -and ($ColumnName -match $Profile.PassThroughRegex)) {
            if ($script:ScrubPolicy -ne 'Strict') { return $text }
            if (($text -match '^[0-9]+$') -or ($text -match '^\d{4}-\d{2}-\d{2}[T ]')) { return $text }
            return [string](Invoke-LeakHardeningText -Text $text)
        }

        if (Test-UlsWindowsEventCsvProfile -Profile $Profile) {
            if ($ColumnName -ieq 'EventDataJson') { return [string](Invoke-UlsWindowsEventDataJsonScrub -Text $text -Profile $Profile) }
            if ($ColumnName -ieq 'Message') { return [string](Invoke-UlsWindowsEventMessageHardening -Text $text -ColumnName $ColumnName) }
        }

        # Multi-valued cells: split on ; or | and tokenize EACH element on its own, so
        # a principal list never collapses to a single token.
        $multiSplit = if ($schemaRule -and $schemaRule.SplitOn) { [string]$schemaRule.SplitOn } else { ';|\|' }
        if ($text -match $multiSplit) {
            $delimiter = if ($text -match ';') { ';' } elseif ($text -match '\|') { '|' } else { $matches[0] }
            $parts = $text -split [regex]::Escape($delimiter)
            $scrubbedParts = foreach ($part in $parts) {
                $p = $part.Trim()
                if ($p) { Invoke-FreeTextHardening -ColumnName $ColumnName -Value (Get-TokenForAtomicValue -ColumnName $ColumnName -Value $p -Profile $Profile) } else { $p }
            }
            return [string]($scrubbedParts -join $delimiter)
        }

        # Exact whole-value first.
        $exact = Get-TokenForAtomicValue -ColumnName $ColumnName -Value $text -Profile $Profile
        if ($exact -ne $text -or (Is-AlreadyToken -Value $exact)) { return [string]$exact }

        # Free-text fallback: deny-by-default profiles harden every column; others use
        # the profile's free-text column regex.
        if (($schemaRule -and $schemaRule.Action -eq 'Scan') -or $Profile.DenyByDefault -or ($Profile.FreeTextRegex -and $ColumnName -match $Profile.FreeTextRegex)) {
            return [string](Invoke-FreeTextHardening -ColumnName $ColumnName -Value $text)
        }
        return $text
    }
    catch {
        # FAIL CLOSED -- a cell we cannot fully process must never leak. First retry
        # with the whole-file-safe pass set (no broad per-field SID/DOMAIN\user/DN
        # passes); if even that fails, replace the entire cell with one token.
        $script:__scrubFallback = [int]$script:__scrubFallback + 1
        if (-not $script:__scrubFallbackCol) { $script:__scrubFallbackCol = $ColumnName }
        try { return [string](Invoke-LeakHardeningText -Text $text) }
        catch {
            $t = Invoke-HmacToken -Value $text -Prefix "OBJECT"
            if ($t) { return $t }
            return "OBJECT_REDACTED"
        }
    }
}

# =====================================================================
# REGION: Whole-file hardening + sensitive-term redaction
# =====================================================================
# CSV-safe whole-file passes (value classes stop at quote/comma/space so they
# never swallow a neighbouring column). Routes every match through Get-Token.
function Invoke-UlsLeakHardeningTextCore {
    param([Parameter(Mandatory)][string]$Text)
    $out = $Text
    $out = Invoke-SecretHardening -Text $out
    $out = Invoke-CustomRegexHardening -Text $out
    $out = Invoke-CommonDetectors -Text $out
    $out = Invoke-UniversalLabelHardening -Text $out
    # ULS perf patch 4: skip an inline pass when its required literal substring is absent from
    # the current text. Byte-identical -- hardening never introduces these sentinels.
    $oic = [System.StringComparison]::OrdinalIgnoreCase
    if ($out.IndexOf('CertificateTemplate', $oic) -ge 0) {
        $out = [regex]::Replace($out, '(?im)(\bCertificateTemplate\s*:\s*)([A-Za-z0-9_.\-]+)', {
            param($m) if (Is-AlreadyToken -Value $m.Groups[2].Value) { return $m.Value } else { return $m.Groups[1].Value + (Get-Token -Value $m.Groups[2].Value -Prefix "TEMPLATE") } })
    }
    $out = [regex]::Replace($out, '(?im)(\b(?:cdc|rmd|ccm)\s*:\s*)([A-Za-z0-9_.\-]+)', {
        param($m) if (Is-AlreadyToken -Value $m.Groups[2].Value) { return $m.Value } else { return $m.Groups[1].Value + (Get-Token -Value $m.Groups[2].Value -Prefix "DNS") } })
    if ($out.IndexOf('=') -ge 0) {
        $out = [regex]::Replace($out, '(?im)(\b(?:DNS Name|Principal Name|RFC822 Name|URL|URI|IP Address)\s*=\s*)([A-Za-z0-9_.@:\-/]+)', {
            param($m)
            $label = $m.Groups[1].Value
            $value = $m.Groups[2].Value
            if (Is-AlreadyToken -Value $value) { return $m.Value }
            if ($label -match '(?i)IP Address') { return $label + (Get-Token -Value $value -Prefix "IP") }
            if ($label -match '(?i)Principal Name|RFC822 Name') { return $label + (Get-Token -Value $value -Prefix "UNMAPPED_UPN") }
            if ($value -match '@') { return $label + (Get-Token -Value $value -Prefix "UNMAPPED_UPN") }
            return $label + (Get-Token -Value $value -Prefix "DNS") })
    }
    if ($out.IndexOf('@') -ge 0) {
        $out = [regex]::Replace($out, '\b[A-Za-z0-9._%+\-$]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', {
            param($m) if ((Is-AlreadyToken -Value $m.Value) -or (Test-AllowedDomain -Value $m.Value)) { return $m.Value } else { return Get-Token -Value $m.Value -Prefix "UNMAPPED_UPN" } })
    }
    $out = [regex]::Replace($out, '(?<!\d)(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)(?!\.\d)', {
        param($m) if ((Is-AlreadyToken -Value $m.Value) -or (Test-PreserveDetectedValue -Value $m.Value -Detector 'IPv4' -Prefix 'IP' -Text $out -Index $m.Index -Length $m.Length)) { return $m.Value } else { return Get-Token -Value $m.Value -Prefix "IP" } })
    $out = [regex]::Replace($out, '\b(?=[A-Za-z0-9.-]*[A-Za-z])[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b', {
        param($m)
        $value = $m.Value
        if (Is-AlreadyToken -Value $value) { return $value }
        if ($value -match '^([0-9]+\.)+[0-9]+$') { return $value }
        if ($value -match '^\d+(?:\.\d+)+$') { return $value }
        if (Test-AllowedDomain -Value $value) { return $value }
        if (Test-PreserveDetectedValue -Value $value -Detector 'FQDN' -Prefix 'DNS' -Text $out -Index $m.Index -Length $m.Length) {
            Add-DetectionTrace -Detector 'FQDN' -Action 'Preserved' -Value $value -Token '' -Reason 'Diagnostic dotted name' -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
            return $value
        }
        $tok = Get-Token -Value $value -Prefix "DNS"
        Add-DetectionTrace -Detector 'FQDN' -Action 'Tokenized' -Value $value -Token $tok -Reason 'Private or unknown dotted host' -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
        return $tok })
    $out = [regex]::Replace($out, '(?<![A-Za-z0-9_])[0-9a-fA-F]{20,}(?![A-Za-z0-9_])', {
        param($m)
        if (Is-AlreadyToken -Value $m.Value) { return $m.Value }
        if (Test-PreserveDetectedValue -Value $m.Value -Detector 'LongHex' -Prefix 'CERT' -Text $out -Index $m.Index -Length $m.Length) {
            Add-DetectionTrace -Detector 'LongHex' -Action 'Preserved' -Value $m.Value -Token '' -Reason 'Diagnostic hash context' -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
            return $m.Value
        }
        $tok = Get-Token -Value $m.Value -Prefix "CERT"
        Add-DetectionTrace -Detector 'LongHex' -Action 'Tokenized' -Value $m.Value -Token $tok -Reason 'Long hex value' -Context (Get-DetectionContext -Text $out -Index $m.Index -Length $m.Length)
        return $tok })
    return $out
}

# Redact explicit shapeless secrets (org / vendor / NetBIOS / codenames). Each is
# a literal resolved ONCE via the shared tokenizer so it collapses consistently.
function Protect-SensitiveTerms {
    param([Parameter(Mandatory)][string]$Text, [string[]]$SensitiveTerms = @())
    if (-not $SensitiveTerms -or @($SensitiveTerms).Count -eq 0) { return $Text }
    $out = $Text
    foreach ($term in $SensitiveTerms) {
        $t = ([string]$term).Trim()
        if ($t.Length -lt 3) { continue }   # 1-2 char terms are too collision-prone
        $prefix = if ($t -match '^(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$') { "DNS" } else { "X500" }
        $tok = Get-Token -Value $t -Prefix $prefix
        $out = [regex]::Replace($out, [regex]::Escape($t), $tok.Replace('$', '$$'), 'IgnoreCase')
    }
    return $out
}

function Initialize-UlsMapOnlyScrubberType {
    # Versioned C# type name: Add-Type cannot replace an existing .NET type in a live PowerShell session.
    if ('UlsMapOnlyTextScrubberV20' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

public sealed class UlsMapOnlyScrubResultV20
{
    public bool Ok = true;
    public long Rows = 0;
    public long Bytes = 0;
    public long OutputBytes = 0;
    public double Seconds = 0;
    public long Replacements = 0;
    public int MapEntries = 0;
    public string Error = "";
}

public sealed class UlsMapOnlyTextScrubberV20
{
    private sealed class Node
    {
        public readonly Dictionary<char, int> Next = new Dictionary<char, int>();
        public string Token = null;
        public bool RequireBoundary = false;
    }

    private readonly List<Node> _nodes = new List<Node>();
    private readonly Dictionary<string, string> _exactMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    private static readonly Regex KnownSidReplaceRx = new Regex(@"(?<![A-Za-z0-9-])S-1-(?:5-21|12-1)-\d+(?:-\d+){3,}(?![A-Za-z0-9-])", RegexOptions.IgnoreCase);
    private static readonly Regex ComputerElementMapRx = new Regex(@"(?is)(<Computer>)([^<]{1,512})(</Computer>)", RegexOptions.IgnoreCase | RegexOptions.Singleline);
    private int _maxPatternLength = 0;
    private int _mapEntries = 0;
    private long _replacementCount = 0;

    public UlsMapOnlyTextScrubberV20()
    {
        _nodes.Add(new Node());
    }

    public int MapEntries { get { return _mapEntries; } }
    public int MaxPatternLength { get { return _maxPatternLength; } }
    public long ReplacementCount { get { return _replacementCount; } }

    private static string TokenPrefix(string token)
    {
        if (String.IsNullOrWhiteSpace(token)) return "";
        int i = token.IndexOf('_');
        return i > 0 ? token.Substring(0, i).ToUpperInvariant() : token.ToUpperInvariant();
    }

    private static bool IsWellKnownReplacementValue(string value, string token)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = value.Trim().Trim('"', '\'', '.', ',', ';', ':', '}', ']', ')');
        string p = TokenPrefix(token);
        if (p == "SID" && Regex.IsMatch(v, @"^S-1-0-0$|^S-1-1-0$|^S-1-[23]-|^S-1-5-(18|19|20|113|114)$|^S-1-5-(32|80|90|96)-|^S-1-15-|^S-1-16-", RegexOptions.IgnoreCase)) return true;
        if (p == "PRINCIPAL" && Regex.IsMatch(v, @"^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|LocalSystem|LocalService|NetworkService|ANONYMOUS LOGON|Everyone|Authenticated Users|Users|Administrators|Administrator|Guest|Guests|DefaultAccount|defaultuser0|WDAGUtilityAccount|DWM-\d+|UMFD-\d+|Registry|LOCAL|localhost|%%\d+|WaaSMedic|WaaSMedicSvc|MoUsoCoreWorker|UsoClient|svchost\.exe,AppXSvc)$", RegexOptions.IgnoreCase)) return true;
        if (p == "PRINCIPAL" && Regex.IsMatch(v, @"^(NT AUTHORITY|BUILTIN|WORKGROUP|Window Manager|Font Driver Host)$", RegexOptions.IgnoreCase)) return true;
        if (p == "PRINCIPAL" && Regex.IsMatch(v, @"^(NT AUTHORITY|BUILTIN|Window Manager|Font Driver Host)\\", RegexOptions.IgnoreCase)) return true;
        if (p == "PRINCIPAL" && Regex.IsMatch(v, @"^(?:WORKGROUP|NT AUTHORITY|BUILTIN)\\(?:SYSTEM|LOCAL SERVICE|NETWORK SERVICE|Administrators|Users|Guest|Guests)$", RegexOptions.IgnoreCase)) return true;
        return false;
    }

    private static bool RequiresBoundary(string value, string token)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = value.Trim();
        string p = TokenPrefix(token);
        if (p == "SID" || p == "IP" || p == "IP6" || p == "MAC") return false;
        if (v.IndexOf('@') >= 0 || v.IndexOf('\\') >= 0 || v.IndexOf('/') >= 0 || v.IndexOf(':') >= 0) return false;
        if (Regex.IsMatch(v, @"^[A-Za-z][A-Za-z0-9_ -]{1,31}\$?$")) return true;
        if ((p == "PRINCIPAL" || p == "COMPUTER" || p == "OBJECT") && Regex.IsMatch(v, @"^[A-Za-z0-9_-]{3,32}\$?$")) return true;
        return false;
    }

    private static bool IsBoundaryChar(char c)
    {
        return !Char.IsLetterOrDigit(c) && c != '_' && c != '-' && c != '.';
    }

    private static bool HasTokenBoundary(string text, int start, int end)
    {
        bool left = start <= 0 || IsBoundaryChar(text[start - 1]);
        bool right = end >= text.Length || IsBoundaryChar(text[end]);
        return left && right;
    }

    public void Add(string value, string token)
    {
        if (String.IsNullOrEmpty(value) || String.IsNullOrEmpty(token)) return;
        if (IsWellKnownReplacementValue(value, token)) return;
        string s = value.ToLowerInvariant();
        int index = 0;
        for (int i = 0; i < s.Length; i++)
        {
            int next;
            if (!_nodes[index].Next.TryGetValue(s[i], out next))
            {
                next = _nodes.Count;
                _nodes[index].Next[s[i]] = next;
                _nodes.Add(new Node());
            }
            index = next;
        }
        if (_nodes[index].Token == null) _mapEntries++;
        _nodes[index].Token = token;
        _nodes[index].RequireBoundary = RequiresBoundary(value, token);
        _exactMap[value] = token;
        if (value.Length > _maxPatternLength) _maxPatternLength = value.Length;
    }

    private string ReplaceKnownContextValues(string text)
    {
        if (String.IsNullOrEmpty(text) || _exactMap.Count == 0) return text;

        string output = text;
        if (output.IndexOf("S-1-5-21", StringComparison.OrdinalIgnoreCase) >= 0 || output.IndexOf("S-1-12-1", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            output = KnownSidReplaceRx.Replace(output, delegate(Match m) {
                string token;
                if (_exactMap.TryGetValue(m.Value, out token) && !String.IsNullOrEmpty(token))
                {
                    _replacementCount++;
                    return token;
                }
                return m.Value;
            });
        }

        if (output.IndexOf("<Computer>", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            output = ComputerElementMapRx.Replace(output, delegate(Match m) {
                string value = m.Groups[2].Value;
                string token;
                if (_exactMap.TryGetValue(value, out token) && !String.IsNullOrEmpty(token))
                {
                    _replacementCount++;
                    return m.Groups[1].Value + token + m.Groups[3].Value;
                }
                return m.Value;
            });
        }

        return output;
    }

    public string ReplaceText(string text)
    {
        if (String.IsNullOrEmpty(text) || _mapEntries == 0) return text;
        string lower = text.ToLowerInvariant();
        StringBuilder output = null;
        int lastWrite = 0;

        for (int i = 0; i < lower.Length; i++)
        {
            int index;
            if (!_nodes[0].Next.TryGetValue(lower[i], out index)) continue;

            string bestToken = _nodes[index].Token;
            bool bestRequiresBoundary = _nodes[index].RequireBoundary;
            int bestEnd = bestToken == null ? -1 : i + 1;
            for (int j = i + 1; j < lower.Length; j++)
            {
                int next;
                if (!_nodes[index].Next.TryGetValue(lower[j], out next)) break;
                index = next;
                if (_nodes[index].Token != null)
                {
                    bestToken = _nodes[index].Token;
                    bestRequiresBoundary = _nodes[index].RequireBoundary;
                    bestEnd = j + 1;
                }
            }

            if (bestEnd > i && bestToken != null)
            {
                if (bestRequiresBoundary && !HasTokenBoundary(text, i, bestEnd)) continue;
                if (output == null) output = new StringBuilder(text.Length);
                if (i > lastWrite) output.Append(text, lastWrite, i - lastWrite);
                output.Append(bestToken);
                _replacementCount++;
                i = bestEnd - 1;
                lastWrite = bestEnd;
            }
        }

        if (output == null) return ReplaceKnownContextValues(text);
        if (lastWrite < text.Length) output.Append(text, lastWrite, text.Length - lastWrite);
        return ReplaceKnownContextValues(output.ToString());
    }

    public bool ContainsAnyInputValue(string text)
    {
        if (String.IsNullOrEmpty(text) || _mapEntries == 0) return false;
        string lower = text.ToLowerInvariant();
        for (int i = 0; i < lower.Length; i++)
        {
            int index;
            if (!_nodes[0].Next.TryGetValue(lower[i], out index)) continue;
            if (_nodes[index].Token != null && (!_nodes[index].RequireBoundary || HasTokenBoundary(text, i, i + 1))) return true;
            for (int j = i + 1; j < lower.Length; j++)
            {
                int next;
                if (!_nodes[index].Next.TryGetValue(lower[j], out next)) break;
                index = next;
                if (_nodes[index].Token != null && (!_nodes[index].RequireBoundary || HasTokenBoundary(text, i, j + 1))) return true;
            }
        }
        return false;
    }

    private static long CountRows(string text)
    {
        if (String.IsNullOrEmpty(text)) return 0;
        long rows = 0;
        for (int i = 0; i < text.Length; i++)
        {
            if (text[i] == '\n') rows++;
        }
        return rows;
    }

    public UlsMapOnlyScrubResultV20 BenchmarkFile(string inputPath, int maxChars)
    {
        UlsMapOnlyScrubResultV20 result = new UlsMapOnlyScrubResultV20();
        Stopwatch sw = Stopwatch.StartNew();
        long before = _replacementCount;
        try
        {
            if (maxChars < 1) maxChars = 1048576;
            char[] buffer = new char[maxChars];
            int read = 0;
            using (StreamReader reader = new StreamReader(inputPath, Encoding.UTF8, true, 1048576))
            {
                read = reader.Read(buffer, 0, buffer.Length);
            }
            string sample = read > 0 ? new string(buffer, 0, read) : "";
            string replaced = ReplaceText(sample);
            result.Rows = CountRows(sample);
            result.Bytes = Encoding.UTF8.GetByteCount(sample);
            result.Replacements = _replacementCount - before;
            result.MapEntries = _mapEntries;
            if (replaced == null) result.Ok = false;
        }
        catch (Exception ex)
        {
            result.Ok = false;
            result.Error = ex.Message;
        }
        finally
        {
            sw.Stop();
            result.Seconds = Math.Max(sw.Elapsed.TotalSeconds, 0.000001);
        }
        return result;
    }

    public UlsMapOnlyScrubResultV20 ScrubFile(string inputPath, string outputPath, int bufferChars)
    {
        UlsMapOnlyScrubResultV20 result = new UlsMapOnlyScrubResultV20();
        Stopwatch sw = Stopwatch.StartNew();
        long before = _replacementCount;
        try
        {
            if (bufferChars < 4096) bufferChars = 1048576;
            string dir = Path.GetDirectoryName(outputPath);
            if (!String.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);

            // Map-only scrubbing used to process fixed-size character chunks with a carry
            // window. That is fast, but it can miss values that begin just before the
            // chunk/carry split and finish inside the carried suffix. The symptom is a
            // mapped value being replaced thousands of times in a file while a few raw
            // copies survive in the same file. Log/event exports are line-oriented, and
            // sensitive values do not intentionally span physical lines, so scrub each
            // line as an atomic unit and preserve the original newline style. This fixes
            // the residual <Computer>HOST</Computer> / userSID misses without adding a
            // second full-file pass.
            using (StreamReader reader = new StreamReader(inputPath, Encoding.UTF8, true, bufferChars))
            using (StreamWriter writer = new StreamWriter(outputPath, false, new UTF8Encoding(false), bufferChars))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    writer.WriteLine(ReplaceText(line));
                    result.Rows++;
                }
            }
            result.Bytes = new FileInfo(inputPath).Length;
            result.OutputBytes = new FileInfo(outputPath).Length;
            result.Replacements = _replacementCount - before;
            result.MapEntries = _mapEntries;
        }
        catch (Exception ex)
        {
            result.Ok = false;
            result.Error = ex.Message;
        }
        finally
        {
            sw.Stop();
            result.Seconds = Math.Max(sw.Elapsed.TotalSeconds, 0.000001);
        }
        return result;
    }

    public UlsMapOnlyScrubResultV20 CheckResidualsFile(string inputPath, int bufferChars)
    {
        UlsMapOnlyScrubResultV20 result = new UlsMapOnlyScrubResultV20();
        Stopwatch sw = Stopwatch.StartNew();
        try
        {
            if (bufferChars < 4096) bufferChars = 1048576;
            int keepChars = Math.Max(_maxPatternLength - 1, 0);
            char[] buffer = new char[bufferChars];
            string carry = "";
            using (StreamReader reader = new StreamReader(inputPath, Encoding.UTF8, true, bufferChars))
            {
                while (true)
                {
                    int read = reader.Read(buffer, 0, buffer.Length);
                    if (read <= 0) break;
                    string chunk = new string(buffer, 0, read);
                    result.Rows += CountRows(chunk);
                    string current = carry.Length == 0 ? chunk : carry + chunk;
                    bool eof = reader.EndOfStream;
                    int processLength = current.Length;
                    if (!eof && keepChars > 0)
                    {
                        int keep = Math.Min(keepChars, current.Length);
                        processLength = current.Length - keep;
                        carry = current.Substring(processLength);
                    }
                    else
                    {
                        carry = "";
                    }
                    if (processLength > 0 && ContainsAnyInputValue(current.Substring(0, processLength)))
                    {
                        result.Replacements++;
                        break;
                    }
                }
                if (result.Replacements == 0 && carry.Length > 0 && ContainsAnyInputValue(carry)) result.Replacements++;
            }
            result.Bytes = new FileInfo(inputPath).Length;
            result.MapEntries = _mapEntries;
        }
        catch (Exception ex)
        {
            result.Ok = false;
            result.Error = ex.Message;
        }
        finally
        {
            sw.Stop();
            result.Seconds = Math.Max(sw.Elapsed.TotalSeconds, 0.000001);
        }
        return result;
    }
}

public sealed class UlsDiscoveryRow
{
    public string InputValue = "";
    public string NormalizedValue = "";
    public string Token = "";
    public string TokenType = "";
    public string Source = "";
    public string SourcePathHash = "";
}

public sealed class UlsDiscoveryResult
{
    public bool Ok = true;
    public string Error = "";
    public long Files = 0;
    public long Bytes = 0;
    public long Lines = 0;
    public int TimeoutCount = 0;
    public bool FallbackUsed = false;
    public UlsDiscoveryRow[] Rows = new UlsDiscoveryRow[0];
}

public sealed class UlsCustomRegexRule
{
    public Regex Regex;
    public string Prefix = "OBJECT";
    public int CaptureGroup = 0;
    public string Pattern = "";
}

public sealed class UlsLabelRegexRule
{
    public Regex Regex;
    public string Prefix = "OBJECT";
}

public sealed class UlsDiscoveryEngine
{
    private static readonly TimeSpan RxTimeout = TimeSpan.FromMilliseconds(250);
    private static readonly Regex EventShapeRx = NewRx(@"(?is)<Event\b.*?<System\b", RegexOptions.IgnoreCase | RegexOptions.Singleline);
    private static readonly Regex EventFragmentRx = NewRx(@"(?is)<Event\b.*?</Event>", RegexOptions.IgnoreCase | RegexOptions.Singleline);
    private static readonly Regex ComputerElementRx = NewRx(@"(?is)<Computer>(?<value>[^<]{1,512})</Computer>", RegexOptions.IgnoreCase | RegexOptions.Singleline);
    private static readonly Regex UserIdAttrRx = NewRx(@"(?is)\bUserID\s*=\s*[""'](?<value>S-1-\d+(?:-\d)+)[""']", RegexOptions.IgnoreCase | RegexOptions.Singleline);
    private static readonly Regex EventDataRx = NewRx(@"(?is)<Data\b(?<attrs>[^>]*)>(?<value>.*?)</Data>", RegexOptions.IgnoreCase | RegexOptions.Singleline);
    private static readonly Regex EventDataNameRx = NewRx(@"\bName\s*=\s*[""'](?<name>[^""']+)[""']", RegexOptions.IgnoreCase);
    private static readonly Regex SensitiveElementRx = NewRx(@"(?is)<(?<key>(?:Target|Subject|Caller|User|Account|Computer|Workstation|Client|Source|Destination|Ip|IP)[A-Za-z0-9_]{0,80})>(?<value>[^<]{1,512})</\k<key>>", RegexOptions.IgnoreCase | RegexOptions.Singleline);
    private static readonly Regex UserProfilePathRx = NewRx(@"(?i)(?:\\\?\\)?[A-Za-z]:\\Users\\([^\\/""',;:<>\r\n]+)", RegexOptions.IgnoreCase);
    private static readonly Regex SidRx = NewRx(@"(?<![A-Za-z0-9-])S-1-\d+(?:-\d+)+(?![A-Za-z0-9-])", RegexOptions.IgnoreCase);
    private static readonly Regex EmailRx = NewRx(@"\b[A-Za-z0-9._%+\-$]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", RegexOptions.IgnoreCase);
    private static readonly Regex UrlEncodedEmailRx = NewRx(@"(?<![A-Za-z0-9%._+\-])[A-Za-z0-9._%+\-]{1,128}(?:%40|%2540)[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,}(?![A-Za-z0-9%._+\-])", RegexOptions.IgnoreCase);
    private static readonly Regex ApiUserPathRx = NewRx(@"(?i)(?:/api/(?:v\d+/)?(?:users|people|members|accounts|principals)|/(?:users|people|members|accounts|principals))/(?:id/)?(?<value>[^/?#\s""'<>]{3,160})", RegexOptions.IgnoreCase);
    private static readonly Regex QueryIdentityRx = NewRx(@"(?i)[?&](?:user|email|upn|login_hint|account|username|principal)=[""']?(?<value>[^&\s""'<>]{3,256})", RegexOptions.IgnoreCase);
    private static readonly Regex QuerySessionRx = NewRx(@"(?i)[?&](?:session|sid|sessionid|session_id)=[""']?(?<value>[^&\s""'<>]{6,256})", RegexOptions.IgnoreCase);
    private static readonly Regex Ipv4Rx = NewRx(@"(?<!\d)(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)(?!\.\d)", RegexOptions.IgnoreCase);
    private static readonly Regex MacRx = NewRx(@"(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}", RegexOptions.IgnoreCase);
    private static readonly Regex DomainUserRx = NewRx(@"(?<![A-Za-z0-9_.\-])[A-Za-z0-9_.\-]+\\[A-Za-z0-9_.\-$]+", RegexOptions.IgnoreCase);
    private static readonly Regex FqdnRx = NewRx(@"(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}", RegexOptions.IgnoreCase);
    private static readonly Regex GuidRx = NewRx(@"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", RegexOptions.IgnoreCase);
    private static readonly Regex LongHexRx = NewRx(@"(?<![A-Za-z0-9_])[0-9a-fA-F]{20,}(?![A-Za-z0-9_])", RegexOptions.IgnoreCase);
    private static readonly Regex JwtRx = NewRx(@"eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}", RegexOptions.IgnoreCase);
    private static readonly Regex AwsArnRx = NewRx(@"arn:aws[A-Za-z0-9\-]*:[A-Za-z0-9\-]*:[A-Za-z0-9\-]*:[0-9]*:[A-Za-z0-9_/.:\-]+", RegexOptions.IgnoreCase);
    private static readonly Regex AwsKeyRx = NewRx(@"(?:AKIA|ASIA)[0-9A-Z]{16,24}", RegexOptions.IgnoreCase);
    private static readonly Regex InstanceRx = NewRx(@"\bi-[0-9a-f]{8,17}\b", RegexOptions.IgnoreCase);
    private static readonly Regex Base64Rx = NewRx(@"(?<![A-Za-z0-9+/=_])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])", RegexOptions.IgnoreCase);
    private static readonly Regex UrlHostRx = NewRx(@"(?i)\b(?:jdbc:[a-z0-9+.-]+:)?(?:postgres(?:ql)?|mysql|mariadb|sqlserver|oracle|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|kafka|zookeeper|ws|wss|http|https)://(?:[^@\s/;,?]+@)?(?<host>\[[^\]\s]+\]|[A-Za-z0-9][A-Za-z0-9_.-]{0,252}|\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?", RegexOptions.IgnoreCase);
    private static readonly Regex KeyHostRx = NewRx(@"(?i)\b(?:dhost|shost|cs-host|server|host|address|bootstrap\.servers|broker\.list|data source)\s*=\s*(?<host>[A-Za-z0-9][A-Za-z0-9_.-]{1,252}|\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?", RegexOptions.IgnoreCase);
    private static readonly Regex SecretGateRx = NewRx(@"(?i)(Authorization\s*[:=]|Bearer\s+|Basic\s+|password\s*[:=]|passwd\s*[:=]|pwd\s*[:=]|secret\s*[:=]|client_secret|api[_-]?key\s*[:=]|access[_-]?token\s*[:=]|refresh[_-]?token\s*[:=]|private[_-]?key\s*[:=]|PRIVATE KEY|connectionstring|connstr|Data Source=|Server=[^\r\n]{0,500}(?:Password|Pwd)=|gh[pousr]_|xox[baprs]-|sk_(?:live|test)_|sk-[A-Za-z0-9]|(?:AKIA|ASIA)[0-9A-Z]{16,24}|\b(?:token|secret|key|password)[A-Za-z0-9_. \-]{0,24}[:=])", RegexOptions.IgnoreCase);
    private static readonly Regex AuthSecretRx = NewRx(@"(?i)\bAuthorization\s*[:=]\s*(?:Bearer|Basic)\s+([A-Za-z0-9+/_=.\-]{12,})", RegexOptions.IgnoreCase);
    private static readonly Regex KvSecretRx = NewRx(@"(?i)\b(?:password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?token|refresh[_-]?token|private[_-]?key)\s*[:=]\s*[""']?([^""'\s;,]{8,})", RegexOptions.IgnoreCase);
    private static readonly Regex KnownKeyRx = NewRx(@"\b(?:gh[pousr]_[A-Za-z0-9_]{30,}|xox[baprs]-[A-Za-z0-9-]{20,}|sk_(?:live|test)_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9]{20,}|(?:AKIA|ASIA)[0-9A-Z]{16,24})\b", RegexOptions.IgnoreCase);
    private static readonly Regex HighEntropySecretRx = NewRx(@"(?i)\b(?:token|secret|key|password)[A-Za-z0-9_. \-]{0,24}[:=]\s*[""']?([A-Za-z0-9+/_=\-.]{24,})", RegexOptions.IgnoreCase);
    private static readonly Regex LabelRx = NewRx(@"(?im)(?:^|[\s,\{;\[])\s*[""']?(?<label>api key|api_key|apikey|access token|access_token|refresh token|refresh_token|client secret|client_secret|secret|password|passwd|pwd|authorization|auth token|bearer token|account name|account|user name|username|user principal name|userprincipalname|user|suser|duser|owner|principal|subject|actor|caller|login|identity|client user|account domain|domain|tenant|tenant id|tenantid|organization|org|realm|host|hostname|host name|server|server name|shost|dhost|machine|machine name|machinename|computer|computer name|computername|managed device name|manageddevicename|device name|devicename|device id|deviceid|device|asset|asset name|endpoint name|endpoint|workstation|workstation name|workstationname|client name|target server name|serial|serial number|serialnumber|imei|meid|mac|mac address|macaddress|wifi|ethernet|ip|ip address|ipaddress|src_ip|dst_ip|src|dst|source ip|destination ip|source address|destination address|source network address|client address|remote addr|remote_addr|x-forwarded-for|url|uri|callback|redirect_uri|redirect uri|request id|request_id|requestid|trace id|trace_id|traceid|ticket id|ticket_id|ticketid|case id|case_id|caseid|correlation id|correlation_id|correlationid)[""']?\s*[:=]\s*(?<value>""[^""\r\n]{1,512}""|'[^'\r\n]{1,512}'|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|NT AUTHORITY|Window Manager|Font Driver Host|[^,\s;|<>{}\[\]]{1,512})", RegexOptions.IgnoreCase | RegexOptions.Multiline);
    private static readonly Regex JsonPairRx = NewRx(@"(?is)[""'](?<key>[A-Za-z0-9_. \-]{1,128})[""']\s*:\s*(?:""(?<value>(?:\\.|[^""\\]){0,1024})""|'(?<value>(?:\\.|[^'\\]){0,1024})'|(?<value>[^,\}\]\r\n]{1,512}))", RegexOptions.IgnoreCase | RegexOptions.Singleline);
    private static readonly Regex ContextualComputerRx = NewRx(@"(?i)\b(?<label>device|computer|machine|workstation|endpoint|host|server|asset)\b(?:\s+(?:name|named|called|is|was|for|of))?\s+(?<value>[A-Za-z][A-Za-z0-9-]{2,63}\d[A-Za-z0-9-]{0,63})\b", RegexOptions.IgnoreCase);

    private readonly string _salt;
    private readonly int _hmacLength;
    private readonly string _scrubPolicy;
    private readonly HashSet<string> _allowedDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, UlsDiscoveryRow> _seen = new Dictionary<string, UlsDiscoveryRow>(StringComparer.OrdinalIgnoreCase);
    private readonly List<UlsCustomRegexRule> _customRules = new List<UlsCustomRegexRule>();
    private readonly List<UlsLabelRegexRule> _labelRules = new List<UlsLabelRegexRule>();

    public UlsDiscoveryEngine(string salt, int hmacLength, string scrubPolicy)
    {
        _salt = salt == null ? "" : salt;
        _hmacLength = Math.Min(Math.Max(hmacLength, 4), 64);
        _scrubPolicy = String.IsNullOrEmpty(scrubPolicy) ? "Balanced" : scrubPolicy;
        string[] defaults = new string[] {
            "microsoft.com","windows.com","microsoftonline.com","office.com","office365.com","live.com",
            "azure.com","windowsupdate.com","msftncsi.com","msn.com","bing.com","outlook.com","msedge.net",
            "google.com","googleapis.com","gstatic.com","apple.com","mozilla.org","amazonaws.com","cloudflare.com",
            "digicert.com","verisign.com","collector.cc","localhost","localdomain","example.com","example.org","example.net",
            "w3.org","cisco.com","hp.com","hpinc.com","zoom.us","github.com","dot.net","nexthink.com","techsmith.com",
            "notepad-plus-plus.org","printerlogic.com","curl.se","okta.com","office.net","teams.static.microsoft",
            "symantec.com","symcd.com","symauth.com","globalsign.com","entrust.net","comodoca.com","sectigo.com",
            "c-ares.org","openssl.org","textexpander.com","datacontract.org","xceedsoft.com"
        };
        for (int i = 0; i < defaults.Length; i++) _allowedDomains.Add(defaults[i]);
    }

    public void AddAllowedDomain(string domain)
    {
        if (String.IsNullOrWhiteSpace(domain)) return;
        _allowedDomains.Add(domain.Trim());
    }

    public void AddCustomRegexRule(string pattern, string prefix, int captureGroup)
    {
        if (String.IsNullOrWhiteSpace(pattern)) return;
        UlsCustomRegexRule rule = new UlsCustomRegexRule();
        rule.Regex = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Multiline, RxTimeout);
        rule.Prefix = String.IsNullOrWhiteSpace(prefix) ? "OBJECT" : prefix.Trim();
        rule.CaptureGroup = Math.Max(captureGroup, 0);
        rule.Pattern = pattern == null ? "" : pattern;
        _customRules.Add(rule);
    }

    public void AddLabelRegexRule(string pattern, string prefix)
    {
        if (String.IsNullOrWhiteSpace(pattern)) return;
        UlsLabelRegexRule rule = new UlsLabelRegexRule();
        rule.Regex = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Multiline, RxTimeout);
        rule.Prefix = String.IsNullOrWhiteSpace(prefix) ? "OBJECT" : prefix.Trim();
        _labelRules.Add(rule);
    }

    private static Regex NewRx(string pattern, RegexOptions options)
    {
        return new Regex(pattern, options, RxTimeout);
    }

    private static string Normalize(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return null;
        string v = value.Trim();
        Match m;
        m = Regex.Match(v, @"(?i)principal name\s*=\s*(.+)$");
        if (m.Success) v = m.Groups[1].Value;
        else {
            m = Regex.Match(v, @"(?i)rfc822 name\s*=\s*(.+)$");
            if (m.Success) v = m.Groups[1].Value;
            else {
                m = Regex.Match(v, @"(?i)upn\s*=\s*(.+)$");
                if (m.Success) v = m.Groups[1].Value;
                else {
                    m = Regex.Match(v, @"(?i)email\s*=\s*(.+)$");
                    if (m.Success) v = m.Groups[1].Value;
                }
            }
        }
        v = Regex.Replace(v, @"(?i)^smtp:", "");
        v = Regex.Replace(v, @"(?i)^mailto:", "");
        v = v.Trim();
        if (String.IsNullOrWhiteSpace(v)) return null;
        if (Regex.IsMatch(v, @"(?i)^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$"))
        {
            return "mac:" + Regex.Replace(v, @"[:-]", "").ToLowerInvariant();
        }
        return Regex.Replace(v, @"\r|\n", " ").ToLowerInvariant();
    }

    private string TokenFor(string raw, string prefix)
    {
        string norm = Normalize(raw);
        if (String.IsNullOrEmpty(norm)) return raw;
        byte[] keyBytes = Encoding.UTF8.GetBytes(_salt);
        byte[] msgBytes = Encoding.UTF8.GetBytes(norm);
        using (HMACSHA256 hmac = new HMACSHA256(keyBytes))
        {
            string hex = BitConverter.ToString(hmac.ComputeHash(msgBytes)).Replace("-", "");
            if (hex.Length > _hmacLength) hex = hex.Substring(0, _hmacLength);
            return prefix + "_" + hex.ToUpperInvariant();
        }
    }

    private static string CleanValue(string value)
    {
        if (value == null) return "";
        string v = WebUtility.HtmlDecode(value).Trim();
        int imeTrailer = v.IndexOf("]LOG]!><time=", StringComparison.OrdinalIgnoreCase);
        if (imeTrailer > 0) v = v.Substring(0, imeTrailer);
        return v.Trim().Trim('"', '\'', '.', ',', ';', ':', '}', ']', ')', ' ');
    }

    private static bool IsAlreadyToken(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        return Regex.IsMatch(value, @"^(HV_)?(PRINCIPAL|COMPUTER|GROUP|OBJECT|SID|DNS|UPN|EMAIL|CERT|TEMPLATE|CA|X500|GUID|IP|IP6|HOST|URL|URI|MAC|JWT|ARN|AWSKEY|INSTANCE|BLOB|SECRET|APIKEY|CONNSTR|PEM|FIELD|LABEL)_[A-F0-9]{4,}$", RegexOptions.IgnoreCase)
            || Regex.IsMatch(value, @"^UNMAPPED_(UPN|PRINCIPAL|DNS|OBJECT|IP)_[A-F0-9]{4,}$", RegexOptions.IgnoreCase)
            || Regex.IsMatch(value, @"^(BROAD|ADCS|HV_GROUP|BUILTIN)_[A-Z0-9_]+$", RegexOptions.IgnoreCase);
    }

    private static bool IsWellKnownSid(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = value.Trim();
        return Regex.IsMatch(v, @"^S-1-0-0$|^S-1-1-0$|^S-1-[23]-|^S-1-5-(18|19|20|113|114)$|^S-1-5-(32|80|90|96)-|^S-1-15-|^S-1-16-", RegexOptions.IgnoreCase);
    }

    private static bool IsWellKnownWindowsPrincipal(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value);
        return Regex.IsMatch(v, @"^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|LocalSystem|LocalService|NetworkService|ANONYMOUS LOGON|Everyone|Authenticated Users|Users|Administrators|Administrator|Guest|Guests|DefaultAccount|defaultuser0|WDAGUtilityAccount|DWM-\d+|UMFD-\d+|Registry|LOCAL|localhost|%%\d+|WaaSMedic|WaaSMedicSvc|MoUsoCoreWorker|UsoClient|svchost\.exe,AppXSvc)$", RegexOptions.IgnoreCase)
            || Regex.IsMatch(v, @"^(NT AUTHORITY|BUILTIN|WORKGROUP|Window Manager|Font Driver Host)$", RegexOptions.IgnoreCase)
            || Regex.IsMatch(v, @"^(NT AUTHORITY|BUILTIN|Window Manager|Font Driver Host)\\", RegexOptions.IgnoreCase)
            || Regex.IsMatch(v, @"^(?:WORKGROUP|NT AUTHORITY|BUILTIN)\\(?:SYSTEM|LOCAL SERVICE|NETWORK SERVICE|Administrators|Users|Guest|Guests)$", RegexOptions.IgnoreCase);
    }

    private bool IsAllowedDomain(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value).ToLowerInvariant();
        if (Regex.IsMatch(v, @"(?i)^[a-z][a-z0-9+.-]*://"))
        {
            string hostFromUrl = ExtractUrlHost(v);
            if (!String.IsNullOrWhiteSpace(hostFromUrl)) v = hostFromUrl.ToLowerInvariant();
        }
        int at = v.LastIndexOf('@');
        if (at >= 0 && at < v.Length - 1) v = v.Substring(at + 1);
        foreach (string d in _allowedDomains)
        {
            if (String.IsNullOrWhiteSpace(d)) continue;
            string dd = d.Trim().ToLowerInvariant();
            if (v == dd || v.EndsWith("." + dd, StringComparison.OrdinalIgnoreCase)) return true;
            if (Regex.IsMatch(v, @"(?i)(^|\.)" + Regex.Escape(dd) + @"\d{1,3}$")) return true;
        }
        return false;
    }

    private static string ExtractUrlHost(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return "";
        try
        {
            Uri uri;
            if (Uri.TryCreate(CleanValue(value), UriKind.Absolute, out uri)) return uri.Host == null ? "" : uri.Host.Trim('[', ']');
        }
        catch { }
        Match m = Regex.Match(CleanValue(value), @"(?i)^[a-z][a-z0-9+.-]*://(?:[^@\s/;,?]+@)?(?<host>\[[^\]\s]+\]|[A-Za-z0-9][A-Za-z0-9_.-]{0,252}|\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?");
        if (m.Success) return m.Groups["host"].Value.Trim('[', ']');
        return "";
    }

    private static bool IsLoopbackIp(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value);
        return Regex.IsMatch(v, @"^127(?:\.\d{1,3}){3}$") || String.Equals(v, "::1", StringComparison.OrdinalIgnoreCase) || String.Equals(v, "localhost", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsValidIpv4(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string[] parts = value.Trim().Split('.');
        if (parts.Length != 4) return false;
        for (int i = 0; i < parts.Length; i++)
        {
            int n;
            if (!Int32.TryParse(parts[i], out n) || n < 0 || n > 255) return false;
        }
        return true;
    }

    private static bool IsValidIpv6(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        IPAddress addr;
        return IPAddress.TryParse(CleanValue(value), out addr) && addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
    }

    private static bool IsDottedDecimalNonIp(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = value.Trim();
        if (!Regex.IsMatch(v, @"^([0-9]+\.)+[0-9]+$")) return false;
        return !IsValidIpv4(v);
    }

    private static bool IsPrivateIpv4(string value)
    {
        if (!IsValidIpv4(value)) return false;
        string[] p = value.Trim().Split('.');
        int a = Int32.Parse(p[0]);
        int b = Int32.Parse(p[1]);
        return a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) || (a == 169 && b == 254);
    }

    private static bool IsVersionOrCorrelationIpv4(string value, string context)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = value.Trim();
        if (!Regex.IsMatch(v, @"^\d{1,3}(?:\.\d{1,3}){3}$")) return false;
        string c = context == null ? "" : context;
        if (Regex.IsMatch(c, @"(?i)\b(version|fileversion|productversion|driver(?:version)?|build|package|appx|msix|appstore|nonstore|enterprise modern app management|enterprisemodernappmanagement|wer|correlation\s*vector|\bcv\b|swv|nodeuri|devdetail|p[0-9]\s*=|param(?:eter)?[0-9])\b")) return true;
        if (Regex.IsMatch(c, @"(?i)(/Device/Vendor/MSFT/|/Vendor/MSFT/|/DevInfo/|/cimv2/|/root/cimv2/)")) return true;
        if (!String.Equals(v, c.Trim(), StringComparison.OrdinalIgnoreCase) && Regex.IsMatch(c, @"(?i)(?:^|[\\/_\-.])\d+\.\d+\.\d+\.\d+(?:[\\/_\-.]|$)")) return true;
        if (Regex.IsMatch(c, @"(?i)(?:^|_)" + Regex.Escape(v) + @"_(?:x64|x86|arm64|neutral|none|[a-z0-9]{8,})(?:_|\b)")) return true;
        return false;
    }

    private static bool IsKnownFileOrDiagnosticName(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value);
        return Regex.IsMatch(v, @"(?i)\.(dll|exe|sys|mui|cat|cab|log|txt|xml|json|html|htm|dat|etl|evtx|reg|zip|manifest|config|ini|pf|etl_\d+|csv|tmp|dmp|mdmp|cpp|cxx|cc|h|hpp|pnf|inf|msi|mca|so|bin|sav|xaml|drv)$")
            || Regex.IsMatch(v, @"(?i)^(kernel32|ntdll|advapi32|user32|gdi32|winhttp|wininet|shell32|combase)\.")
            || Regex.IsMatch(v, @"(?i)^WER\.[0-9a-f-]{8,}\.tmp\.(?:csv|mdmp|dmp)$")
            || Regex.IsMatch(v, @"(?i)^oem\d+\.(?:inf|pnf)$")
            || Regex.IsMatch(v, @"(?i)^(?:document|window|navigator|location|screen|Math|JSON|Object|Array|String|Date|console)\.[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$")
            || Regex.IsMatch(v, @"(?i)^(?:td|tr|th|div|span|table|tbody|thead|body|html|input|button|select|option|a|p|ul|li|ol|svg|path|canvas)\.[A-Za-z0-9_-]+$")
            || Regex.IsMatch(v, @"(?i)^(?:session|style|class|classname|dataset|event|target|currenttarget|response|request|error|status|result|config|policy|context)\.[A-Za-z0-9_.-]+$")
            || Regex.IsMatch(v, @"(?i)^[A-Za-z_$][A-Za-z0-9_$]*\.(?:fillStyle|getElementById|querySelector|addEventListener|appendChild|classList|innerHTML|textContent)$")
            || Regex.IsMatch(v, @"(?i)^Data\.[A-Za-z0-9_.-]+$")
            || Regex.IsMatch(v, @"^(?=.*[A-Z_])[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){2,}$")
            || Regex.IsMatch(v, @"(?i)^(?:Microsoft|System|Windows|Win32|WinRT|UI|MSFT|MDM|CIM|ROOT|Policy|EnterpriseModernAppManagement|DiagnosticLogCSP)(?:[._-][A-Za-z0-9]+){1,}$")
            || Regex.IsMatch(v, @"(?i)^(?:OpenSSH|PowerShell|WindowsPowerShell|Microsoft|System|Windows)\.[A-Za-z0-9_.-]+$")
            || Regex.IsMatch(v, @"(?i)^[A-Za-z0-9_.-]+\.(?:ashx|asmx|svc|aspx|jspx?)$")
            || Regex.IsMatch(v, @"(?i)^[A-Za-z0-9_.-]+\.(?:resources|pri|neutral|none|desktop|appx|appxbundle|msix|msixbundle)$")
            || Regex.IsMatch(v, @"(?i)^(?:PackageMetadata|App)\.AppX[A-Za-z0-9_.-]+$")
            || Regex.IsMatch(v, @"(?i)^(Microsoft|MicrosoftWindows|MicrosoftCorporationII|Global)\.[A-Za-z0-9_.-]+$")
            || Regex.IsMatch(v, @"(?i)^(System|Windows|YourPhone|Language\.Fonts|Rsat|ServerCoreFonts|Office|Activity|Result|context|snapshot|graph|currentPolicy|AggregatedJob|PackageMetadata|App|ndis|Win32|WinRT|Diagnostics|Telemetry)\.")
            || Regex.IsMatch(v, @"(?i)^\d+(?:\.\d+){2,}(?:\.\d+)?$")
            || Regex.IsMatch(v, @"(?i)^\d+\.[A-Za-z][A-Za-z0-9_]+$")
            || Regex.IsMatch(v, @"(?i)^[A-Za-z0-9_.-]+_[0-9]+\.[0-9][A-Za-z0-9_.-]*__(?:[A-Za-z0-9]+)$");
    }

    private static bool IsDiagnosticPathOnlyUri(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value).Replace('\\', '/');
        if (Regex.IsMatch(v, @"(?i)^x-windowsupdate://")) return true;
        if (Regex.IsMatch(v, @"(?i)^https?://[+*](?::\d+)?(?:/|$)")) return true;
        if (Regex.IsMatch(v, @"(?i)^https?://(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?(?:/|$)")) return true;
        if (Regex.IsMatch(v, @"(?i)^https?://schemas\.microsoft\.com/")) return true;
        if (Regex.IsMatch(v, @"(?i)^https?://[^/?#]*(?:microsoft|windowsupdate|windows|office|msft|teams|azure|live|bing|msedge)\.[A-Za-z0-9.-]+/")
            && !Regex.IsMatch(v, @"(?i)[?&](?:token|access_token|refresh_token|sig|signature|key|client_secret)=")) return true;
        if (Regex.IsMatch(v, @"(?i)^file:///(?:[A-Za-z]:/)?(?:Program(?:%20| )Files|Windows|ProgramData)/")) return true;
        if (Regex.IsMatch(v, @"(?i)^[a-z][a-z0-9+.-]*://")) return false;
        return Regex.IsMatch(v, @"(?i)^NodeCache/MS DM Server/Nodes/\d+/(?:NodeUri|ExpectedValue)$")
            || Regex.IsMatch(v, @"(?i)^EnterpriseModernAppManagement/AppManagement/(?:AppStore|nonStore)/")
            || Regex.IsMatch(v, @"(?i)^Policy/Config/")
            || Regex.IsMatch(v, @"(?i)^EnrollmentStatusTracking/")
            || Regex.IsMatch(v, @"(?i)^Device/(?:Vendor|MSFT|[A-Za-z0-9_.-]+)/")
            || Regex.IsMatch(v, @"(?i)^Vendor/MSFT/[A-Za-z0-9_./-]+$")
            || Regex.IsMatch(v, @"(?i)^[A-Za-z0-9_. -]+/[A-Za-z0-9_./~{}()-]+/(?:Name|Version|Publisher|NodeUri|ExpectedValue|Status|State|Config)$");
    }

    private static bool IsDiagnosticConfigPath(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value).Replace('\\', '/');
        return Regex.IsMatch(v, @"(?i)^(?:/)?(?:Device/)?Vendor/MSFT/")
            || Regex.IsMatch(v, @"(?i)^(?:/)?(?:Device/)?MSFT/")
            || Regex.IsMatch(v, @"(?i)^(?:/)?DevInfo/")
            || Regex.IsMatch(v, @"(?i)^(?:/)?(?:root/)?cimv2(?:/|$)")
            || Regex.IsMatch(v, @"(?i)^(?:/)?Policy/Config/")
            || Regex.IsMatch(v, @"(?i)^(?:/)?NodeCache/MS DM Server/")
            || Regex.IsMatch(v, @"(?i)^(?:/)?EnterpriseModernAppManagement/AppManagement/")
            || Regex.IsMatch(v, @"(?i)^(?:/)?EnrollmentStatusTracking/");
    }

    private static bool IsHardwareOrDeviceInventoryId(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value);
        return Regex.IsMatch(v, @"(?i)^(?:\*PNP[0-9A-F]{4}|ACPI\\|ACPI_HAL\\|USB\\|USB4\\|USBSTOR\\|UEFI\\|MMDEVAPI\\|ButtonConverter\\|HID_|HID\\|BTH\\|SWC\\|SW\\|SWD\\|PNP[A-Z0-9]*\\|PCI(?:\\|_)|ROOT\\|PRINTENUM\\|INTELAUDIO\\|DISPLAY\\|MONITOR\\|SCSI\\|IDE\\|STORAGE\\)")
            || Regex.IsMatch(v, @"(?i)^(?:HID_DEVICE|ROOT_HUB|ACPI_HAL|BT(?: LE)? Sideband|Base System Device|PCI to ISA Bridge|SM Bus Controller|Multimedia Audio Controller|Video Controller|Integrated Monitor|Root Print Queue|Microsoft Device Association Root Enumerator|Microsoft Radio Device Enumeration Bus|Media Foundation Sensor Group|Windows Studio Effects Camera|Intel .*(?:Device|Component|Controller|Bus)|Realtek .*Component|HP .*(?:Camera|ZBook|Workstation))")
            || Regex.IsMatch(v, @"(?i)^@oem\d+\.inf,")
            || Regex.IsMatch(v, @"(?i)^\\Device\\HarddiskVolume(?:ShadowCopy)?\d+$")
            || Regex.IsMatch(v, @"(?i)^\{[0-9a-f-]{36}\}\\[A-Za-z0-9_.-]+$");
    }

    private static bool IsWindowsServiceOrDriverName(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value);
        if (v.Length > 48 || v.IndexOf(' ') >= 0 || v.IndexOf('\\') >= 0) return false;
        return Regex.IsMatch(v, @"(?i)^(?:Wof|CldFlt|WIMMount|WdFilter|FileCrypt|UCPD|luafv|applockerfltr|npsvctrig|bfs|storahci|stornvme|storqosflt|wcifs|bindflt|MsSecFlt|acpiapic|iaStor|nvlddmkm|Netwtw|rt640x64|igdkmdn64|ACPI|Tcpip|Dnscache|WinDefend|BITS|W32Time|EventLog|Schedule|Spooler|WaaSMedic|WaaSMedicSvc|MoUsoCoreWorker|UsoSvc|UsoClient|AppXSvc)$");
    }

    private static bool IsWindowsServicingNoiseIdentifier(string value, string context)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value);
        string ctx = context == null ? "" : context;
        if (!Regex.IsMatch(ctx, @"(?i)\b(cbs|servicing|setupact|setuperr|winsxs|package|component|appcompat|pnputil|driver\s+version|fileversion|productversion|windows\s+update|updatesessionorchestration|usoclient|waasmedic|wingetcom)\b")) return false;
        if (Regex.IsMatch(v, @"^\d{6,12}_\d{6,12}$")) return true;
        if (Regex.IsMatch(v, @"(?i)^(?:Package_for_|Microsoft-(?:Windows|OneCore)|Windows-|amd64_|wow64_|x86_|msil_|neutral_)[A-Za-z0-9_.~\-]+$")) return true;
        if (Regex.IsMatch(v, @"(?i)^\d+(?:\.\d+){2,4}$")) return true;
        if (Regex.IsMatch(v, @"(?i)^[0-9a-f]{8}$")) return true;
        if (Regex.IsMatch(v, @"(?i)^(?:UniversalOrchestrator|UsoClient[A-Za-z0-9]*|WaaSMedic|MoUsoCoreWorker|WindowsUpdate[A-Za-z0-9]*)$")) return true;
        return false;
    }

    private static bool IsJunkBackslashPair(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value);
        return Regex.IsMatch(v, @"^(?:.|..|[-_0-9A-Za-z])\\(?:.|..|[-_0-9A-Za-z])$")
            || Regex.IsMatch(v, @"^[\\/\-_.A-Za-z0-9]{1,3}\\[\\/\-_.A-Za-z0-9]{1,3}$")
            || Regex.IsMatch(v, @"(?i)^(?:n\\n|r\\r|t\\t|p\\\d|-\\" + @"[A-Za-z])$");
    }

    private static bool HasStrongNetworkContext(string context)
    {
        if (String.IsNullOrWhiteSpace(context)) return false;
        return Regex.IsMatch(context, @"(?i)\b(host|hostname|server|fqdn|dns|domain|url|uri|endpoint|proxy|gateway|destination|dest|dhost|shost|remote(?:_addr|\s+address)?|client\s+address|source\s+address|destination\s+address|x-forwarded-for|cs-host|s-ip|c-ip|src_ip|dst_ip|address|socket|connect|listen|route|adapter|visit(?:ed|ing)?)\b");
    }

    private static bool HasStrongPrincipalContext(string context)
    {
        if (String.IsNullOrWhiteSpace(context)) return false;
        return Regex.IsMatch(context, @"(?i)\b(user|username|account|principal|identity|owner|caller|subject|target|member|logon|login|domain\\|samaccountname|upn|email|mail)\b");
    }

    private static bool HasStrongComputerContext(string context)
    {
        if (String.IsNullOrWhiteSpace(context)) return false;
        return Regex.IsMatch(context, @"(?i)\b(computer\s*name|machine\s*name|host\s*name|hostname|workstation\s*name|managed\s*device\s*name|device\s*name|deviceid|device\s*id|serial\s*number|serialnumber|serial|imei|meid|asset\s*name|endpoint\s*name)\b");
    }

    private static bool LooksLikeRealDomainPrincipal(string value, string context)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value);
        if (IsJunkBackslashPair(v) || IsDiagnosticBackslashPath(v) || IsHardwareOrDeviceInventoryId(v)) return false;
        Match m = Regex.Match(v, @"^(?<domain>[A-Za-z0-9_.-]{2,64})\\(?<name>[A-Za-z][A-Za-z0-9_.\-$]{1,127})$", RegexOptions.IgnoreCase);
        if (!m.Success) return false;
        string domain = m.Groups["domain"].Value;
        string name = m.Groups["name"].Value;
        if (Regex.IsMatch(domain, @"(?i)^(?:windows|winnt|system32|syswow64|sysnative|systemroot|drivers|users|public|default|programdata|appdata|microsoft|program files|inf|temp|tmp|config|fonts|assembly|servicing|winsxs|tasks|spool|wbem|registry|device|harddiskvolume\d*)$")) return false;
        if (IsKnownFileOrDiagnosticName(name) || Regex.IsMatch(name, @"(?i)\.(?:dll|exe|sys|xml|etl|inf|pnf|cat|log|txt)$")) return false;
        return HasStrongPrincipalContext(context) || Regex.IsMatch(domain, @"^[A-Z0-9_.-]{2,15}$") || name.EndsWith("$", StringComparison.Ordinal);
    }


    private static bool IsStandaloneTimestampLikeValue(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value).Trim();
        if (String.IsNullOrWhiteSpace(v)) return false;

        // Standalone log/event timestamps are operational context, not identifiers.
        // Keep these anchored so hashes, URLs, cert material, and embedded values are untouched.
        return Regex.IsMatch(v, @"(?i)^(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2})[ T]\d{1,2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:\s?(?:AM|PM))?(?:Z|[+-]\d{2}:?\d{2})?$")
            || Regex.IsMatch(v, @"(?i)^\d{4}\d{2}\d{2}[T _-]?\d{2}\d{2}\d{2}(?:\.\d{1,9})?(?:Z)?$");
    }

    private static bool IsCompositeStatusPayload(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value).Trim();
        if (v.Length < 32) return false;

        // Avoid mapping an entire diagnostic status payload as a single host/object.
        // Focused detectors still catch embedded accounts, IPs, SIDs, URLs, and secrets.
        if ((v.StartsWith("{") || v.StartsWith("["))
            && Regex.IsMatch(v, @"(?i)""(?:categoryState|subcategoryState|state|status)""\s*:")
            && Regex.IsMatch(v, @"(?i)""(?:notStarted|succeeded|completed|disabled|enabled|unknown|error|failed)""")
            && !ContainsEmbeddedSensitiveValue(v)) return true;

        return Regex.IsMatch(v, @"(?i)\b(?:Version|Result|MIResult|Output|Status|RetryCount|LastSyncDateTime|HRESULT|ErrorCode|ExpectedValue|NodeUri)\s*[:=]")
            && Regex.IsMatch(v, @"(?i)(?:^|\s)[A-Za-z][A-Za-z0-9_.-]{1,40}\s*=");
    }

    private static bool IsLongNaturalLanguagePrincipalNoise(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value).Trim();
        if (v.Length < 96 || v.IndexOf(' ') < 0) return false;
        if (v.IndexOf('@') >= 0 || v.IndexOf('\\') >= 0 || v.IndexOf('/') >= 0 || v.IndexOf('=') >= 0 || v.IndexOf(':') >= 0) return false;
        if (ContainsEmbeddedSensitiveValue(v)) return false;
        return Regex.IsMatch(v, @"(?i)\b(?:this system|authorized use|unauthorized use|information contained|property of|criminal|disciplinary)\b");
    }


    private static bool IsXmlStateFragment(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = value.Trim();
        return Regex.IsMatch(v, @"(?is)^<(?:enabled|disabled)\s*/>\s*(?:<data\b[^>]{0,256}\s*/>\s*)?$");
    }

    private static bool IsLogonBannerTitle(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value);
        return Regex.IsMatch(v, @"(?i)^(?:[A-Za-z0-9&().,' -]{2,80}\s+)?Logon\s+Banner$");
    }


    private static bool IsBenignPlaceholderValue(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value);
        return Regex.IsMatch(v, @"(?i)^%[A-Z0-9_. -]{2,64}%$")
            || Regex.IsMatch(v, @"(?i)^AP-%SERIAL%$")
            || Regex.IsMatch(v, @"(?i)^(?:EMPTY|UNKNOWN|N/?A|NULL|NONE|Device)$");
    }

    private static bool IsEncodedGuidCnFragment(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value);
        return Regex.IsMatch(v, @"(?i)^CN%3d[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:&amp)?$");
    }

    private static bool IsHighEntropyDotZeroPrincipalNoise(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value);
        return Regex.IsMatch(v, @"^[A-Za-z0-9+/]{16,}\.0$")
            && Regex.IsMatch(v, @"[A-Z]")
            && Regex.IsMatch(v, @"[a-z]");
    }

    private static bool IsBenignUriPrincipalValue(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value);
        if (!Regex.IsMatch(v, @"(?i)^https?://")) return false;
        if (Regex.IsMatch(v, @"(?i)[?&](?:token|access_token|refresh_token|sig|signature|key|client_secret|password|pwd)=")) return false;
        return Regex.IsMatch(v, @"(?i)^https?://(?:login\.windows\.net|login\.microsoftonline\.com|device\.login\.microsoftonline\.com|enterpriseregistration\.windows\.net)(?:/|$)");
    }

    private static bool IsHashAsMacValue(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value);
        return Regex.IsMatch(v, @"(?i)^[0-9a-f]{24,}$");
    }

    private static bool IsFileNameLikeDnsValue(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value);
        return Regex.IsMatch(v, @"(?i)^[A-Za-z0-9_.-]+\.(?:cer|crt|crl|pem|p7b|p7c)$");
    }


    private static bool IsRelativeDiagnosticBackslashPath(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value);
        if (v.IndexOf('\\') < 0) return false;
        return Regex.IsMatch(v, @"(?i)^(?:\d+\.\d+\.\d+_\d+|AUTHORITY|Google|Chrome|Store|Explorer|Launch|Service|Services|Extensions|Downloads|Sessions|Pinned|RemoteActions|EntityExtraction|Active_Projects|Center)\\")
            || Regex.IsMatch(v, @"(?i)\\(?:assets|assets\.db|Files|Scripts|TaskBar|Quick|Application|Account|User)$")
            || Regex.IsMatch(v, @"(?i)\\[^\\]+\.(?:db|js-?|crx|txt|log|xml|json|csv)$");
    }

    private static bool IsStatusPayload(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value);
        return Regex.IsMatch(v, @"(?i),\s*Status\s*:")
            || Regex.IsMatch(v, @"(?i)\b(RetryCount|LastSyncDateTime|DocumentId|ExpectedValue|NodeUri|HRESULT|ErrorCode)\s*:")
            || IsCompositeStatusPayload(v);
    }

    private static bool IsLongHexOrHashNoise(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value);
        return Regex.IsMatch(v, @"(?i)^[0-9a-f]{24,}$")
            || Regex.IsMatch(v, @"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:[;,]\d+)*(?:[;,][0-9a-f-]{36})?$");
    }

    private static bool HasSensitiveContext(string text)
    {
        if (String.IsNullOrWhiteSpace(text)) return false;
        return Regex.IsMatch(text, @"(?i)\b(user|upn|email|mail|account|principal|tenant|aad|azure\s*ad|entra|device\s*id|managed\s*device|enrollment|serial|imei|meid|sid|session|sessionid|session_id|mac|ip|host|hostname|computer|workstation|secret|token|password|passwd|pwd|credential|authorization|bearer|client[_\s-]*secret|api[_\s-]*key|private[_\s-]*key)\b");
    }

    private static bool ContainsEmbeddedSensitiveValue(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value);
        return Regex.IsMatch(v, @"(?i)[A-Za-z0-9._%+\-$]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
            || Regex.IsMatch(v, @"S-1-\d+(?:-\d)+")
            || Regex.IsMatch(v, @"(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}")
            || Regex.IsMatch(v, @"(?<!\d)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\d)")
            || Regex.IsMatch(v, @"(?i)\b(secret|token|password|passwd|pwd|credential|authorization|bearer|client[_-]*secret|api[_-]*key|private[_-]*key)\b");
    }

    private static bool IsBenignCredentialTargetName(string value, string context)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value).Trim();
        string ctx = context == null ? "" : context;
        if (!Regex.IsMatch(ctx, @"(?i)\b(TargetName|Identity|Resource|credential|vault|Windows Web Password Credential)\b")) return false;

        // Preserve only generic credential/vault target labels. Actual account-bearing
        // target names such as MicrosoftAccount:user=..., WindowsLive:name=..., emails,
        // domain\user values, private IPs, SIDs, and secret-looking values continue to scrub.
        if (Regex.IsMatch(v, @"(?i)[A-Za-z0-9._%+\-$]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")) return false;
        if (Regex.IsMatch(v, @"(?i)\b(?:user|name)\s*=")) return false;
        if (Regex.IsMatch(v, @"S-1-\d+(?:-\d)+")) return false;
        if (Regex.IsMatch(v, @"(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}")) return false;
        if (Regex.IsMatch(v, @"(?<!\d)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\d)")) return false;
        if (v.IndexOf('\\') >= 0) return false;

        if (Regex.IsMatch(v, @"(?i)^(?:WindowsLive:target=virtualapp/didlogical|gh:github\.com|git:https://github\.com)$")) return true;
        if (v.IndexOf("://", StringComparison.Ordinal) >= 0 || v.IndexOf('/') >= 0) return false;

        if (Regex.IsMatch(v, @"(?i)\b(password|passwd|pwd|secret|token|key|credential|username|proxy)\b")) return false;

        if (Regex.IsMatch(v, @"(?i)^Microsoft(?:Office|Store| OneDrive| Office| Windows| Edge)?[A-Za-z0-9 .&+_-]*(?:\*|-Installs)?$")) return true;

        if (Regex.IsMatch(v, @"(?i)^Adobe\b")
            && Regex.IsMatch(v, @"(?i)\b(?:Info|Package|Prefetched|Profile|OS|App|User)\b")
            && Regex.IsMatch(v, @"(?i)(?:\(Part\d+|\(.*\)\(Part\d+|Part\d+)"))
            return true;

        if (Regex.IsMatch(v, @"(?i)^[A-Z][A-Za-z0-9&+._ -]{2,80}\b(?:Info|Data|Installs|Settings)(?:\s*[-–]\s*[A-Z][A-Za-z0-9&+._ -]+)?(?:\s*\([^)]{0,80}\))*\(?Part\d+\)?$"))
            return true;

        return false;
    }

    private static bool IsDiagnosticBackslashPath(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value);
        if (v.IndexOf('\\') < 0) return false;
        return Regex.IsMatch(v, @"(?i)^ReportArchive\\")
            || Regex.IsMatch(v, @"(?i)^(?:Reports|ReportQueue|MISC|Driver|Drivers|Services|Channels|setup|WinGet|nativeimages|SCRIPTING|ROOT_HUB\d*|onedrive|defender|SideCarPolicies|Files|Tools|shared|Operational|Status|DefaultPowerSchemeValues|BackgroundCapability|CBS|Inventories|Catalog_Entries\d*|params|appcompatflags|HealthScripts|DRIVERENUM|DOTNET|build)\\")
            || Regex.IsMatch(v, @"(?i)^MoUpdateO_[^\\]+\\")
            || Regex.IsMatch(v, @"(?i)^(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)\\")
            || Regex.IsMatch(v, @"(?i)^(?:SOFTWARE|SYSTEM|SECURITY|SAM|DEFAULT|Microsoft|Windows|NT|CurrentVersion|ControlSet\d*|Enum|PCI|USBSTOR|SWD|ROOT)\\")
            || Regex.IsMatch(v, @"(?i)^(?:Intc[A-Za-z0-9_]*|IrDeviceV2|L2CAP|MIC|ISH_[A-Za-z0-9_]*|PNP\d+|REV_[A-Za-z0-9_]*|Col\d+|Q)\\")
            || Regex.IsMatch(v, @"(?i)^(?:USB\\VID_[0-9A-F]{4}|Devices\\UEFI)")
            || Regex.IsMatch(v, @"(?i)^AUTHORITY\\(?:NetworkService|LocalService|System)$")
            || Regex.IsMatch(v, @"(?i)\\[^\\]+\.(?:dll|exe|xml|etl|inf|pnf|sys|mui|cat|manifest|log|txt|json)$")
            || Regex.IsMatch(v, @"(?i)^(?:Microsoft|MicrosoftWindows|MicrosoftCorporationII|Global|msteams|AppUp|Realtek)[A-Za-z0-9_.-]*\\")
            || Regex.IsMatch(v, @"(?i)^[A-Za-z0-9_.-]+_[0-9]+\.[0-9][A-Za-z0-9_.-]*__[A-Za-z0-9]+\\");
    }

    private static bool IsLowSignalValue(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return true;
        string v = CleanValue(value);
        if (v.Length < 3) return true;
        if (Regex.IsMatch(v, @"(?i)^(true|false|null|none|unknown|default|failed|failure|success|succeeded|successful|successfully|complete|completed|supported|unsupported|enabled|disabled|present|absent|error|warning|info|ok|yes|no|has|is|was|were|be|been|being|are|the|and|or|not|for|from|with|to|of|in|on|by|public|n/a|\(null\)|-)$")) return true;
        if (Regex.IsMatch(v, @"^(0x[0-9a-fA-F]+|\d+)$")) return true;
        return false;
    }

    private static bool IsSensitiveNumericIdentifierContext(string context)
    {
        if (String.IsNullOrWhiteSpace(context)) return false;
        return Regex.IsMatch(context, @"(?i)\b(serial\s*number|serialnumber|serial|imei|meid)\b");
    }

    private static string LocalContext(string text, int index, int length)
    {
        if (String.IsNullOrEmpty(text)) return "";
        int radius = 48;
        int start = Math.Max(0, index - radius);
        int end = Math.Min(text.Length, index + Math.Max(length, 0) + radius);
        if (end <= start) return text;
        return text.Substring(start, end - start);
    }

    private static bool LooksLikeSecretValue(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = CleanValue(value);
        if (v.Length < 12) return false;
        if (IsKnownFileOrDiagnosticName(v) || IsDiagnosticBackslashPath(v) || IsDiagnosticPathOnlyUri(v)) return false;
        if (Regex.IsMatch(v, @"(?i)^(true|false|null|none|default|unknown|enabled|disabled|success|failed)$")) return false;
        if (Regex.IsMatch(v, @"(?i)^(?:gh[pousr]_|xox[baprs]-|sk_(?:live|test)_|sk-|eyJ|AKIA|ASIA)")) return true;
        if (Regex.IsMatch(v, @"(?i)^[a-z]+/[A-Za-z0-9_/.-]+$")) return false;
        if (Regex.IsMatch(v, @"^[A-Z][A-Za-z]+(?:Controller|Service|Provider|Manager|Factory|Handler)$")) return false;
        if (Regex.IsMatch(v, @"(?i)^(?:Package_for_|Microsoft\.|MicrosoftWindows|Cisco Secure Client|VC,redist|DisableV2ChainValidation)")) return false;
        bool hasLower = Regex.IsMatch(v, @"[a-z]");
        bool hasUpper = Regex.IsMatch(v, @"[A-Z]");
        bool hasDigit = Regex.IsMatch(v, @"\d");
        bool hasSymbol = Regex.IsMatch(v, @"[+/_=\-.]");
        int score = (hasLower ? 1 : 0) + (hasUpper ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSymbol ? 1 : 0);
        return v.Length >= 24 && score >= 3;
    }

    private bool ShouldMap(string raw, string prefix, string context)
    {
        string v = CleanValue(raw);
        string ctx = context == null ? "" : context;
        bool sensitiveNumericIdentifier = IsSensitiveNumericIdentifierContext(context) && Regex.IsMatch(v, @"^\d{5,20}$");
        if ((IsLowSignalValue(v) && !sensitiveNumericIdentifier) || String.IsNullOrWhiteSpace(prefix)) return false;
        if (IsAlreadyToken(v)) return false;
        if (IsDottedDecimalNonIp(v)) return false;
        bool balanced = !String.Equals(_scrubPolicy, "Strict", StringComparison.OrdinalIgnoreCase);
        if (balanced && IsStandaloneTimestampLikeValue(v)) return false;
        if (balanced && IsCompositeStatusPayload(v)) return false;
        if (balanced && IsXmlStateFragment(v)) return false;
        if (balanced && IsBenignPlaceholderValue(v)) return false;
        if (balanced && prefix == "DNS" && IsFileNameLikeDnsValue(v)) return false;
        if (balanced && prefix == "PRINCIPAL" && (IsLongNaturalLanguagePrincipalNoise(v) || IsLogonBannerTitle(v) || IsRelativeDiagnosticBackslashPath(v) || IsEncodedGuidCnFragment(v) || IsHighEntropyDotZeroPrincipalNoise(v) || IsBenignUriPrincipalValue(v))) return false;
        if (balanced && prefix == "MAC" && (Regex.IsMatch(v, @"(?i)^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$") || IsHashAsMacValue(v))) return false;
        if (balanced && IsDiagnosticConfigPath(v) && !ContainsEmbeddedSensitiveValue(v)) return false;
        if (balanced && IsWindowsServicingNoiseIdentifier(v, ctx) && !ContainsEmbeddedSensitiveValue(v)) return false;
        if (balanced && prefix == "PRINCIPAL" && IsBenignCredentialTargetName(v, ctx)) return false;
        if ((prefix == "IP" || prefix == "IP6") && balanced && IsVersionOrCorrelationIpv4(v, context)) return false;
        if (IsWellKnownSid(v) || IsWellKnownWindowsPrincipal(v)) return false;
        if ((prefix == "IP" || prefix == "IP6") && IsLoopbackIp(v)) return false;
        if (prefix == "IP" && !IsValidIpv4(v)) return false;
        if (prefix == "IP6" && !IsValidIpv6(v)) return false;
        if (prefix == "IP" && balanced && Regex.IsMatch(v, @"^(?:10|172|192)\.\d{1,3}\.\d{1,3}\.0$")) return false;
        if (prefix == "IP" && balanced && !IsPrivateIpv4(v) && !HasStrongNetworkContext(ctx)) return false;

        // CustomRegexRule hits are useful, but they still need the normal
        // prefix-specific false-positive gates below. A previous short-circuit
        // here allowed built-in Intune custom regexes to map whole composite
        // status payloads such as:
        //   DeviceId: HOST123, Status: Committed, RetryCount: 0, LastSyncDateTime: ...
        // as a different COMPUTER token for every timestamp. Keeping the
        // context allows the OBJECT/session gates below to honor BYOP/session
        // rules without bypassing COMPUTER, CERT, GUID, and diagnostic-noise
        // protections.
        if ((prefix == "DNS" || prefix == "UNMAPPED_UPN" || prefix == "URI") && IsAllowedDomain(v)) return false;
        bool strongNetworkContextForValue = HasStrongNetworkContext(ctx);
        bool privateOrInternalDnsName = Regex.IsMatch(v, @"(?i)\.(local|lan|corp|internal|intranet|home|test)$");
        if (prefix == "UNMAPPED_UPN" && IsKnownFileOrDiagnosticName(v)) return false;
        if (prefix == "DNS" && IsKnownFileOrDiagnosticName(v) && !(strongNetworkContextForValue && privateOrInternalDnsName)) return false;
        if (prefix == "URI" && balanced && (IsDiagnosticPathOnlyUri(v) || IsDiagnosticConfigPath(v))) return false;
        if (prefix == "URI" && balanced)
        {
            bool hasScheme = Regex.IsMatch(v, @"(?i)^[a-z][a-z0-9+.-]*://");
            string uriHost = hasScheme ? ExtractUrlHost(v) : "";
            if (Regex.IsMatch(v, @"(?i)^https?://(?:localhost|127\.0\.0\.1|\[::1\])")) return false;
            if (hasScheme && IsAllowedDomain(uriHost) && !Regex.IsMatch(v, @"(?i)[?&](?:token|access_token|refresh_token|sig|signature|key|client_secret|password|pwd)=")) return false;
            if (hasScheme && Regex.IsMatch(v, @"(?i)^https?://(?:www\.)?(?:cisco|hpinc?|zoom|github|dot|nexthink|techsmith|textexpander|printerlogic|mozilla|notepad-plus-plus)\.")) return false;
            if (!hasScheme)
            {
                if (IsDiagnosticPathOnlyUri(v)) return false;
                if (!HasSensitiveContext(context) && !ContainsEmbeddedSensitiveValue(v)) return false;
            }
        }
        if (prefix == "DNS" && balanced)
        {
            if (v.IndexOf("://", StringComparison.Ordinal) >= 0 && !Regex.IsMatch(v, @"(?i)^https?://")) return false;
            if ((IsKnownFileOrDiagnosticName(v) && !(strongNetworkContextForValue && privateOrInternalDnsName)) || IsHardwareOrDeviceInventoryId(v)) return false;
            if (Regex.IsMatch(v, @"(?i)^(?:legend\.fillStyle|document\.getElementById|OpenSSH\.Server|cimhandler\.ashx)$")) return false;
            if (Regex.IsMatch(v, @"_")) return false;
            if (!HasStrongNetworkContext(context) && !ContainsEmbeddedSensitiveValue(v) && !Regex.IsMatch(context == null ? "" : context, @"(?i)://")) return false;
        }
        if (prefix == "PRINCIPAL" && balanced)
        {
            if (Regex.IsMatch(v, @"(?i)^(?:CN|OU|O|C|L|S|E)=")) return false;
            if (Regex.IsMatch(v, @"(?i)^\{[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+}\.\{[0-9a-f-]+$")) return false;
            if (Regex.IsMatch(v, @"(?i)^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$")) return false;
            if (Regex.IsMatch(v, @"(?i)^(?:data|driverstore|drivers|system32|syswow64|programdata|public)\\[A-Za-z0-9_.-]+$")) return false;
            if (Regex.IsMatch(v, @"(?i)^CN=(?:\{?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\}?|Root|USERTrust|Microsoft|Windows)") ) return false;
            if (Regex.IsMatch(v, @"(?i)^[A-Za-z0-9_.-]+_(?:cw5n1h2txyewy|8wekyb3d8bbwe|[A-Za-z0-9]{8,})![A-Za-z0-9_.-]+$")) return false;
            if (Regex.IsMatch(v, @"(?i)^(?:Microsoft|MicrosoftWindows|MicrosoftCorporationII|Global|PackageMetadata|App)\.?[A-Za-z0-9_.-]*![A-Za-z0-9_.-]+$")) return false;
            if (Regex.IsMatch(v, @"(?i)^(?:successfully|supported|unsupported|complete|completed|default|has|failed)$")) return false;
            if (IsJunkBackslashPair(v) || IsDiagnosticBackslashPath(v) || IsHardwareOrDeviceInventoryId(v) || IsKnownFileOrDiagnosticName(v)) return false;
            if (v.IndexOf('\\') >= 0 && !LooksLikeRealDomainPrincipal(v, context)) return false;
        }
        if (prefix == "PRINCIPAL" && Regex.IsMatch(v, @"(?i)^(windows|winnt|system32|syswow64|sysnative|systemroot|drivers|users|public|default|programdata|appdata|microsoft|program files( \(x86\))?|inf|temp|tmp|config|fonts|assembly|servicing|winsxs|tasks|spool|wbem|registry|device|harddiskvolume\d*)\\")) return false;
        if (prefix == "COMPUTER" && balanced)
        {
            bool strongComputerContext = HasStrongComputerContext(context);
            if (IsAllowedDomain(v)) return false;
            if (Regex.IsMatch(ctx, @"(?i)\b(certutil|certificate\s+store|certificate|cert|issuer|subject|thumbprint)\b") && Regex.IsMatch(v, @"(?i)^[0-9a-f]{6,}$")) return false;
            if (IsStatusPayload(v) || IsHardwareOrDeviceInventoryId(v) || IsWindowsServiceOrDriverName(v) || IsDiagnosticBackslashPath(v) || IsKnownFileOrDiagnosticName(v) || IsLongHexOrHashNoise(v)) return false;
            if (Regex.IsMatch(v, @"(?i)^(?:Base|BuildBranch|Edition|Bluetooth|POLYDRIVER|COMPUTER\\Generic|Cisco|Intel\(R|Microsoft|RAS|WAN|Wi-Fi|FileInfo|BootPerformance|UnionFS|Number|GenDisk)$")) return false;
            if (Regex.IsMatch(v, @"(?i)^[0-9a-f]{6,}$") && !(Regex.IsMatch(ctx, @"(?i)\b(serial|serialnumber|serial\s*number|imei|meid)\b") && !Regex.IsMatch(ctx, @"(?i)\b(certutil|certificate|cert|issuer|subject|thumbprint)\b"))) return false;
            if (v.IndexOf(' ') >= 0 && !Regex.IsMatch(context == null ? "" : context, @"(?i)\b(serial|imei|meid)\b")) return false;
            if (!strongComputerContext && !v.EndsWith("$", StringComparison.Ordinal) && !ContainsEmbeddedSensitiveValue(v) && v.Length > 32) return false;
        }
        if ((prefix == "SECRET" || prefix == "APIKEY") && balanced)
        {
            if (v.IndexOf(' ') >= 0 && !Regex.IsMatch(v, @"(?i)^(?:Bearer|Basic)\s+[A-Za-z0-9+/_=.\-]{12,}$")) return false;
            if (Regex.IsMatch(v, @"(?i)^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{11,12}\}?$")) return false;
            if (Regex.IsMatch(v, @"(?i)^(?:te|tr)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")) return false;
            if (Regex.IsMatch(v, @"(?i)^(?:Package_for_|Microsoft\.|MicrosoftWindows|Cisco Secure Client|VC,redist|DisableV2ChainValidation|HyperV-|Windows-)")) return false;
            if (Regex.IsMatch(v, @"^\d+(?:\.\d+){2,4};\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")) return false;
            bool contextualSecret = HasSensitiveContext(context) && v.Length >= 8 && !IsKnownFileOrDiagnosticName(v) && !IsDiagnosticBackslashPath(v) && !IsDiagnosticPathOnlyUri(v) && !IsDiagnosticConfigPath(v) && !IsHardwareOrDeviceInventoryId(v)
                && Regex.IsMatch(v, @"[A-Za-z]") && Regex.IsMatch(v, @"[0-9_\-.]");
            if (!LooksLikeSecretValue(v) && !contextualSecret) return false;
        }
        if (prefix == "X500" && balanced && Regex.IsMatch(v, @"(?i)^CN=\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$")) return false;
        if (balanced)
        {
            if (prefix == "OBJECT" && Regex.IsMatch(v, @"(?i)^[A-Za-z_$][A-Za-z0-9_$]*(?:Bounds)?\[[A-Za-z0-9_$]*$|^[A-Za-z_$][A-Za-z0-9_$]*\([A-Za-z0-9_$]*$")) return false;
            if (prefix == "OBJECT" && !Regex.IsMatch(ctx, @"(?i)\b(custom\s+regex|generated|profile|seed|label|tenant|device|aad|azure\s*ad|entra|enrollment|managed\s*device|user|principal|serial|imei|meid|certificate|cert|credential|secret|token|session|sessionid|session_id|sid|project|case|ticket|request|trace|src_ip|dst_ip|ip|address|host|server)\b|deviceid|device_id|azureaddeviceid|azure_ad_device_id|aaddeviceid|manageddeviceid|enrollmentid")) return false;
            if (prefix == "GUID") return false;
            if (prefix == "CERT")
            {
                if (Regex.IsMatch(ctx, @"(?i)\b(msinfo32|wlan-report|setupact|setuperr|clienthealth|appcompat|package|servicing)\b") && !Regex.IsMatch(ctx, @"(?i)\b(certutil|certificate\s+store|thumbprint|issuer|subject|serial\s*number)\b")) return false;
                if (!Regex.IsMatch(ctx, @"(?i)\b(thumbprint|certificate|cert|serial|serialnumber|serial\s*number|signature|signed|signer|issuer|subject|sha1|sha256|sha512|md5|token|secret|key|password|credential)\b")) return false;
            }
            if (prefix == "BLOB")
            {
                if (Regex.IsMatch(v, @"(?i)^[a-z]+/[A-Za-z0-9_/.-]+$")) return false;
                if (!LooksLikeSecretValue(v) && !Regex.IsMatch(ctx, @"(?i)\b(secret|token|password|passwd|pwd|credential|authorization|bearer|client[_\s-]*secret|api[_\s-]*key|private[_\s-]*key)\b")) return false;
            }
            if (prefix == "MAC")
            {
                if (Regex.Matches(v, @"(?i)(?:^|[:-])20(?=[:-]|$)").Count >= 1 && Regex.IsMatch(v, @"(?i)(?:^|[:-])(?:41|52|53|56|59|4E)(?=[:-]|$)")) return false;
                if (!Regex.IsMatch(ctx, @"(?i)(^|[^A-Za-z0-9])(mac|bssid|ssid|adapter|physical\s+address|ethernet|wi-?fi|wireless|network|interface)|mac[_\s-]*addresses?|wifimac|wi-fi\s*mac|ethernetmac")) return false;
            }
        }
        return true;
    }

    private void AddIdentifier(List<UlsDiscoveryRow> rows, string raw, string prefix, string source, string sourcePathHash, string context)
    {
        string v = CleanValue(raw);
        string norm = Normalize(v);
        if (String.IsNullOrEmpty(norm) || _seen.ContainsKey(norm)) return;
        string mapContext = ((context == null ? "" : context) + " " + (source == null ? "" : source)).Trim();
        if (!ShouldMap(v, prefix, mapContext)) return;
        UlsDiscoveryRow row = new UlsDiscoveryRow();
        row.InputValue = v;
        row.NormalizedValue = norm;
        row.TokenType = prefix;
        row.Token = TokenFor(v, prefix);
        row.Source = source == null ? "Discovery" : source;
        row.SourcePathHash = sourcePathHash == null ? "" : sourcePathHash;
        _seen[norm] = row;
        rows.Add(row);
    }

    private void RunDetector(Action action, UlsDiscoveryResult result, Action fallback)
    {
        try
        {
            action();
        }
        catch (RegexMatchTimeoutException)
        {
            result.TimeoutCount++;
            result.FallbackUsed = true;
            if (fallback != null) fallback();
        }
    }

    private void AddFallbackMatches(string text, string pattern, RegexOptions options, Action<Match> onMatch, UlsDiscoveryResult result)
    {
        if (String.IsNullOrEmpty(text) || onMatch == null) return;
        try
        {
            foreach (Match m in Regex.Matches(text, pattern, options, RxTimeout))
            {
                if (m.Success) onMatch(m);
            }
        }
        catch (RegexMatchTimeoutException)
        {
            result.TimeoutCount++;
        }
    }

    private void DiscoverFallbackChunk(string text, List<UlsDiscoveryRow> rows, string source, string sourcePathHash, UlsDiscoveryResult result)
    {
        if (text.IndexOf("<", StringComparison.Ordinal) >= 0)
        {
            AddFallbackMatches(text, @"(?is)<Computer>(?<value>[^<]{1,512})</Computer>", RegexOptions.IgnoreCase | RegexOptions.Singleline, m =>
            {
                AddIdentifier(rows, m.Groups["value"].Value, "COMPUTER", source, sourcePathHash, "fallback Computer element");
            }, result);
            AddFallbackMatches(text, @"(?is)\bUserID\s*=\s*[""'](?<value>S-1-\d+(?:-\d)+)[""']", RegexOptions.IgnoreCase | RegexOptions.Singleline, m =>
            {
                AddIdentifier(rows, m.Groups["value"].Value, "SID", source, sourcePathHash, "fallback Security UserID attribute");
            }, result);
            AddFallbackMatches(text, @"(?is)<Data\b[^>]*\bName\s*=\s*[""'](?<key>[^""']{1,128})[""'][^>]*>(?<value>[^<]{1,512})</Data>", RegexOptions.IgnoreCase | RegexOptions.Singleline, m =>
            {
                string key = m.Groups["key"].Value;
                string value = m.Groups["value"].Value;
                string prefix = EventPrefixForKey(key, value);
                if (prefix != null) AddIdentifier(rows, value, prefix, source, sourcePathHash, "fallback event data " + key);
            }, result);
        }
        AddFallbackMatches(text, @"(?im)\b(?<label>user principal name|upn|email|mail|user name|username|user|account name|account|principal|computer name|computer|machine name|machine|device name|device|workstation|host name|hostname|server name|server|serial number|serial|imei|meid|mac address|mac|wifi|ethernet|ip address|client address|source network address|destination address|remote addr|url|uri|endpoint)\s*[:=]\s*[""']?(?<value>[^""'\s,;|<>{}\[\]]{3,256})", RegexOptions.IgnoreCase | RegexOptions.Multiline, m =>
        {
            string label = m.Groups["label"].Value;
            string value = m.Groups["value"].Value;
            AddIdentifier(rows, value, PrefixForLabel(label, value), source, sourcePathHash, "fallback label " + label);
        }, result);

        if (text.IndexOf("\\Users\\", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            AddFallbackMatches(text, @"(?i)(?:\\\?\\)?[A-Za-z]:\\Users\\([^\\/""',;:<>\r\n]+)", RegexOptions.IgnoreCase, m =>
            {
                if (m.Groups.Count > 1) AddIdentifier(rows, m.Groups[1].Value, "PRINCIPAL", source, sourcePathHash, "fallback user profile path");
            }, result);
        }
        if (text.IndexOf("S-1-", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            AddFallbackMatches(text, @"S-1-\d+(?:-\d)+", RegexOptions.IgnoreCase, m =>
            {
                AddIdentifier(rows, m.Value, "SID", source, sourcePathHash, "fallback sid");
            }, result);
        }
        if (text.IndexOf("@", StringComparison.Ordinal) >= 0)
        {
            AddFallbackMatches(text, @"\b[A-Za-z0-9._%+\-$]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", RegexOptions.IgnoreCase, m =>
            {
                AddIdentifier(rows, m.Value, "UNMAPPED_UPN", source, sourcePathHash, "fallback email");
            }, result);
        }
        AddFallbackMatches(text, @"(?<!\d)(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)(?!\.\d)", RegexOptions.IgnoreCase, m =>
        {
            AddIdentifier(rows, m.Value, "IP", source, sourcePathHash, "fallback ipv4 " + LocalContext(text, m.Index, m.Length));
        }, result);
        AddFallbackMatches(text, @"(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}", RegexOptions.IgnoreCase, m =>
        {
            AddIdentifier(rows, m.Value, "MAC", source, sourcePathHash, "fallback mac");
        }, result);
        AddFallbackMatches(text, @"(?i)\b(?:https?|wss?)://(?:[^@\s/;,?]+@)?(?<host>\[[^\]\s]+\]|[A-Za-z0-9][A-Za-z0-9_.-]{0,252}|\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?", RegexOptions.IgnoreCase, m =>
        {
            string host = CleanValue(m.Groups["host"].Value).Trim('[', ']');
            string prefix = ConnectionHostPrefix(host);
            if (prefix != null) AddIdentifier(rows, host, prefix, source, sourcePathHash, "fallback url host");
        }, result);
        AddFallbackMatches(text, @"(?i)(?<![A-Za-z0-9_.\-])[A-Za-z0-9_.\-]+\\[A-Za-z0-9_.\-$]+", RegexOptions.IgnoreCase, m =>
        {
            AddIdentifier(rows, m.Value, "PRINCIPAL", source, sourcePathHash, "fallback domain user");
        }, result);
    }

    private void DiscoverTextFallback(string text, List<UlsDiscoveryRow> rows, string source, string sourcePathHash, UlsDiscoveryResult result)
    {
        if (String.IsNullOrWhiteSpace(text)) return;
        result.FallbackUsed = true;
        const int chunkSize = 65536;
        const int overlap = 512;
        if (text.Length <= chunkSize)
        {
            DiscoverFallbackChunk(text, rows, source, sourcePathHash, result);
            return;
        }
        for (int offset = 0; offset < text.Length; offset += chunkSize)
        {
            int start = Math.Max(0, offset - overlap);
            int length = Math.Min(chunkSize + (offset == 0 ? 0 : overlap), text.Length - start);
            if (length <= 0) break;
            DiscoverFallbackChunk(text.Substring(start, length), rows, source, sourcePathHash, result);
        }
    }

    private string PrefixForLabel(string label, string value)
    {
        string l = label == null ? "" : label.ToLowerInvariant();
        string v = CleanValue(value);
        if (Regex.IsMatch(l, @"(?i)^(?:site[_\s-]*code|sitecode)$")) return null;
        if (Regex.IsMatch(v, @"^[A-Za-z0-9._%+\-$]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")) return "UNMAPPED_UPN";
        if (Regex.IsMatch(l, @"(?i)(displayname|display_name|device.*display|workstation.*display)") && Regex.IsMatch(v, @"(?i)^[A-Za-z][A-Za-z0-9-]{2,63}\d[A-Za-z0-9-]{0,63}$")) return "COMPUTER";
        if ((l.IndexOf("sid", StringComparison.OrdinalIgnoreCase) >= 0 || Regex.IsMatch(l, @"security\s*identifier|userid|user\s*id")) && Regex.IsMatch(v, @"(?i)^S-1-\d+(?:-\d+)+$")) return "SID";
        if (Regex.IsMatch(l, @"(?i)(device\s*id|deviceid|aad\s*device|azure\s*ad\s*device|entra\s*device|managed\s*device)") && Regex.IsMatch(v, @"(?i)^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$")) return "OBJECT";
        if (Regex.IsMatch(l, @"key|secret|token|password|passwd|pwd|auth")) return l.Contains("api") ? "APIKEY" : "SECRET";
        if (Regex.IsMatch(l, @"request|trace|ticket|case|correlation")) return "OBJECT";
        if (Regex.IsMatch(l, @"mac|wifi|ethernet")) return "MAC";
        if (Regex.IsMatch(l, @"url|uri|callback|redirect")) return "URI";
        if (Regex.IsMatch(l, @"address|addr|ip|x-forwarded"))
        {
            if (v.IndexOf(':') >= 0) return "IP6";
            return "IP";
        }
        if (Regex.IsMatch(l, @"endpoint")) return "URI";
        if (Regex.IsMatch(l, @"machine|computer|device|workstation|asset|client name")) return "COMPUTER";
        if (Regex.IsMatch(l, @"host|server|node|pod|container|instance")) return "DNS";
        if (Regex.IsMatch(l, @"domain|tenant|organization|org|realm")) return "X500";
        if (Regex.IsMatch(l, @"serial|imei|meid")) return "COMPUTER";
        if (Regex.IsMatch(l, @"user|account|principal|actor|caller|assignee|assigned[_ -]?to|assignedto|subject|identity|login|owner|requester|suser|duser")) return "PRINCIPAL";
        if (v.EndsWith("$", StringComparison.Ordinal)) return "COMPUTER";
        return "PRINCIPAL";
    }

    private static string UnquoteValue(string value)
    {
        string v = CleanValue(value);
        if (v.Length >= 2)
        {
            if ((v[0] == '"' && v[v.Length - 1] == '"') || (v[0] == '\'' && v[v.Length - 1] == '\''))
                v = v.Substring(1, v.Length - 2);
        }
        return v.Replace("\\\"", "\"").Replace("\\\\", "\\");
    }

    private string PrefixForStructuredKey(string key, string value)
    {
        string k = key == null ? "" : key.Trim();
        string l = k.ToLowerInvariant();
        string v = CleanValue(value);
        if (String.IsNullOrWhiteSpace(l)) return null;
        if (Regex.IsMatch(l, @"(?i)^(?:site[_\s-]*code|sitecode)$")) return null;
        if (Regex.IsMatch(l, @"^(timestamp|time|date|datetime|level|severity|status|state|result|action|method|operation|eventid|event_id|id|version|count|bytes|duration|elapsed|latency|port|pid|processid|threadid)$")) return null;
        if (Regex.IsMatch(v, @"^[A-Za-z0-9._%+\-$]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")) return "UNMAPPED_UPN";
        if (Regex.IsMatch(l, @"(?i)(displayname|display_name|device.*display|workstation.*display)") && Regex.IsMatch(v, @"(?i)^[A-Za-z][A-Za-z0-9-]{2,63}\d[A-Za-z0-9-]{0,63}$")) return "COMPUTER";
        if ((l.IndexOf("sid", StringComparison.OrdinalIgnoreCase) >= 0 || Regex.IsMatch(l, @"(^|[_\-. ])(?:securityidentifier|security_identifier|user\s*id|userid)(?:$|[_\-. ])")) && Regex.IsMatch(v, @"(?i)^S-1-\d+(?:-\d+)+$")) return "SID";
        if (Regex.IsMatch(v, @"(?i)^S-1-\d+(?:-\d+)+$")) return "SID";
        if (Regex.IsMatch(v, @"(?i)^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$") && Regex.IsMatch(l, @"(tenant|device|aad|azuread|azure_ad|entra|enrollment|manageddevice|managed_device|user|principal)")) return "OBJECT";
        if (Regex.IsMatch(v, @"(?i)^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$") && Regex.IsMatch(l, @"(mac|wifi|wi-fi|ethernet|adapter)")) return "MAC";
        if (Regex.IsMatch(v, @"(?i)^[0-9a-f]{2}(?:-[0-9a-f]{2}){5}$") && Regex.IsMatch(l, @"(mac|wifi|wi-fi|ethernet|adapter)")) return "MAC";
        if ((IsValidIpv4(v) || v.IndexOf(':') >= 0) && Regex.IsMatch(l, @"(src_ip|dst_ip|clientip|client_ip|remote_addr|ipaddress|ip_address|source.*address|destination.*address|\bc-ip\b|\bs-ip\b|\bip\b|x-forwarded-for|address|addr)")) return v.IndexOf(':') >= 0 ? "IP6" : "IP";
        if (Regex.IsMatch(l, @"(api[_ -]?key|secret|token|password|passwd|pwd|credential|authorization|auth|private[_ -]?key|client[_ -]?secret)")) return l.Contains("api") ? "APIKEY" : "SECRET";
        if (Regex.IsMatch(l, @"(sha1|sha256|sha512|md5|hash|thumbprint)")) return "CERT";
        if (Regex.IsMatch(l, @"(user|username|user_id|userid|account|principal|actor|caller|assignee|assigned[_ -]?to|assignedto|subject|identity|login|owner|requester|suser|duser|cs-username)")) return "PRINCIPAL";
        if (Regex.IsMatch(l, @"(src_ip|dst_ip|clientip|client_ip|remote_addr|ipaddress|ip_address|source.*address|destination.*address|\bc-ip\b|\bs-ip\b|\bip\b|x-forwarded-for)")) return CleanValue(value).IndexOf(':') >= 0 ? "IP6" : "IP";
        if (Regex.IsMatch(l, @"(^name0$|netbios|manageddevicename|managed_device_name|device_name|devicename|cmdb_ci|configuration[_ -]?item|machine|device|asset|endpoint|workstation|computer)")) return "COMPUTER";
        if (Regex.IsMatch(l, @"(destination|dest|host|hostname|server|node|pod|container|dhost|shost|cs-host|upstream_host)")) return "DNS";
        if (Regex.IsMatch(l, @"(tenant|tenantid|tenant_id|org|organization|domain|realm|subscription|accountid|account_id|project)")) return "X500";
        if (Regex.IsMatch(l, @"(url|uri|endpoint|referer|referrer|callback|redirect)")) return "URI";
        if (Regex.IsMatch(l, @"(serial|serialnumber|imei|meid)")) return "COMPUTER";
        if (Regex.IsMatch(l, @"(mac|wifi|ethernet)")) return "MAC";
        if (Regex.IsMatch(l, @"(session|requestid|request_id|request id|correlation|trace|trace_id|trace id|span|transaction|ticket|case|incident)")) return "OBJECT";
        return null;
    }

    private static bool IsMessageLikeKey(string key)
    {
        if (String.IsNullOrWhiteSpace(key)) return false;
        return Regex.IsMatch(key, @"(?i)(message|msg|detail|details|description|error|exception|stack|payload|raw|body|query|command|line|text|output)");
    }

    private void DiscoverCustomRegexRules(string text, List<UlsDiscoveryRow> rows, string source, string sourcePathHash, UlsDiscoveryResult result)
    {
        if (_customRules.Count == 0 || String.IsNullOrWhiteSpace(text)) return;
        foreach (UlsCustomRegexRule rule in _customRules)
        {
            try
            {
                foreach (Match m in rule.Regex.Matches(text))
                {
                    if (!m.Success) continue;
                    int group = rule.CaptureGroup;
                    if (group >= m.Groups.Count || !m.Groups[group].Success) continue;
                    AddIdentifier(rows, m.Groups[group].Value, rule.Prefix, source, sourcePathHash, "custom regex " + rule.Prefix + " " + rule.Pattern);
                }
            }
            catch (RegexMatchTimeoutException)
            {
                result.TimeoutCount++;
                result.FallbackUsed = true;
            }
        }
    }

    private string PrefixForLabelWithDefault(string label, string value, string defaultPrefix)
    {
        string inferred = PrefixForLabel(label, value);
        if (!String.IsNullOrWhiteSpace(inferred) && !String.Equals(inferred, "PRINCIPAL", StringComparison.OrdinalIgnoreCase)) return inferred;
        string l = label == null ? "" : label;
        if (Regex.IsMatch(l, @"(?i)(user|username|account|principal|actor|caller|assignee|assigned[_ -]?to|assignedto|subject|identity|login|owner|requester|suser|duser|cs-username)")) return "PRINCIPAL";
        if (!String.IsNullOrWhiteSpace(defaultPrefix)) return defaultPrefix;
        return inferred;
    }

    private void DiscoverProfileLabelRules(string text, List<UlsDiscoveryRow> rows, string source, string sourcePathHash, UlsDiscoveryResult result)
    {
        if (_labelRules.Count == 0 || String.IsNullOrWhiteSpace(text)) return;
        foreach (UlsLabelRegexRule rule in _labelRules)
        {
            try
            {
                foreach (Match m in rule.Regex.Matches(text))
                {
                    if (!m.Success || m.Groups.Count < 3 || !m.Groups[2].Success) continue;
                    string label = m.Groups[1].Success ? m.Groups[1].Value : "";
                    label = Regex.Replace(label, @"\s*(?:[:=])\s*$", "").Trim();
                    string raw = m.Groups[2].Value.Trim().Trim('"', '\'');
                    string prefix = PrefixForLabelWithDefault(label, raw, rule.Prefix);
                    AddIdentifier(rows, raw, prefix, source, sourcePathHash, "profile label " + label);
                }
            }
            catch (RegexMatchTimeoutException)
            {
                result.TimeoutCount++;
                result.FallbackUsed = true;
            }
        }
    }

    private List<string> ParseDelimitedLine(string line, char delimiter)
    {
        List<string> values = new List<string>();
        if (line == null) return values;
        StringBuilder current = new StringBuilder();
        bool quoted = false;
        for (int i = 0; i < line.Length; i++)
        {
            char ch = line[i];
            if (ch == '"')
            {
                if (quoted && i + 1 < line.Length && line[i + 1] == '"')
                {
                    current.Append('"');
                    i++;
                }
                else quoted = !quoted;
            }
            else if (ch == delimiter && !quoted)
            {
                values.Add(current.ToString());
                current.Length = 0;
            }
            else current.Append(ch);
        }
        values.Add(current.ToString());
        return values;
    }

    private void DiscoverStructuredValue(string key, string value, List<UlsDiscoveryRow> rows, string source, string sourcePathHash, UlsDiscoveryResult result)
    {
        string v = UnquoteValue(value);
        if (String.IsNullOrWhiteSpace(v)) return;

        if (LooksLikeStructuredPayload(v))
        {
            DiscoverJsonLine(v, rows, source, sourcePathHash, result);
            DiscoverText(v, rows, source, sourcePathHash, result);
            return;
        }

        string prefix = PrefixForStructuredKey(key, v);
        DiscoverIntuneCompositeIdentityText(v, rows, source, sourcePathHash);
        if (prefix != null) AddIdentifier(rows, v, prefix, source, sourcePathHash, "field " + key);
        if (LooksLikeUrlOrPathIdentityCarrier(key, v)) DiscoverUrlSensitiveParts(v, rows, source, sourcePathHash);
        if (IsMessageLikeKey(key) || prefix == null) DiscoverText(v, rows, source, sourcePathHash, result);
    }

    private void DiscoverJsonLine(string line, List<UlsDiscoveryRow> rows, string source, string sourcePathHash, UlsDiscoveryResult result)
    {
        bool matched = false;
        try
        {
            foreach (Match m in JsonPairRx.Matches(line))
            {
                matched = true;
                DiscoverStructuredValue(m.Groups["key"].Value, m.Groups["value"].Value, rows, source, sourcePathHash, result);
            }
        }
        catch (RegexMatchTimeoutException)
        {
            result.TimeoutCount++;
            result.FallbackUsed = true;
            DiscoverTextFallback(line, rows, source, sourcePathHash, result);
            return;
        }
        if (!matched) DiscoverText(line, rows, source, sourcePathHash, result);
    }

    private void DiscoverLabels(string text, List<UlsDiscoveryRow> rows, string source, string sourcePathHash)
    {
        foreach (Match m in LabelRx.Matches(text))
        {
            string label = m.Groups["label"].Value;
            string value = m.Groups["value"].Value;
            AddIdentifier(rows, value, PrefixForLabel(label, value), source, sourcePathHash, label);
        }
    }

    private void DiscoverContextualComputerNames(string text, List<UlsDiscoveryRow> rows, string source, string sourcePathHash)
    {
        if (String.IsNullOrWhiteSpace(text)) return;
        foreach (Match m in ContextualComputerRx.Matches(text))
        {
            string label = m.Groups["label"].Value;
            string value = CleanValue(m.Groups["value"].Value);
            if (String.IsNullOrWhiteSpace(value)) continue;
            AddIdentifier(rows, value, "COMPUTER", source, sourcePathHash, "contextual computer name " + label);
        }
    }

    private static bool LooksLikeStructuredPayload(string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return false;
        string v = value.Trim();
        if (v.Length < 6) return false;
        if ((v.StartsWith("{", StringComparison.Ordinal) && v.Contains(":")) ||
            (v.StartsWith("[", StringComparison.Ordinal) && v.Contains(":"))) return true;
        if (v.IndexOf("\":", StringComparison.Ordinal) >= 0 || v.IndexOf("'" + ":", StringComparison.Ordinal) >= 0) return true;
        return false;
    }

    private static bool LooksLikeUrlOrPathIdentityCarrier(string key, string value)
    {
        string k = key == null ? "" : key;
        string v = value == null ? "" : value;
        return Regex.IsMatch(k, @"(?i)(url|uri|endpoint|referer|referrer|callback|redirect|requesturi|request_uri|path|query)") ||
               v.IndexOf("%40", StringComparison.OrdinalIgnoreCase) >= 0 ||
               v.IndexOf("%2540", StringComparison.OrdinalIgnoreCase) >= 0 ||
               v.IndexOf("/api/", StringComparison.OrdinalIgnoreCase) >= 0 ||
               Regex.IsMatch(v, @"(?i)[?&](?:user|email|upn|login_hint|account|username|principal|session|sid)=");
    }

    private void DiscoverUrlSensitiveParts(string text, List<UlsDiscoveryRow> rows, string source, string sourcePathHash)
    {
        if (String.IsNullOrWhiteSpace(text)) return;

        if (text.IndexOf("%40", StringComparison.OrdinalIgnoreCase) >= 0 || text.IndexOf("%2540", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            foreach (Match m in UrlEncodedEmailRx.Matches(text))
            {
                string value = CleanValue(m.Value);
                if (!String.IsNullOrWhiteSpace(value)) AddIdentifier(rows, value, "PRINCIPAL", source, sourcePathHash, "url-encoded email/upn");
            }
        }

        if (text.IndexOf("/users", StringComparison.OrdinalIgnoreCase) >= 0 ||
            text.IndexOf("/api/", StringComparison.OrdinalIgnoreCase) >= 0 ||
            text.IndexOf("/people", StringComparison.OrdinalIgnoreCase) >= 0 ||
            text.IndexOf("/accounts", StringComparison.OrdinalIgnoreCase) >= 0 ||
            text.IndexOf("/principals", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            foreach (Match m in ApiUserPathRx.Matches(text))
            {
                string value = CleanValue(m.Groups["value"].Value);
                if (String.IsNullOrWhiteSpace(value) || value == "-" || IsLowSignalValue(value)) continue;
                string prefix = (value.IndexOf("@", StringComparison.Ordinal) >= 0 || value.IndexOf("%40", StringComparison.OrdinalIgnoreCase) >= 0 || value.IndexOf('.', StringComparison.Ordinal) >= 0) ? "PRINCIPAL" : "OBJECT";
                AddIdentifier(rows, value, prefix, source, sourcePathHash, "user/account API path");
            }
        }

        if (text.IndexOf("?", StringComparison.Ordinal) >= 0 || text.IndexOf("&", StringComparison.Ordinal) >= 0)
        {
            foreach (Match m in QueryIdentityRx.Matches(text))
            {
                string value = CleanValue(m.Groups["value"].Value);
                if (String.IsNullOrWhiteSpace(value) || value == "-" || IsLowSignalValue(value)) continue;
                AddIdentifier(rows, value, "PRINCIPAL", source, sourcePathHash, "identity query parameter");
            }
            foreach (Match m in QuerySessionRx.Matches(text))
            {
                string value = CleanValue(m.Groups["value"].Value);
                if (String.IsNullOrWhiteSpace(value) || value == "-" || IsLowSignalValue(value)) continue;
                AddIdentifier(rows, value, "OBJECT", source, sourcePathHash, "session query parameter");
            }
        }
    }

    private void DiscoverSecrets(string text, List<UlsDiscoveryRow> rows, string source, string sourcePathHash)
    {
        if (!SecretGateRx.IsMatch(text)) return;
        foreach (Match m in AuthSecretRx.Matches(text)) AddIdentifier(rows, m.Groups[1].Value, "SECRET", source, sourcePathHash, m.Value);
        foreach (Match m in KvSecretRx.Matches(text)) AddIdentifier(rows, m.Groups[1].Value, m.Value.IndexOf("api", StringComparison.OrdinalIgnoreCase) >= 0 ? "APIKEY" : "SECRET", source, sourcePathHash, m.Value);
        foreach (Match m in KnownKeyRx.Matches(text)) AddIdentifier(rows, m.Value, "APIKEY", source, sourcePathHash, m.Value);
        foreach (Match m in HighEntropySecretRx.Matches(text)) AddIdentifier(rows, m.Groups[1].Value, "SECRET", source, sourcePathHash, m.Value);
    }

    private string ConnectionHostPrefix(string host)
    {
        string h = CleanValue(host).Trim('[', ']');
        if (IsLowSignalValue(h)) return null;
        if (IsValidIpv4(h)) return "IP";
        if (h.IndexOf(':') >= 0) return "IP6";
        if (Regex.IsMatch(h, @"^[A-Za-z0-9][A-Za-z0-9_.-]{0,252}$")) return "DNS";
        return null;
    }

    private void DiscoverConnectionHosts(string text, List<UlsDiscoveryRow> rows, string source, string sourcePathHash)
    {
        if (text.IndexOf("://", StringComparison.Ordinal) < 0 && !Regex.IsMatch(text, @"(?i)\b(dhost|shost|cs-host|server|host|address|bootstrap\.servers|broker\.list|data source)\s*=")) return;
        foreach (Match m in UrlHostRx.Matches(text))
        {
            string host = CleanValue(m.Groups["host"].Value).Trim('[', ']');
            string prefix = ConnectionHostPrefix(host);
            if (prefix != null) AddIdentifier(rows, host, prefix, source, sourcePathHash, m.Value);
        }
        foreach (Match m in KeyHostRx.Matches(text))
        {
            string host = CleanValue(m.Groups["host"].Value);
            string prefix = ConnectionHostPrefix(host);
            if (prefix != null) AddIdentifier(rows, host, prefix, source, sourcePathHash, m.Value);
        }
    }

    private static bool ContainsIgnoreCase(string text, string value)
    {
        if (String.IsNullOrEmpty(text) || String.IsNullOrEmpty(value)) return false;
        return text.IndexOf(value, StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static bool IsUrlTerminator(char ch)
    {
        return Char.IsWhiteSpace(ch) || ch == '"' || ch == '\'' || ch == '<' || ch == '>' || ch == ')' || ch == '(' || ch == ',' || ch == ';' || ch == '|';
    }

    private void DiscoverUrlHostsFast(string text, List<UlsDiscoveryRow> rows, string source, string sourcePathHash)
    {
        if (String.IsNullOrEmpty(text)) return;
        int search = 0;
        while (search >= 0 && search < text.Length)
        {
            int scheme = text.IndexOf("://", search, StringComparison.Ordinal);
            if (scheme < 0) break;
            int start = scheme + 3;
            if (start >= text.Length) break;
            while (start < text.Length && text[start] == '/') start++;
            int end = start;
            while (end < text.Length && !IsUrlTerminator(text[end]) && text[end] != '/' && text[end] != '?' && text[end] != '#') end++;
            if (end <= start) { search = start + 1; continue; }
            string authority = text.Substring(start, end - start);
            int at = authority.LastIndexOf('@');
            if (at >= 0 && at < authority.Length - 1) authority = authority.Substring(at + 1);
            string host = authority;
            if (host.StartsWith("[", StringComparison.Ordinal))
            {
                int close = host.IndexOf(']');
                if (close > 0) host = host.Substring(1, close - 1);
            }
            else
            {
                int colon = host.IndexOf(':');
                if (colon > 0) host = host.Substring(0, colon);
            }
            host = CleanValue(host);
            string prefix = ConnectionHostPrefix(host);
            if (prefix != null) AddIdentifier(rows, host, prefix, source, sourcePathHash, "web access url host ://");
            search = end + 1;
        }
    }

    private void DiscoverShapes(string text, List<UlsDiscoveryRow> rows, string source, string sourcePathHash)
    {
        bool strict = String.Equals(_scrubPolicy, "Strict", StringComparison.OrdinalIgnoreCase);
        if (text.IndexOf("\\Users\\", StringComparison.OrdinalIgnoreCase) >= 0)
            foreach (Match m in UserProfilePathRx.Matches(text)) AddIdentifier(rows, m.Groups[1].Value, "PRINCIPAL", source, sourcePathHash, m.Value);
        if (text.IndexOf("S-1-", StringComparison.OrdinalIgnoreCase) >= 0)
            foreach (Match m in SidRx.Matches(text)) AddIdentifier(rows, m.Value, "SID", source, sourcePathHash, m.Value);
        if (text.IndexOf("@", StringComparison.Ordinal) >= 0)
            foreach (Match m in EmailRx.Matches(text)) AddIdentifier(rows, m.Value, "UNMAPPED_UPN", source, sourcePathHash, m.Value);
        foreach (Match m in Ipv4Rx.Matches(text)) AddIdentifier(rows, m.Value, "IP", source, sourcePathHash, LocalContext(text, m.Index, m.Length));
        foreach (Match m in MacRx.Matches(text)) AddIdentifier(rows, m.Value, "MAC", source, sourcePathHash, LocalContext(text, m.Index, m.Length));
        if (strict || HasStrongPrincipalContext(text))
            foreach (Match m in DomainUserRx.Matches(text)) AddIdentifier(rows, m.Value, "PRINCIPAL", source, sourcePathHash, LocalContext(text, m.Index, m.Length));
        if (strict || HasStrongNetworkContext(text))
            foreach (Match m in FqdnRx.Matches(text))
            {
                if (m.Index > 0 && text[m.Index - 1] == '@') continue;
                AddIdentifier(rows, m.Value, "DNS", source, sourcePathHash, LocalContext(text, m.Index, m.Length));
            }
        if (strict)
        {
            foreach (Match m in GuidRx.Matches(text)) AddIdentifier(rows, m.Value, "GUID", source, sourcePathHash, m.Value);
        }
        if (strict || Regex.IsMatch(text, @"(?i)\b(thumbprint|certificate|cert|sha1|sha256|md5|signature|secret|token|password|credential|api[_ -]?key)\b"))
            foreach (Match m in LongHexRx.Matches(text)) AddIdentifier(rows, m.Value, "CERT", source, sourcePathHash, text);
        if (text.IndexOf("eyJ", StringComparison.Ordinal) >= 0)
            foreach (Match m in JwtRx.Matches(text)) AddIdentifier(rows, m.Value, "JWT", source, sourcePathHash, m.Value);
        if (text.IndexOf("arn:", StringComparison.OrdinalIgnoreCase) >= 0)
            foreach (Match m in AwsArnRx.Matches(text)) AddIdentifier(rows, m.Value, "ARN", source, sourcePathHash, m.Value);
        foreach (Match m in AwsKeyRx.Matches(text)) AddIdentifier(rows, m.Value, "AWSKEY", source, sourcePathHash, m.Value);
        if (text.IndexOf("i-", StringComparison.OrdinalIgnoreCase) >= 0)
            foreach (Match m in InstanceRx.Matches(text)) AddIdentifier(rows, m.Value, "INSTANCE", source, sourcePathHash, m.Value);
        if (strict || Regex.IsMatch(text, @"(?i)\b(secret|token|password|credential|authorization|bearer|client[_ -]?secret|api[_ -]?key|private[_ -]?key|certificate|cert|thumbprint)\b"))
            foreach (Match m in Base64Rx.Matches(text)) AddIdentifier(rows, m.Value, "BLOB", source, sourcePathHash, text);
    }

    private void DiscoverRegistryLine(string line, List<UlsDiscoveryRow> rows, string source, string sourcePathHash, UlsDiscoveryResult result)
    {
        if (String.IsNullOrWhiteSpace(line)) return;
        string trimmed = line.Trim();
        if (trimmed.Length == 0 || trimmed[0] == '[' || trimmed.StartsWith("Windows Registry Editor", StringComparison.OrdinalIgnoreCase)) return;

        int eq = trimmed.IndexOf('=');
        if (eq < 0)
        {
            DiscoverText(trimmed, rows, source, sourcePathHash, result);
            return;
        }

        string name = trimmed.Substring(0, eq).Trim().Trim('"');
        string value = trimmed.Substring(eq + 1).Trim();
        if (String.IsNullOrWhiteSpace(value)) return;
        if (value.StartsWith("hex", StringComparison.OrdinalIgnoreCase) || value.StartsWith("dword:", StringComparison.OrdinalIgnoreCase) || value.StartsWith("qword:", StringComparison.OrdinalIgnoreCase))
        {
            if (Regex.IsMatch(name, @"(?i)(sid|tenant|device|enrollment|serial|imei|meid|user|upn|email|mail|account|password|secret|token|credential|key)"))
                DiscoverText(value, rows, source, sourcePathHash, result);
            return;
        }

        value = value.Trim('"').Replace("\\\\", "\\");
        bool sensitiveRegistryValue = Regex.IsMatch(name, @"(?i)(sid|tenant|device|enrollment|serial|imei|meid|user|upn|email|mail|account|principal|host|hostname|server|url|uri|endpoint|password|secret|token|credential|key|mac|ip)");
        if (IsLowSignalValue(value)) return;
        if ((IsDiagnosticBackslashPath(value) || IsKnownFileOrDiagnosticName(value)) && !sensitiveRegistryValue && !ContainsEmbeddedSensitiveValue(value)) return;
        if (sensitiveRegistryValue)
        {
            AddIdentifier(rows, value, PrefixForLabel(name, value), source, sourcePathHash, "registry value " + name);
        }
        if (sensitiveRegistryValue || ContainsEmbeddedSensitiveValue(value) || String.Equals(_scrubPolicy, "Strict", StringComparison.OrdinalIgnoreCase))
            DiscoverText(value, rows, source, sourcePathHash, result);
    }

    private void DiscoverHtmlLine(string line, List<UlsDiscoveryRow> rows, string source, string sourcePathHash, UlsDiscoveryResult result)
    {
        if (String.IsNullOrWhiteSpace(line)) return;
        if (Regex.IsMatch(line, @"(?i)<\s*(script|style|svg|path|canvas|meta|link)\b")) return;
        string visible = Regex.Replace(line, @"(?is)<[^>]+>", " ");
        visible = WebUtility.HtmlDecode(visible);
        if (String.IsNullOrWhiteSpace(visible)) return;
        foreach (Match m in Regex.Matches(visible, @"(?i)\b(?<label>serial\s*number|serial|imei|meid|device\s*name|computer\s*name|host\s*name|hostname|managed\s*device\s*name|user\s*principal\s*name|primary\s*user|upn|email(?:\s*address)?)\s+(?<value>[A-Za-z0-9._%+\-@:\\]{3,160})\b"))
        {
            AddIdentifier(rows, m.Groups["value"].Value, PrefixForLabel(m.Groups["label"].Value, m.Groups["value"].Value), source, sourcePathHash, "html visible label " + m.Groups["label"].Value);
        }
        DiscoverText(visible, rows, source, sourcePathHash, result);
        if (line.IndexOf("://", StringComparison.Ordinal) >= 0 && Regex.IsMatch(line, @"(?i)\b(?:href|src|action)\s*="))
            DiscoverConnectionHosts(line, rows, source, sourcePathHash);
    }

    private bool IsEventXmlFile(string path)
    {
        string ext = Path.GetExtension(path).ToLowerInvariant();
        if (ext != ".txt" && ext != ".log" && ext != ".log_" && ext != ".xml") return false;
        string name = Path.GetFileName(path);
        bool nameLooksRight = Regex.IsMatch(name, @"(?i)(^|\s)Events? .+ Events\.txt$|Microsoft-Windows-.+Events\.txt$|\.events\.txt$");
        string sample = "";
        try
        {
            char[] chars = new char[65536];
            using (StreamReader reader = new StreamReader(path, Encoding.UTF8, true, 65536))
            {
                int read = reader.Read(chars, 0, chars.Length);
                if (read > 0) sample = new string(chars, 0, read);
            }
        }
        catch { return nameLooksRight; }
        if (String.IsNullOrWhiteSpace(sample)) return nameLooksRight;
        try
        {
            if (!EventShapeRx.IsMatch(sample)) return false;
        }
        catch (RegexMatchTimeoutException)
        {
            return nameLooksRight;
        }
        return sample.IndexOf("<Channel>", StringComparison.OrdinalIgnoreCase) >= 0
            || nameLooksRight
            || sample.IndexOf("<EventID", StringComparison.OrdinalIgnoreCase) >= 0
            || sample.IndexOf("<EventData", StringComparison.OrdinalIgnoreCase) >= 0
            || Regex.IsMatch(sample, @"(?is)<Data\b[^>]*\bName\s*=\s*[""'][^""']+[""']");
    }

    private static bool IsConvertedEventXmlTextFile(string path)
    {
        string name = Path.GetFileName(path);
        return Regex.IsMatch(name ?? "", @"(?i)\.events\.txt$");
    }

    private static bool IsWebAccessProfile(string profileName)
    {
        return String.Equals(profileName, "WebAccess", StringComparison.OrdinalIgnoreCase);
    }

    private bool IsLowRiskEventKey(string key)
    {
        if (String.IsNullOrWhiteSpace(key)) return false;
        return Regex.IsMatch(key.Trim(), @"^(Provider|ProviderName|ProviderGuid|Guid|EventID|EventRecordID|RecordID|ProcessID|ThreadID|Version|Level|Task|Opcode|Keywords|Channel|RuleId|RuleID|FileHash|Fqbn|PolicyName|RuleName|FilePath|FullFilePath|TargetFilePath|SourceFilePath|ProcessName|Image|ImagePath|CommandLine|UtcTime|TimeCreated|Execution|Correlation|ActivityID|RelatedActivityID)$", RegexOptions.IgnoreCase);
    }

    private string EventPrefixForKey(string key, string value)
    {
        if (String.IsNullOrWhiteSpace(key) || String.IsNullOrWhiteSpace(value)) return null;
        string k = key.Trim();
        string v = CleanValue(value);
        bool sensitiveNumericIdentifier = IsSensitiveNumericIdentifierContext(k) && Regex.IsMatch(v, @"^\d{5,20}$");
        if (IsLowRiskEventKey(k) || (IsLowSignalValue(v) && !sensitiveNumericIdentifier) || IsWellKnownSid(v) || IsWellKnownWindowsPrincipal(v)) return null;
        if (Regex.IsMatch(k, @"(?i)(sid|security\s*userid|user\s*id|userid)$") || Regex.IsMatch(v, @"^S-1-\d+(?:-\d)+$")) return "SID";
        if (Regex.IsMatch(k, @"(?i)(computer|machine|workstation|hostname|host|server|device)(\s*name)?$")) return "COMPUTER";
        if (Regex.IsMatch(k, @"(?i)(ip|address|network\s*address|client\s*address|source\s*address|destination\s*address)")) return v.IndexOf(':') >= 0 ? "IP6" : "IP";
        if (Regex.IsMatch(k, @"(?i)(upn|email|mail|user|account|subject|target|caller|member|identity|principal|owner|enrolled)")) return v.EndsWith("$", StringComparison.Ordinal) ? "COMPUTER" : "PRINCIPAL";
        if (Regex.IsMatch(k, @"(?i)(tenant|organization|domain|realm)$")) return "X500";
        if (Regex.IsMatch(k, @"(?i)(serial|imei|meid)$")) return "COMPUTER";
        if (Regex.IsMatch(k, @"(?i)(mac|wifi|ethernet)") && MacRx.IsMatch(v)) return "MAC";
        if (Regex.IsMatch(k, @"(?i)(url|uri|endpoint)$")) return "URI";
        return null;
    }

    private void DiscoverEventMessage(string value, string reason, List<UlsDiscoveryRow> rows, string source, string sourcePathHash, UlsDiscoveryResult result)
    {
        string decoded = WebUtility.HtmlDecode(value ?? "");
        if (String.IsNullOrWhiteSpace(decoded)) return;
        DiscoverIntuneCompositeIdentityText(decoded, rows, source, sourcePathHash);
        bool fallbackDone = false;
        Action fallback = () => {
            if (fallbackDone) return;
            fallbackDone = true;
            DiscoverTextFallback(decoded, rows, source, sourcePathHash, result);
        };
        RunDetector(() => {
            if (decoded.IndexOf("\\Users\\", StringComparison.OrdinalIgnoreCase) >= 0)
                foreach (Match m in UserProfilePathRx.Matches(decoded)) AddIdentifier(rows, m.Groups[1].Value, "PRINCIPAL", source, sourcePathHash, reason);
        }, result, fallback);
        RunDetector(() => { foreach (Match m in SidRx.Matches(decoded)) AddIdentifier(rows, m.Value, "SID", source, sourcePathHash, reason); }, result, fallback);
        RunDetector(() => { foreach (Match m in EmailRx.Matches(decoded)) AddIdentifier(rows, m.Value, "UNMAPPED_UPN", source, sourcePathHash, reason); }, result, fallback);
        RunDetector(() => { foreach (Match m in Ipv4Rx.Matches(decoded)) AddIdentifier(rows, m.Value, "IP", source, sourcePathHash, reason + " " + LocalContext(decoded, m.Index, m.Length)); }, result, fallback);
        RunDetector(() => { DiscoverConnectionHosts(decoded, rows, source, sourcePathHash); }, result, fallback);
        RunDetector(() => { DiscoverSecrets(decoded, rows, source, sourcePathHash); }, result, fallback);
    }

    private void DiscoverEventFragment(string fragment, List<UlsDiscoveryRow> rows, string source, string sourcePathHash, UlsDiscoveryResult result)
    {
        bool fallbackDone = false;
        Action fallback = () => {
            if (fallbackDone) return;
            fallbackDone = true;
            DiscoverTextFallback(fragment, rows, source, sourcePathHash, result);
        };
        RunDetector(() => { foreach (Match m in ComputerElementRx.Matches(fragment)) AddIdentifier(rows, m.Groups["value"].Value, "COMPUTER", source, sourcePathHash, "Computer element"); }, result, fallback);
        RunDetector(() => { foreach (Match m in UserIdAttrRx.Matches(fragment)) AddIdentifier(rows, m.Groups["value"].Value, "SID", source, sourcePathHash, "Security UserID attribute"); }, result, fallback);
        RunDetector(() => { foreach (Match m in SidRx.Matches(fragment)) AddIdentifier(rows, m.Value, "SID", source, sourcePathHash, "event sid"); }, result, fallback);
        RunDetector(() => {
            foreach (Match m in EventDataRx.Matches(fragment))
            {
                string attrs = m.Groups["attrs"].Value;
                Match nameMatch = EventDataNameRx.Match(attrs);
                if (!nameMatch.Success) continue;
                string key = nameMatch.Groups["name"].Value;
                string value = m.Groups["value"].Value;
                string prefix = EventPrefixForKey(key, value);
                if (prefix != null) AddIdentifier(rows, value, prefix, source, sourcePathHash, key);
                if (Regex.IsMatch(key, @"(?i)(message|description|details|data|payload|xml|json|script|command|url|uri|path)"))
                    DiscoverEventMessage(value, key, rows, source, sourcePathHash, result);
            }
        }, result, fallback);
        RunDetector(() => {
            foreach (Match m in SensitiveElementRx.Matches(fragment))
            {
                string key = m.Groups["key"].Value;
                string value = m.Groups["value"].Value;
                string prefix = EventPrefixForKey(key, value);
                if (prefix != null) AddIdentifier(rows, value, prefix, source, sourcePathHash, key);
            }
        }, result, fallback);
    }

    private void DiscoverIntuneCompositeIdentityText(string text, List<UlsDiscoveryRow> rows, string source, string sourcePathHash)
    {
        if (String.IsNullOrWhiteSpace(text)) return;

        if (text.IndexOf("_Windows_", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            foreach (Match m in Regex.Matches(text, @"(?i)(?<![A-Za-z0-9_.-])(?<user>[A-Za-z][A-Za-z0-9._'-]{2,80})_Windows_\d{1,2}/\d{1,2}/\d{4}_\d{1,2}:\d{2}(?:\s*[AP]M)?(?![A-Za-z0-9_.-])"))
            {
                AddIdentifier(rows, m.Groups["user"].Value, "PRINCIPAL", source, sourcePathHash, "Intune enterprise device name user");
            }
        }

        if (text.IndexOf("IntuneWindowsAgent_Proxy_", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            foreach (Match m in Regex.Matches(text, @"(?i)\b(?<full>IntuneWindowsAgent_Proxy_(?<id>[A-Za-z][A-Za-z0-9-]{1,40}_[A-Za-z][A-Za-z0-9._-]{2,64})(?:\.txt)?)\b"))
            {
                AddIdentifier(rows, m.Groups["id"].Value, "PRINCIPAL", source, sourcePathHash, "Intune proxy identity file");
                AddIdentifier(rows, m.Groups["full"].Value, "PRINCIPAL", source, sourcePathHash, "Intune proxy identity file");
            }
        }

        if (text.IndexOf("DeviceHash_", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            foreach (Match m in Regex.Matches(text, @"(?i)\b(?<full>DeviceHash_(?<host>[A-Za-z0-9][A-Za-z0-9-]{4,31})(?:\.csv)?)\b"))
            {
                AddIdentifier(rows, m.Groups["host"].Value, "COMPUTER", source, sourcePathHash, "Intune DeviceHash filename host");
                AddIdentifier(rows, m.Groups["full"].Value, "COMPUTER", source, sourcePathHash, "Intune DeviceHash filename");
            }
        }

        if (text.IndexOf("_defaultuser0", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            foreach (Match m in Regex.Matches(text, @"(?i)\b(?<full>AP-(?<host>[A-Za-z0-9][A-Za-z0-9-]{4,31})_defaultuser0)\b"))
            {
                AddIdentifier(rows, m.Groups["host"].Value, "COMPUTER", source, sourcePathHash, "Autopilot defaultuser0 host");
                AddIdentifier(rows, m.Groups["full"].Value, "COMPUTER", source, sourcePathHash, "Autopilot defaultuser0 host");
            }
        }
    }

    private void DiscoverText(string text, List<UlsDiscoveryRow> rows, string source, string sourcePathHash, UlsDiscoveryResult result)
    {
        if (String.IsNullOrWhiteSpace(text)) return;
        DiscoverCustomRegexRules(text, rows, source, sourcePathHash, result);
        DiscoverIntuneCompositeIdentityText(text, rows, source, sourcePathHash);
        if (text.Length > 1048576)
        {
            DiscoverTextFallback(text, rows, source, sourcePathHash, result);
            return;
        }
        bool fallbackDone = false;
        Action fallback = () => {
            if (fallbackDone) return;
            fallbackDone = true;
            DiscoverTextFallback(text, rows, source, sourcePathHash, result);
        };
        RunDetector(() => { DiscoverProfileLabelRules(text, rows, source, sourcePathHash, result); }, result, fallback);
        RunDetector(() => { DiscoverLabels(text, rows, source, sourcePathHash); }, result, fallback);
        RunDetector(() => { DiscoverContextualComputerNames(text, rows, source, sourcePathHash); }, result, fallback);
        RunDetector(() => { DiscoverUrlSensitiveParts(text, rows, source, sourcePathHash); }, result, fallback);
        RunDetector(() => { DiscoverSecrets(text, rows, source, sourcePathHash); }, result, fallback);
        RunDetector(() => { DiscoverConnectionHosts(text, rows, source, sourcePathHash); }, result, fallback);
        RunDetector(() => { DiscoverShapes(text, rows, source, sourcePathHash); }, result, fallback);
    }

    private void DiscoverWebAccessLine(string line, List<UlsDiscoveryRow> rows, string source, string sourcePathHash, UlsDiscoveryResult result)
    {
        if (String.IsNullOrWhiteSpace(line)) return;
        string text = line;
        DiscoverCustomRegexRules(text, rows, source, sourcePathHash, result);
        DiscoverUrlSensitiveParts(text, rows, source, sourcePathHash);
        bool strict = String.Equals(_scrubPolicy, "Strict", StringComparison.OrdinalIgnoreCase);
        int firstSpace = text.IndexOf(' ');
        if (firstSpace > 0 && firstSpace <= 128)
        {
            string first = CleanValue(text.Substring(0, firstSpace));
            if (IsValidIpv4(first)) AddIdentifier(rows, first, "IP", source, sourcePathHash, "web access client ip");
            else if (first.IndexOf(':') >= 0 && first.Length <= 64) AddIdentifier(rows, first, "IP6", source, sourcePathHash, "web access client ip");
        }
        if (strict && text.IndexOf("://", StringComparison.Ordinal) >= 0) DiscoverUrlHostsFast(text, rows, source, sourcePathHash);
        if (text.IndexOf("@", StringComparison.Ordinal) >= 0)
            foreach (Match m in EmailRx.Matches(text)) AddIdentifier(rows, m.Value, "UNMAPPED_UPN", source, sourcePathHash, "web access email");
        if (text.IndexOf("S-1-", StringComparison.OrdinalIgnoreCase) >= 0)
            foreach (Match m in SidRx.Matches(text)) AddIdentifier(rows, m.Value, "SID", source, sourcePathHash, "web access sid");
        if (ContainsIgnoreCase(text, "password") || ContainsIgnoreCase(text, "passwd") || ContainsIgnoreCase(text, "pwd=") ||
            ContainsIgnoreCase(text, "secret") || ContainsIgnoreCase(text, "token") || ContainsIgnoreCase(text, "authorization") ||
            ContainsIgnoreCase(text, "bearer") || ContainsIgnoreCase(text, "api_key") || ContainsIgnoreCase(text, "apikey") ||
            ContainsIgnoreCase(text, "client_secret"))
            DiscoverSecrets(text, rows, source, sourcePathHash);
        if (ContainsIgnoreCase(text, "x-forwarded-for") || ContainsIgnoreCase(text, "forwarded") || ContainsIgnoreCase(text, "remote_addr"))
        {
            foreach (Match m in Ipv4Rx.Matches(text)) AddIdentifier(rows, m.Value, "IP", source, sourcePathHash, "web access forwarded ip");
        }
    }

    public UlsDiscoveryResult DiscoverFileRange(string path, string profileName, string source, string sourcePathHash, long startOffset, long endOffset)
    {
        UlsDiscoveryResult result = new UlsDiscoveryResult();
        List<UlsDiscoveryRow> rows = new List<UlsDiscoveryRow>();
        try
        {
            FileInfo info = new FileInfo(path);
            result.Files = 1;
            if (!info.Exists || info.Length <= 0)
            {
                result.Rows = rows.ToArray();
                return result;
            }

            long fileLength = info.Length;
            if (startOffset < 0) startOffset = 0;
            if (endOffset <= 0 || endOffset > fileLength) endOffset = fileLength;
            if (startOffset >= endOffset)
            {
                result.Rows = rows.ToArray();
                return result;
            }
            result.Bytes = endOffset - startOffset;

            bool convertedEventXmlText = IsConvertedEventXmlTextFile(path);
            if (IsEventXmlFile(path) && !convertedEventXmlText)
            {
                return DiscoverFile(path, profileName, source, sourcePathHash);
            }

            string ext = Path.GetExtension(path).ToLowerInvariant();
            bool regFile = String.Equals(ext, ".reg", StringComparison.OrdinalIgnoreCase);
            bool eventXmlLineFile = convertedEventXmlText;
            bool htmlFile = String.Equals(ext, ".html", StringComparison.OrdinalIgnoreCase) || String.Equals(ext, ".htm", StringComparison.OrdinalIgnoreCase);
            bool jsonFile = String.Equals(ext, ".json", StringComparison.OrdinalIgnoreCase) || String.Equals(ext, ".jsonl", StringComparison.OrdinalIgnoreCase) || String.Equals(ext, ".ndjson", StringComparison.OrdinalIgnoreCase);
            bool delimitedFile = startOffset == 0 && (String.Equals(ext, ".csv", StringComparison.OrdinalIgnoreCase) || String.Equals(ext, ".tsv", StringComparison.OrdinalIgnoreCase) || String.Equals(ext, ".psv", StringComparison.OrdinalIgnoreCase));
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 65536))
            {
                fs.Seek(startOffset, SeekOrigin.Begin);
                using (StreamReader reader = new StreamReader(fs, Encoding.UTF8, true, 16384))
                {
                    if (startOffset > 0) reader.ReadLine();
                    List<string> headers = null;
                    char delimiter = ',';
                    if (delimitedFile)
                    {
                        if (String.Equals(ext, ".tsv", StringComparison.OrdinalIgnoreCase)) delimiter = '\t';
                        else if (String.Equals(ext, ".psv", StringComparison.OrdinalIgnoreCase)) delimiter = '|';
                        string headerLine = reader.ReadLine();
                        result.Lines++;
                        headers = ParseDelimitedLine(headerLine, delimiter);
                    }
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        result.Lines++;
                        if (eventXmlLineFile)
                        {
                            if (line.IndexOf("<Event", StringComparison.OrdinalIgnoreCase) >= 0) DiscoverEventFragment(line, rows, source, sourcePathHash, result);
                        }
                        else if (regFile) DiscoverRegistryLine(line, rows, source, sourcePathHash, result);
                        else if (htmlFile) DiscoverHtmlLine(line, rows, source, sourcePathHash, result);
                        else if (IsWebAccessProfile(profileName)) DiscoverWebAccessLine(line, rows, source, sourcePathHash, result);
                        else if (jsonFile) DiscoverJsonLine(line, rows, source, sourcePathHash, result);
                        else if (headers != null)
                        {
                            List<string> values = ParseDelimitedLine(line, delimiter);
                            int count = Math.Min(headers.Count, values.Count);
                            for (int i = 0; i < count; i++) DiscoverStructuredValue(headers[i], values[i], rows, source, sourcePathHash, result);
                        }
                        else DiscoverText(line, rows, source, sourcePathHash, result);
                        if (fs.Position >= endOffset) break;
                    }
                }
            }
            result.Rows = rows.ToArray();
        }
        catch (RegexMatchTimeoutException ex)
        {
            result.TimeoutCount++;
            result.FallbackUsed = true;
            result.Error = "Regex timeout recovered: " + ex.Message;
            result.Rows = rows.ToArray();
        }
        catch (Exception ex)
        {
            result.Ok = false;
            result.Error = ex.Message;
            result.Rows = rows.ToArray();
        }
        return result;
    }

    public UlsDiscoveryResult DiscoverFile(string path, string profileName, string source, string sourcePathHash)
    {
        UlsDiscoveryResult result = new UlsDiscoveryResult();
        List<UlsDiscoveryRow> rows = new List<UlsDiscoveryRow>();
        try
        {
            FileInfo info = new FileInfo(path);
            result.Files = 1;
            result.Bytes = info.Exists ? info.Length : 0;
            if (!info.Exists || info.Length <= 0)
            {
                result.Rows = rows.ToArray();
                return result;
            }

            bool eventXml = IsEventXmlFile(path);
            if (eventXml)
            {
                string carry = "";
                int fragmentCount = 0;
                if (IsConvertedEventXmlTextFile(path))
                {
                    using (StreamReader reader = new StreamReader(path, Encoding.UTF8, true, 65536))
                    {
                        while (true)
                        {
                            string line = reader.ReadLine();
                            if (line == null) break;
                            if (line.IndexOf("<Event", StringComparison.OrdinalIgnoreCase) < 0) continue;
                            DiscoverEventFragment(line, rows, source, sourcePathHash, result);
                            fragmentCount++;
                        }
                    }
                }
                else
                {
                    char[] buffer = new char[65536];
                    using (StreamReader reader = new StreamReader(path, Encoding.UTF8, true, 65536))
                    {
                        while (true)
                        {
                            int read = reader.Read(buffer, 0, buffer.Length);
                            if (read <= 0) break;
                            string chunk = carry + new string(buffer, 0, read);
                            while (true)
                            {
                                Match m = null;
                                try { m = EventFragmentRx.Match(chunk); }
                                catch (RegexMatchTimeoutException)
                                {
                                    result.TimeoutCount++;
                                    result.FallbackUsed = true;
                                    DiscoverTextFallback(chunk, rows, source, sourcePathHash, result);
                                    chunk = "";
                                    break;
                                }
                                if (!m.Success) break;
                                DiscoverEventFragment(m.Value, rows, source, sourcePathHash, result);
                                fragmentCount++;
                                chunk = chunk.Substring(m.Index + m.Length);
                            }
                            if (chunk.Length > 1048576) chunk = chunk.Substring(chunk.Length - 1048576);
                            carry = chunk;
                        }
                    }
                }
                if (fragmentCount == 0 && carry.IndexOf("<Event", StringComparison.OrdinalIgnoreCase) >= 0)
                    DiscoverEventFragment(carry, rows, source, sourcePathHash, result);
            }
            else
            {
                string ext = Path.GetExtension(path).ToLowerInvariant();
                bool regFile = String.Equals(ext, ".reg", StringComparison.OrdinalIgnoreCase);
                bool htmlFile = String.Equals(ext, ".html", StringComparison.OrdinalIgnoreCase) || String.Equals(ext, ".htm", StringComparison.OrdinalIgnoreCase);
                bool jsonFile = String.Equals(ext, ".json", StringComparison.OrdinalIgnoreCase) || String.Equals(ext, ".jsonl", StringComparison.OrdinalIgnoreCase) || String.Equals(ext, ".ndjson", StringComparison.OrdinalIgnoreCase);
                bool delimitedFile = String.Equals(ext, ".csv", StringComparison.OrdinalIgnoreCase) || String.Equals(ext, ".tsv", StringComparison.OrdinalIgnoreCase) || String.Equals(ext, ".psv", StringComparison.OrdinalIgnoreCase);
                using (StreamReader reader = new StreamReader(path, Encoding.UTF8, true, 1048576))
                {
                    List<string> headers = null;
                    char delimiter = ',';
                    if (delimitedFile)
                    {
                        if (String.Equals(ext, ".tsv", StringComparison.OrdinalIgnoreCase)) delimiter = '\t';
                        else if (String.Equals(ext, ".psv", StringComparison.OrdinalIgnoreCase)) delimiter = '|';
                        string headerLine = reader.ReadLine();
                        result.Lines++;
                        headers = ParseDelimitedLine(headerLine, delimiter);
                    }
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        result.Lines++;
                        if (regFile) DiscoverRegistryLine(line, rows, source, sourcePathHash, result);
                        else if (htmlFile) DiscoverHtmlLine(line, rows, source, sourcePathHash, result);
                        else if (IsWebAccessProfile(profileName)) DiscoverWebAccessLine(line, rows, source, sourcePathHash, result);
                        else if (jsonFile) DiscoverJsonLine(line, rows, source, sourcePathHash, result);
                        else if (headers != null)
                        {
                            List<string> values = ParseDelimitedLine(line, delimiter);
                            int count = Math.Min(headers.Count, values.Count);
                            for (int i = 0; i < count; i++) DiscoverStructuredValue(headers[i], values[i], rows, source, sourcePathHash, result);
                        }
                        else DiscoverText(line, rows, source, sourcePathHash, result);
                    }
                }
            }
            result.Rows = rows.ToArray();
        }
        catch (RegexMatchTimeoutException ex)
        {
            result.TimeoutCount++;
            result.FallbackUsed = true;
            result.Error = "Regex timeout recovered: " + ex.Message;
            result.Rows = rows.ToArray();
        }
        catch (Exception ex)
        {
            result.Ok = false;
            result.Error = ex.Message;
            result.Rows = rows.ToArray();
        }
        return result;
    }
}
'@
}

function Initialize-UlsCSharpProcessingEngine {
    param([switch]$ThrowOnFailure)
    try {
        Initialize-UlsMapOnlyScrubberType
        $script:CSharpAvailable = $true
        $script:CSharpEngineVersion = 'UlsMapOnlyTextScrubberV20+UlsDiscoveryEngine'
        $script:CSharpFallbackReason = ''
        return $true
    }
    catch {
        $script:CSharpAvailable = $false
        $script:CSharpEngineVersion = ''
        $script:CSharpFallbackReason = $_.Exception.Message
        if ($ThrowOnFailure) { throw }
        return $false
    }
}

function Add-UlsCSharpRuntimeRules {
    param([Parameter(Mandatory)]$Engine)
    foreach ($rule in @($script:RuntimeLabelRules)) {
        if ($null -eq $rule -or $null -eq $rule.RegexObject) { continue }
        $prefix = if ($rule.Prefix) { [string]$rule.Prefix } else { 'OBJECT' }
        try { $Engine.AddLabelRegexRule([string]$rule.RegexObject.ToString(), $prefix) } catch { throw "CSharp label rule '$($rule.Name)' failed to load: $($_.Exception.Message)" }
    }
    foreach ($rule in @($script:RuntimeCustomRegexRules)) {
        if ($null -eq $rule -or [string]::IsNullOrWhiteSpace([string]$rule.Regex)) { continue }
        $prefix = if ($rule.Prefix) { [string]$rule.Prefix } else { 'OBJECT' }
        $captureGroup = 0
        try { $captureGroup = [int]$rule.CaptureGroup } catch { $captureGroup = 0 }
        try { $Engine.AddCustomRegexRule([string]$rule.Regex, $prefix, $captureGroup) } catch { throw "CSharp custom regex rule '$($rule.Name)' failed to load: $($_.Exception.Message)" }
    }
}

function Get-UlsRuntimeProfileByName {
    param([string]$ProfileName)
    $prof = Get-ScrubProfile -Name $ProfileName
    if ($prof) { return $prof }
    try {
        if ($script:CurrentProfile -and [string]$script:CurrentProfile.Name -ieq $ProfileName) { return $script:CurrentProfile }
    } catch { }
    return $null
}

function Test-UlsBuiltInProfileName {
    param([string]$ProfileName)
    return [bool](Get-ScrubProfile -Name $ProfileName)
}

function Invoke-UlsCSharpDiscoverFileBatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$BatchIndex,
        [Parameter(Mandatory)][string[]]$Files,
        [Parameter(Mandatory)][string]$ProfileName,
        [Parameter(Mandatory)][string]$Salt,
        [int]$HmacLength = 24,
        [ValidateSet('Strict','Balanced','Readable')][string]$ScrubPolicy = 'Balanced',
        [string[]]$AllowlistFile = @()
    )

    $script:Salt = $Salt
    $script:HmacLength = $HmacLength
    $script:ScrubPolicy = $ScrubPolicy
    $prof = Get-UlsRuntimeProfileByName -ProfileName $ProfileName
    if ($prof) { Initialize-ScrubProfileRuntime -Profile $prof -AllowlistFiles $AllowlistFile }
    [void](Initialize-UlsCSharpProcessingEngine -ThrowOnFailure)

    $engine = [UlsDiscoveryEngine]::new($Salt, $HmacLength, $ScrubPolicy)
    foreach ($domain in @($script:AllowedDomains)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$domain)) { $engine.AddAllowedDomain([string]$domain) }
    }
    Add-UlsCSharpRuntimeRules -Engine $engine

    $rows = New-Object System.Collections.Generic.List[object]
    $fileCount = 0
    $totalBytes = 0L
    foreach ($file in @($Files)) {
        if ([string]::IsNullOrWhiteSpace($file) -or -not (Test-Path -LiteralPath $file)) { continue }
        $fileCount++
        $name = [System.IO.Path]::GetFileName($file)
        $fileHash = Get-PathFingerprint -Path $file -Length 12
        $source = "Discovery:$name"
        try { $totalBytes += [int64](Get-Item -LiteralPath $file).Length } catch { }
        $result = $engine.DiscoverFile($file, $ProfileName, $source, $fileHash)
        if (-not $result.Ok) { throw ("CSharp discovery failed for {0}: {1}" -f $name, [string]$result.Error) }
        foreach ($row in @($result.Rows)) {
            [void]$rows.Add([pscustomobject]@{
                InputValue      = [string]$row.InputValue
                NormalizedValue = [string]$row.NormalizedValue
                Token           = [string]$row.Token
                TokenType       = [string]$row.TokenType
                Source          = [string]$row.Source
                SourcePathHash  = [string]$row.SourcePathHash
            })
        }
    }

    return [pscustomobject]@{
        BatchIndex = $BatchIndex
        Rows       = @($rows.ToArray())
        FileCount  = $fileCount
        Bytes      = $totalBytes
        Engine     = 'CSharp'
    }
}

function Invoke-UlsCSharpDiscoveryWorkerShard {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$WorkerId,
        [Parameter(Mandatory)][string[]]$Files,
        [Parameter(Mandatory)][string]$ProfileName,
        [Parameter(Mandatory)][string]$Salt,
        [int]$HmacLength = 24,
        [ValidateSet('Strict','Balanced','Readable')][string]$ScrubPolicy = 'Balanced',
        [string[]]$AllowlistFile = @()
    )

    function _WriteDiscoveryWorkerJson {
        param([Parameter(Mandatory)]$Message)
        try {
            $json = $Message | ConvertTo-Json -Compress -Depth 8
            [Console]::Out.WriteLine($json)
            [Console]::Out.Flush()
        }
        catch { }
    }

    try {
        $script:Salt = $Salt
        $script:HmacLength = $HmacLength
        $script:ScrubPolicy = $ScrubPolicy
        $prof = Get-UlsRuntimeProfileByName -ProfileName $ProfileName
        if ($prof) { Initialize-ScrubProfileRuntime -Profile $prof -AllowlistFiles $AllowlistFile }
        [void](Initialize-UlsCSharpProcessingEngine -ThrowOnFailure)

        $engine = [UlsDiscoveryEngine]::new($Salt, $HmacLength, $ScrubPolicy)
        foreach ($domain in @($script:AllowedDomains)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$domain)) { $engine.AddAllowedDomain([string]$domain) }
        }
        Add-UlsCSharpRuntimeRules -Engine $engine

        $validFiles = New-Object System.Collections.Generic.List[string]
        $totalBytes = 0L
        foreach ($file in @($Files)) {
            if ([string]::IsNullOrWhiteSpace($file) -or -not (Test-Path -LiteralPath $file)) { continue }
            [void]$validFiles.Add([string]$file)
            try { $totalBytes += [int64](Get-Item -LiteralPath $file).Length } catch { }
        }

        $fileCount = $validFiles.Count
        $doneBytes = 0L
        $fileIndex = 0
        $fallbackFiles = 0
        $timeoutCount = 0
        foreach ($file in @($validFiles.ToArray())) {
            $fileIndex++
            $name = [System.IO.Path]::GetFileName($file)
            $fileBytes = 0L
            try { $fileBytes = [int64](Get-Item -LiteralPath $file).Length } catch { }
            _WriteDiscoveryWorkerJson ([pscustomobject]@{
                type       = 'start'
                workerId   = $WorkerId
                fileIndex  = $fileIndex
                fileCount  = $fileCount
                filesDone  = ($fileIndex - 1)
                bytesDone  = $doneBytes
                bytesTotal = $totalBytes
                name       = $name
                fileBytes  = $fileBytes
            })

            $fileHash = Get-PathFingerprint -Path $file -Length 12
            $source = "Discovery:$name"
            $result = $engine.DiscoverFile($file, $ProfileName, $source, $fileHash)
            if (-not $result.Ok) { throw ("CSharp discovery failed for {0}: {1}" -f $name, [string]$result.Error) }
            if ([bool]$result.FallbackUsed) { $fallbackFiles++ }
            try { $timeoutCount += [int]$result.TimeoutCount } catch { }

            $rows = New-Object System.Collections.Generic.List[object]
            foreach ($row in @($result.Rows)) {
                [void]$rows.Add([pscustomobject]@{
                    InputValue      = [string]$row.InputValue
                    NormalizedValue = [string]$row.NormalizedValue
                    Token           = [string]$row.Token
                    TokenType       = [string]$row.TokenType
                    Source          = [string]$row.Source
                    SourcePathHash  = [string]$row.SourcePathHash
                })
            }

            $doneBytes += $fileBytes
            _WriteDiscoveryWorkerJson ([pscustomobject]@{
                type       = 'result'
                workerId   = $WorkerId
                fileIndex  = $fileIndex
                fileCount  = $fileCount
                filesDone  = $fileIndex
                bytesDone  = $doneBytes
                bytesTotal = $totalBytes
                name       = $name
                fileBytes  = $fileBytes
                rowCount   = $rows.Count
                fallbackUsed = [bool]$result.FallbackUsed
                timeoutCount = [int]$result.TimeoutCount
                rows       = @($rows.ToArray())
            })
        }

        _WriteDiscoveryWorkerJson ([pscustomobject]@{
            type       = 'done'
            workerId   = $WorkerId
            fileIndex  = $fileCount
            fileCount  = $fileCount
            filesDone  = $fileCount
            bytesDone  = $doneBytes
            bytesTotal = $totalBytes
            name       = 'Done'
            fallbackFiles = $fallbackFiles
            timeoutCount = $timeoutCount
        })
    }
    catch {
        _WriteDiscoveryWorkerJson ([pscustomobject]@{
            type     = 'error'
            workerId = $WorkerId
            message  = $_.Exception.Message
        })
    }
}

function New-UlsBalancedDiscoveryShards {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$InputPath,
        [int]$WorkerCount = 4
    )

    if ($WorkerCount -lt 1) { $WorkerCount = 1 }
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($path in @($InputPath)) {
        if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) { continue }
        $len = 0L
        try { $len = [int64](Get-Item -LiteralPath $path).Length } catch { $len = 0L }
        [void]$items.Add([pscustomobject]@{ Path = [string]$path; Length = $len; Name = [System.IO.Path]::GetFileName([string]$path) })
    }

    $workerCount = [Math]::Min($WorkerCount, [Math]::Max($items.Count, 1))
    $shards = New-Object System.Collections.Generic.List[object]
    for ($wi = 0; $wi -lt $workerCount; $wi++) {
        [void]$shards.Add([pscustomobject]@{
            WorkerId = $wi
            Files    = (New-Object System.Collections.Generic.List[string])
            Bytes    = [int64]0
            Count    = [int64]0
        })
    }

    foreach ($item in @($items.ToArray() | Sort-Object @{Expression='Length';Descending=$true}, @{Expression='Path';Descending=$false})) {
        $target = @($shards.ToArray() | Sort-Object @{Expression='Bytes';Descending=$false}, @{Expression='Count';Descending=$false}, @{Expression='WorkerId';Descending=$false} | Select-Object -First 1)[0]
        [void]$target.Files.Add([string]$item.Path)
        $target.Bytes = [int64]$target.Bytes + [int64]$item.Length
        $target.Count = [int64]$target.Count + 1
    }

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($shard in @($shards.ToArray())) {
        if ([int64]$shard.Count -le 0) { continue }
        [void]$out.Add([pscustomobject]@{
            WorkerId = [int]$shard.WorkerId
            Files    = [string[]]$shard.Files.ToArray()
            Bytes    = [int64]$shard.Bytes
            Count    = [int64]$shard.Count
        })
    }
    return @($out.ToArray())
}

function Initialize-UlsProcessLinePumpType {
    if ('UlsProcessLinePump' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Threading;

public sealed class UlsProcessLinePump
{
    public readonly ConcurrentQueue<string> OutputLines = new ConcurrentQueue<string>();
    public readonly ConcurrentQueue<string> ErrorLines = new ConcurrentQueue<string>();
    private Thread _outputThread;
    private Thread _errorThread;

    public void Start(Process process)
    {
        if (process == null) throw new ArgumentNullException("process");
        _outputThread = new Thread(() => ReadLoop(process.StandardOutput, OutputLines));
        _errorThread = new Thread(() => ReadLoop(process.StandardError, ErrorLines));
        _outputThread.IsBackground = true;
        _errorThread.IsBackground = true;
        _outputThread.Start();
        _errorThread.Start();
    }

    private static void ReadLoop(TextReader reader, ConcurrentQueue<string> queue)
    {
        try
        {
            string line;
            while ((line = reader.ReadLine()) != null)
            {
                queue.Enqueue(line);
            }
        }
        catch (Exception ex)
        {
            queue.Enqueue("line pump failed: " + ex.Message);
        }
    }
}
'@
}

function Invoke-UlsCSharpDiscoverFilesProcessPool {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$InputPath,
        [Parameter(Mandatory)][string]$ProfileName,
        [string[]]$AllowlistFile = @(),
        [ValidateSet('Strict','Balanced','Readable')][string]$ScrubPolicy = $script:ScrubPolicy,
        [int]$HmacLength = $script:HmacLength,
        [int]$ThrottleLimit = 4
    )

    if ($ThrottleLimit -lt 1) { $ThrottleLimit = 1 }
    $modulePath = Get-UlsCurrentModulePath
    $saltValue = Get-SessionSalt
    $paths = @($InputPath | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    $shards = @(New-UlsBalancedDiscoveryShards -InputPath ([string[]]$paths) -WorkerCount $ThrottleLimit)
    if ($shards.Count -eq 0) { return @() }
    Initialize-UlsProcessLinePumpType

    $totalBytes = 0L
    $totalFiles = 0L
    foreach ($shard in @($shards)) {
        $totalBytes += [int64]$shard.Bytes
        $totalFiles += [int64]$shard.Count
    }

    $allRows = New-Object System.Collections.Generic.List[object]
    $messages = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
    $errors = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
    $workers = New-Object System.Collections.Generic.List[object]
    $workerState = @{}
    $progressIdBase = 4600
    $startedUtc = [datetime]::UtcNow
    $lastProgress = [datetime]::UtcNow.AddSeconds(-10)
    $aggregateState = [pscustomobject]@{
        FilesDone       = 0L
        BytesDone       = 0L
        FallbackFiles   = 0L
        TimeoutCount    = 0L
        FallbackSamples = (New-Object System.Collections.Generic.List[string])
    }

    $hostExe = ''
    try { $hostExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName } catch { }
    if ([string]::IsNullOrWhiteSpace($hostExe) -or -not (Test-Path -LiteralPath $hostExe)) {
        $cmd = Get-Command pwsh -ErrorAction SilentlyContinue
        if (-not $cmd) { $cmd = Get-Command powershell.exe -ErrorAction SilentlyContinue }
        if ($cmd) { $hostExe = [string]$cmd.Source }
    }
    if ([string]::IsNullOrWhiteSpace($hostExe)) { throw "Could not locate PowerShell host for CSharp discovery process pool." }
    $executionPolicyArg = ''
    try {
        $isWindowsRuntime = $true
        $isWindowsVar = Get-Variable -Name IsWindows -Scope Global -ErrorAction SilentlyContinue
        if ($isWindowsVar) { $isWindowsRuntime = [bool]$isWindowsVar.Value }
        if ($isWindowsRuntime) { $executionPolicyArg = ' -ExecutionPolicy Bypass' }
    } catch { $executionPolicyArg = ' -ExecutionPolicy Bypass' }

    $childScript = @'
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
try {
    $payloadText = [Console]::In.ReadToEnd()
    $payload = $payloadText | ConvertFrom-Json
    Import-Module -Name ([string]$payload.ModulePath) -Force
    Invoke-UlsCSharpDiscoveryWorkerShard `
        -WorkerId ([int]$payload.WorkerId) `
        -Files ([string[]]$payload.Files) `
        -ProfileName ([string]$payload.ProfileName) `
        -Salt ([string]$payload.Salt) `
        -HmacLength ([int]$payload.HmacLength) `
        -ScrubPolicy ([string]$payload.ScrubPolicy) `
        -AllowlistFile ([string[]]$payload.AllowlistFile)
}
catch {
    $msg = [pscustomobject]@{ type = 'error'; workerId = -1; message = $_.Exception.Message }
    [Console]::Out.WriteLine(($msg | ConvertTo-Json -Compress -Depth 5))
    [Console]::Out.Flush()
    exit 1
}
'@
    $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($childScript))

    $writeProgress = {
        param([switch]$Force)
        $now = [datetime]::UtcNow
        if (-not $Force -and (($now - $lastProgress).TotalMilliseconds -lt 500)) { return }
        $lastProgress = $now

        $doneFiles = [int64]$aggregateState.FilesDone
        $doneBytes = [int64]$aggregateState.BytesDone
        $activeWorkers = 0
        $workerFilesDone = 0L
        foreach ($key in @($workerState.Keys)) {
            $st = $workerState[$key]
            if (-not [bool]$st.Done) { $activeWorkers++ }
            try { $workerFilesDone += [int64]$st.FilesDone } catch { }
        }
        if ($workerFilesDone -gt $doneFiles) { $doneFiles = $workerFilesDone }
        if ($doneBytes -gt $totalBytes) { $doneBytes = $totalBytes }
        if ($doneFiles -gt $totalFiles) { $doneFiles = $totalFiles }

        for ($wi = 0; $wi -lt $shards.Count; $wi++) {
            $st = $workerState[[string]$wi]
            if (-not $st) { continue }
            $pctWorker = -1
            if ([int64]$st.BytesTotal -gt 0) { $pctWorker = [Math]::Min(100, [Math]::Max(0, [int](([int64]$st.BytesDone / [double][int64]$st.BytesTotal) * 100))) }
            $name = [string]$st.Name
            if ($name.Length -gt 58) { $name = $name.Substring(0,55) + '...' }
            if ([bool]$st.Done) {
                $status = ("Done - shard {0} files, {1:N1}/{2:N1} MB" -f [int64]$st.FilesDone, ([int64]$st.BytesDone / 1MB), ([int64]$st.BytesTotal / 1MB))
            }
            else {
                $status = ("shard file {0}/{1} - {2} - {3:N1}/{4:N1} MB" -f [int64]$st.FileIndex, [int64]$st.FileCount, $name, ([int64]$st.BytesDone / 1MB), ([int64]$st.BytesTotal / 1MB))
            }
            try {
                if ($pctWorker -ge 0) { Write-Progress -Id ($progressIdBase + $wi + 1) -Activity ("Worker {0}" -f ($wi + 1)) -Status $status -PercentComplete $pctWorker }
                else { Write-Progress -Id ($progressIdBase + $wi + 1) -Activity ("Worker {0}" -f ($wi + 1)) -Status $status }
            } catch { }
        }

        $pct = -1
        if ($totalBytes -gt 0) { $pct = [Math]::Min(100, [Math]::Max(0, [int](($doneBytes / [double]$totalBytes) * 100))) }
        $elapsed = ''
        try { $elapsed = ("elapsed {0:hh\:mm\:ss}" -f ([datetime]::UtcNow - $startedUtc)) } catch { }
        $aggregate = ("files {0}/{1} | {2:N1}/{3:N1} MB | {4}" -f $doneFiles, $totalFiles, ($doneBytes / 1MB), ($totalBytes / 1MB), $elapsed)
        $activity = 'CSharp discovery'
        try {
            if ($pct -ge 0) { Write-Progress -Id $progressIdBase -Activity $activity -Status $aggregate -PercentComplete $pct }
            else { Write-Progress -Id $progressIdBase -Activity $activity -Status $aggregate }
        } catch { }
    }.GetNewClosure()

    $drainMessages = {
        foreach ($worker in @($workers.ToArray())) {
            $pump = $worker.Pump
            if ($null -eq $pump) { continue }
            $outLine = $null
            while ($pump.OutputLines.TryDequeue([ref]$outLine)) {
                if (-not [string]::IsNullOrWhiteSpace($outLine)) { $messages.Enqueue([string]$outLine) }
                $outLine = $null
            }
            $errLine = $null
            while ($pump.ErrorLines.TryDequeue([ref]$errLine)) {
                if (-not [string]::IsNullOrWhiteSpace($errLine)) { $errors.Enqueue(("worker {0}: {1}" -f ([int]$worker.WorkerId + 1), [string]$errLine)) }
                $errLine = $null
            }
        }
        while ($true) {
            $line = $null
            if (-not $messages.TryDequeue([ref]$line)) { break }
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            if ($line.TrimStart()[0] -ne '{') { continue }
            $msg = $null
            try { $msg = $line | ConvertFrom-Json -ErrorAction Stop } catch { continue }
            $wid = [string]([int]$msg.workerId)
            if (-not $workerState.ContainsKey($wid)) {
                if ([string]$msg.type -eq 'error') { $errors.Enqueue(("worker {0}: {1}" -f $wid, [string]$msg.message)) }
                continue
            }
            $st = $workerState[$wid]
            switch ([string]$msg.type) {
                'start' {
                    $st.FileIndex = [int64]$msg.fileIndex
                    $st.FileCount = [int64]$msg.fileCount
                    $st.FilesDone = [int64]$msg.filesDone
                    $st.BytesDone = [int64]$msg.bytesDone
                    $st.BytesTotal = [int64]$msg.bytesTotal
                    $st.Name = [string]$msg.name
                    $st.Done = $false
                }
                'result' {
                    foreach ($row in @($msg.rows)) {
                        if ($null -ne $row) { [void]$allRows.Add($row) }
                    }
                    $deltaBytes = 0L
                    try { $deltaBytes = [int64]$msg.fileBytes } catch { $deltaBytes = 0L }
                    if ($deltaBytes -le 0) {
                        try { $deltaBytes = [int64]$msg.bytesDone - [int64]$st.BytesDone } catch { $deltaBytes = 0L }
                    }
                    if ($deltaBytes -lt 0) { $deltaBytes = 0L }
                    $aggregateState.FilesDone = [int64]$aggregateState.FilesDone + 1
                    $aggregateState.BytesDone = [int64]$aggregateState.BytesDone + $deltaBytes
                    if ([bool]$msg.fallbackUsed) {
                        $aggregateState.FallbackFiles = [int64]$aggregateState.FallbackFiles + 1L
                        if ($aggregateState.FallbackSamples.Count -lt 6 -and -not [string]::IsNullOrWhiteSpace([string]$msg.name)) {
                            [void]$aggregateState.FallbackSamples.Add([string]$msg.name)
                        }
                    }
                    try { $aggregateState.TimeoutCount = [int64]$aggregateState.TimeoutCount + [int64]$msg.timeoutCount } catch { }
                    $st.FileIndex = [int64]$msg.fileIndex
                    $st.FileCount = [int64]$msg.fileCount
                    $st.FilesDone = [int64]$msg.filesDone
                    $st.BytesDone = [int64]$msg.bytesDone
                    $st.BytesTotal = [int64]$msg.bytesTotal
                    $st.Name = [string]$msg.name
                }
                'done' {
                    $missingFiles = 0L
                    $missingBytes = 0L
                    try { $missingFiles = [int64]$msg.filesDone - [int64]$st.FilesDone } catch { $missingFiles = 0L }
                    try { $missingBytes = [int64]$msg.bytesDone - [int64]$st.BytesDone } catch { $missingBytes = 0L }
                    if ($missingFiles -gt 0) { $aggregateState.FilesDone = [int64]$aggregateState.FilesDone + $missingFiles }
                    if ($missingBytes -gt 0) { $aggregateState.BytesDone = [int64]$aggregateState.BytesDone + $missingBytes }
                    $st.FileIndex = [int64]$msg.fileIndex
                    $st.FileCount = [int64]$msg.fileCount
                    $st.FilesDone = [int64]$msg.filesDone
                    $st.BytesDone = [int64]$msg.bytesDone
                    $st.BytesTotal = [int64]$msg.bytesTotal
                    $st.Name = 'Done'
                    $st.Done = $true
                }
                'error' {
                    $st.Error = [string]$msg.message
                    $st.Done = $true
                }
            }
        }
    }.GetNewClosure()

    try {
        foreach ($shard in @($shards)) {
            $wid = [int]$shard.WorkerId
            $workerState[[string]$wid] = [pscustomobject]@{
                WorkerId   = $wid
                FileIndex  = 0L
                FileCount  = [int64]$shard.Count
                FilesDone  = 0L
                BytesDone  = 0L
                BytesTotal = [int64]$shard.Bytes
                Name       = 'Starting'
                Done       = $false
                Error      = ''
            }

            $psi = [System.Diagnostics.ProcessStartInfo]::new()
            $psi.FileName = $hostExe
            $psi.Arguments = "-NoLogo -NoProfile -NonInteractive$executionPolicyArg -EncodedCommand $encodedCommand"
            $psi.UseShellExecute = $false
            $psi.RedirectStandardInput = $true
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.CreateNoWindow = $true

            $proc = [System.Diagnostics.Process]::new()
            $proc.StartInfo = $psi
            if (-not $proc.Start()) { throw "Failed to start CSharp discovery worker $($wid + 1)." }
            $pump = [UlsProcessLinePump]::new()
            $pump.Start($proc)

            $payload = [pscustomobject]@{
                ModulePath    = $modulePath
                WorkerId      = $wid
                Files         = [string[]]$shard.Files
                ProfileName   = $ProfileName
                Salt          = $saltValue
                HmacLength    = $HmacLength
                ScrubPolicy   = $ScrubPolicy
                AllowlistFile = [string[]]$AllowlistFile
            }
            $payloadJson = $payload | ConvertTo-Json -Compress -Depth 5
            $proc.StandardInput.Write($payloadJson)
            $proc.StandardInput.Close()

            [void]$workers.Add([pscustomobject]@{ Process = $proc; WorkerId = $wid; Pump = $pump })
        }

        & $writeProgress -Force
        while ($true) {
            & $drainMessages
            $running = @($workers.ToArray() | Where-Object { -not $_.Process.HasExited })
            & $writeProgress
            if ($running.Count -eq 0) { break }
            Start-Sleep -Milliseconds 100
        }
        & $drainMessages
        & $writeProgress -Force

        $workerErrors = New-Object System.Collections.Generic.List[string]
        foreach ($worker in @($workers.ToArray())) {
            $proc = $worker.Process
            try { $proc.WaitForExit() } catch { }
            $wid = [string]([int]$worker.WorkerId)
            $st = $workerState[$wid]
            if ($st -and -not [string]::IsNullOrWhiteSpace([string]$st.Error)) { [void]$workerErrors.Add(("worker {0}: {1}" -f ([int]$worker.WorkerId + 1), [string]$st.Error)) }
            if ($proc.ExitCode -ne 0) { [void]$workerErrors.Add(("worker {0} exited with code {1}" -f ([int]$worker.WorkerId + 1), $proc.ExitCode)) }
        }
        $stderrLine = $null
        while ($errors.TryDequeue([ref]$stderrLine)) {
            if (-not [string]::IsNullOrWhiteSpace($stderrLine)) { [void]$workerErrors.Add($stderrLine) }
        }
        if ($workerErrors.Count -gt 0) { throw ("CSharp process-pool discovery failed: {0}" -f ((@($workerErrors.ToArray()) | Select-Object -First 6) -join '; ')) }

        foreach ($key in @($workerState.Keys)) {
            $st = $workerState[$key]
            if ($st) {
                $st.FileIndex = [int64]$st.FileCount
                $st.FilesDone = [int64]$st.FileCount
                $st.BytesDone = [int64]$st.BytesTotal
                $st.Name = 'Done'
                $st.Done = $true
            }
        }
        $aggregateState.FilesDone = [int64]$totalFiles
        $aggregateState.BytesDone = [int64]$totalBytes
        & $writeProgress -Force
        if ([int64]$aggregateState.FallbackFiles -gt 0) {
            $sampleText = ''
            try { $sampleText = ((@($aggregateState.FallbackSamples.ToArray()) | Select-Object -First 6) -join ', ') } catch { }
            if (-not [string]::IsNullOrWhiteSpace($sampleText)) {
                Write-Warn ("CSharp discovery fallback used for {0} file(s), {1} regex timeout(s). First files: {2}" -f [int64]$aggregateState.FallbackFiles, [int64]$aggregateState.TimeoutCount, $sampleText)
            }
            else {
                Write-Warn ("CSharp discovery fallback used for {0} file(s), {1} regex timeout(s)." -f [int64]$aggregateState.FallbackFiles, [int64]$aggregateState.TimeoutCount)
            }
        }
        return @($allRows.ToArray() | Sort-Object SourcePathHash, Source, TokenType, NormalizedValue, InputValue)
    }
    finally {
        foreach ($worker in @($workers.ToArray())) {
            try {
                if ($worker.Process -and -not $worker.Process.HasExited) { $worker.Process.Kill() }
            } catch { }
            try { $worker.Process.Dispose() } catch { }
        }
        try { Write-Progress -Id $progressIdBase -Activity 'CSharp process-pool discovery' -Completed } catch { }
        for ($wi = 0; $wi -lt [Math]::Max($shards.Count, $ThrottleLimit); $wi++) {
            try { Write-Progress -Id ($progressIdBase + $wi + 1) -Activity ("Worker {0}" -f ($wi + 1)) -Completed } catch { }
        }
    }
}

function New-UlsLargeFileDiscoveryRanges {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [int]$ThrottleLimit = 4
    )
    $file = Get-Item -LiteralPath $InputPath -ErrorAction Stop
    $length = [int64]$file.Length
    $ranges = New-Object System.Collections.Generic.List[object]
    if ($length -le 0) { return @() }
    if ($ThrottleLimit -lt 1) { $ThrottleLimit = 1 }
    $targetChunk = [int64](64MB)
    if ($length -gt 0) {
        $dynamicChunk = [int64][Math]::Ceiling($length / [double]([Math]::Max($ThrottleLimit * 8, 1)))
        if ($dynamicChunk -gt $targetChunk) { $targetChunk = [Math]::Min([int64](256MB), $dynamicChunk) }
        if ($targetChunk -lt 8MB) { $targetChunk = [int64](8MB) }
    }
    $start = 0L
    $idx = 0
    while ($start -lt $length) {
        $end = [Math]::Min($length, $start + $targetChunk)
        [void]$ranges.Add([pscustomobject]@{
            Index = $idx
            Start = [int64]$start
            End   = [int64]$end
            Bytes = [int64]($end - $start)
            Name  = $file.Name
        })
        $idx++
        $start = $end
    }
    return @($ranges.ToArray())
}

function Invoke-UlsCSharpDiscoverRangeBatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$ProfileName,
        [Parameter(Mandatory)][string]$Salt,
        [int]$HmacLength = 24,
        [ValidateSet('Strict','Balanced','Readable')][string]$ScrubPolicy = 'Balanced',
        [string[]]$AllowlistFile = @(),
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$SourcePathHash,
        [Parameter(Mandatory)][long]$Start,
        [Parameter(Mandatory)][long]$End
    )
    $script:Salt = $Salt
    $script:HmacLength = $HmacLength
    $script:ScrubPolicy = $ScrubPolicy
    $prof = Get-UlsRuntimeProfileByName -ProfileName $ProfileName
    if ($prof) { Initialize-ScrubProfileRuntime -Profile $prof -AllowlistFiles $AllowlistFile }
    [void](Initialize-UlsCSharpProcessingEngine -ThrowOnFailure)

    $engine = [UlsDiscoveryEngine]::new($Salt, $HmacLength, $ScrubPolicy)
    foreach ($domain in @($script:AllowedDomains)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$domain)) { $engine.AddAllowedDomain([string]$domain) }
    }
    Add-UlsCSharpRuntimeRules -Engine $engine
    $result = $engine.DiscoverFileRange($InputPath, $ProfileName, $Source, $SourcePathHash, [int64]$Start, [int64]$End)
    if (-not $result.Ok) { throw ("CSharp discovery failed for {0}: {1}" -f ([System.IO.Path]::GetFileName($InputPath)), [string]$result.Error) }
    $outRows = New-Object System.Collections.Generic.List[object]
    foreach ($row in @($result.Rows)) {
        [void]$outRows.Add([pscustomobject]@{
            InputValue      = [string]$row.InputValue
            NormalizedValue = [string]$row.NormalizedValue
            Token           = [string]$row.Token
            TokenType       = [string]$row.TokenType
            Source          = [string]$row.Source
            SourcePathHash  = [string]$row.SourcePathHash
        })
    }
    return [pscustomobject]@{
        Rows         = @($outRows.ToArray())
        Bytes        = ([int64]$End - [int64]$Start)
        TimeoutCount = [int]$result.TimeoutCount
        FallbackUsed = [bool]$result.FallbackUsed
    }
}

function Invoke-UlsCSharpDiscoverLargeFileParallel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$ProfileName,
        [string[]]$AllowlistFile = @(),
        [ValidateSet('Strict','Balanced','Readable')][string]$ScrubPolicy = $script:ScrubPolicy,
        [int]$HmacLength = $script:HmacLength,
        [int]$ThrottleLimit = 4
    )
    if ($ThrottleLimit -lt 1) { $ThrottleLimit = 1 }
    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($InputPath)
    $file = Get-Item -LiteralPath $fullPath -ErrorAction Stop
    $ranges = @(New-UlsLargeFileDiscoveryRanges -InputPath $fullPath -ThrottleLimit $ThrottleLimit)
    if ($ranges.Count -eq 0) { return @() }

    $saltValue = Get-SessionSalt
    $script:Salt = $saltValue
    $script:HmacLength = $HmacLength
    $script:ScrubPolicy = $ScrubPolicy
    $prof = Get-UlsRuntimeProfileByName -ProfileName $ProfileName
    if ($prof) { Initialize-ScrubProfileRuntime -Profile $prof -AllowlistFiles $AllowlistFile }
    [void](Initialize-UlsCSharpProcessingEngine -ThrowOnFailure)
    $allowedDomainsForWorker = [string[]]@($script:AllowedDomains | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    $customRulesForWorker = @(
        foreach ($rule in @($script:RuntimeCustomRegexRules)) {
            if ($null -eq $rule) { continue }
            [pscustomobject]@{
                Regex        = [string]$rule.Regex
                Prefix       = [string]$rule.Prefix
                CaptureGroup = [int]$rule.CaptureGroup
            }
        }
    )
    $sourceName = [System.IO.Path]::GetFileName($fullPath)
    $source = "Discovery:$sourceName"
    $pathHash = Get-PathFingerprint -Path $fullPath -Length 12
    $rows = New-Object System.Collections.Generic.List[object]
    $cursor = 0

    $worker = {
        param($InputPath,$ProfileName,$Salt,$HmacLength,$ScrubPolicy,$AllowedDomains,$CustomRules,$Source,$SourcePathHash,$Start,$End)
        if (-not ('UlsDiscoveryEngine' -as [type])) {
            throw "CSharp discovery engine type is not loaded in the worker runspace."
        }
        $engine = [UlsDiscoveryEngine]::new([string]$Salt, [int]$HmacLength, [string]$ScrubPolicy)
        foreach ($domain in @($AllowedDomains)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$domain)) { $engine.AddAllowedDomain([string]$domain) }
        }
        foreach ($rule in @($CustomRules)) {
            if ($null -eq $rule -or [string]::IsNullOrWhiteSpace([string]$rule.Regex)) { continue }
            $prefix = if ([string]::IsNullOrWhiteSpace([string]$rule.Prefix)) { 'OBJECT' } else { [string]$rule.Prefix }
            $captureGroup = 0
            try { $captureGroup = [int]$rule.CaptureGroup } catch { $captureGroup = 0 }
            $engine.AddCustomRegexRule([string]$rule.Regex, $prefix, $captureGroup)
        }
        $result = $engine.DiscoverFileRange([string]$InputPath, [string]$ProfileName, [string]$Source, [string]$SourcePathHash, [int64]$Start, [int64]$End)
        if (-not $result.Ok) {
            throw ("CSharp discovery failed for {0} range {1}-{2}: {3}" -f ([System.IO.Path]::GetFileName([string]$InputPath)), [int64]$Start, [int64]$End, [string]$result.Error)
        }
        $outRows = New-Object System.Collections.Generic.List[object]
        foreach ($row in @($result.Rows)) {
            [void]$outRows.Add([pscustomobject]@{
                InputValue      = [string]$row.InputValue
                NormalizedValue = [string]$row.NormalizedValue
                Token           = [string]$row.Token
                TokenType       = [string]$row.TokenType
                Source          = [string]$row.Source
                SourcePathHash  = [string]$row.SourcePathHash
            })
        }
        return [pscustomobject]@{
            Rows         = @($outRows.ToArray())
            Bytes        = ([int64]$End - [int64]$Start)
            TimeoutCount = [int]$result.TimeoutCount
            FallbackUsed = [bool]$result.FallbackUsed
        }
    }
    $readBatch = {
        if ($cursor -ge $ranges.Count) { return $null }
        $range = $ranges[$cursor]
        Set-Variable -Name cursor -Scope 1 -Value ($cursor + 1)
        $argsList = @($fullPath,$ProfileName,$saltValue,$HmacLength,$ScrubPolicy,[string[]]$allowedDomainsForWorker,[object[]]$customRulesForWorker,$source,$pathHash,[int64]$range.Start,[int64]$range.End)
        return [pscustomobject]@{ Index=$range.Index; Args=[object[]]$argsList; Rows=0; Bytes=[int64]$range.Bytes; Name=$sourceName }
    }
    $fallbackRanges = 0
    $timeoutCount = 0
    $handle = {
        param($BatchResult)
        if ($null -eq $BatchResult) { return }
        foreach ($row in @($BatchResult.Rows)) { if ($null -ne $row) { [void]$rows.Add($row) } }
        if ([bool]$BatchResult.FallbackUsed) { Set-Variable -Name fallbackRanges -Scope 1 -Value ($fallbackRanges + 1) }
        try { Set-Variable -Name timeoutCount -Scope 1 -Value ($timeoutCount + [int]$BatchResult.TimeoutCount) } catch { }
    }

    $sw = New-UlsPerfStopwatch
    Invoke-UlsRunspaceBatchPool -WorkerScript $worker -ReadBatch $readBatch -HandleResult $handle -ThrottleLimit $ThrottleLimit -Activity ("CSharp large-file discovery {0}" -f $sourceName) -TotalBytes ([int64]$file.Length) -TotalRows 1 -ProgressIdBase 4700
    if ($fallbackRanges -gt 0) { Write-Warn ("CSharp large-file discovery fallback used for {0} range(s), {1} regex timeout(s)." -f $fallbackRanges, $timeoutCount) }
    Add-UlsPerfPhase -Phase 'CSharp large-file discovery' -Stopwatch $sw -File $sourceName -Rows $rows.Count -Notes ("ranges={0}; throttle={1}; bytes={2}" -f $ranges.Count,$ThrottleLimit,[int64]$file.Length)
    return @($rows.ToArray() | Sort-Object SourcePathHash, Source, TokenType, NormalizedValue, InputValue)
}

function Get-UlsCSharpMapOnlyScrubber {
    param([Parameter(Mandatory)][string]$TokenMapCsv)
    if (-not (Test-Path -LiteralPath $TokenMapCsv)) { throw "Token map not found: $TokenMapCsv" }
    [void](Initialize-UlsCSharpProcessingEngine -ThrowOnFailure)
    $resolved = (Resolve-Path -LiteralPath $TokenMapCsv).Path
    $cacheKey = Get-UlsTokenMapFileCacheKey -Path $resolved
    if ($script:CSharpMapOnlyScrubberCacheKey -eq $cacheKey -and $script:CSharpMapOnlyScrubber) {
        return [pscustomobject]@{ Scrubber = $script:CSharpMapOnlyScrubber; ValueCount = $script:CSharpMapOnlyScrubberEntryCount; CacheKey = $cacheKey }
    }

    $scrubber = [UlsMapOnlyTextScrubberV20]::new()
    $seen = @{}
    $count = 0
    foreach ($row in @(Import-Csv -LiteralPath $resolved)) {
        $inputCol = Get-MapColumnName -Row $row -Candidates @('InputValue','OriginalValue','Value','SourceValue')
        $tokenCol = Get-MapColumnName -Row $row -Candidates @('Token','OutputValue','TokenValue','ScrubbedValue')
        if (-not $inputCol -or -not $tokenCol) { continue }
        $raw = ([string]$row.$inputCol).Trim()
        $token = ([string]$row.$tokenCol).Trim()
        if ($raw.Length -lt 3 -or [string]::IsNullOrWhiteSpace($token) -or (Is-AlreadyToken -Value $raw) -or [string]::Equals($raw, $token, [System.StringComparison]::Ordinal)) { continue }
        $key = $raw.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $scrubber.Add($raw, $token)
        if ($token -match '^(?:PRINCIPAL|UNMAPPED_UPN|COMPUTER)_' -and $raw -match '^[A-Za-z0-9][A-Za-z0-9._''-]{2,80}$') {
            $scrubber.Add(($raw + '.'), ($token + '.'))
        }
        if ($token -match '^MAC_') {
            foreach ($macVariant in @(Get-UlsMacAddressVariants -Value $raw)) {
                if (-not [string]::IsNullOrWhiteSpace($macVariant)) { $scrubber.Add($macVariant, $token) }
            }
        }
        $count++
    }

    $script:CSharpMapOnlyScrubber = $scrubber
    $script:CSharpMapOnlyScrubberCacheKey = $cacheKey
    $script:CSharpMapOnlyScrubberEntryCount = $count
    return [pscustomobject]@{ Scrubber = $scrubber; ValueCount = $count; CacheKey = $cacheKey }
}

function Test-UlsCSharpScrubEligibility {
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)]$Profile,
        [Parameter(Mandatory)][string]$Format,
        [string]$TokenMapCsv,
        [switch]$DryRun,
        [switch]$ExplainDetections
    )
    if (-not $script:CSharpAvailable) { return [pscustomobject]@{ Eligible=$false; Reason=$script:CSharpFallbackReason } }
    if ($DryRun) { return [pscustomobject]@{ Eligible=$false; Reason='Dry-run explanation stays on PowerShell.' } }
    if ($ExplainDetections -or $script:FalsePositiveReport -or $script:DetectionSummaryReport) { return [pscustomobject]@{ Eligible=$false; Reason='Detection reports require the PowerShell detector trace.' } }
    if ([string]::IsNullOrWhiteSpace($TokenMapCsv) -or -not (Test-Path -LiteralPath $TokenMapCsv)) { return [pscustomobject]@{ Eligible=$false; Reason='CSharp scrub requires an existing token map.' } }
    if ($Format -notin @('Text','Kv','Csv','Tsv','Psv','Json')) { return [pscustomobject]@{ Eligible=$false; Reason="Format '$Format' is not eligible for map-only CSharp scrub." } }
    $ext = [System.IO.Path]::GetExtension($InputPath).ToLowerInvariant()
    try {
        $profileName = [string]$Profile.Name
        if ($profileName -ieq 'IntuneDiagnostics' -and $ext -notin @('.log','.txt','.reg','.html','.htm','.xml','.log_')) {
            return [pscustomobject]@{ Eligible=$false; Reason='IntuneDiagnostics CSharp scrub is limited to supported text/report extensions.' }
        }
    } catch { }
    return [pscustomobject]@{ Eligible=$true; Reason='Eligible for map-only CSharp scrub.' }
}

function Invoke-UlsCSharpMapOnlyScrubFile {
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][string]$TokenMapCsv,
        [string[]]$SensitiveTerms = @(),
        [string]$Format = 'Text',
        [switch]$Quiet
    )
    $outFull = Resolve-OutPath -Path $OutputPath
    $name = [System.IO.Path]::GetFileName($InputPath)
    if (-not $Quiet) { Write-Work ("CSharp scrub ({0}, map-only): {1}" -f $Format, $name) }
    $bundle = Get-UlsCSharpMapOnlyScrubber -TokenMapCsv $TokenMapCsv
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $result = $bundle.Scrubber.ScrubFile($InputPath, $outFull, 1048576)
    $sw.Stop()
    if (-not $result.Ok) {
        try { Remove-Item -LiteralPath $outFull -Force -ErrorAction SilentlyContinue } catch { }
        throw ([string]$result.Error)
    }
    Add-UlsPerfPhase -Phase 'CSharp scrub' -Seconds $sw.Elapsed.TotalSeconds -File $name -Rows ([int]$result.Rows) -Notes ("map entries={0}; replacements={1}; engineSeconds={2}" -f $result.MapEntries,$result.Replacements,$result.Seconds)
    if (-not $Quiet) {
        Write-Detail "Output: $([System.IO.Path]::GetFileName($outFull))"
    }
    return [pscustomobject]@{
        Input               = $InputPath
        Output              = $outFull
        Clean               = $true
        Rows                = [int64]$result.Rows
        Streamed            = $true
        Engine              = 'CSharp'
        Replacements        = [int64]$result.Replacements
        Bytes               = [int64]$result.Bytes
        OutputBytes         = [int64]$result.OutputBytes
        MapLoadCount        = 1
        Format              = $Format
    }
}

function Invoke-UlsCSharpScrubFileBatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$BatchIndex,
        [Parameter(Mandatory)][object[]]$Jobs,
        [Parameter(Mandatory)][string]$TokenMapCsv,
        [string[]]$SensitiveTerms = @(),
        [hashtable]$StatusTable = $null
    )
    $bundle = Get-UlsCSharpMapOnlyScrubber -TokenMapCsv $TokenMapCsv
    $results = New-Object System.Collections.Generic.List[object]
    $totalBytes = 0L
    foreach ($j in @($Jobs)) { try { $totalBytes += [int64]$j.Length } catch { } }
    $doneBytes = 0L
    $idx = 0
    foreach ($job in @($Jobs)) {
        $idx++
        $name = ''
        try { $name = [string]$job.Name } catch { $name = [System.IO.Path]::GetFileName([string]$job.InputPath) }
        if ($StatusTable) {
            $StatusTable[[string]$BatchIndex] = [pscustomobject]@{
                Worker     = ([int]$BatchIndex + 1)
                FileIndex  = $idx
                FileCount  = @($Jobs).Count
                FilesDone  = ($idx - 1)
                BytesDone  = $doneBytes
                BytesTotal = $totalBytes
                Name       = $name
                Done       = $false
                Error      = ''
            }
        }
        try {
            $outFull = Resolve-OutPath -Path ([string]$job.OutputPath)
            $r = $bundle.Scrubber.ScrubFile([string]$job.InputPath, $outFull, 1048576)
            if (-not $r.Ok) { throw ([string]$r.Error) }
            [void]$results.Add([pscustomobject]@{
                Input               = [string]$job.InputPath
                Output              = $outFull
                Clean               = $true
                Rows                = [int64]$r.Rows
                Streamed            = $true
                Engine              = 'CSharp'
                CSharpBatch         = $true
                MapLoadCount        = 1
                Format              = if ($job.Format) { [string]$job.Format } else { 'Text' }
                Bytes               = [int64]$r.Bytes
                OutputBytes         = [int64]$r.OutputBytes
                Replacements        = [int64]$r.Replacements
                Error               = $null
            })
        }
        catch {
            [void]$results.Add([pscustomobject]@{
                Input               = [string]$job.InputPath
                Output              = [string]$job.OutputPath
                Clean               = $false
                Rows                = 0
                Streamed            = $true
                Engine              = 'CSharp'
                CSharpBatch         = $true
                MapLoadCount        = 1
                Format              = if ($job.Format) { [string]$job.Format } else { 'Text' }
                Bytes               = [int64]$job.Length
                OutputBytes         = 0
                Replacements        = 0
                Error               = $_.Exception.Message
            })
        }
        try { $doneBytes += [int64]$job.Length } catch { }
        if ($StatusTable) {
            $StatusTable[[string]$BatchIndex] = [pscustomobject]@{
                Worker     = ([int]$BatchIndex + 1)
                FileIndex  = $idx
                FileCount  = @($Jobs).Count
                FilesDone  = $idx
                BytesDone  = $doneBytes
                BytesTotal = $totalBytes
                Name       = $name
                Done       = ($idx -ge @($Jobs).Count)
                Error      = ''
            }
        }
    }
    return [pscustomobject]@{ BatchIndex = $BatchIndex; Results = @($results.ToArray()); MapLoadCount = 1; Bytes = $doneBytes }
}

function Invoke-UlsCSharpScrubFilesParallel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Jobs,
        [Parameter(Mandatory)]$Profile,
        [Parameter(Mandatory)][string]$TokenMapCsv,
        [string[]]$SensitiveTerms = @(),
        [int]$ThrottleLimit = 4
    )

    if (-not $script:CSharpAvailable) {
        throw $script:CSharpFallbackReason
    }
    if (-not (Test-Path -LiteralPath $TokenMapCsv)) { throw "CSharp batch scrub requires an existing token map. Not found: $TokenMapCsv" }

    $jobList = @($Jobs | Where-Object { $_ -and $_.InputPath -and $_.OutputPath })
    if ($jobList.Count -eq 0) { return @() }
    if ($ThrottleLimit -lt 1) { $ThrottleLimit = 1 }
    $workerCount = [Math]::Min($ThrottleLimit, $jobList.Count)
    $modulePath = Get-UlsCurrentModulePath
    $tokenMapFull = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($TokenMapCsv)

    $buckets = New-Object System.Collections.Generic.List[object]
    for ($bi = 0; $bi -lt $workerCount; $bi++) {
        [void]$buckets.Add([pscustomobject]@{
            Index = $bi
            Jobs  = (New-Object System.Collections.Generic.List[object])
            Bytes = [int64]0
        })
    }
    foreach ($job in @($jobList | Sort-Object Length -Descending)) {
        $target = $buckets | Sort-Object Bytes | Select-Object -First 1
        [void]$target.Jobs.Add($job)
        try { $target.Bytes = [int64]$target.Bytes + [int64]$job.Length } catch { }
    }
    $batches = @($buckets | Where-Object { $_.Jobs.Count -gt 0 })
    $statusTable = [hashtable]::Synchronized(@{})
    foreach ($bucket in @($batches)) {
        $statusTable[[string]$bucket.Index] = [pscustomobject]@{
            Worker     = ([int]$bucket.Index + 1)
            FileIndex  = 0
            FileCount  = [int]$bucket.Jobs.Count
            FilesDone  = 0
            BytesDone  = 0L
            BytesTotal = [int64]$bucket.Bytes
            Name       = 'Queued'
            Done       = $false
            Error      = ''
        }
    }

    $cursor = 0
    $results = New-Object System.Collections.Generic.List[object]
    $totalBytes = 0L
    foreach ($j in $jobList) { try { $totalBytes += [int64]$j.Length } catch { } }

    $worker = {
        param($ModulePath,$BatchIndex,$Jobs,$TokenMapCsv,$SensitiveTerms,$StatusTable)
        if (-not (Get-Module -Name UniversalLogScrubber)) { Import-Module $ModulePath -Force }
        Invoke-UlsCSharpScrubFileBatch -BatchIndex $BatchIndex -Jobs ([object[]]$Jobs) -TokenMapCsv $TokenMapCsv -SensitiveTerms ([string[]]$SensitiveTerms) -StatusTable $StatusTable
    }
    $readBatch = {
        if ($cursor -ge $batches.Count) { return $null }
        $bucket = $batches[$cursor]
        Set-Variable -Name cursor -Scope 1 -Value ($cursor + 1)
        $jobsForWorker = @($bucket.Jobs.ToArray())
        $firstName = ''
        try { $firstName = [string]$jobsForWorker[0].Name } catch { }
        $argsList = @($modulePath,[int]$bucket.Index,[object[]]$jobsForWorker,$tokenMapFull,[string[]]$SensitiveTerms,$statusTable)
        return [pscustomobject]@{ Index=$bucket.Index; Args=[object[]]$argsList; Rows=$jobsForWorker.Count; Bytes=[int64]$bucket.Bytes; Name=$firstName }
    }
    $handle = {
        param($BatchResult)
        if ($null -eq $BatchResult) { return }
        foreach ($r in @($BatchResult.Results)) { [void]$results.Add($r) }
    }

    $sw = New-UlsPerfStopwatch
    Invoke-UlsRunspaceBatchPool -WorkerScript $worker -ReadBatch $readBatch -HandleResult $handle -ThrottleLimit $workerCount -Activity 'CSharp batch scrub' -TotalBytes $totalBytes -TotalRows $jobList.Count -WorkerStatus $statusTable -ProgressIdBase 4300
    Add-UlsPerfPhase -Phase 'CSharp scrub' -Stopwatch $sw -Rows $jobList.Count -Notes ("batch workers={0}; map loads={0}; files={1}" -f $workerCount,$jobList.Count)
    return @($results.ToArray())
}

function Invoke-UlsCSharpScrubIfSelected {
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)]$Profile,
        [Parameter(Mandatory)][string]$Format,
        [Parameter(Mandatory)][string]$TokenMapCsv,
        [string[]]$SensitiveTerms = @(),
        [switch]$DryRun,
        [switch]$ExplainDetections
    )
    $name = [System.IO.Path]::GetFileName($InputPath)
    $eligible = Test-UlsCSharpScrubEligibility -InputPath $InputPath -Profile $Profile -Format $Format -TokenMapCsv $TokenMapCsv -DryRun:$DryRun -ExplainDetections:$ExplainDetections
    if (-not $eligible.Eligible) { return $null }
    try {
        return Invoke-UlsCSharpMapOnlyScrubFile -InputPath $InputPath -OutputPath $OutputPath -TokenMapCsv $TokenMapCsv -SensitiveTerms $SensitiveTerms -Format $Format
    }
    catch {
        try { Remove-Item -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue } catch { }
        throw
    }
}

# =====================================================================
# REGION: JSON adapter (values only -- keys are preserved)
#   Walks a parsed JSON tree and tokenizes leaf STRING values through the same
#   Scrub-Field path as CSV cells (so the JSON key acts as the column hint).
#   Sensitive-key numeric values are tokenized conservatively; booleans / nulls
#   and all keys pass through unchanged.
# =====================================================================
function Get-JsonNodeIdentity {
    param($Node)
    if ($null -eq $Node) { return $null }
    if ($Node -is [string] -or $Node -is [bool] -or $Node -is [int] -or $Node -is [long] -or $Node -is [double] -or $Node -is [decimal] -or $Node -is [datetime] -or $Node -is [guid]) { return $null }
    try { return [string][System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($Node) } catch { return $null }
}

function Get-UniversalLogScrubberVersionInfo {
    $modulePath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($modulePath)) {
        try { if ($MyInvocation.MyCommand.Module -and $MyInvocation.MyCommand.Module.Path) { $modulePath = $MyInvocation.MyCommand.Module.Path } } catch { }
    }

    $manifestPath = Join-Path $PSScriptRoot 'UniversalLogScrubber.psd1'
    if (-not (Test-Path -LiteralPath $manifestPath)) { $manifestPath = $null }

    return [pscustomobject]@{
        Name              = $script:ModuleName
        Version           = $script:ModuleVersion
        ModulePath        = $modulePath
        ManifestPath      = $manifestPath
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        PSEdition         = $PSVersionTable.PSEdition
    }
}

function Test-JsonNumericNode {
    param($Node)
    return (
        $Node -is [byte] -or $Node -is [sbyte] -or
        $Node -is [System.Int16] -or $Node -is [System.UInt16] -or
        $Node -is [int] -or $Node -is [uint32] -or
        $Node -is [long] -or $Node -is [uint64] -or
        $Node -is [single] -or $Node -is [double] -or $Node -is [decimal]
    )
}

function Get-JsonSensitiveNumericPrefix {
    param([string]$KeyName)
    if ([string]::IsNullOrWhiteSpace($KeyName)) { return $null }

    $key = $KeyName.Trim()
    if ($key -match '(?i)(?:time|timestamp|date|duration|elapsed|latency|count|size|bytes|statuscode|httpstatus|eventid|port|pid|processid|threadid|row|line|version|ttl|retry|retries|attempt|attempts|year|month|day|hour|minute|second|milliseconds|seconds|ms)$') {
        return $null
    }
    if ($key -match '(?i)(^|[_\-.])(?:time|timestamp|date|duration|elapsed|latency|count|size|bytes|status|code|level|severity|eventid|event_id|port|pid|processid|threadid|row|line|version|httpstatus|http_status|ttl|retry|retries|attempt|attempts|year|month|day|hour|minute|second|ms|milliseconds|seconds)(?:$|[_\-.])') {
        return $null
    }
    if ($key -match '(?i)(secret|password|passwd|pwd|token|api[_-]?key|key[_-]?id|credential)') { return 'SECRET' }
    if ($key -match '(?i)(^|[_\-.])(?:ip|ipaddr|ipaddress|srcip|dstip|src_ip|dst_ip|source_ip|destination_ip|client_ip|remote_ip)(?:$|[_\-.])') { return 'IP' }
    if ($key -match '(?i)(host|hostname|server|machine|device|asset|node|instance|ip|address)') { return 'DNS' }
    if ($key -match '(?i)(user|account|principal|subject|actor|tenant|client|customer|owner|member|identity|person|employee)') { return 'PRINCIPAL' }
    if ($key -match '(?i)(session|object|request|correlation|trace|span|transaction|resource|target)') { return 'OBJECT' }
    return $null
}

function Invoke-JsonStringValueScrub {
    param(
        [string]$KeyName,
        [string]$Value,
        $Profile
    )

    $wholeRule = Get-MatchingProfileColumnRule -Profile $Profile -ColumnName $KeyName -RuleSet 'WholeColumnRules'
    if ($wholeRule) {
        return [string](Invoke-TokenizeWholeValue -ColumnName $KeyName -Value $Value -Prefix $wholeRule.Prefix -SplitOn $wholeRule.SplitOn)
    }

    $schemaRule = Get-MatchingProfileColumnRule -Profile $Profile -ColumnName $KeyName -RuleSet 'SchemaColumns'
    if ($schemaRule -and $schemaRule.Action -eq 'Scrub') {
        return [string](Invoke-TokenizeWholeValue -ColumnName $KeyName -Value $Value -Prefix $schemaRule.Prefix -SplitOn $schemaRule.SplitOn)
    }

    $scrubbed = [string](Scrub-Field -ColumnName $KeyName -Value $Value -Profile $Profile)
    if ($scrubbed -ne $Value -or (Is-AlreadyToken -Value $scrubbed)) { return $scrubbed }

    $fallbackPrefix = Get-JsonSensitiveNumericPrefix -KeyName $KeyName
    if ($fallbackPrefix -and -not (Test-ScrubAllowlist -Value $Value)) {
        return [string](Get-Token -Value $Value -Prefix $fallbackPrefix)
    }

    return $scrubbed
}

function Invoke-JsonSerializedKeyValueHardening {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)]$Profile,
        $Changes
    )

    if ([string]::IsNullOrEmpty($Text)) { return $Text }

    $stringPattern = '(?<prefix>"(?<key>[A-Za-z0-9_.-]+)"\s*:\s*)"(?<value>[^"\\]*(?:\\.[^"\\]*)*)"'
    $stringMatches = [System.Text.RegularExpressions.Regex]::Matches($Text, $stringPattern)
    if ($stringMatches.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        $lastIndex = 0
        foreach ($Match in $stringMatches) {
            if ($Match.Index -gt $lastIndex) { [void]$sb.Append($Text.Substring($lastIndex, $Match.Index - $lastIndex)) }
            $replacement = $Match.Value
            $key = $Match.Groups['key'].Value
            $value = $Match.Groups['value'].Value
            if (-not ([string]::IsNullOrWhiteSpace($key) -or [string]::IsNullOrWhiteSpace($value) -or (Is-AlreadyToken -Value $value))) {
                $scrubbed = Invoke-JsonStringValueScrub -KeyName $key -Value $value -Profile $Profile
                if ($scrubbed -ne $value) {
                    if ($null -ne $Changes) { [void]$Changes.Add([pscustomobject]@{ Field = $key; Original = $value; Token = $scrubbed }) }
                    $replacement = $Match.Groups['prefix'].Value + '"' + $scrubbed + '"'
                }
            }
            [void]$sb.Append($replacement)
            $lastIndex = $Match.Index + $Match.Length
        }
        if ($lastIndex -lt $Text.Length) { [void]$sb.Append($Text.Substring($lastIndex)) }
        $hardened = $sb.ToString()
    }
    else {
        $hardened = $Text
    }

    $numberPattern = '(?<prefix>"(?<key>[A-Za-z0-9_.-]+)"\s*:\s*)(?<value>-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)'
    $numberMatches = [System.Text.RegularExpressions.Regex]::Matches($hardened, $numberPattern)
    if ($numberMatches.Count -eq 0) { return $hardened }

    $sb = New-Object System.Text.StringBuilder
    $lastIndex = 0
    foreach ($Match in $numberMatches) {
        if ($Match.Index -gt $lastIndex) { [void]$sb.Append($hardened.Substring($lastIndex, $Match.Index - $lastIndex)) }
        $replacement = $Match.Value
        $key = $Match.Groups['key'].Value
        $value = $Match.Groups['value'].Value
        if (-not ([string]::IsNullOrWhiteSpace($key) -or [string]::IsNullOrWhiteSpace($value) -or (Is-AlreadyToken -Value $value))) {
            $prefix = Get-JsonSensitiveNumericPrefix -KeyName $key
            if ($prefix) {
                $token = Get-Token -Value $value -Prefix $prefix
                if ($token -ne $value) {
                    if ($null -ne $Changes) { [void]$Changes.Add([pscustomobject]@{ Field = $key; Original = $value; Token = $token }) }
                    $replacement = $Match.Groups['prefix'].Value + '"' + $token + '"'
                }
            }
        }
        [void]$sb.Append($replacement)
        $lastIndex = $Match.Index + $Match.Length
    }
    if ($lastIndex -lt $hardened.Length) { [void]$sb.Append($hardened.Substring($lastIndex)) }

    return $sb.ToString()
}

function Invoke-JsonNodeScrub {
    param(
        $Node,
        $Profile,
        [string]$KeyName = '',
        $Changes,
        [int]$Depth = 0,
        [int]$MaxDepth = 80,
        $Seen
    )
    if ($null -eq $Seen) { $Seen = @{} }
    if ($Depth -ge $MaxDepth) {
        $marker = '[SCRUB_JSON_MAX_DEPTH_EXCEEDED]'
        if ($null -ne $Changes) { [void]$Changes.Add([pscustomobject]@{ Field = $KeyName; Original = '(json depth limit)'; Token = $marker }) }
        return $marker
    }
    if ($null -eq $Node) { return $null }
    if ($Node -is [string]) {
        $s = Invoke-JsonStringValueScrub -KeyName $KeyName -Value $Node -Profile $Profile
        if (($null -ne $Changes) -and ($s -ne $Node)) { [void]$Changes.Add([pscustomobject]@{ Field = $KeyName; Original = $Node; Token = $s }) }
        return $s
    }
    if (Test-JsonNumericNode -Node $Node) {
        $numericPrefix = Get-JsonSensitiveNumericPrefix -KeyName $KeyName
        if ($numericPrefix) {
            $rawNumber = [System.Convert]::ToString($Node, [System.Globalization.CultureInfo]::InvariantCulture)
            $token = Get-Token -Value $rawNumber -Prefix $numericPrefix
            if (($null -ne $Changes) -and ($token -ne $rawNumber)) { [void]$Changes.Add([pscustomobject]@{ Field = $KeyName; Original = $rawNumber; Token = $token }) }
            return $token
        }
        return $Node
    }
    if ($Node -is [bool] -or $Node -is [datetime] -or $Node -is [guid]) { return $Node }

    $id = Get-JsonNodeIdentity -Node $Node
    if ($id -and $Seen.ContainsKey($id)) {
        $marker = '[SCRUB_JSON_CYCLIC_REFERENCE]'
        if ($null -ne $Changes) { [void]$Changes.Add([pscustomobject]@{ Field = $KeyName; Original = '(json cycle)'; Token = $marker }) }
        return $marker
    }
    if ($id) { $Seen[$id] = $true }

    try {
        if ($Node -is [System.Collections.IDictionary]) {
            $newMap = [ordered]@{}
            foreach ($k in @($Node.Keys)) {
                $childKey = [string]$k
                $newMap[$childKey] = Invoke-JsonNodeScrub -Node $Node[$k] -Profile $Profile -KeyName $childKey -Changes $Changes -Depth ($Depth + 1) -MaxDepth $MaxDepth -Seen $Seen
            }
            return [pscustomobject]$newMap
        }

        $props = @()
        if ($Node.PSObject) { $props = @($Node.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' }) }
        if ($props.Count -gt 0) {
            $new = [ordered]@{}
            foreach ($p in $props) {
                $new[$p.Name] = Invoke-JsonNodeScrub -Node $p.Value -Profile $Profile -KeyName $p.Name -Changes $Changes -Depth ($Depth + 1) -MaxDepth $MaxDepth -Seen $Seen
            }
            return [pscustomobject]$new
        }

        if (($Node -is [System.Collections.IEnumerable]) -and -not ($Node -is [string])) {
            $arr = New-Object System.Collections.Generic.List[object]
            foreach ($item in $Node) {
                [void]$arr.Add((Invoke-JsonNodeScrub -Node $item -Profile $Profile -KeyName $KeyName -Changes $Changes -Depth ($Depth + 1) -MaxDepth $MaxDepth -Seen $Seen))
            }
            return ,@($arr.ToArray())
        }
        return $Node
    }
    finally {
        if ($id) { [void]$Seen.Remove($id) }
    }
}

function Invoke-ScrubJsonText {
    param(
        [Parameter(Mandatory)][string]$Text,
        [switch]$IsNdjson,
        [Parameter(Mandatory)]$Profile,
        $Changes,
        [int]$MaxDepth = 80
    )
    if ($null -eq $Changes) { $Changes = New-Object System.Collections.Generic.List[object] }
    $jsonDepth = [Math]::Min([Math]::Max($MaxDepth, 2), 100)
    if ($IsNdjson) {
        # One JSON object per line (NDJSON / JSON Lines).
        $sb = New-Object System.Text.StringBuilder
        foreach ($line in ($Text -split '\r?\n')) {
            $trim = $line.Trim().TrimStart([char]0xFEFF)
            if ($trim -eq '') { continue }
            try {
                $obj = $trim | ConvertFrom-Json -ErrorAction Stop
                $scrubbed = Invoke-JsonNodeScrub -Node $obj -Profile $Profile -KeyName '' -Changes $Changes -MaxDepth $MaxDepth -Seen @{}
                $lineOut = $scrubbed | ConvertTo-Json -Depth $jsonDepth -Compress
                $lineOut = Invoke-JsonSerializedKeyValueHardening -Text $lineOut -Profile $Profile -Changes $Changes
                [void]$sb.AppendLine($lineOut)
            }
            catch { [void]$sb.AppendLine((Invoke-LeakHardeningText -Text $line)) }
        }
        return $sb.ToString()
    }
    try {
        $jsonText = ([string]$Text).TrimStart([char]0xFEFF)
        $obj = $jsonText | ConvertFrom-Json -ErrorAction Stop
        $scrubbed = Invoke-JsonNodeScrub -Node $obj -Profile $Profile -KeyName '' -Changes $Changes -MaxDepth $MaxDepth -Seen @{}
        $jsonOut = $scrubbed | ConvertTo-Json -Depth $jsonDepth
        return (Invoke-JsonSerializedKeyValueHardening -Text $jsonOut -Profile $Profile -Changes $Changes)
    }
    catch {
        Write-Warn "Not valid JSON or JSON scrub failed; falling back to whole-text hardening. $($_.Exception.Message)"
        return (Invoke-LeakHardeningText -Text $Text)
    }
}

# =====================================================================
# REGION: Dry-run preview (report-only, writes nothing)
# =====================================================================
function Get-TokenKind {
    param([string]$Token)
    # Long values are whole scrubbed free-text cells (a message with embedded
    # tokens), not a single token -- group them together and skip the regex
    # (which would backtrack badly on a long string).
    if ([string]::IsNullOrEmpty($Token)) { return '(blank)' }
    if ($Token.Length -gt 80) { return '(free-text)' }
    if ($Token -match '^(.*)_[A-F0-9]{4,}$') { return $matches[1] }
    return $Token
}

function Write-DryRunSummary {
    param([Parameter(Mandatory)][string]$Name, $Changes)
    # Wrapped so a summary hiccup can never crash the (read-only) preview.
    try {
        $items = New-Object System.Collections.Generic.List[object]
        if ($Changes) {
            foreach ($change in $Changes) {
                if ($null -ne $change) { [void]$items.Add($change) }
            }
        }
        $list = @($items.ToArray())
        Write-Host ""
        Write-Status -Tag INFO -Message "DRY RUN -- $Name : $($list.Count) distinct value(s) would be tokenized."
        if ($list.Count -eq 0) { return }
        # Count by token kind manually (avoids Group-Object/Sort-Object edge cases).
        $counts = @{}
        foreach ($c in $list) {
            $kind = [string](Get-TokenKind ([string]$c.Token))
            if ($counts.ContainsKey($kind)) { $counts[$kind] = [int]$counts[$kind] + 1 } else { $counts[$kind] = 1 }
        }
        Write-Detail "By token type:"
        foreach ($kind in (@($counts.Keys) | Sort-Object { $counts[$_] } -Descending)) {
            Write-Detail ("  {0,-22} {1}" -f $kind, $counts[$kind])
        }
        $sample = @($list | Select-Object -First 12)
        Write-Detail "Examples (original -> token):"
        foreach ($c in $sample) {
            $orig = [string]$c.Original
            if ($orig.Length -gt 40) { $orig = $orig.Substring(0, 37) + "..." }
            $tok = [string]$c.Token
            if ($tok.Length -gt 60) { $tok = $tok.Substring(0, 57) + "..." }
            Write-Detail ("  {0,-42} -> {1}" -f $orig, $tok)
        }
        if ($list.Count -gt $sample.Count) { Write-Detail ("  ... and {0} more" -f ($list.Count - $sample.Count)) }
        $traceItems = New-Object System.Collections.Generic.List[object]
        if ($script:DetectionTrace) {
            foreach ($trace in $script:DetectionTrace) {
                if ($null -ne $trace) { [void]$traceItems.Add($trace) }
            }
        }
        $highKinds = @('SECRET','APIKEY','CONNSTR','PEM','JWT','AWSKEY','ARN','IP','IP6','SID','GUID','MAC','UNMAPPED_UPN','EMAIL')
        $high = 0; $review = 0
        foreach ($c in $list) {
            $kind = [string](Get-TokenKind ([string]$c.Token))
            if ($highKinds -contains $kind) { $high++ } else { $review++ }
        }
        $preserved = @($traceItems.ToArray() | Where-Object { $_.Action -eq 'Preserved' }).Count
        Write-Detail "Review guide:"
        Write-Detail ("  High confidence tokenizations: {0}" -f $high)
        Write-Detail ("  Review for context/readability: {0}" -f $review)
        Write-Detail ("  Preserved by allowlist/diagnostic rules: {0}" -f $preserved)
        if ($script:ExplainDetections -and $traceItems.Count -gt 0) {
            Write-Detail "Detection decisions:"
            foreach ($d in (@($traceItems.ToArray()) | Select-Object -First 20)) {
                $val = [string]$d.Value
                if ($val.Length -gt 34) { $val = $val.Substring(0, 31) + "..." }
                Write-Detail ("  {0,-12} {1,-10} {2,-14} {3}" -f $d.Action, $d.Detector, $d.Reason, $val)
            }
            if ($traceItems.Count -gt 20) { Write-Detail ("  ... and {0} more detection decisions" -f ($traceItems.Count - 20)) }
        }
        if ($script:DetectionCounts -and $script:DetectionCounts.Count -gt 0) {
            Write-Detail "Detector counts:"
            foreach ($k in ($script:DetectionCounts.Keys | Sort-Object)) {
                Write-Detail ("  {0,-42} {1}" -f $k, $script:DetectionCounts[$k])
            }
        }
    }
    catch {
        Write-Detail "(preview summary detail unavailable: $($_.Exception.Message))"
    }
}

function Initialize-UlsCSharpEventLogConverterType {
    if ('UlsEventLogTextConverter' -as [type]) { return $true }
    if (-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
        throw "Windows event log conversion requires Windows."
    }
    $source = @'
using System;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;

public sealed class UlsEventLogTextConvertResult
{
    public bool Ok = true;
    public string Error = "";
    public long Events = 0;
    public long OutputBytes = 0;
    public double Seconds = 0;
}

public static class UlsEventLogTextConverter
{
    private static string EscapeXml(string value)
    {
        if (String.IsNullOrEmpty(value)) return "";
        return value.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;").Replace("'", "&apos;");
    }

    public static UlsEventLogTextConvertResult ConvertToEventXmlText(string inputPath, string outputPath)
    {
        var result = new UlsEventLogTextConvertResult();
        var sw = Stopwatch.StartNew();
        try
        {
            string dir = Path.GetDirectoryName(outputPath);
            if (!String.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var query = new EventLogQuery(inputPath, PathType.FilePath);
            query.ReverseDirection = false;
            using (var reader = new EventLogReader(query))
            using (var writer = new StreamWriter(outputPath, false))
            {
                EventRecord record;
                while ((record = reader.ReadEvent()) != null)
                {
                    using (record)
                    {
                        string xml = "";
                        try { xml = record.ToXml(); } catch { xml = ""; }
                        if (String.IsNullOrWhiteSpace(xml)) continue;
                        writer.WriteLine(xml);
                        result.Events++;
                    }
                }
            }
            if (File.Exists(outputPath)) result.OutputBytes = new FileInfo(outputPath).Length;
        }
        catch (Exception ex)
        {
            result.Ok = false;
            result.Error = ex.Message;
            try { if (File.Exists(outputPath)) File.Delete(outputPath); } catch { }
        }
        finally
        {
            sw.Stop();
            result.Seconds = Math.Max(sw.Elapsed.TotalSeconds, 0.000001);
        }
        return result;
    }
}
'@
    try {
        $refs = New-Object System.Collections.Generic.List[string]
        try { Add-Type -AssemblyName System.Diagnostics.EventLog -ErrorAction SilentlyContinue } catch { }
        try {
            $eventLogAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
                Where-Object { $_.GetName().Name -eq 'System.Diagnostics.EventLog' } |
                Select-Object -First 1
            if ($eventLogAssembly -and -not [string]::IsNullOrWhiteSpace([string]$eventLogAssembly.Location)) {
                [void]$refs.Add([string]$eventLogAssembly.Location)
            }
        } catch { }
        if ($refs.Count -eq 0) {
            $candidateRefs = @(
                (Join-Path $PSHOME 'System.Diagnostics.EventLog.dll'),
                (Join-Path $PSHOME 'ref\System.Diagnostics.EventLog.dll')
            )
            foreach ($candidateRef in $candidateRefs) {
                if (Test-Path -LiteralPath $candidateRef) {
                    [void]$refs.Add($candidateRef)
                    break
                }
            }
        }
        try {
            Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop | Out-Null
            return $true
        }
        catch {
            if ($refs.Count -eq 0) { throw }
            $addTypeArgs = @{
                TypeDefinition        = $source
                Language              = 'CSharp'
                ErrorAction           = 'Stop'
                ReferencedAssemblies  = [string[]]$refs.ToArray()
            }
            Add-Type @addTypeArgs | Out-Null
        }
        return $true
    }
    catch {
        throw "C# EventLogReader converter could not be initialized: $($_.Exception.Message)"
    }
}

function ConvertFrom-EventLogToEventXmlText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$OutText,
        [Parameter(Mandatory)][string]$InputKind
    )
    if (-not (Test-Path -LiteralPath $InputPath)) { throw "$InputKind not found: $InputPath" }
    [void](Initialize-UlsCSharpEventLogConverterType)
    $out = Resolve-OutPath -Path $OutText
    $name = [System.IO.Path]::GetFileName($InputPath)
    Write-Work "Converting $InputKind -> event XML: $name"
    $sw = New-UlsPerfStopwatch
    $result = [UlsEventLogTextConverter]::ConvertToEventXmlText($InputPath, $out)
    if (-not $result.Ok) { throw "$InputKind conversion failed: $($result.Error)" }
    Add-UlsPerfPhase -Phase 'Convert event log' -Stopwatch $sw -File $name -Rows ([int64]$result.Events) -Notes ("{0}; outputBytes={1}; engineSeconds={2}" -f $InputKind, [int64]$result.OutputBytes, [double]$result.Seconds)
    Write-Ok "$InputKind converted: $out  ($([int64]$result.Events) events)"
    return $out
}

function ConvertFrom-EvtxToEventXmlText {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$EvtxPath, [Parameter(Mandatory)][string]$OutText)
    return ConvertFrom-EventLogToEventXmlText -InputPath $EvtxPath -OutText $OutText -InputKind 'EVTX'
}

function ConvertFrom-EtlToEventXmlText {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$EtlPath, [Parameter(Mandatory)][string]$OutText)
    return ConvertFrom-EventLogToEventXmlText -InputPath $EtlPath -OutText $OutText -InputKind 'ETL'
}

# =====================================================================
# REGION: Bring-your-own profile (JSON / PSD1)
# =====================================================================
function ConvertTo-CustomRegexRules {
    param($Rules)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rules)) {
        if ($null -eq $r) { continue }
        $name = if ($r.Name) { [string]$r.Name } elseif ($r.Id) { [string]$r.Id } else { 'CustomRegex' }
        $pat = if ($r.Regex) { [string]$r.Regex } elseif ($r.Pattern) { [string]$r.Pattern } else { $null }
        if ([string]::IsNullOrWhiteSpace($pat)) { throw "CustomRegexRules '$name' requires Regex." }
        $prefixRaw = if ($r.Prefix) { [string]$r.Prefix } else { 'SECRET' }
        $prefix = Resolve-ProfileTokenPrefix -Prefix $prefixRaw -Context "CustomRegexRules '$name'"
        $group = 0
        if ($r.CaptureGroup) { $group = [int]$r.CaptureGroup }
        elseif ($r.SecretGroup) { $group = [int]$r.SecretGroup }
        $allowExact = @{}
        if ($r.Allowlist) { foreach ($a in @($r.Allowlist)) { if ($a) { $allowExact[([string]$a).Trim().ToLowerInvariant()] = $true } } }
        if ($r.Stopwords) { foreach ($a in @($r.Stopwords)) { if ($a) { $allowExact[([string]$a).Trim().ToLowerInvariant()] = $true } } }
        $allowRegex = @()
        if ($r.AllowlistRegex) { foreach ($a in @($r.AllowlistRegex)) { if ($a) { $allowRegex += (New-ScrubRegex -Pattern ([string]$a) -Context "custom regex allowlist '$name'") } } }
        [void]$out.Add([pscustomobject]@{
            Name = $name
            Prefix = $prefix
            Regex = $pat
            RegexObject = (New-ScrubRegex -Pattern $pat -Context "custom regex rule '$name'")
            CaptureGroup = $group
            Keywords = if ($r.Keywords) { @($r.Keywords) } else { @() }
            Entropy = if ($r.Entropy) { [double]$r.Entropy } else { $null }
            AllowExact = $allowExact
            AllowRegex = @($allowRegex)
            Description = if ($r.Description) { [string]$r.Description } else { '' }
        })
    }
    return @($out.ToArray())
}

function Initialize-ScrubProfileRuntime {
    param($Profile, [string[]]$AllowlistFiles = @())
    if (-not $Profile) { return }
    $script:CurrentProfile = $Profile
    $extraAllowed = @()
    try { if ($Profile.AllowedDomains) { $extraAllowed = @($Profile.AllowedDomains) } } catch { }
    $script:AllowedDomains = @($script:AllowedDomainsDefault + $extraAllowed)
    $script:RuntimeAllowExact = @{}
    $script:RuntimeAllowRegex = @()
    foreach ($entry in @($Profile.Allowlist)) { Add-AllowlistEntry -Entry $entry -BasePath $Profile.ProfileRoot }
    $profileAllowFiles = @()
    try { if ($Profile.AllowlistFile) { $profileAllowFiles += @($Profile.AllowlistFile) } } catch { }
    try { if ($Profile.AllowlistFiles) { $profileAllowFiles += @($Profile.AllowlistFiles) } } catch { }
    foreach ($file in @($profileAllowFiles + $AllowlistFiles)) {
        if ([string]::IsNullOrWhiteSpace($file)) { continue }
        foreach ($entry in (Read-ScrubListFile -Path $file -BasePath $Profile.ProfileRoot)) { Add-AllowlistEntry -Entry $entry -BasePath $Profile.ProfileRoot }
    }
    $labelRules = New-Object System.Collections.Generic.List[object]
    foreach ($rule in (Get-DefaultUniversalLabelRules)) { [void]$labelRules.Add((ConvertTo-UniversalLabelRule -Rule $rule -Context 'default label rule')) }
    foreach ($rule in @($Profile.LabelRules)) {
        if ($null -eq $rule) { continue }
        [void]$labelRules.Add((ConvertTo-UniversalLabelRule -Rule $rule -Context 'profile LabelRules'))
    }
    foreach ($label in @($script:AdditionalBroadLabels)) {
        if ([string]::IsNullOrWhiteSpace($label)) { continue }
        [void]$labelRules.Add((ConvertTo-UniversalLabelRule -Rule ([pscustomobject]@{ Name="Additional:$label"; Labels=@($label); Prefix='OBJECT' }) -Context 'additional label'))
    }
    $script:RuntimeLabelRules = @($labelRules.ToArray())
    $script:RuntimeCustomRegexRules = if ($Profile.CustomRegexRules) { @(ConvertTo-CustomRegexRules -Rules $Profile.CustomRegexRules) } else { @() }
}

function Import-ScrubProfileFile {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { throw "Profile file not found: $Path" }
    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    $raw = if ($ext -eq '.psd1') { Import-PowerShellDataFile -Path $Path } else { (Get-Content -Path $Path -Raw) | ConvertFrom-Json }
    if (-not $raw) { throw "Profile file is empty or invalid: $Path" }
    $name = if ($raw.Name) { [string]$raw.Name } else { [System.IO.Path]::GetFileNameWithoutExtension($Path) }
    $protection = Get-UlsObjectPropertyValue -Object $raw -Name 'Protection' -Default $null
    Assert-UlsProfileProtectionContext -Protection $protection -Context "Profile '$name'"
    $validFormats = @('Auto','Csv','Tsv','Psv','Text','Json','Kv')
    $fmt = if ($raw.Format) { [string]$raw.Format } else { 'Auto' }
    if (@($validFormats | Where-Object { $_ -ieq $fmt }).Count -eq 0) { throw "Invalid profile Format '$fmt'. Expected one of: $($validFormats -join ', ')." }
    $cp = @()
    if ($raw.ColumnPrefix) {
        foreach ($r in @($raw.ColumnPrefix)) {
            $pat = [string]$r.Pattern
            $pre = [string]$r.Prefix
            if ([string]::IsNullOrWhiteSpace($pat)) { throw "Invalid profile ColumnPrefix entry: Pattern is required." }
            try { [void][regex]::new($pat) } catch { throw "Invalid profile ColumnPrefix regex '$pat': $($_.Exception.Message)" }
            $pre = Resolve-ProfileTokenPrefix -Prefix $pre -Context 'ColumnPrefix'
            $cp += @{ Pattern = $pat; Prefix = $pre; NotOid = [bool]$r.NotOid; DollarComputer = [bool]$r.DollarComputer }
        }
    }
    if ($raw.PassThroughRegex) { [void](New-ScrubRegex -Pattern ([string]$raw.PassThroughRegex) -Context 'PassThroughRegex') }
    if ($raw.FreeTextRegex) { [void](New-ScrubRegex -Pattern ([string]$raw.FreeTextRegex) -Context 'FreeTextRegex') }
    $schemaColumns = ConvertTo-ProfileColumnRules -Rules $raw.SchemaColumns -DefaultAction 'Scan' -DefaultPrefix 'OBJECT' -Context 'SchemaColumns'
    $wholeColumnRules = ConvertTo-ProfileColumnRules -Rules $raw.WholeColumnRules -DefaultAction 'Scrub' -DefaultPrefix 'OBJECT' -Context 'WholeColumnRules'
    $customRegexRules = ConvertTo-CustomRegexRules -Rules $raw.CustomRegexRules
    $prof = [pscustomobject]@{
        Name             = $name
        Description      = if ($raw.Description) { [string]$raw.Description } else { "Custom profile ($name)" }
        SchemaVersion    = if ($raw.SchemaVersion) { [int]$raw.SchemaVersion } else { 1 }
        Protection       = $protection
        Format           = $fmt
        Delimiter        = if ($raw.Delimiter) { [string]$raw.Delimiter } else { ',' }
        PassThroughRegex = if ($raw.PassThroughRegex) { [string]$raw.PassThroughRegex } else { $null }
        ColumnPrefix     = $cp
        FreeTextRegex    = if ($raw.FreeTextRegex) { [string]$raw.FreeTextRegex } else { '.*' }
        DenyByDefault    = if ($null -ne $raw.DenyByDefault) { [bool]$raw.DenyByDefault } else { $true }
        AllowedDomains   = if ($raw.AllowedDomains) { @($raw.AllowedDomains) } else { @() }
        SchemaColumns    = @($schemaColumns)
        WholeColumnRules = @($wholeColumnRules)
        LabelRules       = if ($raw.LabelRules) { @($raw.LabelRules) } else { @() }
        CustomRegexRules = @($customRegexRules)
        Allowlist        = if ($raw.Allowlist) { @($raw.Allowlist) } else { @() }
        AllowlistFile    = if ($raw.AllowlistFile) { @($raw.AllowlistFile) } else { @() }
        AllowlistFiles   = if ($raw.AllowlistFiles) { @($raw.AllowlistFiles) } else { @() }
        SeedTerms        = if ($raw.SeedTerms) { @($raw.SeedTerms) } else { @() }
        SeedFiles        = if ($raw.SeedFiles) { @($raw.SeedFiles) } else { @() }
        ProfileRoot      = Split-Path -Parent (Resolve-Path -LiteralPath $Path).Path
    }
    Write-Ok "Loaded custom profile '$($prof.Name)' from $([System.IO.Path]::GetFileName($Path))"
    return $prof
}

function Get-UlsObjectPropertyArray {
    param($Object, [string]$Name)
    if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($Name)) { return @() }
    try {
        if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($Name) -and $null -ne $Object[$Name]) {
            return @($Object[$Name])
        }
    } catch { }
    try {
        $prop = $Object.PSObject.Properties[$Name]
        if ($prop -and $null -ne $prop.Value) { return @($prop.Value) }
    } catch { }
    return @()
}

function Get-UlsObjectPropertyValue {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($Name)) { return $Default }
    try {
        if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($Name) -and $null -ne $Object[$Name]) {
            return $Object[$Name]
        }
    } catch { }
    try {
        $prop = $Object.PSObject.Properties[$Name]
        if ($prop -and $null -ne $prop.Value) { return $prop.Value }
    } catch { }
    return $Default
}

function Resolve-UlsProfileRelativePath {
    param([string]$Path, [string]$BasePath)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    if ([System.IO.Path]::IsPathRooted($Path) -or [string]::IsNullOrWhiteSpace($BasePath)) { return $Path }
    return (Join-Path $BasePath $Path)
}

function ConvertTo-UlsProfilePathList {
    param($Values, [string]$BasePath)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($v in @($Values)) {
        $s = ([string]$v).Trim()
        if ($s) { [void]$out.Add((Resolve-UlsProfileRelativePath -Path $s -BasePath $BasePath)) }
    }
    return @($out.ToArray())
}

function ConvertTo-UlsColumnPrefixRules {
    param($Rules, [string]$Context = 'profile extension ColumnPrefix')
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rules)) {
        if ($null -eq $r) { continue }
        $pat = [string](Get-UlsObjectPropertyValue -Object $r -Name 'Pattern')
        $pre = [string](Get-UlsObjectPropertyValue -Object $r -Name 'Prefix')
        if ([string]::IsNullOrWhiteSpace($pat)) { throw "$Context entry requires Pattern." }
        try { [void][regex]::new($pat) } catch { throw "Invalid $Context regex '$pat': $($_.Exception.Message)" }
        $prefix = Resolve-ProfileTokenPrefix -Prefix $pre -Context $Context
        [void]$out.Add(@{
            Pattern = $pat
            Prefix = $prefix
            NotOid = [bool](Get-UlsObjectPropertyValue -Object $r -Name 'NotOid' -Default $false)
            DollarComputer = [bool](Get-UlsObjectPropertyValue -Object $r -Name 'DollarComputer' -Default $false)
        })
    }
    return @($out.ToArray())
}

function Import-ScrubProfileExtensionFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Profile extension file not found: $Path" }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $root = Split-Path -Parent $resolved
    $ext = [System.IO.Path]::GetExtension($resolved).ToLowerInvariant()
    $raw = if ($ext -eq '.psd1') { Import-PowerShellDataFile -Path $resolved } else { (Get-Content -LiteralPath $resolved -Raw) | ConvertFrom-Json }
    if (-not $raw) { throw "Profile extension file is empty or invalid: $Path" }

    $name = [string](Get-UlsObjectPropertyValue -Object $raw -Name 'Name' -Default ([System.IO.Path]::GetFileNameWithoutExtension($resolved)))
    $schemaColumns = ConvertTo-ProfileColumnRules -Rules (Get-UlsObjectPropertyArray -Object $raw -Name 'SchemaColumns') -DefaultAction 'Scan' -DefaultPrefix 'OBJECT' -Context "profile extension '$name' SchemaColumns"
    $wholeColumnRules = ConvertTo-ProfileColumnRules -Rules (Get-UlsObjectPropertyArray -Object $raw -Name 'WholeColumnRules') -DefaultAction 'Scrub' -DefaultPrefix 'OBJECT' -Context "profile extension '$name' WholeColumnRules"
    $customRegexRules = ConvertTo-CustomRegexRules -Rules (Get-UlsObjectPropertyArray -Object $raw -Name 'CustomRegexRules')
    $allowlistFiles = @()
    $allowlistFiles += ConvertTo-UlsProfilePathList -Values (Get-UlsObjectPropertyArray -Object $raw -Name 'AllowlistFile') -BasePath $root
    $allowlistFiles += ConvertTo-UlsProfilePathList -Values (Get-UlsObjectPropertyArray -Object $raw -Name 'AllowlistFiles') -BasePath $root
    $seedFiles = ConvertTo-UlsProfilePathList -Values (Get-UlsObjectPropertyArray -Object $raw -Name 'SeedFiles') -BasePath $root

    return [pscustomobject]@{
        Name             = $name
        Description      = [string](Get-UlsObjectPropertyValue -Object $raw -Name 'Description' -Default '')
        Path             = $resolved
        ProfileRoot      = $root
        ColumnPrefix     = @(ConvertTo-UlsColumnPrefixRules -Rules (Get-UlsObjectPropertyArray -Object $raw -Name 'ColumnPrefix') -Context "profile extension '$name' ColumnPrefix")
        SchemaColumns    = @($schemaColumns)
        WholeColumnRules = @($wholeColumnRules)
        LabelRules       = @(Get-UlsObjectPropertyArray -Object $raw -Name 'LabelRules')
        CustomRegexRules = @($customRegexRules)
        AllowedDomains   = @(Get-UlsObjectPropertyArray -Object $raw -Name 'AllowedDomains')
        Allowlist        = @(Get-UlsObjectPropertyArray -Object $raw -Name 'Allowlist')
        AllowlistFile    = @($allowlistFiles)
        AllowlistFiles   = @()
        SeedTerms        = @(Get-UlsObjectPropertyArray -Object $raw -Name 'SeedTerms')
        SeedFiles        = @($seedFiles)
    }
}

function Merge-ScrubProfileExtension {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Profile,
        [string[]]$Path = @()
    )
    $paths = @($Path | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($paths.Count -eq 0) { return $Profile }

    $merged = $Profile
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($p in $paths) {
        $extension = Import-ScrubProfileExtensionFile -Path $p
        [void]$names.Add($extension.Name)
        $description = [string](Get-UlsObjectPropertyValue -Object $merged -Name 'Description' -Default '')
        if ($description -notmatch [regex]::Escape($extension.Name)) { $description = ($description + " + extension $($extension.Name)").Trim() }
        $merged = [pscustomobject]@{
            Name             = [string](Get-UlsObjectPropertyValue -Object $merged -Name 'Name' -Default 'ExtendedProfile')
            Description      = $description
            SchemaVersion    = [int](Get-UlsObjectPropertyValue -Object $merged -Name 'SchemaVersion' -Default 2)
            Format           = [string](Get-UlsObjectPropertyValue -Object $merged -Name 'Format' -Default 'Auto')
            Delimiter        = [string](Get-UlsObjectPropertyValue -Object $merged -Name 'Delimiter' -Default ',')
            PassThroughRegex = Get-UlsObjectPropertyValue -Object $merged -Name 'PassThroughRegex' -Default $null
            ColumnPrefix     = @($extension.ColumnPrefix + (Get-UlsObjectPropertyArray -Object $merged -Name 'ColumnPrefix'))
            FreeTextRegex    = [string](Get-UlsObjectPropertyValue -Object $merged -Name 'FreeTextRegex' -Default '.*')
            DenyByDefault    = [bool](Get-UlsObjectPropertyValue -Object $merged -Name 'DenyByDefault' -Default $true)
            AllowedDomains   = @((Get-UlsObjectPropertyArray -Object $merged -Name 'AllowedDomains') + $extension.AllowedDomains)
            SchemaColumns    = @($extension.SchemaColumns + (Get-UlsObjectPropertyArray -Object $merged -Name 'SchemaColumns'))
            WholeColumnRules = @($extension.WholeColumnRules + (Get-UlsObjectPropertyArray -Object $merged -Name 'WholeColumnRules'))
            LabelRules       = @((Get-UlsObjectPropertyArray -Object $merged -Name 'LabelRules') + $extension.LabelRules)
            CustomRegexRules = @((Get-UlsObjectPropertyArray -Object $merged -Name 'CustomRegexRules') + $extension.CustomRegexRules)
            Allowlist        = @((Get-UlsObjectPropertyArray -Object $merged -Name 'Allowlist') + $extension.Allowlist)
            AllowlistFile    = @((Get-UlsObjectPropertyArray -Object $merged -Name 'AllowlistFile') + $extension.AllowlistFile)
            AllowlistFiles   = @((Get-UlsObjectPropertyArray -Object $merged -Name 'AllowlistFiles') + $extension.AllowlistFiles)
            SeedTerms        = @((Get-UlsObjectPropertyArray -Object $merged -Name 'SeedTerms') + $extension.SeedTerms)
            SeedFiles        = @((Get-UlsObjectPropertyArray -Object $merged -Name 'SeedFiles') + $extension.SeedFiles)
            ProfileRoot      = Get-UlsObjectPropertyValue -Object $merged -Name 'ProfileRoot' -Default $null
            ProfileExtensions = @((Get-UlsObjectPropertyArray -Object $merged -Name 'ProfileExtensions') + $extension.Path)
        }
    }
    Write-Ok ("Applied profile extension(s): {0}" -f (($names.ToArray()) -join ', '))
    return $merged
}

function New-ScrubProfileTemplate {
    param(
        [Parameter(Mandatory)][ValidateSet('Generic','Csv','Json','Kv','WebAccess','Cloud','App')][string]$Template,
        [Parameter(Mandatory)][string]$OutputPath
    )
    $format = switch ($Template) {
        'Csv' { 'Csv' }
        'Json' { 'Json' }
        'Kv' { 'Kv' }
        'Cloud' { 'Json' }
        'App' { 'Json' }
        default { 'Auto' }
    }
    $body = @"
{
  "SchemaVersion": 2,
  "Name": "$Template-Custom",
  "Description": "Custom $Template profile for Universal Log Scrubber.",
  "Format": "$format",
  "Delimiter": ",",
  "DenyByDefault": true,
  "AllowedDomains": [
    "example.com"
  ],
  "SchemaColumns": [
    { "Exact": "timestamp", "Action": "PassThrough", "Description": "Analytical timestamp" },
    { "Wildcard": "*message*", "Action": "Scan", "Description": "Free-text message field" }
  ],
  "WholeColumnRules": [
    { "Regex": "(?i)^(user(id|name)?|account|principal)$", "Prefix": "PRINCIPAL", "SplitOn": "[;,|]" },
    { "Regex": "(?i)^(host|server|machine|device)$", "Prefix": "DNS", "SplitOn": "[;,|]" },
    { "Regex": "(?i)^(ip|clientip|src_ip|dst_ip|address)$", "Prefix": "IP", "SplitOn": "[;,|]" },
    { "Regex": "(?i)(api[_ -]?key|token|secret|password)", "Prefix": "SECRET" }
  ],
  "LabelRules": [
    { "Name": "LocalApiKey", "Labels": [ "API Key", "api_key", "client_secret" ], "Prefix": "SECRET" },
    { "Name": "LocalHostLabels", "Labels": [ "host", "server", "node" ], "Prefix": "DNS" }
  ],
  "CustomRegexRules": [
    {
      "Name": "CompanyProjectId",
      "Regex": "(?i)\\b(project[_ -]?id\\s*[:=]\\s*)(PROJ-[0-9]{4}-[A-Z]{3})\\b",
      "CaptureGroup": 2,
      "Prefix": "OBJECT",
      "Keywords": [ "project", "PROJ-" ],
      "Entropy": 0
    }
  ],
  "SeedTerms": [],
  "SeedFiles": [],
  "Allowlist": [],
  "AllowlistFiles": []
}
"@
    $out = Resolve-OutPath -Path $OutputPath
    $dir = Split-Path -Parent $out
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    [System.IO.File]::WriteAllText($out, $body, [System.Text.Encoding]::UTF8)
    Write-Ok "Profile template written: $out"
    return $out
}

# =====================================================================
# REGION: Profile validation, sample analysis, and safe upload bundles
# =====================================================================
function Test-ScrubProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Quiet
    )
    try {
        $prof = Import-ScrubProfileFile -Path $Path
        Initialize-ScrubProfileRuntime -Profile $prof
        if (-not $Quiet) { Write-Ok "Profile is valid: $Path" }
        return $true
    }
    catch {
        if ($Quiet) { return $false }
        Write-Fail "Profile validation failed: $($_.Exception.Message)"
        throw
    }
}

function Get-ProfileBuilderPrefixForName {
    param([string]$Name)
    $n = ([string]$Name).ToLowerInvariant()
    if ($n -match '(api[_ -]?key|secret|password|passwd|pwd|token|credential|authorization|auth|private[_ -]?key|client[_ -]?secret)') { return 'SECRET' }
    if ($n -match '(user|username|user_id|userid|account|principal|actor|caller|subject|identity|login|suser|duser|cs-username)') { return 'PRINCIPAL' }
    if ($n -match '(src_ip|dst_ip|clientip|client_ip|remote_addr|ipaddress|ip_address|source.*address|destination.*address|\bc-ip\b|\bs-ip\b|\bip\b|x-forwarded-for)') { return 'IP' }
    if ($n -match '(host|hostname|server|machine|device|node|pod|container|workstation|computer|dhost|shost|cs-host|upstream_host)') { return 'DNS' }
    if ($n -match '(tenant|tenantid|tenant_id|org|organization|domain|realm|subscription|accountid|account_id|project)') { return 'X500' }
    if ($n -match '(url|uri|endpoint|referer|referrer|callback|redirect)') { return 'URI' }
    if ($n -match '(session|requestid|request_id|correlation|trace|span|transaction|ticket|case|incident)') { return 'OBJECT' }
    return $null
}

function Get-ProfileBuilderSchemaAction {
    param([string]$Name)
    $n = ([string]$Name).ToLowerInvariant()
    if ($n -match '^(date|time|timestamp|eventtime|created|updated|level|severity|status|result|method|action|operation|category|count|bytes|duration|elapsed|latency|version|protocol|port|http_method|http_status|sc-status|sc-bytes|cs-bytes|time-taken)$') { return 'PassThrough' }
    if ($n -match '(message|msg|detail|details|description|error|exception|stack|payload|raw|body|query|command|line|text)') { return 'Scan' }
    return $null
}

function Get-ProfileBuilderFormat {
    param([string]$Path, [ValidateSet('Auto','Csv','Json','Kv','Text')][string]$Requested = 'Auto')
    if ($Requested -ne 'Auto') { return $Requested }
    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    if ($ext -in @('.csv','.tsv','.psv')) { return 'Csv' }
    if ($ext -in @('.json','.jsonl','.ndjson')) { return 'Json' }
    $first = ''
    foreach ($line in [System.IO.File]::ReadLines($Path)) {
        if (-not [string]::IsNullOrWhiteSpace($line)) { $first = $line.Trim(); break }
    }
    if ($first -match '^[\{\[]') { return 'Json' }
    if (($first | Select-String -Pattern '\b[A-Za-z][A-Za-z0-9_.-]{1,40}=' -AllMatches).Matches.Count -ge 2) { return 'Kv' }
    return 'Text'
}

function Get-ProfileBuilderDelimiter {
    param([string]$Path)
    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    if ($ext -eq '.tsv') { return "`t" }
    if ($ext -eq '.psv') { return '|' }
    $header = ''
    foreach ($line in [System.IO.File]::ReadLines($Path)) {
        if (-not [string]::IsNullOrWhiteSpace($line)) { $header = $line; break }
    }
    $commas = ($header.ToCharArray() | Where-Object { $_ -eq ',' }).Count
    $tabs = ($header.ToCharArray() | Where-Object { $_ -eq "`t" }).Count
    $pipes = ($header.ToCharArray() | Where-Object { $_ -eq '|' }).Count
    if ($tabs -gt $commas -and $tabs -ge $pipes) { return "`t" }
    if ($pipes -gt $commas -and $pipes -gt $tabs) { return '|' }
    return ','
}

function New-ProfileBuilderStats {
    return @{
        Columns = @{}
        Labels = @{}
        Shapes = @{}
        SeedCandidates = @{}
        AllowCandidates = @{}
        Lines = 0
        Rows = 0
    }
}

function Add-ProfileBuilderExample {
    param($Bucket, [string]$Value, [int]$Limit = 5)
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    $v = $Value.Trim()
    if ($Bucket.Examples.Count -lt $Limit -and -not $Bucket.Examples.Contains($v)) { [void]$Bucket.Examples.Add($v) }
}

function Add-ProfileBuilderColumnValue {
    param($Stats, [string]$Name, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Name)) { return }
    $key = $Name.Trim().ToLowerInvariant()
    if (-not $Stats.Columns.ContainsKey($key)) {
        $Stats.Columns[$key] = [pscustomobject]@{
            Name = $Name.Trim()
            Count = 0
            NonBlank = 0
            Examples = (New-Object System.Collections.Generic.List[string])
        }
    }
    $c = $Stats.Columns[$key]
    $c.Count = [int]$c.Count + 1
    if (-not [string]::IsNullOrWhiteSpace($Value)) {
        $c.NonBlank = [int]$c.NonBlank + 1
        Add-ProfileBuilderExample -Bucket $c -Value $Value
    }
}

function Add-ProfileBuilderAllowCandidate {
    param($Stats, [string]$Value, [string]$Reason)
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    $v = $Value.Trim().Trim('"', "'")
    if ($v.Length -lt 2 -or $v.Length -gt 120) { return }
    $isAllow = $false
    if ($v -match '^(127\.0\.0\.1|::1|0\.0\.0\.0|localhost)$') { $isAllow = $true }
    elseif ($v -match '^00000000-0000-0000-0000-000000000000$') { $isAllow = $true }
    elseif ($v -match '^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)$') { $isAllow = $true }
    elseif ($v -match '^(health|ready|live|ok|true|false|null|none|success|failed|warning|info|error)$') { $isAllow = $true }
    elseif (Test-AllowedDomain -Value $v) { $isAllow = $true }
    if (-not $isAllow) { return }
    $k = $v.ToLowerInvariant()
    if (-not $Stats.AllowCandidates.ContainsKey($k)) {
        $Stats.AllowCandidates[$k] = [pscustomobject]@{ Value=$v; Reason=$Reason }
    }
}

function Add-ProfileBuilderSeedCandidate {
    param($Stats, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    $v = $Value.Trim().Trim('"', "'", '.', ',', ';', ':')
    if ($v.Length -lt 5 -or $v.Length -gt 60) { return }
    if ($v -match '^\d+$|^(true|false|null|none|error|warning|info|debug|trace|status|message|request|response|success|failed)$') { return }
    if ($v -match '@|\\|/|:|=') { return }
    if ($v -match '^\d{4}-\d{2}-\d{2}') { return }
    if ($v -match '^(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$') { return }
    if ($v -notmatch '[A-Za-z]') { return }
    $k = $v.ToLowerInvariant()
    if (-not $Stats.SeedCandidates.ContainsKey($k)) {
        $Stats.SeedCandidates[$k] = [pscustomobject]@{ Value=$v; Count=0 }
    }
    $Stats.SeedCandidates[$k].Count = [int]$Stats.SeedCandidates[$k].Count + 1
}

function Get-ProfileBuilderShapeRegex {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = $Value.Trim().Trim('"', "'")
    if ($v.Length -lt 8 -or $v.Length -gt 80) { return $null }
    if ($v -notmatch '[A-Za-z]' -or $v -notmatch '\d') { return $null }
    if ($v -match '@|\\|/|://') { return $null }
    if ($v -match '^\d{1,3}(\.\d{1,3}){3}$') { return $null }
    if ($v -match '^(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$') { return $null }
    $parts = New-Object System.Collections.Generic.List[string]
    $i = 0
    while ($i -lt $v.Length) {
        $ch = $v[$i]
        $start = $i
        if ($ch -match '[A-Z]') { while ($i -lt $v.Length -and ([string]$v[$i]) -match '[A-Z]') { $i++ }; $n = $i - $start; [void]$parts.Add(("[A-Z]{{{0}}}" -f $n)); continue }
        if ($ch -match '[a-z]') { while ($i -lt $v.Length -and ([string]$v[$i]) -match '[a-z]') { $i++ }; $n = $i - $start; [void]$parts.Add(("[a-z]{{{0}}}" -f $n)); continue }
        if ($ch -match '[0-9]') { while ($i -lt $v.Length -and ([string]$v[$i]) -match '[0-9]') { $i++ }; $n = $i - $start; [void]$parts.Add(("[0-9]{{{0}}}" -f $n)); continue }
        if ($ch -match '[-_.]') { [void]$parts.Add([regex]::Escape([string]$ch)); $i++; continue }
        return $null
    }
    return ($parts -join '')
}

function Add-ProfileBuilderTextFacts {
    param($Stats, [string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return }
    foreach ($m in [regex]::Matches($Text, '(?im)(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9_. -]{1,40})\s*[:=]\s*("[^"\r\n]{1,160}"|''[^''\r\n]{1,160}''|[^,\s;|]{1,160})')) {
        $label = $m.Groups[1].Value.Trim()
        $value = $m.Groups[2].Value.Trim().Trim('"', "'")
        if ($label -match '^\d+$' -or $label.Length -lt 2) { continue }
        $prefix = Get-UniversalLabeledValuePrefix -Label $label -Value $value -DefaultPrefix (Get-ProfileBuilderPrefixForName -Name $label)
        if (-not $prefix) { $prefix = 'OBJECT' }
        $key = ($prefix + '|' + $label.ToLowerInvariant())
        if (-not $Stats.Labels.ContainsKey($key)) {
            $Stats.Labels[$key] = [pscustomobject]@{ Label=$label; Prefix=$prefix; Count=0; Examples=(New-Object System.Collections.Generic.List[string]) }
        }
        $Stats.Labels[$key].Count = [int]$Stats.Labels[$key].Count + 1
        Add-ProfileBuilderExample -Bucket $Stats.Labels[$key] -Value $value
        Add-ProfileBuilderAllowCandidate -Stats $Stats -Value $value -Reason "Observed after label '$label'"
        Add-ProfileBuilderSeedCandidate -Stats $Stats -Value $value
        $shape = Get-ProfileBuilderShapeRegex -Value $value
        if ($shape) {
            if (-not $Stats.Shapes.ContainsKey($shape)) {
                $Stats.Shapes[$shape] = [pscustomobject]@{ Regex=$shape; Count=0; Prefix='OBJECT'; Examples=(New-Object System.Collections.Generic.List[string]) }
            }
            $Stats.Shapes[$shape].Count = [int]$Stats.Shapes[$shape].Count + 1
            Add-ProfileBuilderExample -Bucket $Stats.Shapes[$shape] -Value $value
        }
    }
    foreach ($m in [regex]::Matches($Text, '\b[A-Za-z][A-Za-z0-9_.-]{4,80}\b')) {
        $v = $m.Value
        Add-ProfileBuilderAllowCandidate -Stats $Stats -Value $v -Reason 'Public diagnostic candidate'
        Add-ProfileBuilderSeedCandidate -Stats $Stats -Value $v
        $shape = Get-ProfileBuilderShapeRegex -Value $v
        if ($shape) {
            if (-not $Stats.Shapes.ContainsKey($shape)) {
                $Stats.Shapes[$shape] = [pscustomobject]@{ Regex=$shape; Count=0; Prefix='OBJECT'; Examples=(New-Object System.Collections.Generic.List[string]) }
            }
            $Stats.Shapes[$shape].Count = [int]$Stats.Shapes[$shape].Count + 1
            Add-ProfileBuilderExample -Bucket $Stats.Shapes[$shape] -Value $v
        }
    }
}

function Add-JsonSamplePairs {
    param($Stats, $Node, [string]$KeyName = '')
    if ($null -eq $Node) { return }
    if ($Node -is [string]) {
        Add-ProfileBuilderColumnValue -Stats $Stats -Name $KeyName -Value $Node
        Add-ProfileBuilderTextFacts -Stats $Stats -Text $Node
        return
    }
    if ($Node -is [bool] -or
        $Node -is [int] -or
        $Node -is [long] -or
        $Node -is [double] -or
        $Node -is [decimal] -or
        $Node -is [datetime] -or
        $Node -is [guid]) {
        if ($KeyName) { Add-ProfileBuilderColumnValue -Stats $Stats -Name $KeyName -Value ([string]$Node) }
        return
    }
    if (($Node -is [System.Collections.IEnumerable]) -and -not ($Node -is [string])) {
        foreach ($item in $Node) { Add-JsonSamplePairs -Stats $Stats -Node $item -KeyName $KeyName }
        return
    }
    if ($Node.PSObject -and @($Node.PSObject.Properties).Count -gt 0) {
        foreach ($p in $Node.PSObject.Properties) { Add-JsonSamplePairs -Stats $Stats -Node $p.Value -KeyName $p.Name }
    }
}

function Invoke-SampleProfileAnalysis {
    param(
        [Parameter(Mandatory)][string[]]$Files,
        [ValidateSet('Auto','Csv','Json','Kv','Text')][string]$SampleFormat = 'Auto',
        [int]$MaxSampleRows = 500
    )
    $stats = New-ProfileBuilderStats
    $format = $null
    $delimiter = ','
    foreach ($file in $Files) {
        $fmt = Get-ProfileBuilderFormat -Path $file -Requested $SampleFormat
        if (-not $format) { $format = $fmt }
        if ($fmt -eq 'Csv') {
            $delimiter = Get-ProfileBuilderDelimiter -Path $file
            $rn = 0
            Import-Csv -Path $file -Delimiter $delimiter | ForEach-Object {
                if ($stats.Rows -ge $MaxSampleRows) { return }
                $stats.Rows = [int]$stats.Rows + 1
                $rn++
                foreach ($prop in $_.PSObject.Properties) {
                    $val = [string]$prop.Value
                    Add-ProfileBuilderColumnValue -Stats $stats -Name $prop.Name -Value $val
                    Add-ProfileBuilderTextFacts -Stats $stats -Text $val
                }
            }
        }
        elseif ($fmt -eq 'Json') {
            $ext = [System.IO.Path]::GetExtension($file).ToLowerInvariant()
            if ($ext -in @('.jsonl','.ndjson')) {
                foreach ($line in [System.IO.File]::ReadLines($file)) {
                    if ($stats.Rows -ge $MaxSampleRows) { break }
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }
                    try {
                        $obj = $line | ConvertFrom-Json -ErrorAction Stop
                        $stats.Rows = [int]$stats.Rows + 1
                        Add-JsonSamplePairs -Stats $stats -Node $obj
                    } catch { Add-ProfileBuilderTextFacts -Stats $stats -Text $line }
                }
            }
            else {
                $raw = [System.IO.File]::ReadAllText($file)
                try {
                    $obj = $raw | ConvertFrom-Json -ErrorAction Stop
                    $stats.Rows = [Math]::Max(1, [int]$stats.Rows)
                    Add-JsonSamplePairs -Stats $stats -Node $obj
                } catch { Add-ProfileBuilderTextFacts -Stats $stats -Text $raw }
            }
        }
        else {
            foreach ($line in [System.IO.File]::ReadLines($file)) {
                if ($stats.Rows -ge $MaxSampleRows) { break }
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                $stats.Rows = [int]$stats.Rows + 1
                $stats.Lines = [int]$stats.Lines + 1
                Add-ProfileBuilderTextFacts -Stats $stats -Text $line
                if ($fmt -eq 'Kv') {
                    foreach ($m in [regex]::Matches($line, '(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9_.-]{1,40})=("[^"\r\n]{0,200}"|[^,\s;|]{0,200})')) {
                        Add-ProfileBuilderColumnValue -Stats $stats -Name $m.Groups[1].Value -Value $m.Groups[2].Value.Trim().Trim('"')
                    }
                }
            }
        }
    }
    if (-not $format) { $format = 'Text' }
    return [pscustomobject]@{ Format=$format; Delimiter=$delimiter; Stats=$stats; Files=$Files; MaxSampleRows=$MaxSampleRows }
}

function ConvertTo-GeneratedProfile {
    param($Analysis, [string]$Name, [switch]$IncludeSeeds, [switch]$IncludeAllowlist, [switch]$IncludeCustomRegex = $true)
    $schema = New-Object System.Collections.Generic.List[object]
    $whole = New-Object System.Collections.Generic.List[object]
    foreach ($c in (@($Analysis.Stats.Columns.Values) | Sort-Object Name)) {
        $action = Get-ProfileBuilderSchemaAction -Name $c.Name
        $prefix = Get-ProfileBuilderPrefixForName -Name $c.Name
        if ($action) {
            [void]$schema.Add([ordered]@{ Exact=$c.Name; Action=$action; Description='Generated from sample schema.' })
        }
        if ($prefix) {
            [void]$whole.Add([ordered]@{ Exact=$c.Name; Prefix=$prefix; SplitOn='[;,|]'; Description='Generated from sample schema.' })
        }
    }
    foreach ($default in @(
        @{ Wildcard='*message*'; Action='Scan'; Description='Message-like free text.' },
        @{ Wildcard='*detail*'; Action='Scan'; Description='Detail-like free text.' },
        @{ Wildcard='*description*'; Action='Scan'; Description='Description-like free text.' }
    )) {
        if (@($schema | Where-Object { $_.Wildcard -eq $default.Wildcard }).Count -eq 0) {
            [void]$schema.Add([ordered]@{ Wildcard=$default.Wildcard; Action=$default.Action; Description=$default.Description })
        }
    }

    $labelsByPrefix = @{}
    foreach ($l in @($Analysis.Stats.Labels.Values)) {
        if ($l.Count -lt 1) { continue }
        if (-not $labelsByPrefix.ContainsKey($l.Prefix)) { $labelsByPrefix[$l.Prefix] = New-Object System.Collections.Generic.List[string] }
        if (-not $labelsByPrefix[$l.Prefix].Contains($l.Label)) { [void]$labelsByPrefix[$l.Prefix].Add($l.Label) }
    }
    $labelRules = New-Object System.Collections.Generic.List[object]
    foreach ($prefix in (@($labelsByPrefix.Keys) | Sort-Object)) {
        $labels = @($labelsByPrefix[$prefix].ToArray() | Sort-Object | Select-Object -First 24)
        if ($labels.Count -gt 0) {
            [void]$labelRules.Add([ordered]@{ Name=("Generated{0}Labels" -f $prefix); Labels=$labels; Prefix=$prefix })
        }
    }

    $custom = New-Object System.Collections.Generic.List[object]
    if ($IncludeCustomRegex) {
        $i = 0
        foreach ($shape in (@($Analysis.Stats.Shapes.Values) | Where-Object { $_.Count -ge 2 } | Sort-Object Count -Descending | Select-Object -First 8)) {
            $i++
            [void]$custom.Add([ordered]@{
                Name = ("GeneratedShape{0}" -f $i)
                Regex = ("\b({0})\b" -f $shape.Regex)
                CaptureGroup = 1
                Prefix = $shape.Prefix
                Keywords = @()
                Entropy = 0
                Description = 'Generated from repeated sample value shape; review before production.'
            })
        }
    }

    $profile = [ordered]@{
        SchemaVersion = 2
        Name = $Name
        Description = 'Generated from a local sample. Review before production use.'
        Format = $Analysis.Format
        Delimiter = $Analysis.Delimiter
        DenyByDefault = $true
        SchemaColumns = @($schema.ToArray())
        WholeColumnRules = @($whole.ToArray())
        LabelRules = @($labelRules.ToArray())
        CustomRegexRules = @($custom.ToArray())
    }
    if ($IncludeSeeds) { $profile.SeedFiles = @('generated-seeds.txt') }
    if ($IncludeAllowlist) { $profile.AllowlistFile = @('generated-allowlist.txt') }
    return $profile
}

function Remove-UlsObjectProperty {
    param($Object, [string]$Name)
    if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($Name)) { return }
    try {
        if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($Name)) {
            [void]$Object.Remove($Name)
            return
        }
    } catch { }
    try {
        if ($Object.PSObject.Properties[$Name]) { $Object.PSObject.Properties.Remove($Name) }
    } catch { }
}

function Set-UlsObjectProperty {
    param($Object, [string]$Name, $Value)
    if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($Name)) { return }
    try {
        if ($Object -is [System.Collections.IDictionary]) {
            $Object[$Name] = $Value
            return
        }
    } catch { }
    try {
        if ($Object.PSObject.Properties[$Name]) { $Object.PSObject.Properties[$Name].Value = $Value }
        else { Add-Member -InputObject $Object -NotePropertyName $Name -NotePropertyValue $Value -Force }
    } catch { }
}

function Protect-UlsGeneratedProfile {
    param([Parameter(Mandatory)]$Profile)
    [void](Get-SessionSalt)
    $profileProtection = [ordered]@{
        Enabled         = $true
        Algorithm       = 'HMAC-SHA256'
        SaltFingerprint = (Get-SaltFingerprint)
        HmacLength      = [int]$script:HmacLength
    }
    Set-UlsObjectProperty -Object $Profile -Name 'Protection' -Value $profileProtection

    foreach ($propName in @('SchemaColumns','WholeColumnRules')) {
        foreach ($rule in @(Get-UlsObjectPropertyArray -Object $Profile -Name $propName)) {
            $protected = New-Object System.Collections.Generic.List[string]
            foreach ($fieldName in @('Exact','Column','Columns','Name')) {
                foreach ($value in @(Get-UlsObjectPropertyArray -Object $rule -Name $fieldName)) {
                    if ([string]::IsNullOrWhiteSpace([string]$value)) { continue }
                    $tok = Invoke-HmacToken -Value ([string]$value) -Prefix FIELD
                    if ($tok -and -not $protected.Contains($tok)) { [void]$protected.Add($tok) }
                }
                Remove-UlsObjectProperty -Object $rule -Name $fieldName
            }
            if ($protected.Count -gt 0) { Set-UlsObjectProperty -Object $rule -Name 'ProtectedExact' -Value @($protected.ToArray()) }
        }
    }

    foreach ($rule in @(Get-UlsObjectPropertyArray -Object $Profile -Name 'LabelRules')) {
        $protected = New-Object System.Collections.Generic.List[string]
        foreach ($fieldName in @('Labels','Label')) {
            foreach ($value in @(Get-UlsObjectPropertyArray -Object $rule -Name $fieldName)) {
                if ([string]::IsNullOrWhiteSpace([string]$value)) { continue }
                $tok = Invoke-HmacToken -Value ([string]$value) -Prefix LABEL
                if ($tok -and -not $protected.Contains($tok)) { [void]$protected.Add($tok) }
            }
            Remove-UlsObjectProperty -Object $rule -Name $fieldName
        }
        if ($protected.Count -gt 0) { Set-UlsObjectProperty -Object $rule -Name 'ProtectedLabels' -Value @($protected.ToArray()) }
    }
    return $Profile
}

function Assert-UlsProfileProtectionContext {
    param($Protection, [string]$Context = 'profile')
    $enabled = $false
    try { $enabled = [bool](Get-UlsObjectPropertyValue -Object $Protection -Name 'Enabled' -Default $false) } catch { }
    if (-not $enabled) { return }
    if ([string]::IsNullOrWhiteSpace($script:Salt)) {
        throw "$Context is protected and requires the same salt used to generate it. Pass -Salt, -SaltFromEnv, or -SaltFile before loading the profile."
    }
    $expectedAlg = [string](Get-UlsObjectPropertyValue -Object $Protection -Name 'Algorithm' -Default 'HMAC-SHA256')
    if ($expectedAlg -and $expectedAlg -ne 'HMAC-SHA256') { throw "$Context uses unsupported protection algorithm '$expectedAlg'." }
    $expectedLen = [int](Get-UlsObjectPropertyValue -Object $Protection -Name 'HmacLength' -Default $script:HmacLength)
    if ($expectedLen -ne [int]$script:HmacLength) {
        throw "$Context was protected with HMAC length $expectedLen, but this run is using $script:HmacLength."
    }
    $expectedFp = [string](Get-UlsObjectPropertyValue -Object $Protection -Name 'SaltFingerprint' -Default '')
    if (-not [string]::IsNullOrWhiteSpace($expectedFp)) {
        $actualFp = Get-SaltFingerprint
        if (-not [string]::Equals($expectedFp, $actualFp, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "$Context salt fingerprint mismatch. Use the same salt that generated the protected profile."
        }
    }
}

function ConvertTo-UlsSerializableColumnPrefixRules {
    param($Rules)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rules)) {
        if ($null -eq $r) { continue }
        $pat = [string](Get-UlsObjectPropertyValue -Object $r -Name 'Pattern')
        $pre = [string](Get-UlsObjectPropertyValue -Object $r -Name 'Prefix')
        if ([string]::IsNullOrWhiteSpace($pat) -or [string]::IsNullOrWhiteSpace($pre)) { continue }
        $entry = [ordered]@{ Pattern=$pat; Prefix=$pre }
        if ([bool](Get-UlsObjectPropertyValue -Object $r -Name 'NotOid' -Default $false)) { $entry.NotOid = $true }
        if ([bool](Get-UlsObjectPropertyValue -Object $r -Name 'DollarComputer' -Default $false)) { $entry.DollarComputer = $true }
        [void]$out.Add($entry)
    }
    return @($out.ToArray())
}

function ConvertTo-UlsSerializableCustomRegexRules {
    param($Rules)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rules)) {
        if ($null -eq $r) { continue }
        $rx = [string](Get-UlsObjectPropertyValue -Object $r -Name 'Regex')
        if ([string]::IsNullOrWhiteSpace($rx)) { continue }
        $entry = [ordered]@{
            Name = [string](Get-UlsObjectPropertyValue -Object $r -Name 'Name' -Default 'CustomRegex')
            Regex = $rx
            CaptureGroup = [int](Get-UlsObjectPropertyValue -Object $r -Name 'CaptureGroup' -Default 0)
            Prefix = [string](Get-UlsObjectPropertyValue -Object $r -Name 'Prefix' -Default 'OBJECT')
            Keywords = @(Get-UlsObjectPropertyArray -Object $r -Name 'Keywords')
            Entropy = Get-UlsObjectPropertyValue -Object $r -Name 'Entropy' -Default 0
        }
        $desc = [string](Get-UlsObjectPropertyValue -Object $r -Name 'Description' -Default '')
        if (-not [string]::IsNullOrWhiteSpace($desc)) { $entry.Description = $desc }
        [void]$out.Add($entry)
    }
    return @($out.ToArray())
}

function Import-UlsRawProfileLikeFile {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Profile extension file not found: $Path" }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $ext = [System.IO.Path]::GetExtension($resolved).ToLowerInvariant()
    if ($ext -eq '.psd1') { return Import-PowerShellDataFile -Path $resolved }
    return ((Get-Content -LiteralPath $resolved -Raw) | ConvertFrom-Json)
}

function Merge-UlsGeneratedProfileWithBase {
    param(
        [Parameter(Mandatory)]$GeneratedProfile,
        [string]$BaseProfile,
        [string[]]$ProfileExtensionFile = @()
    )

    $merged = $GeneratedProfile
    if (-not [string]::IsNullOrWhiteSpace($BaseProfile)) {
        $base = Get-ScrubProfile -Name $BaseProfile
        if (-not $base) { throw "Unknown base profile for sample profile builder: $BaseProfile" }
        $merged = [ordered]@{
            SchemaVersion = 2
            Name = [string](Get-UlsObjectPropertyValue -Object $GeneratedProfile -Name 'Name' -Default 'GeneratedSampleProfile')
            Description = "Generated from a local sample and based on built-in profile '$($base.Name)'. Review before production use."
            BaseProfile = $base.Name
            Format = [string](Get-UlsObjectPropertyValue -Object $base -Name 'Format' -Default (Get-UlsObjectPropertyValue -Object $GeneratedProfile -Name 'Format' -Default 'Auto'))
            Delimiter = [string](Get-UlsObjectPropertyValue -Object $base -Name 'Delimiter' -Default (Get-UlsObjectPropertyValue -Object $GeneratedProfile -Name 'Delimiter' -Default ','))
            DenyByDefault = [bool](Get-UlsObjectPropertyValue -Object $base -Name 'DenyByDefault' -Default $true)
        }
        $protection = Get-UlsObjectPropertyValue -Object $GeneratedProfile -Name 'Protection' -Default $null
        if ($protection) { $merged.Protection = $protection }
        $pass = Get-UlsObjectPropertyValue -Object $base -Name 'PassThroughRegex' -Default $null
        if ($pass) { $merged.PassThroughRegex = [string]$pass }
        $free = Get-UlsObjectPropertyValue -Object $base -Name 'FreeTextRegex' -Default $null
        if ($free) { $merged.FreeTextRegex = [string]$free }
        $allowed = @(Get-UlsObjectPropertyArray -Object $base -Name 'AllowedDomains')
        if ($allowed.Count -gt 0) { $merged.AllowedDomains = @($allowed) }
        $baseColumns = @(ConvertTo-UlsSerializableColumnPrefixRules -Rules (Get-UlsObjectPropertyArray -Object $base -Name 'ColumnPrefix'))
        if ($baseColumns.Count -gt 0) { $merged.ColumnPrefix = @($baseColumns) }
        $merged.SchemaColumns = @(Get-UlsObjectPropertyArray -Object $GeneratedProfile -Name 'SchemaColumns')
        $merged.WholeColumnRules = @(Get-UlsObjectPropertyArray -Object $GeneratedProfile -Name 'WholeColumnRules')
        $merged.LabelRules = @((Get-UlsObjectPropertyArray -Object $base -Name 'LabelRules') + (Get-UlsObjectPropertyArray -Object $GeneratedProfile -Name 'LabelRules'))
        $merged.CustomRegexRules = @((ConvertTo-UlsSerializableCustomRegexRules -Rules (Get-UlsObjectPropertyArray -Object $base -Name 'CustomRegexRules')) + (Get-UlsObjectPropertyArray -Object $GeneratedProfile -Name 'CustomRegexRules'))
        foreach ($propName in @('SeedFiles','AllowlistFile')) {
            $vals = @(Get-UlsObjectPropertyArray -Object $GeneratedProfile -Name $propName)
            if ($vals.Count -gt 0) { $merged[$propName] = @($vals) }
        }
    }

    foreach ($extensionPath in @($ProfileExtensionFile)) {
        if ([string]::IsNullOrWhiteSpace([string]$extensionPath)) { continue }
        $raw = Import-UlsRawProfileLikeFile -Path $extensionPath
        if (-not $raw) { continue }
        $extensionName = [string](Get-UlsObjectPropertyValue -Object $raw -Name 'Name' -Default ([System.IO.Path]::GetFileNameWithoutExtension($extensionPath)))
        $existingExtensions = @(Get-UlsObjectPropertyArray -Object $merged -Name 'ProfileExtensions')
        $merged.ProfileExtensions = @($existingExtensions + $extensionName)
        foreach ($propName in @('SchemaColumns','WholeColumnRules','ColumnPrefix')) {
            $vals = @(Get-UlsObjectPropertyArray -Object $raw -Name $propName)
            if ($vals.Count -gt 0) {
                $existing = @(Get-UlsObjectPropertyArray -Object $merged -Name $propName)
                $merged[$propName] = @($vals + $existing)
            }
        }
        foreach ($propName in @('LabelRules','CustomRegexRules','AllowedDomains','Allowlist','AllowlistFile','AllowlistFiles','SeedTerms','SeedFiles')) {
            $vals = @(Get-UlsObjectPropertyArray -Object $raw -Name $propName)
            if ($vals.Count -gt 0) {
                $existing = @(Get-UlsObjectPropertyArray -Object $merged -Name $propName)
                $merged[$propName] = @($existing + $vals)
            }
        }
    }

    return $merged
}

function Write-ProfileBuilderReport {
    param($Analysis, [string]$Path, [string]$ProfilePath)
    $lines = New-Object System.Collections.Generic.List[string]
    [void]$lines.Add('# Profile Build Report - DO_NOT_UPLOAD')
    [void]$lines.Add('')
    [void]$lines.Add('This report may contain raw sample values. Keep it local.')
    [void]$lines.Add('')
    [void]$lines.Add(('Generated profile: {0}' -f $ProfilePath))
    [void]$lines.Add(('Detected format: {0}' -f $Analysis.Format))
    [void]$lines.Add(("Rows/lines inspected: {0}" -f $Analysis.Stats.Rows))
    [void]$lines.Add('')
    [void]$lines.Add('## Files')
    foreach ($f in $Analysis.Files) { [void]$lines.Add(("- {0}" -f $f)) }
    [void]$lines.Add('')
    [void]$lines.Add('## Column/Key Suggestions')
    foreach ($c in (@($Analysis.Stats.Columns.Values) | Sort-Object Name)) {
        $prefix = Get-ProfileBuilderPrefixForName -Name $c.Name
        $action = Get-ProfileBuilderSchemaAction -Name $c.Name
        $examples = (@($c.Examples.ToArray()) | Select-Object -First 3) -join ', '
        [void]$lines.Add(("- {0}: prefix={1} action={2} examples={3}" -f $c.Name, $prefix, $action, $examples))
    }
    [void]$lines.Add('')
    [void]$lines.Add('## Label Suggestions')
    foreach ($l in (@($Analysis.Stats.Labels.Values) | Sort-Object Prefix,Label)) {
        $examples = (@($l.Examples.ToArray()) | Select-Object -First 3) -join ', '
        [void]$lines.Add(("- {0} -> {1} ({2} hit(s)); examples={3}" -f $l.Label, $l.Prefix, $l.Count, $examples))
    }
    [void]$lines.Add('')
    [void]$lines.Add('## Repeated Shape Suggestions')
    foreach ($s in (@($Analysis.Stats.Shapes.Values) | Sort-Object Count -Descending | Select-Object -First 20)) {
        $examples = (@($s.Examples.ToArray()) | Select-Object -First 3) -join ', '
        [void]$lines.Add(("- {0} ({1} hit(s)); examples={2}" -f $s.Regex, $s.Count, $examples))
    }
    [void]$lines.Add('')
    [void]$lines.Add('## Seed Candidates')
    foreach ($s in (@($Analysis.Stats.SeedCandidates.Values) | Sort-Object Count -Descending | Select-Object -First 40)) {
        [void]$lines.Add(("- {0} ({1} hit(s))" -f $s.Value, $s.Count))
    }
    [void]$lines.Add('')
    [void]$lines.Add('## Allowlist Candidates')
    foreach ($a in (@($Analysis.Stats.AllowCandidates.Values) | Sort-Object Value | Select-Object -First 40)) {
        [void]$lines.Add(("- {0} - {1}" -f $a.Value, $a.Reason))
    }
    $out = Resolve-OutPath -Path $Path
    [System.IO.File]::WriteAllText($out, ($lines -join "`r`n"), [System.Text.Encoding]::UTF8)
    return $out
}

function Write-ProfileBuilderOptionalFiles {
    param($Analysis, [string]$Directory, [switch]$ProfileWizard, [switch]$NonInteractive)
    $writeSeeds = $false
    $writeAllow = $false
    if ($ProfileWizard -and -not $NonInteractive) {
        Write-Host ''
        Write-Step 'Profile builder wizard'
        Write-Info 'The generated profile never stores raw sample values. Seed and allowlist files may, so they are optional.'
        if ($Analysis.Stats.SeedCandidates.Count -gt 0) {
            Write-Detail ("Seed candidates: {0}" -f $Analysis.Stats.SeedCandidates.Count)
            $writeSeeds = Read-YesNo -Prompt 'Write generated-seeds.txt from sample candidates' -Default $false
        }
        if ($Analysis.Stats.AllowCandidates.Count -gt 0) {
            Write-Detail ("Allowlist candidates: {0}" -f $Analysis.Stats.AllowCandidates.Count)
            $writeAllow = Read-YesNo -Prompt 'Write generated-allowlist.txt from public diagnostic candidates' -Default $false
        }
    }
    $seedPath = $null
    $allowPath = $null
    if ($writeSeeds) {
        $seedPath = Join-Path $Directory 'generated-seeds.txt'
        $items = @($Analysis.Stats.SeedCandidates.Values | Sort-Object Count -Descending | Select-Object -First 100 | ForEach-Object { $_.Value })
        [System.IO.File]::WriteAllText($seedPath, (("# Generated seed terms. Review before use.`r`n" + ($items -join "`r`n") + "`r`n")), [System.Text.Encoding]::UTF8)
    }
    if ($writeAllow) {
        $allowPath = Join-Path $Directory 'generated-allowlist.txt'
        $items = @($Analysis.Stats.AllowCandidates.Values | Sort-Object Value | ForEach-Object { $_.Value })
        [System.IO.File]::WriteAllText($allowPath, (("# Generated allowlist. Review before use.`r`n" + ($items -join "`r`n") + "`r`n")), [System.Text.Encoding]::UTF8)
    }
    return [pscustomobject]@{ SeedPath=$seedPath; AllowlistPath=$allowPath; IncludeSeeds=[bool]$writeSeeds; IncludeAllowlist=[bool]$writeAllow }
}

function New-ScrubProfileFromSample {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$ProfileOut,
        [string]$ProfileReportOut,
        [string]$BaseProfile,
        [string[]]$ProfileExtensionFile,
        [switch]$ProfileWizard,
        [int]$MaxSampleRows = 500,
        [ValidateSet('Auto','Csv','Json','Kv','Text')][string]$SampleFormat = 'Auto',
        [switch]$ProtectGeneratedProfile,
        [string]$Salt,
        [string]$SaltFromEnv,
        [string]$SaltFile,
        [int]$HmacLength = $script:HmacLength,
        [switch]$Force,
        [switch]$NonInteractive
    )
    if (-not (Test-Path -LiteralPath $Path)) { throw "Sample path not found: $Path" }
    $files = @()
    if (Test-Path -LiteralPath $Path -PathType Container) {
        $files = @(Get-ChildItem -LiteralPath $Path -File -ErrorAction Stop |
            Where-Object { $_.Name -notmatch '(?i)(_scrubbed|\.scrubbed\.|token_map|DO_NOT_UPLOAD|false_positive|detection_report)' } |
            Sort-Object FullName | Select-Object -First 20 | ForEach-Object { $_.FullName })
    }
    else { $files = @((Resolve-Path -LiteralPath $Path).Path) }
    if ($files.Count -eq 0) { throw "No sample files found: $Path" }
    if ($MaxSampleRows -lt 1) { throw "MaxSampleRows must be at least 1." }

    $outPath = if ($ProfileOut) { $ProfileOut } else { Join-Path (Get-Location).Path 'generated-profile.json' }
    $outPath = Resolve-OutPath -Path $outPath
    $outDir = Split-Path -Parent $outPath
    if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    if ((Test-Path -LiteralPath $outPath) -and -not $Force) { throw "Profile output already exists: $outPath. Use -Force to overwrite." }
    $reportPath = if ($ProfileReportOut) { $ProfileReportOut } else { Join-Path $outDir 'profile_build_report_DO_NOT_UPLOAD.md' }
    $reportPath = Resolve-OutPath -Path $reportPath
    if ((Test-Path -LiteralPath $reportPath) -and -not $Force) { throw "Profile report already exists: $reportPath. Use -Force to overwrite." }

    if ($ProtectGeneratedProfile) {
        $resolvedSalt = Resolve-UlsSaltInput -Salt $Salt -SaltFromEnv $SaltFromEnv -SaltFile $SaltFile
        if ([string]::IsNullOrWhiteSpace($resolvedSalt)) {
            throw "Protected generated profiles require -Salt, -SaltFromEnv, or -SaltFile."
        }
        $script:Salt = $resolvedSalt
        if ($HmacLength -lt 4 -or $HmacLength -gt 64) { throw "HmacLength must be between 4 and 64 for protected generated profiles." }
        $script:HmacLength = $HmacLength
    }

    Write-Work "Analyzing sample log(s) locally"
    $analysis = Invoke-SampleProfileAnalysis -Files $files -SampleFormat $SampleFormat -MaxSampleRows $MaxSampleRows
    if ($analysis.Stats.Rows -eq 0 -and $analysis.Stats.Columns.Count -eq 0 -and $analysis.Stats.Labels.Count -eq 0) {
        throw "Sample appears empty or unsupported: $Path"
    }
    $optional = Write-ProfileBuilderOptionalFiles -Analysis $analysis -Directory $outDir -ProfileWizard:$ProfileWizard -NonInteractive:$NonInteractive
    $name = 'GeneratedSampleProfile'
    try { $name = ('Generated-' + [System.IO.Path]::GetFileNameWithoutExtension($files[0])) -replace '[^A-Za-z0-9_.-]', '-' } catch { }
    $profile = ConvertTo-GeneratedProfile -Analysis $analysis -Name $name -IncludeSeeds:($optional.IncludeSeeds) -IncludeAllowlist:($optional.IncludeAllowlist)
    if ($ProtectGeneratedProfile) { $profile = Protect-UlsGeneratedProfile -Profile $profile }
    $profile = Merge-UlsGeneratedProfileWithBase -GeneratedProfile $profile -BaseProfile $BaseProfile -ProfileExtensionFile $ProfileExtensionFile
    $profile | ConvertTo-Json -Depth 8 | Set-Content -Path $outPath -Encoding UTF8
    [void](Test-ScrubProfile -Path $outPath -Quiet)
    $report = Write-ProfileBuilderReport -Analysis $analysis -Path $reportPath -ProfilePath $outPath
    Write-Ok "Generated profile: $outPath"
    Write-Warn "Profile build report is local-only: $report"
    if ($optional.SeedPath) { Write-Warn "Generated seeds are local-only: $($optional.SeedPath)" }
    if ($optional.AllowlistPath) { Write-Info "Generated allowlist: $($optional.AllowlistPath)" }
    return [pscustomobject]@{
        ProfilePath = $outPath
        ReportPath = $report
        Format = $analysis.Format
        FilesAnalyzed = $files.Count
        RowsAnalyzed = $analysis.Stats.Rows
        SeedPath = $optional.SeedPath
        AllowlistPath = $optional.AllowlistPath
        Protected = [bool]$ProtectGeneratedProfile
    }
}

function New-SafeScrubBundle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Results,
        [Parameter(Mandatory)][string]$OutputPath,
        [string]$WorkDir = '',
        [switch]$Force
    )
    $clean = @($Results | Where-Object { $_.Clean -and $_.Output -and (Test-Path -LiteralPath $_.Output) })
    if ($clean.Count -eq 0) { throw "No clean scrubbed outputs are available for bundling." }
    $out = Resolve-OutPath -Path $OutputPath
    if ((Test-Path -LiteralPath $out) -and -not $Force) { throw "Safe bundle already exists: $out. Use -Force to overwrite." }
    if ((Test-Path -LiteralPath $out) -and $Force) { Remove-Item -LiteralPath $out -Force }
    $stage = Join-Path ([System.IO.Path]::GetTempPath()) ("scrub_safe_bundle_" + ([System.IO.Path]::GetRandomFileName().Replace('.', '')))
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    try {
        $usedDest = @{}
        foreach ($r in $clean) {
            $rel = ''
            if (-not [string]::IsNullOrWhiteSpace($WorkDir)) {
                try { $rel = Get-UlsRelativePathForManifest -Path ([string]$r.Output) -BasePath $WorkDir } catch { }
            }
            if ([string]::IsNullOrWhiteSpace($rel)) { $rel = [System.IO.Path]::GetFileName([string]$r.Output) }
            $relParts = @($rel -split '[\\/]' | Where-Object { $_ -and $_ -ne '.' -and $_ -ne '..' } | ForEach-Object { ConvertTo-UlsSafePathSegment -Segment $_ })
            if ($relParts.Count -eq 0) { $relParts = @([System.IO.Path]::GetFileName([string]$r.Output)) }
            $dest = $stage
            foreach ($part in $relParts) { $dest = Join-Path $dest $part }
            $destKey = $dest.ToLowerInvariant()
            if ($usedDest.ContainsKey($destKey)) {
                $dir = Split-Path -Parent $dest
                $base = [System.IO.Path]::GetFileNameWithoutExtension($dest)
                $ext = [System.IO.Path]::GetExtension($dest)
                $dest = Join-Path $dir ("{0}_{1}{2}" -f $base,(Get-PathFingerprint -Path ([string]$r.Output) -Length 8),$ext)
                $destKey = $dest.ToLowerInvariant()
            }
            $usedDest[$destKey] = $true
            $destDir = Split-Path -Parent $dest
            if ($destDir -and -not (Test-Path -LiteralPath $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
            Copy-Item -LiteralPath $r.Output -Destination $dest -Force
        }
        $summary = @(
            'Universal Log Scrubber safe bundle',
            '',
            ('GeneratedUtc: {0}' -f ((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))),
            ('ScrubPolicy: {0}' -f $script:ScrubPolicy),
            ('CleanFiles: {0}' -f $clean.Count),
            '',
            'This bundle intentionally excludes token maps, salts, manifests, raw logs, and detailed detection reports.'
        ) -join "`r`n"
        [System.IO.File]::WriteAllText((Join-Path $stage 'SAFE_UPLOAD_README.txt'), $summary, [System.Text.Encoding]::UTF8)
        Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $out -Force
    }
    finally {
        try { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue } catch { }
    }
    Write-Ok "Safe upload bundle written: $out"
    return $out
}

# =====================================================================
# REGION: Pre-converters -- W3C/IIS logs and XLSX workbooks -> CSV
# =====================================================================
function ConvertFrom-W3CToCsv {
    param([Parameter(Mandatory)][string]$LogPath, [Parameter(Mandatory)][string]$OutCsv)
    Write-Work "Converting W3C/IIS -> CSV: $([System.IO.Path]::GetFileName($LogPath))"
    $fields = $null
    $rows = New-Object System.Collections.Generic.List[object]
    $reader = [System.IO.StreamReader]::new($LogPath)
    $lineNo = 0
    $dataRows = 0
    try {
        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            $lineNo++
            if ($null -eq $line) { break }
            if ($line.StartsWith('#')) {
                if ($line -match '^#Fields:\s*(.+)$') { $fields = @($matches[1].Trim() -split '\s+') }
                continue
            }
            if (-not $fields -or [string]::IsNullOrWhiteSpace($line)) { continue }
            $dataRows++
            if ($dataRows % 1000 -eq 0) {
                Write-UlsProgress -Activity "Convert W3C" -Phase ("lines {0}" -f $lineNo) -File ([System.IO.Path]::GetFileName($LogPath)) -RowsDone $dataRows
            }
            $vals = @($line -split '\s+')
            $obj = [ordered]@{}
            for ($i = 0; $i -lt $fields.Count; $i++) { $obj[$fields[$i]] = if ($i -lt $vals.Count) { $vals[$i] } else { '' } }
            $rows.Add([pscustomobject]$obj)
        }
    }
    finally {
        $reader.Close()
        Write-UlsProgress -Activity "Convert W3C" -File ([System.IO.Path]::GetFileName($LogPath)) -Completed
    }
    $out = Resolve-OutPath -Path $OutCsv
    if ($rows.Count -gt 0) { $rows | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8 }
    else { [pscustomobject]@{ Note = 'No data rows / no #Fields header found.' } | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8 }
    Write-Ok "W3C/IIS converted: $out  ($($rows.Count) rows)"
    Write-Detail "Note: this CSV is UNSCRUBBED -- it gets scrubbed next."
    return $out
}

# Best-effort native XLSX reader (first worksheet). Prefers the ImportExcel module
# when present. EXPERIMENTAL -- validate output before trusting it.
function ConvertFrom-XlsxToCsv {
    param([Parameter(Mandatory)][string]$XlsxPath, [Parameter(Mandatory)][string]$OutCsv)
    if (-not (Test-Path $XlsxPath)) { throw "XLSX not found: $XlsxPath" }
    Write-Work "Converting XLSX -> CSV: $([System.IO.Path]::GetFileName($XlsxPath))"
    if (Get-Command Import-Excel -ErrorAction SilentlyContinue) {
        $data = Import-Excel -Path $XlsxPath
        $out = Resolve-OutPath -Path $OutCsv
        $data | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8
        Write-Ok "XLSX converted via ImportExcel: $out"
        return $out
    }
    try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch { }
    $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path $XlsxPath).Path)
    try {
        $readEntry = {
            param($z, $rx)
            $e = $z.Entries | Where-Object { $_.FullName -match $rx } | Select-Object -First 1
            if (-not $e) { return $null }
            $sr = New-Object System.IO.StreamReader($e.Open())
            try { return $sr.ReadToEnd() } finally { $sr.Close() }
        }
        $shared = @()
        $ssXml = & $readEntry $zip '^xl/sharedStrings\.xml$'
        if ($ssXml) {
            [xml]$sx = $ssXml
            foreach ($si in $sx.sst.si) {
                if ($si.r) { $shared += (($si.r | ForEach-Object { [string]$_.t }) -join '') }
                elseif ($si.t -is [string]) { $shared += [string]$si.t }
                elseif ($si.t.'#text') { $shared += [string]$si.t.'#text' }
                else { $shared += '' }
            }
        }
        $sheetXml = & $readEntry $zip '^xl/worksheets/sheet1\.xml$'
        if (-not $sheetXml) { $sheetXml = & $readEntry $zip '^xl/worksheets/.*\.xml$' }
        if (-not $sheetXml) { throw "No worksheet found in workbook." }
        [xml]$sh = $sheetXml
        $colToIndex = {
            param($ref)
            $letters = ($ref -replace '\d', '')
            $idx = 0
            foreach ($ch in $letters.ToCharArray()) { $idx = $idx * 26 + ([int][char]([string]$ch).ToUpper()) - 64 }
            return $idx - 1
        }
        $parsed = @()
        $maxCol = 0
        foreach ($row in $sh.worksheet.sheetData.row) {
            $cells = @{}
            foreach ($c in @($row.c)) {
                $ci = if ($c.r) { & $colToIndex ([string]$c.r) } else { 0 }
                $val = ''
                if ($c.t -eq 's') { $ii = [int]$c.v; if ($ii -ge 0 -and $ii -lt $shared.Count) { $val = $shared[$ii] } }
                elseif ($c.t -eq 'inlineStr') { $val = [string]$c.is.t }
                else { $val = [string]$c.v }
                $cells[$ci] = $val
                if ($ci -gt $maxCol) { $maxCol = $ci }
            }
            $parsed += , $cells
        }
        if ($parsed.Count -eq 0) { throw "Worksheet has no rows." }
        $hc = $parsed[0]
        $headers = @()
        for ($i = 0; $i -le $maxCol; $i++) {
            $h = if ($hc.ContainsKey($i)) { [string]$hc[$i] } else { '' }
            if ([string]::IsNullOrWhiteSpace($h)) { $h = "Column$($i + 1)" }
            $headers += $h
        }
        $rowsOut = New-Object System.Collections.Generic.List[object]
        for ($r = 1; $r -lt $parsed.Count; $r++) {
            $obj = [ordered]@{}
            for ($i = 0; $i -le $maxCol; $i++) { $obj[$headers[$i]] = if ($parsed[$r].ContainsKey($i)) { [string]$parsed[$r][$i] } else { '' } }
            $rowsOut.Add([pscustomobject]$obj)
        }
        $out = Resolve-OutPath -Path $OutCsv
        if ($rowsOut.Count -gt 0) { $rowsOut | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8 }
        else { [pscustomobject]@{ Note = 'No data rows.' } | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8 }
        Write-Ok "XLSX converted (first sheet): $out  ($($rowsOut.Count) rows)"
        Write-Detail "Native reader = first sheet only; for multi-sheet books export each sheet to CSV."
        return $out
    }
    finally { $zip.Dispose() }
}

function Get-UlsOpenXmlEntryText {
    param(
        [Parameter(Mandatory)][System.IO.Compression.ZipArchive]$Zip,
        [Parameter(Mandatory)][string]$EntryName
    )

    $entry = $Zip.GetEntry($EntryName)
    if (-not $entry) { return '' }
    $sr = New-Object System.IO.StreamReader($entry.Open())
    try { $xmlText = $sr.ReadToEnd() } finally { $sr.Close() }
    if ([string]::IsNullOrWhiteSpace($xmlText)) { return '' }

    try { [xml]$xml = $xmlText } catch { return '' }
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($node in $xml.GetElementsByTagName('*')) {
        if ($node.LocalName -eq 't' -and $null -ne $node.InnerText) {
            $s = [string]$node.InnerText
            if (-not [string]::IsNullOrWhiteSpace($s)) { [void]$parts.Add($s) }
        }
        elseif ($node.LocalName -match '^(br|cr|p)$') {
            if ($parts.Count -gt 0 -and $parts[$parts.Count - 1] -ne '') { [void]$parts.Add('') }
        }
    }
    $text = (($parts.ToArray()) -join "`r`n")
    return ($text -replace "(`r`n){3,}", "`r`n`r`n").Trim()
}

function ConvertFrom-OpenXmlToText {
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$OutText,
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][string[]]$PartPatterns
    )

    if (-not (Test-Path -LiteralPath $InputPath)) { throw "$Kind not found: $InputPath" }
    try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch { }
    $name = [System.IO.Path]::GetFileName($InputPath)
    Write-Work "Converting $Kind -> text: $name"
    $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $InputPath).Path)
    $out = Resolve-OutPath -Path $OutText
    try {
        $entries = @($zip.Entries | Where-Object {
            $entryName = $_.FullName
            foreach ($pat in $PartPatterns) { if ($entryName -match $pat) { return $true } }
            return $false
        } | Sort-Object FullName)
        if ($entries.Count -eq 0) { throw "No readable OpenXML text parts were found." }

        $lines = New-Object System.Collections.Generic.List[string]
        $i = 0
        foreach ($entry in $entries) {
            $i++
            Write-UlsProgress -Activity "Convert $Kind" -File $name -RowsDone $i -RowsTotal $entries.Count
            $text = Get-UlsOpenXmlEntryText -Zip $zip -EntryName $entry.FullName
            if ([string]::IsNullOrWhiteSpace($text)) { continue }
            [void]$lines.Add(("## {0}" -f $entry.FullName))
            foreach ($line in ($text -split "`r?`n")) { [void]$lines.Add($line) }
            [void]$lines.Add('')
        }
        Write-UlsProgress -Activity "Convert $Kind" -File $name -Completed
        if ($lines.Count -eq 0) { throw "OpenXML package contained no extractable text." }
        [System.IO.File]::WriteAllLines($out, [string[]]$lines.ToArray(), [System.Text.Encoding]::UTF8)
        Write-Ok "$Kind converted to local text: $out"
        Write-Detail "Note: this text is UNSCRUBBED -- it gets scrubbed next."
        return $out
    }
    finally {
        try { $zip.Dispose() } catch { }
        Write-UlsProgress -Activity "Convert $Kind" -File $name -Completed
    }
}

function ConvertFrom-DocxToText {
    param([Parameter(Mandatory)][string]$DocxPath, [Parameter(Mandatory)][string]$OutText)
    return ConvertFrom-OpenXmlToText -InputPath $DocxPath -OutText $OutText -Kind 'DOCX' -PartPatterns @(
        '^word/document\.xml$',
        '^word/header\d*\.xml$',
        '^word/footer\d*\.xml$',
        '^word/footnotes\.xml$',
        '^word/endnotes\.xml$',
        '^word/comments.*\.xml$'
    )
}

function ConvertFrom-PptxToText {
    param([Parameter(Mandatory)][string]$PptxPath, [Parameter(Mandatory)][string]$OutText)
    return ConvertFrom-OpenXmlToText -InputPath $PptxPath -OutText $OutText -Kind 'PPTX' -PartPatterns @(
        '^ppt/slides/slide\d+\.xml$',
        '^ppt/notesSlides/notesSlide\d+\.xml$',
        '^ppt/comments/comment\d+\.xml$',
        '^ppt/commentAuthors\.xml$'
    )
}

# =====================================================================
# REGION: Streaming scrub (bounded memory, opt-in for very large files)
# =====================================================================
function Get-UlsCurrentModulePath {
    $modulePath = $null
    if ($PSCommandPath -and ([System.IO.Path]::GetExtension($PSCommandPath) -ieq '.psm1')) { $modulePath = $PSCommandPath }
    try {
        if (-not $modulePath -and $MyInvocation.MyCommand.Module -and $MyInvocation.MyCommand.Module.Path) {
            $candidate = $MyInvocation.MyCommand.Module.Path
            if ([System.IO.Path]::GetExtension($candidate) -ieq '.psm1') { $modulePath = $candidate }
            elseif ([System.IO.Path]::GetExtension($candidate) -ieq '.psd1') {
                $candidateModule = Join-Path (Split-Path -Parent $candidate) 'UniversalLogScrubber.psm1'
                if (Test-Path -LiteralPath $candidateModule) { $modulePath = $candidateModule }
            }
        }
    } catch { }
    if (-not $modulePath) { $modulePath = Join-Path $PSScriptRoot 'UniversalLogScrubber.psm1' }
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($modulePath)
}

function Get-UlsCSharpEngineSummary {
    return [pscustomobject]@{
        name     = 'CSharp'
        available = [bool]$script:CSharpAvailable
        version  = [string]$script:CSharpEngineVersion
        error    = [string]$script:CSharpFallbackReason
    }
}

function Invoke-UlsRunspaceBatchPool {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$WorkerScript,
        [Parameter(Mandatory)][scriptblock]$ReadBatch,
        [Parameter(Mandatory)][scriptblock]$HandleResult,
        [int]$ThrottleLimit = 4,
        [string]$Activity = 'Streaming parallel work',
        [long]$TotalBytes = 0,
        [long]$TotalRows = 0,
        [hashtable]$WorkerStatus = $null,
        [int]$ProgressIdBase = 4200
    )
    if ($ThrottleLimit -lt 1) { $ThrottleLimit = 1 }
    Write-UlsProgress -Activity $Activity -Reset

    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $ThrottleLimit)
    $pool.ApartmentState = 'MTA'
    $pool.Open()
    $progressCompleted = $false

    # Mutable state is stored in hashtable keys and updated through the indexer.
    # Avoid $state.Completed++ / $state.CompletedRows += ... here: under nested
    # scriptblocks and hashtable dot-notation, progress counters can appear to
    # reset or stop moving even though runspaces are doing work.
    $state = @{
        Running = (New-Object System.Collections.Generic.List[object])
        Submitted = [int64]0
        Completed = [int64]0
        SubmittedRows = [int64]0
        CompletedRows = [int64]0
        SubmittedBytes = [int64]0
        CompletedBytes = [int64]0
        StartedUtc = [datetime]::UtcNow
        LastProgressUpdate = [datetime]::UtcNow.AddSeconds(-10)
    }

    $writeProgress = {
        param([switch]$Force)
        $nowProgress = [datetime]::UtcNow
        $last = [datetime]$state['LastProgressUpdate']
        if (-not $Force -and (($nowProgress - $last).TotalMilliseconds -lt 500)) { return }

        $runningCount = 0
        try { $runningCount = $state['Running'].Count } catch { $runningCount = 0 }
        $progressBytes = [Math]::Max([int64]$state['CompletedBytes'], [int64]0)
        $progressRows = [Math]::Max([int64]$state['CompletedRows'], [int64]0)
        if ($null -ne $WorkerStatus) {
            $statusBytes = 0L
            $statusRows = 0L
            try {
                foreach ($statusEntry in @($WorkerStatus.Values)) {
                    try { $statusBytes += [int64]$statusEntry.BytesDone } catch { }
                    try { $statusRows += [int64]$statusEntry.FilesDone } catch { }
                }
            } catch { }
            if ($statusBytes -gt $progressBytes) { $progressBytes = $statusBytes }
            if ($statusRows -gt $progressRows) { $progressRows = $statusRows }
        }
        if ($TotalBytes -gt 0) { $progressBytes = [Math]::Min([int64]$TotalBytes, [int64]$progressBytes) }
        if ($TotalRows -gt 0) { $progressRows = [Math]::Min([int64]$TotalRows, [int64]$progressRows) }
        if ($null -ne $WorkerStatus) {
            $pct = -1
            if ($TotalBytes -gt 0) { $pct = [Math]::Min(100, [Math]::Max(0, [int](($progressBytes / [double]$TotalBytes) * 100))) }
            for ($wi = 0; $wi -lt $ThrottleLimit; $wi++) {
                $workerLine = 'Waiting'
                $workerPct = -1
                $entry = $null
                try { if ($WorkerStatus.ContainsKey([string]$wi)) { $entry = $WorkerStatus[[string]$wi] } } catch { }
                if ($entry) {
                    $workerBytesDone = 0L; $workerBytesTotal = 0L
                    try { $workerBytesDone = [int64]$entry.BytesDone } catch { }
                    try { $workerBytesTotal = [int64]$entry.BytesTotal } catch { }
                    if ($workerBytesTotal -gt 0) { $workerPct = [Math]::Min(100, [Math]::Max(0, [int](($workerBytesDone / [double]$workerBytesTotal) * 100))) }
                    $workerName = [string]$entry.Name
                    if ($workerName.Length -gt 58) { $workerName = $workerName.Substring(0,55) + '...' }
                    if ([bool]$entry.Done) {
                        $workerLine = ("Done - shard {0} files, {1:N1}/{2:N1} MB" -f [int]$entry.FilesDone, ($workerBytesDone / 1MB), ($workerBytesTotal / 1MB))
                    }
                    else {
                        $workerLine = ("shard file {0}/{1} - {2} - {3:N1}/{4:N1} MB" -f [int]$entry.FileIndex, [int]$entry.FileCount, $workerName, ($workerBytesDone / 1MB), ($workerBytesTotal / 1MB))
                    }
                }
                try {
                    if ($workerPct -ge 0) { Write-Progress -Id ($ProgressIdBase + $wi + 1) -Activity ("Worker {0}" -f ($wi + 1)) -Status $workerLine -PercentComplete $workerPct }
                    else { Write-Progress -Id ($ProgressIdBase + $wi + 1) -Activity ("Worker {0}" -f ($wi + 1)) -Status $workerLine }
                } catch { }
            }
            $elapsed = ''
            try {
                $elapsedSpan = [datetime]::UtcNow - ([datetime]$state['StartedUtc'])
                $elapsed = ("elapsed {0:hh\:mm\:ss}" -f $elapsedSpan)
            } catch { }
            $totalRowsForDisplay = if ($TotalRows -gt 0) { [int64]$TotalRows } else { [Math]::Max([int64]$state['SubmittedRows'], $progressRows) }
            $aggregate = ("files {0}/{1} | {2:N1}/{3:N1} MB | {4}" -f $progressRows, $totalRowsForDisplay, ($progressBytes / 1MB), ($TotalBytes / 1MB), $elapsed).Trim()
            try {
                if ($pct -ge 0) { Write-Progress -Id $ProgressIdBase -Activity $Activity -Status $aggregate -PercentComplete $pct }
                else { Write-Progress -Id $ProgressIdBase -Activity $Activity -Status $aggregate }
            } catch { }
        }
        else {
            $phaseBits = New-Object System.Collections.Generic.List[string]
            $totalRowsForDisplay = if ($TotalRows -gt 0) { [int64]$TotalRows } else { [Math]::Max([int64]$state['SubmittedRows'], $progressRows) }
            [void]$phaseBits.Add(("files {0}/{1}" -f $progressRows, $totalRowsForDisplay))
            Write-UlsProgress -Activity $Activity -Phase (($phaseBits.ToArray()) -join '; ') -RowsDone ([int64]$progressRows) -RowsTotal $totalRowsForDisplay -BytesDone ([int64]$progressBytes) -BytesTotal $TotalBytes -Workers $runningCount -Force:$Force -MinIntervalMs 500
        }
        $state['LastProgressUpdate'] = $nowProgress
    }

    $drainOne = {
        param([switch]$Wait)
        while ($true) {
            $running = $state['Running']
            $readyIndex = -1
            for ($i = 0; $i -lt $running.Count; $i++) {
                if ($running[$i].Async.IsCompleted) { $readyIndex = $i; break }
            }
            if ($readyIndex -lt 0) {
                if ($Wait -and $running.Count -gt 0) {
                    & $writeProgress
                    Start-Sleep -Milliseconds 50
                    continue
                }
                return $false
            }

            $item = $running[$readyIndex]
            $running.RemoveAt($readyIndex)
            try {
                try {
                    $resultCollection = $item.PowerShell.EndInvoke($item.Async)
                }
                catch {
                    throw ("Streaming parallel batch {0} failed: {1}" -f $item.BatchIndex, $_.Exception.Message)
                }
                foreach ($r in @($resultCollection)) { & $HandleResult $r }

                $state['Completed'] = [int64]$state['Completed'] + 1
                $state['CompletedRows'] = [int64]$state['CompletedRows'] + [int64]$item.Rows
                $state['CompletedBytes'] = [int64]$state['CompletedBytes'] + [int64]$item.Bytes
                & $writeProgress -Force
            }
            finally {
                try { $item.PowerShell.Dispose() } catch { }
            }
            return $true
        }
    }

    try {
        while ($true) {
            while ($state['Running'].Count -lt $ThrottleLimit) {
                $batch = & $ReadBatch
                if ($null -eq $batch) { break }

                $ps = [powershell]::Create()
                $ps.RunspacePool = $pool
                [void]$ps.AddScript($WorkerScript.ToString())
                foreach ($arg in ([object[]]$batch.Args)) { [void]$ps.AddArgument($arg) }
                $async = $ps.BeginInvoke()

                $batchRows = 0L; try { $batchRows = [int64]$batch.Rows } catch { }
                $batchBytes = 0L; try { $batchBytes = [int64]$batch.Bytes } catch { }
                $batchName = ''
                try { $batchName = [string]$batch.Name } catch { }
                [void]$state['Running'].Add([pscustomobject]@{ PowerShell = $ps; Async = $async; BatchIndex = $batch.Index; Rows = $batchRows; Bytes = $batchBytes; Name = $batchName })
                $state['Submitted'] = [int64]$state['Submitted'] + 1
                $state['SubmittedRows'] = [int64]$state['SubmittedRows'] + $batchRows
                $state['SubmittedBytes'] = [int64]$state['SubmittedBytes'] + $batchBytes
                & $writeProgress
            }

            if ($state['Running'].Count -eq 0) { break }
            [void](& $drainOne -Wait)
        }
        # Force a final 100% completion state before clearing the progress record.
        if ($TotalBytes -gt 0) { $state['CompletedBytes'] = [Math]::Max([int64]$state['CompletedBytes'], [int64]$TotalBytes) }
        if ($TotalRows -gt 0) { $state['CompletedRows'] = [Math]::Max([int64]$state['CompletedRows'], [int64]$TotalRows) }
        & $writeProgress -Force
        if ($null -ne $WorkerStatus) {
            try { Write-Progress -Id $ProgressIdBase -Activity $Activity -Completed } catch { }
            for ($wi = 0; $wi -lt $ThrottleLimit; $wi++) { try { Write-Progress -Id ($ProgressIdBase + $wi + 1) -Activity ("Worker {0}" -f ($wi + 1)) -Completed } catch { } }
        }
        else {
            Write-UlsProgress -Activity $Activity -Completed
        }
        $progressCompleted = $true
    }
    finally {
        if (-not $progressCompleted) {
            if ($null -ne $WorkerStatus) {
                try { Write-Progress -Id $ProgressIdBase -Activity $Activity -Completed } catch { }
                for ($wi = 0; $wi -lt $ThrottleLimit; $wi++) { try { Write-Progress -Id ($ProgressIdBase + $wi + 1) -Activity ("Worker {0}" -f ($wi + 1)) -Completed } catch { } }
            }
            else {
                try { Write-UlsProgress -Activity $Activity -Completed } catch { }
            }
        }
        try {
            foreach ($item in @($state['Running'])) {
                try { $item.PowerShell.Stop() } catch { }
                try { $item.PowerShell.Dispose() } catch { }
            }
        } catch { }
        try { $pool.Close() } catch { }
        try { $pool.Dispose() } catch { }
    }
}

# =====================================================================
# REGION: Self-test (synthetic data only -- validates a build with no real logs)
# =====================================================================
function Restore-ScrubbedFile {
    <#
      Un-scrub: replace tokens with their original values using your private token
      map, so a finding referenced by token can be turned back into the real value.
      Correlated aliases collapse to one token, so a token restores to its canonical
      original (an email is preferred when several aliases share a token).
    #>
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$TokenMapCsv,
        [Parameter(Mandatory)][string]$OutputPath
    )
    if (-not (Test-Path $InputPath)) { throw "Input not found: $InputPath" }
    if (-not (Test-Path $TokenMapCsv)) { throw "Token map not found: $TokenMapCsv" }
    $byToken = @{}
    foreach ($r in (Import-Csv $TokenMapCsv)) {
        $tok = [string]$r.Token; $orig = [string]$r.InputValue
        if ([string]::IsNullOrWhiteSpace($tok) -or [string]::IsNullOrWhiteSpace($orig)) { continue }
        if (-not $byToken.ContainsKey($tok)) { $byToken[$tok] = $orig }
        elseif (($orig -match '@') -and ($byToken[$tok] -notmatch '@')) { $byToken[$tok] = $orig }   # prefer an email alias
    }
    $text = [System.IO.File]::ReadAllText($InputPath)
    $rxTok = '(?:HV_|UNMAPPED_)?[A-Z0-9]+(?:_[A-Z0-9]+)*_[A-F0-9]{4,}|(?:BROAD|ADCS|HV_GROUP|BUILTIN)_[A-Z0-9_]+'
    $restored = [regex]::Replace($text, $rxTok, {
        param($m) if ($byToken.ContainsKey($m.Value)) { return $byToken[$m.Value] } else { return $m.Value }
    })
    $out = Resolve-OutPath -Path $OutputPath
    [System.IO.File]::WriteAllText($out, $restored, [System.Text.Encoding]::UTF8)
    Write-Ok "Restored: $out"
    return $out
}

# Generate a synthetic log for a given profile, with planted identifiers that MUST
# be removed and (optionally) values that MUST be preserved. Used by the self-test
# and handy for ad-hoc testing. Returns Path/ScrubProfile/Planted/Preserve/PreConvert.
function New-SyntheticLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Profile,
        [Parameter(Mandatory)][string]$Dir,
        [string]$Name
    )
    if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }
    $tab = "`t"
    $stem = if ($Name) { $Name } else { "syn_$Profile" }
    $scrubProfile = $Profile; $preConvert = $null; $ext = 'csv'
    $planted = @(); $preserve = @(); $lines = @()
    switch ($Profile) {
        'Generic' {
            $lines = @('User,Email,IP,Host,Note',
                       'CORP\jdoe,jdoe@corp.local,10.1.2.3,dc01.corp.local,ok',
                       'CORP\asmith,asmith@corp.local,10.1.2.4,web01.corp.local,visit https://portal.corp.local/x')
            $planted = @('CORP\jdoe','jdoe@corp.local','10.1.2.3','dc01.corp.local','portal.corp.local')
        }
        'CA' {
            $scrubProfile = 'CA'
            $lines = @('RequestID,RequesterName,SAN_UPN,CertSubject,EKU_OIDs,SerialNumber,Published',
                       '1001,CORP\svcweb$,svcweb@corp.local,"CN=web01.corp.local, O=Contoso",1.3.6.1.5.5.7.3.2; 1.3.6.1.4.1.311.20.2.2,1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d,True')
            $planted = @('CORP\svcweb$','svcweb@corp.local','web01.corp.local','1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d')
            $preserve = @('1.3.6.1.5.5.7.3.2')
        }
        'Tsv' {
            $ext = 'tsv'; $scrubProfile = 'Tsv'
            $lines = @("User${tab}Email${tab}IP", "CORP\bmiller${tab}bmiller@corp.local${tab}10.2.2.2")
            $planted = @('CORP\bmiller','bmiller@corp.local','10.2.2.2')
        }
        'Psv' {
            $ext = 'psv'; $scrubProfile = 'Psv'
            $lines = @('User|Email|IP', 'CORP\cwright|cwright@corp.local|10.3.3.3')
            $planted = @('CORP\cwright','cwright@corp.local','10.3.3.3')
        }
        'Syslog' {
            $ext = 'log'; $scrubProfile = 'Syslog'
            $lines = @('Jan  1 12:00:00 host01 sshd[111]: Accepted password for user1 from 10.4.4.4 port 22',
                       'Jan  1 12:00:01 host01 app: admin@corp.local connected to db.corp.local')
            $planted = @('10.4.4.4','admin@corp.local','db.corp.local')
        }
        'Apache' {
            $ext = 'log'; $scrubProfile = 'Apache'
            $lines = @('203.0.113.5 - bob [01/Jan/2025:00:00:00 +0000] "GET /index HTTP/1.1" 200 123 "https://ref.corp.local/" "Mozilla/5.0"')
            $planted = @('203.0.113.5','ref.corp.local')
        }
        'Cef' {
            $ext = 'log'; $scrubProfile = 'Cef'
            $lines = @('CEF:0|Vendor|Product|1.0|100|Login|5|src=10.5.5.5 suser=dwilson@corp.local dhost=app.corp.local')
            $planted = @('10.5.5.5','dwilson@corp.local','app.corp.local')
            $preserve = @('src=')
        }
        'Logfmt' {
            $ext = 'log'; $scrubProfile = 'Logfmt'
            $lines = @('level=info user=egarcia@corp.local ip=10.6.6.6 host=svc.corp.local msg="ok"')
            $planted = @('egarcia@corp.local','10.6.6.6','svc.corp.local')
            $preserve = @('level=info')
        }
        'WindowsEventCsv' {
            $scrubProfile = 'WindowsEventCsv'
            $lines = @('RecordId,TimeCreated,ProviderName,MachineName,UserId,Message',
                       '1,2025-01-01T00:00:00Z,Microsoft-Windows-Security-Auditing,WINDC01,S-1-5-21-111-222-333-1104,"Logon by CORP\fadmin from 10.7.7.7"')
            $planted = @('S-1-5-21-111-222-333-1104','CORP\fadmin','10.7.7.7')
            $preserve = @('2025-01-01T00:00:00Z')
        }
        'Text' {
            $ext = 'txt'; $scrubProfile = 'Text'
            $lines = @('Contact gharris@corp.local at 10.8.8.8 or visit files.corp.local')
            $planted = @('gharris@corp.local','10.8.8.8','files.corp.local')
        }
        'Json' {
            $ext = 'json'; $scrubProfile = 'Generic'
            $lines = @('{"user":"CORP\\hlee","ip":"10.9.0.1","host":"node.corp.local","ok":true,"count":5}')
            $planted = @('hlee','10.9.0.1','node.corp.local')
            $preserve = @('"count"')
        }
        'IIS' {
            $ext = 'log'; $scrubProfile = 'IIS'; $preConvert = 'W3C'
            $lines = @('#Software: Microsoft Internet Information Services 10.0',
                       '#Fields: date time c-ip cs-username cs-host cs-uri-stem sc-status',
                       '2025-01-01 00:00:00 10.10.0.1 CORP\iuser intranet.corp.local /home 200')
            $planted = @('10.10.0.1','CORP\iuser','intranet.corp.local')
            $preserve = @('2025-01-01')
        }
        default {
            $ext = 'txt'; $scrubProfile = 'Text'
            $lines = @('user test@corp.local ip 10.0.0.9 host generic.corp.local')
            $planted = @('test@corp.local','10.0.0.9','generic.corp.local')
        }
    }
    $path = Join-Path $Dir ("$stem.$ext")
    ($lines -join "`r`n") | Set-Content -Path $path -Encoding UTF8
    return [pscustomobject]@{ Path = $path; ScrubProfile = $scrubProfile; Planted = $planted; Preserve = $preserve; PreConvert = $preConvert }
}


# =====================================================================
# REGION: Scrub one file (CSV field-aware, JSON values-only, or whole-text)
# =====================================================================
function Get-ScrubbedOutPath {
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$OutDir,
        [string]$BasePath = '',
        [switch]$UseHash
    )
    $ext = [System.IO.Path]::GetExtension($InputPath)
    $stem = [System.IO.Path]::GetFileNameWithoutExtension($InputPath) -replace '(?i)_UNSCRUBBED$', ''
    if ($UseHash) { $stem = "{0}_{1}" -f $stem, (Get-PathFingerprint -Path $InputPath -Length 8) }
    $stem = Protect-UlsDerivedPathText -Text $stem
    $targetDir = $OutDir
    $relDir = Get-UlsRelativeDirectory -Path $InputPath -BasePath $BasePath
    if (-not [string]::IsNullOrWhiteSpace($relDir)) { $targetDir = Join-Path $OutDir (Protect-UlsDerivedRelativePath -Path $relDir) }
    if ($ext.ToLowerInvariant() -eq '.csv') { return (Join-Path $targetDir ("{0}_scrubbed.csv" -f $stem)) }
    return (Join-Path $targetDir ("{0}.scrubbed{1}" -f $stem, $ext))
}

function Invoke-ScrubFile {
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)]$Profile,
        [string[]]$SensitiveTerms = @(),
        [string[]]$AdditionalBroadLabels = @(),
        [string[]]$AllowlistFile = @(),
        [ValidateSet('Strict','Balanced','Readable')][string]$ScrubPolicy = $script:ScrubPolicy,
        [switch]$ExplainDetections,
        [string]$FalsePositiveReport,
        [switch]$DryRun
    )
    if (-not (Test-Path $InputPath)) { throw "Input not found: $InputPath" }
    $script:AdditionalBroadLabels = $AdditionalBroadLabels
    $script:ScrubPolicy = $ScrubPolicy
    if ($ExplainDetections) { $script:ExplainDetections = $true }
    if ($FalsePositiveReport) { $script:FalsePositiveReport = $FalsePositiveReport }
    Initialize-ScrubProfileRuntime -Profile $Profile -AllowlistFiles $AllowlistFile
    [void](Get-SessionSalt)
    $script:__scrubFallback = 0; $script:__scrubFallbackCol = ''
    $script:__cellCache = @{}   # ULS perf patch 1: fresh per-file (column,value)->scrubbed cache
    $script:__hmacTokenCache = @{}   # low-risk perf patch: fresh per-file fallback HMAC token cache

    $name = [System.IO.Path]::GetFileName($InputPath)
    $ext = [System.IO.Path]::GetExtension($InputPath).ToLowerInvariant()
    $format = $Profile.Format
    if ($format -eq 'Auto') {
        if ($ext -eq '.csv') { $format = 'Csv' }
        elseif ($ext -eq '.tsv') { $format = 'Tsv' }
        elseif ($ext -eq '.psv') { $format = 'Psv' }
        elseif ($ext -in @('.json','.ndjson','.jsonl')) { $format = 'Json' }
        else { $format = 'Text' }
    }
    # Delimiter for the CSV-family formats.
    $delim = ','
    try { if ($Profile.Delimiter) { $delim = [string]$Profile.Delimiter } } catch { }
    if ($format -eq 'Tsv') { $delim = "`t" }
    elseif ($format -eq 'Psv') { $delim = '|' }

    $outFull = Resolve-OutPath -Path $OutputPath
    $isWindowsEventXmlText = $false
    try { $isWindowsEventXmlText = (([string]$Profile.Name -ieq 'IntuneDiagnostics') -and (Test-UlsWindowsEventXmlTextFile -Path $InputPath)) } catch { $isWindowsEventXmlText = $false }

    if ($isWindowsEventXmlText -and -not $DryRun) {
        return Invoke-UlsWindowsEventXmlTextFileScrub -InputPath $InputPath -OutputPath $outFull -SensitiveTerms $SensitiveTerms
    }

    # --- Dry run: report what WOULD change, write nothing. ---
    if ($DryRun) {
        $changes = New-Object System.Collections.Generic.List[object]
        if ($format -eq 'Csv' -or $format -eq 'Tsv' -or $format -eq 'Psv') {
            $rn = 0; $seenPairs = @{}
            Import-Csv -Path $InputPath -Delimiter $delim | ForEach-Object {
                $row = $_
                $rn++
                if ($rn % 250 -eq 0) { Write-UlsProgress -Activity "Dry run" -Phase $format -File $name -RowsDone $rn }
                foreach ($prop in $row.PSObject.Properties) {
                    $cell = [string]$prop.Value
                    if ([string]::IsNullOrWhiteSpace($cell)) { continue }
                    try {
                        $s = [string](Scrub-Field -ColumnName $prop.Name -Value $cell -Profile $Profile)
                        $s = [string](Protect-SensitiveTerms -Text $s -SensitiveTerms $SensitiveTerms)
                        if (-not [string]::Equals($s, $cell)) {
                            $k = ([string]$prop.Name) + '|' + $cell
                            if (-not $seenPairs.ContainsKey($k)) { $seenPairs[$k] = $true; [void]$changes.Add([pscustomobject]@{ Field = [string]$prop.Name; Original = $cell; Token = $s }) }
                        }
                    }
                    catch {
                        $script:__scrubFallback = [int]$script:__scrubFallback + 1
                        if (-not $script:__scrubFallbackCol) { $script:__scrubFallbackCol = "col '$($prop.Name)' [$($_.Exception.GetType().Name)] $($_.Exception.Message)" }
                    }
                }
            }
            Write-UlsProgress -Activity "Dry run" -File $name -Completed
        }
        elseif ($format -eq 'Json') {
            $raw = [System.IO.File]::ReadAllText($InputPath)
            $jsonPreview = Invoke-ScrubJsonText -Text $raw -IsNdjson:($ext -ne '.json') -Profile $Profile -Changes $changes
            $jsonPreview = Protect-SensitiveTerms -Text $jsonPreview -SensitiveTerms $SensitiveTerms
            foreach ($term in $SensitiveTerms) {
                $t = ([string]$term).Trim()
                if ($t.Length -ge 3 -and $raw.IndexOf($t, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    $seedPrefix = if ($t -match '^(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$') { 'DNS' } else { 'X500' }
                    [void]$changes.Add([pscustomobject]@{ Field='(seed)'; Original=$t; Token=(Get-Token -Value $t -Prefix $seedPrefix) })
                }
            }
        }
        else {
            $text = [System.IO.File]::ReadAllText($InputPath)
            $seenPairs = @{}
            $dryRunIds = if ($isWindowsEventXmlText) { @(Find-UlsWindowsEventXmlTextFileIdentifiers -Path $InputPath) } else { @(Find-Identifiers -Text $text) }
            foreach ($id in $dryRunIds) {
                if (-not $seenPairs.ContainsKey($id.Raw)) { $seenPairs[$id.Raw] = $true; [void]$changes.Add([pscustomobject]@{ Field = '(text)'; Original = $id.Raw; Token = (Get-Token -Value $id.Raw -Prefix $id.Prefix) }) }
            }
            foreach ($term in $SensitiveTerms) {
                $t = ([string]$term).Trim()
                if ($t.Length -ge 3 -and $text.IndexOf($t, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and -not $seenPairs.ContainsKey($t)) {
                    $seedPrefix = if ($t -match '^(?=[A-Za-z0-9.\-]*[A-Za-z])[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$') { 'DNS' } else { 'X500' }
                    [void]$changes.Add([pscustomobject]@{ Field = '(seed)'; Original = $t; Token = (Get-Token -Value $t -Prefix $seedPrefix) })
                }
            }
        }
        Write-DryRunSummary -Name $name -Changes $changes
        if ($script:__scrubFallback -gt 0) { Write-Warn "$($script:__scrubFallback) cell(s) couldn't be fully hardened and were handled safely (fail-closed). First column: '$($script:__scrubFallbackCol)'." }
        if ($FalsePositiveReport) { [void](Write-DetectionReport -Path $FalsePositiveReport) }
        return [pscustomobject]@{ Input = $InputPath; Output = $null; Clean = $true; DryRun = $true; ChangeCount = $changes.Count }
    }

    if ($format -eq 'Csv' -or $format -eq 'Tsv' -or $format -eq 'Psv') {
        Write-Work "Scrubbing ($format, profile '$($Profile.Name)'): $name"
        $ulsPerfRead = New-UlsPerfStopwatch
        $raw = @(Import-Csv $InputPath -Delimiter $delim)
        Add-UlsPerfPhase -Phase 'Read CSV' -Stopwatch $ulsPerfRead -File $name -Rows $raw.Count -Notes 'Scrub Import-Csv'
        $total = $raw.Count
        $rn = 0
        $ulsPerfScrub = New-UlsPerfStopwatch
        $ulsPerfScrubColumnTicks = @{}
        $ulsPerfScrubColumnCounts = @{}
        $scrubbed = foreach ($row in $raw) {
            $rn++
            if ($rn % 250 -eq 0) {
                Write-UlsProgress -Activity "Scrub" -Phase $format -File $name -RowsDone $rn -RowsTotal $total
            }
            $new = [ordered]@{}
            foreach ($prop in $row.PSObject.Properties) {
                if ($script:PerfReportDetailedEnabled) {
                    $ulsPerfColBlock = [System.Diagnostics.Stopwatch]::StartNew()
                    $scrubbedValue = Scrub-Field -ColumnName $prop.Name -Value $prop.Value -Profile $Profile
                    $ulsPerfColBlock.Stop()
                    $colName = [string]$prop.Name
                    if (-not $ulsPerfScrubColumnTicks.ContainsKey($colName)) { $ulsPerfScrubColumnTicks[$colName] = [long]0; $ulsPerfScrubColumnCounts[$colName] = 0 }
                    $ulsPerfScrubColumnTicks[$colName] = [long]$ulsPerfScrubColumnTicks[$colName] + [long]$ulsPerfColBlock.ElapsedTicks
                    $ulsPerfScrubColumnCounts[$colName] = [int]$ulsPerfScrubColumnCounts[$colName] + 1
                    $new[$prop.Name] = $scrubbedValue
                }
                else {
                    $new[$prop.Name] = Scrub-Field -ColumnName $prop.Name -Value $prop.Value -Profile $Profile
                }
            }
            [pscustomobject]$new
        }
        Write-UlsProgress -Activity "Scrub" -File $name -Completed
        $ulsPerfCells = if ($total -gt 0) { $total * (@($raw[0].PSObject.Properties).Count) } else { 0 }
        Add-UlsPerfPhase -Phase 'Scrub fields' -Stopwatch $ulsPerfScrub -File $name -Rows $total -Cells $ulsPerfCells -Notes 'In-memory row/cell scrub'
        if ($script:PerfReportDetailedEnabled) {
            $freq = [double][System.Diagnostics.Stopwatch]::Frequency
            foreach ($col in ($ulsPerfScrubColumnTicks.Keys | Sort-Object)) {
                Add-UlsPerfPhase -Phase 'Scrub column' -Seconds ([double]$ulsPerfScrubColumnTicks[$col] / $freq) -File $name -Rows $total -Cells ([int]$ulsPerfScrubColumnCounts[$col]) -Notes ("Column=$col")
            }
        }

        # Per-cell hardening covers every column; render once, redact seed terms, write.
        $ulsPerfPost = New-UlsPerfStopwatch
        $csvText = (($scrubbed | ConvertTo-Csv -NoTypeInformation -Delimiter $delim) -join "`r`n") + "`r`n"
        $csvText = Protect-SensitiveTerms -Text $csvText -SensitiveTerms $SensitiveTerms
        Add-UlsPerfPhase -Phase 'Post hardening' -Stopwatch $ulsPerfPost -File $name -Rows $total -Cells $ulsPerfCells -Notes 'ConvertTo-Csv + sensitive terms'
        $ulsPerfWrite = New-UlsPerfStopwatch
        [System.IO.File]::WriteAllText($outFull, $csvText, [System.Text.Encoding]::UTF8)
        Add-UlsPerfPhase -Phase 'Write output' -Stopwatch $ulsPerfWrite -File $name -Rows $total -Notes 'WriteAllText'
        Write-Detail "Rows: $total  ->  $([System.IO.Path]::GetFileName($outFull))"
    }
    elseif ($format -eq 'Json') {
        $isNd = ($ext -ne '.json')
        Write-Work "Scrubbing (JSON$(if ($isNd) { ' lines' }), profile '$($Profile.Name)'): $name"
        $raw = [System.IO.File]::ReadAllText($InputPath)
        $jsonOut = Invoke-ScrubJsonText -Text $raw -IsNdjson:$isNd -Profile $Profile
        $jsonOut = Protect-SensitiveTerms -Text $jsonOut -SensitiveTerms $SensitiveTerms
        [System.IO.File]::WriteAllText($outFull, $jsonOut, [System.Text.Encoding]::UTF8)
        Write-Detail "Output: $([System.IO.Path]::GetFileName($outFull))"
    }
    elseif ($format -eq 'Kv') {
        Write-Work "Scrubbing (key=value, profile '$($Profile.Name)'): $name"
        Write-UlsProgress -Activity "Scrub" -Phase "read kv" -File $name -Force
        $text = [System.IO.File]::ReadAllText($InputPath)
        Write-UlsProgress -Activity "Scrub" -Phase "kv values" -File $name -Force
        $text = Invoke-KvValueOnlyText -Text $text
        Write-UlsProgress -Activity "Scrub" -Phase "harden" -File $name -Force
        $text = Invoke-LeakHardeningText -Text $text
        Write-UlsProgress -Activity "Scrub" -Phase "seed terms" -File $name -Force
        $text = Protect-SensitiveTerms -Text $text -SensitiveTerms $SensitiveTerms
        [System.IO.File]::WriteAllText($outFull, $text, [System.Text.Encoding]::UTF8)
        Write-UlsProgress -Activity "Scrub" -File $name -Completed
        Write-Detail "Output: $([System.IO.Path]::GetFileName($outFull))"
    }
    else {
        Write-Work "Scrubbing (text, profile '$($Profile.Name)'): $name"
        Write-UlsProgress -Activity "Scrub" -Phase "read text" -File $name -Force
        $text = [System.IO.File]::ReadAllText($InputPath)
        Write-Detail "Input size: $($text.Length) characters"
        Write-UlsProgress -Activity "Scrub" -Phase "harden" -File $name -Force
        $text = Invoke-LeakHardeningText -Text $text
        Write-UlsProgress -Activity "Scrub" -Phase "seed terms" -File $name -Force
        $text = Protect-SensitiveTerms -Text $text -SensitiveTerms $SensitiveTerms
        [System.IO.File]::WriteAllText($outFull, $text, [System.Text.Encoding]::UTF8)
        Write-UlsProgress -Activity "Scrub" -File $name -Completed
        Write-Detail "Output: $([System.IO.Path]::GetFileName($outFull))"
    }

    if ($script:__scrubFallback -gt 0) { Write-Warn "$($script:__scrubFallback) cell(s) couldn't be fully hardened and were replaced with a safe token (fail-closed, no leak). First column: '$($script:__scrubFallbackCol)'." }
    if ($FalsePositiveReport) { [void](Write-DetectionReport -Path $FalsePositiveReport) }
    $outBytes = 0L
    try { $outBytes = [int64](Get-Item -LiteralPath $outFull).Length } catch { }
    return [pscustomobject]@{ Input = $InputPath; Output = $outFull; Clean = $true; Engine = 'PowerShell'; Format = $format; OutputBytes = $outBytes }
}

# =====================================================================
# REGION: Run manifest
# =====================================================================
function Get-SaltFingerprint {
    $salt = Get-SessionSalt
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($salt)) } finally { $sha.Dispose() }
    return (ConvertTo-HexString -Bytes $bytes).Substring(0, 12).ToUpperInvariant()
}

function Write-RunManifest {
    param(
        [Parameter(Mandatory)][string]$WorkDir,
        [Parameter(Mandatory)][array]$Results,
        [string]$TokenMapCsv,
        [string]$TokenMapMode = $script:TokenMapMode,
        [array]$SkippedFiles = @(),
        [string]$InputRoot = '',
        [string]$OutputRoot = '',
        [int]$ConvertedFiles = 0
    )
    $manifestSw = New-UlsPerfStopwatch
    Write-Info "Building manifest summary..."
    $failedEntries = @()
    $skippedEntries = @()
    $engineCounts = @{}
    $formatCounts = @{}
    $totalBytes = 0L
    $totalRows = 0L
    $totalReplacements = 0L
    foreach ($r in $Results) {
        if (-not $r) { continue }
        $fileName = if ($r.Output) { [System.IO.Path]::GetFileName($r.Output) } else { [System.IO.Path]::GetFileName($r.Input) }
        $engine = if ($r.Engine) { [string]$r.Engine } else { 'PowerShell' }
        if (-not $engineCounts.ContainsKey($engine)) { $engineCounts[$engine] = 0 }
        $engineCounts[$engine] = [int]$engineCounts[$engine] + 1
        $fmt = if ($r.Format) { [string]$r.Format } else { 'Unknown' }
        if (-not $formatCounts.ContainsKey($fmt)) { $formatCounts[$fmt] = 0 }
        $formatCounts[$fmt] = [int]$formatCounts[$fmt] + 1
        try { if ($null -ne $r.Rows -and [int64]$r.Rows -gt 0) { $totalRows += [int64]$r.Rows } } catch { }
        try { if ($null -ne $r.Replacements -and [int64]$r.Replacements -gt 0) { $totalReplacements += [int64]$r.Replacements } } catch { }
        try {
            if ($null -ne $r.OutputBytes -and [int64]$r.OutputBytes -gt 0) {
                $totalBytes += [int64]$r.OutputBytes
            }
            elseif ($null -ne $r.Bytes -and [int64]$r.Bytes -gt 0) {
                $totalBytes += [int64]$r.Bytes
            }
            elseif ($r.Output -and (Test-Path -LiteralPath ([string]$r.Output))) {
                $totalBytes += [int64](Get-Item -LiteralPath ([string]$r.Output)).Length
            }
        } catch { }
        if (-not [bool]$r.Clean -or -not [string]::IsNullOrWhiteSpace([string]$r.Error)) {
            $inputRel = ''
            $outputRel = ''
            try { $inputRel = Get-UlsRelativePathForManifest -Path ([string]$r.Input) -BasePath $InputRoot } catch { }
            try { $outputRel = Get-UlsRelativePathForManifest -Path ([string]$r.Output) -BasePath $WorkDir } catch { }
            $failedEntries += [pscustomobject]@{
                file                = $fileName
                inputRelativePath   = $inputRel
                outputRelativePath  = $outputRel
                inputPathHash       = if ($r.Input) { Get-PathFingerprint -Path $r.Input -Length 12 } else { "" }
                scrubbedPath        = if ($r.Output) { [string]$r.Output } else { "" }
                error               = [string]$r.Error
            }
        }
    }
    foreach ($s in @($SkippedFiles)) {
        if (-not $s) { continue }
        $sp = ''
        try { $sp = [string]$s.path } catch { $sp = '' }
        $rel = ''
        try { $rel = Get-UlsRelativePathForManifest -Path $sp -BasePath $InputRoot } catch { }
        $sn = ''; try { $sn = [string]$s.name } catch { $sn = [System.IO.Path]::GetFileName($sp) }
        $se = ''; try { $se = [string]$s.extension } catch { $se = [System.IO.Path]::GetExtension($sp) }
        $sb = -1L; try { $sb = [int64]$s.bytes } catch { $sb = -1L }
        $sr = ''; try { $sr = [string]$s.reason } catch { }
        $sa = ''; try { $sa = [string]$s.actionRequired } catch { }
        $skippedEntries += [pscustomobject]@{
            path              = $sp
            relativePath      = $rel
            name              = $sn
            extension         = $se
            bytes             = $sb
            reason            = $sr
            actionRequired    = $sa
        }
    }
    $okCount = @($Results | Where-Object { $_ -and $_.Clean }).Count
    $badCount = @($Results | Where-Object { $_ -and -not $_.Clean }).Count
    $manifest = [pscustomobject]@{
        tool            = "UniversalLogScrubber.psm1"
        toolVersion     = $script:ModuleVersion
        schemaVersion   = "1.0"
        generatedUtc    = ((Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"))
        saltFingerprint = (Get-SaltFingerprint)
        hmacLength      = $script:HmacLength
        scrubPolicy     = $script:ScrubPolicy
        processingEngine = (Get-UlsCSharpEngineSummary)
        tokenMapCsv     = $TokenMapCsv
        tokenMapMode    = $TokenMapMode
        inputRoot       = $InputRoot
        outputRoot      = if ([string]::IsNullOrWhiteSpace($OutputRoot)) { $WorkDir } else { $OutputRoot }
        summary         = [pscustomobject]@{
            totalFiles        = @($Results).Count
            scrubbedFiles     = $okCount
            failedFiles       = $badCount
            skippedFiles      = @($skippedEntries).Count
            convertedFiles    = $ConvertedFiles
            mapRows           = @($script:TokenByNorm.Keys).Count
            engine            = 'CSharp'
            outputBytes       = $totalBytes
            rows              = $totalRows
            replacements      = $totalReplacements
            engineCounts      = $engineCounts
            formatCounts      = $formatCounts
        }
        failedFiles     = @($failedEntries)
        skippedFiles    = @($skippedEntries)
    }
    $out = Resolve-OutPath -Path (Join-Path $WorkDir "scrub_run_manifest.json")
    Write-Info "Writing manifest JSON..."
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -Path $out -Encoding UTF8
    Write-Ok "Run manifest written: $out"
    Add-UlsPerfPhase -Phase 'Write manifest' -Stopwatch $manifestSw -File ([System.IO.Path]::GetFileName($out)) -Rows @($Results).Count -Notes ("skipped={0}; failed={1}; outputBytes={2}" -f @($skippedEntries).Count, $failedEntries.Count, $totalBytes)
    return $out
}

# =====================================================================
# REGION: Interactive driver
# =====================================================================
function Invoke-UniversalScrubber {
        [CmdletBinding()]
    param(
        [switch]$Version,
        [string]$Path,
        [string]$WorkDir,
        [switch]$RecommendOnly,
        [switch]$SafeFirstRun,
        [switch]$AutoProfile,
        [string]$Salt,
        [int]$HmacLength = 24,
        [string]$Profile,
        [string]$ProfileFile,
        [string[]]$ProfileExtensionFile,
        [string]$TokenMapCsv,
        [ValidateSet('Discover','ExistingMap','AD')][string]$MapSource,
        [ValidateSet('Merge','Replace')][string]$TokenMapMode = 'Merge',
        [string[]]$SensitiveTerms,
        [Alias('SeedTermsFile')][string[]]$SensitiveTermsFile,
        [string[]]$SeedFile,
        [string[]]$AllowlistFile,
        [ValidateSet('Generic','Csv','Json','Kv','WebAccess','Cloud','App')][string]$ProfileTemplate,
        [switch]$BuildProfileFromSample,
        [string]$ProfileOut,
        [string]$ProfileReportOut,
        [string]$BaseProfile,
        [switch]$ProfileWizard,
        [int]$MaxSampleRows = 500,
        [ValidateSet('Auto','Csv','Json','Kv','Text')][string]$SampleFormat = 'Auto',
        [switch]$ProtectGeneratedProfile,
        [string]$SafeBundleOut,
        [switch]$Force,
        [ValidateSet('Strict','Balanced','Readable')][string]$ScrubPolicy = 'Balanced',
        [switch]$ExplainDetections,
        [string]$FalsePositiveReport,
        [string]$DetectionSummaryReport,
        [string]$SaltFromEnv,
        [string]$SaltFile,
        [switch]$KeepIntermediate,
        [switch]$ExtractCab,
        [switch]$ConvertEtl,
        [switch]$Recurse,
        [string[]]$Include,
        [string[]]$Exclude,
        [switch]$DryRun,
        [switch]$NoCorrelate,
        [switch]$PerfReport,
        [switch]$PerfReportDetailed,
        [switch]$DiscoveryOnly,
        [switch]$PassThru,
        [int]$ThrottleLimit = 4,
        [int]$LargeFileThresholdMB = 100,
        [switch]$NonInteractive
    )

    if ($Version) { return Get-UniversalLogScrubberVersionInfo }

    if ($LargeFileThresholdMB -lt 1) { $LargeFileThresholdMB = 100 }
    if ($ThrottleLimit -lt 1) { $ThrottleLimit = 1 }

    $script:HmacLength = $HmacLength
    $script:ScrubPolicy = $ScrubPolicy
    $script:TokenMapMode = $TokenMapMode
    $script:ExplainDetections = [bool]$ExplainDetections
    $script:FalsePositiveReport = $FalsePositiveReport
    $script:DetectionSummaryReport = $DetectionSummaryReport
    $script:DetectionTrace = New-Object System.Collections.Generic.List[object]
    $script:DetectionTraceSeen = @{}
    $script:DetectionCounts = @{}
    $script:PerfReportEnabled = [bool]($PerfReport -or $PerfReportDetailed)
    $script:PerfReportDetailedEnabled = [bool]$PerfReportDetailed
    $script:PerfReportRows = New-Object System.Collections.Generic.List[object]
    $script:PerfReportPath = $null
    $script:PerfReportTextPath = $null
    $script:DerivedPathProtectionCache = @{}

    Write-Banner ">_ ULS  v$script:ModuleVersion" "   map first  ::  scrub second  ::  package safely"
    [void](Initialize-UlsCSharpProcessingEngine -ThrowOnFailure)
    if ($RecommendOnly) { Write-Info "RECOMMEND ONLY mode -- local sample analysis only." }
    if ($SafeFirstRun) { Write-Info "SAFE FIRST RUN mode -- local sample analysis only." }
    if ($AutoProfile) { Write-Info "AUTO PROFILE mode -- use one high-confidence recommendation when possible." }
    if ($DryRun) { Write-Info "DRY RUN mode -- nothing will be written." }
    if ($PerfReport -or $PerfReportDetailed) { Write-Info "PERF REPORT mode -- phase timings will be written locally." }
    if ($PerfReportDetailed) { Write-Info "PERF REPORT DETAILED mode -- per-column timings add overhead and should not be used for baseline timings." }
    if ($ExtractCab) { Write-Detail "CAB extraction enabled; supported extracted contents will be scrubbed locally." }
    Write-Detail ("Large-file auto threshold: {0} MB." -f $LargeFileThresholdMB)
    Write-Detail "Scrub policy: $script:ScrubPolicy"

    if ($RecommendOnly -or $SafeFirstRun) {
        if ([string]::IsNullOrWhiteSpace($Path)) {
            if ($NonInteractive) { throw "Path is required in -NonInteractive recommendation mode." }
            Write-Host ""
            Write-Step "What log file or folder should be analyzed?"
            $Path = Read-DefaultString -Prompt "Path to a log file OR a folder of logs"
        }
        $recs = Test-LogFormat -Path $Path -Recurse:$Recurse -Include $Include -Exclude $Exclude -Quiet
        Write-LogFormatRecommendationSummary -Recommendations $recs -SafeFirstRun:$SafeFirstRun -Title 'Recommendation summary'
        return $recs
    }

    if ($SaltFile) {
        if (-not (Test-Path $SaltFile)) { throw "Salt file not found: $SaltFile" }
        $Salt = ([System.IO.File]::ReadAllText((Resolve-Path -Path $SaltFile).Path)).Trim()
    }
    elseif ($SaltFromEnv) {
        $Salt = [Environment]::GetEnvironmentVariable($SaltFromEnv)
        if ([string]::IsNullOrWhiteSpace($Salt)) { throw "Environment variable '$SaltFromEnv' is empty or not set." }
    }
    if ($Salt) { $script:Salt = $Salt }

    # --- Working directory ---
    if ([string]::IsNullOrWhiteSpace($WorkDir)) {
        if ($NonInteractive) { $WorkDir = (Get-Location).Path }
        else { $WorkDir = Read-DefaultString -Prompt "Working folder for outputs" -Default (Get-Location).Path }
    }
    $WorkDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($WorkDir)
    if (-not (Test-Path $WorkDir)) { New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null }
    if ($ExplainDetections -and [string]::IsNullOrWhiteSpace($FalsePositiveReport)) {
        $FalsePositiveReport = Join-Path $WorkDir 'detection_review_DO_NOT_UPLOAD.csv'
        $script:FalsePositiveReport = $FalsePositiveReport
        Write-Warn "Detection review report will be written locally: $FalsePositiveReport"
    }
    elseif (-not [string]::IsNullOrWhiteSpace($FalsePositiveReport)) {
        $script:FalsePositiveReport = $FalsePositiveReport
    }
    Write-Info "Working folder: $WorkDir"
    $skippedFiles = New-Object System.Collections.Generic.List[object]
    $cabExtractionRoots = New-Object System.Collections.Generic.List[string]
    $intermediateTargets = @()

    if ($ProfileTemplate) {
        $templatePath = Join-Path $WorkDir ("profile-template-{0}.json" -f $ProfileTemplate.ToLowerInvariant())
        $written = New-ScrubProfileTemplate -Template $ProfileTemplate -OutputPath $templatePath
        Write-Info "Edit this template, then run with -ProfileFile $written."
        return [pscustomobject]@{ ProfileTemplate = $ProfileTemplate; OutputPath = $written }
    }

    if ($BuildProfileFromSample) {
        if ([string]::IsNullOrWhiteSpace($Path)) {
            if ($NonInteractive) { throw "Path is required with -BuildProfileFromSample in -NonInteractive mode." }
            Write-Host ""
            Write-Step "What sample should be analyzed?"
            $Path = Read-DefaultString -Prompt "Path to a sample log file OR folder"
        }
        if ([string]::IsNullOrWhiteSpace($ProfileOut)) { $ProfileOut = Join-Path $WorkDir 'generated-profile.json' }
        if ([string]::IsNullOrWhiteSpace($ProfileReportOut)) { $ProfileReportOut = Join-Path $WorkDir 'profile_build_report_DO_NOT_UPLOAD.md' }
        return New-ScrubProfileFromSample -Path $Path -ProfileOut $ProfileOut -ProfileReportOut $ProfileReportOut -BaseProfile $BaseProfile -ProfileExtensionFile $ProfileExtensionFile -ProfileWizard:$ProfileWizard -MaxSampleRows $MaxSampleRows -SampleFormat $SampleFormat -ProtectGeneratedProfile:$ProtectGeneratedProfile -Salt $Salt -SaltFromEnv $SaltFromEnv -SaltFile $SaltFile -HmacLength $HmacLength -Force:$Force -NonInteractive
    }

    # --- Input file(s) ---
    if ([string]::IsNullOrWhiteSpace($Path)) {
        if ($NonInteractive) { throw "Path is required in -NonInteractive mode." }
        Write-Host ""
        Write-Step "What do you want to scrub?"
        $Path = Read-DefaultString -Prompt "Path to a log file OR a folder of logs"
    }
    $targets = @()
    $inputRoot = ''
    if (Test-Path $Path -PathType Container) {
        $inputRoot = (Resolve-Path -LiteralPath $Path).Path
        $targets = @(Get-ChildItem -Path $Path -File -Recurse:$Recurse -ErrorAction SilentlyContinue |
            Where-Object { -not (Test-GeneratedScrubArtifactName -Name $_.Name) })
        if ($Include -and $Include.Count -gt 0) {
            $targets = @($targets | Where-Object {
                $n = $_.Name; $ok = $false
                foreach ($pat in $Include) { if ($n -like $pat) { $ok = $true; break } }
                $ok
            })
        }
        if ($Exclude -and $Exclude.Count -gt 0) {
            $targets = @($targets | Where-Object {
                $n = $_.Name; $skip = $false
                foreach ($pat in $Exclude) { if ($n -like $pat) { $skip = $true; break } }
                -not $skip
            })
        }
    }
    elseif (Test-Path $Path -PathType Leaf) {
        $targets = @(Get-Item $Path)
    }
    else { throw "Path not found: $Path" }

    $classifiedTargets = New-Object System.Collections.Generic.List[object]
    foreach ($t in @($targets | Sort-Object FullName)) {
        $ext = ''
        try { $ext = ([string]$t.Extension).ToLowerInvariant() } catch { }
        if ([int64]$t.Length -eq 0) {
            [void]$skippedFiles.Add((New-UlsSkippedFileRecord -File $t -Reason 'Empty file' -ActionRequired 'No action required.'))
            continue
        }
        if ($ext -eq '.cab') {
            if (-not $ExtractCab) {
                [void]$skippedFiles.Add((New-UlsSkippedFileRecord -File $t -Reason 'CAB archive was not extracted' -ActionRequired 'Re-run with -ExtractCab to extract and scrub supported contents.'))
                continue
            }
            if ($DryRun) {
                [void]$skippedFiles.Add((New-UlsSkippedFileRecord -File $t -Reason 'CAB extraction is disabled during dry-run' -ActionRequired 'Run without -DryRun to extract and scrub supported contents.'))
                continue
            }
            try {
                $expanded = Expand-UlsCabArchive -File $t -WorkDir $WorkDir
                if ($expanded.Root) { [void]$cabExtractionRoots.Add([string]$expanded.Root) }
                $expandedFiles = @($expanded.Files)
                if ($expandedFiles.Count -eq 0) {
                    [void]$skippedFiles.Add((New-UlsSkippedFileRecord -File $t -Reason 'CAB archive contained no files' -ActionRequired 'No supported content was available to scrub.'))
                    continue
                }
                foreach ($ef in $expandedFiles) {
                    $efExt = ''
                    try { $efExt = ([string]$ef.Extension).ToLowerInvariant() } catch { }
                    if ([int64]$ef.Length -eq 0) {
                        [void]$skippedFiles.Add((New-UlsSkippedFileRecord -File $ef -Reason 'Empty file' -ActionRequired 'No action required.'))
                    }
                    elseif ($efExt -eq '.cab') {
                        [void]$skippedFiles.Add((New-UlsSkippedFileRecord -File $ef -Reason 'Nested CAB archive was not extracted' -ActionRequired 'Extract the nested archive locally, then scrub the supported contents.'))
                    }
                    else {
                        [void]$classifiedTargets.Add($ef)
                        $intermediateTargets += $ef
                    }
                }
            }
            catch {
                [void]$skippedFiles.Add((New-UlsSkippedFileRecord -File $t -Reason ("CAB extraction failed: {0}" -f $_.Exception.Message) -ActionRequired 'Confirm the archive opens locally, then retry with -ExtractCab.'))
            }
            continue
        }
        [void]$classifiedTargets.Add($t)
    }
    $targets = @($classifiedTargets.ToArray() | Sort-Object FullName)
    if ($targets.Count -eq 0) {
        if ($skippedFiles.Count -gt 0) {
            foreach ($s in @($skippedFiles.ToArray())) { Write-Detail ("Skipped {0}: {1}" -f $s.name, $s.reason) }
        }
        throw "No supported non-empty files found to scrub: $Path"
    }
    if (Test-Path $Path -PathType Container) {
        $skipSummary = if ($skippedFiles.Count -gt 0) { "; skipped $($skippedFiles.Count)." } else { "." }
        Write-Ok "Found $($targets.Count) file(s) to scrub$skipSummary"
        $targetMix = @(
            $targets |
                Group-Object { $ext = ([string]$_.Extension).ToLowerInvariant(); if ([string]::IsNullOrWhiteSpace($ext)) { '(no extension)' } else { $ext } } |
                Sort-Object Count -Descending |
                ForEach-Object { "{0}={1}" -f $_.Name,$_.Count }
        )
        if ($targetMix.Count -gt 0) { Write-Info ("Target mix: {0}" -f ($targetMix -join '; ')) }
    }
    else {
        Write-Ok "Target: $($targets[0].Name)"
        if ($skippedFiles.Count -gt 0) { Write-Info "Skipped $($skippedFiles.Count) unsupported/empty file(s)." }
    }

    if ($AutoProfile -and -not $Profile -and -not $ProfileFile) {
        $autoRecs = @()
        foreach ($t in $targets) { $autoRecs += Get-LogFormatRecommendation -File $t -SampleLines 50 }
        $confident = @($autoRecs | Where-Object { $_.Confidence -ge 80 -and (Get-ScrubProfile -Name $_.SuggestedProfile) })
        $profiles = @($confident | Select-Object -ExpandProperty SuggestedProfile -Unique)
        if ($autoRecs.Count -gt 0 -and $confident.Count -eq $autoRecs.Count -and $profiles.Count -eq 1) {
            $Profile = [string]$profiles[0]
            Write-Ok "AutoProfile selected: $Profile"
        }
        else {
            Write-LogFormatRecommendationSummary -Recommendations $autoRecs -Title 'AutoProfile recommendations'
            if ($NonInteractive) {
                throw "AutoProfile could not choose one high-confidence profile for all selected files. Pass -Profile explicitly or split files by type."
            }
            Write-Warn "AutoProfile could not choose one profile; falling back to the interactive profile picker."
        }
    }

    # --- Pre-convert special inputs (EVTX / XLSX / Office / W3C-IIS) locally before scrubbing ---
    $evtxConverted = $false
    $iisConverted = $false
    $convertedFileCount = 0
    if (@($targets | Where-Object { $_.Extension -imatch '^\.(evtx|evt|etl|xlsx|docx|pptx|doc|ppt|log)$' }).Count -gt 0) {
        Write-Host ""
        Write-Step "Preparing special inputs (event logs / ETL / workbooks / Office / IIS logs)"
        $conversionNameCounts = @{}
        foreach ($ct in $targets) {
            $cext = ([string]$ct.Extension).ToLowerInvariant()
            $suffix = if ($cext -eq '.evtx') { '.evtx.events.txt' } elseif ($cext -eq '.evt') { '.evt.events.txt' } elseif ($cext -eq '.etl') { '.etl.events.txt' } elseif ($cext -eq '.xlsx') { '.xlsx.csv' } elseif ($cext -eq '.docx') { '.docx.txt' } elseif ($cext -eq '.pptx') { '.pptx.txt' } elseif ($cext -eq '.log') { '.w3c.csv' } else { $null }
            if (-not $suffix) { continue }
            $ctx = Get-UlsOutputContext -InputPath $ct.FullName -WorkDir $WorkDir -InputRoot $inputRoot -CabExtractionRoots @($cabExtractionRoots.ToArray())
            $key = (Get-SafeDerivedPath -InputPath $ct.FullName -OutDir $ctx.OutDir -BasePath $ctx.BasePath -Suffix $suffix).ToLowerInvariant()
            if (-not $conversionNameCounts.ContainsKey($key)) { $conversionNameCounts[$key] = 0 }
            $conversionNameCounts[$key] = [int]$conversionNameCounts[$key] + 1
        }
        $newTargets = @()
        foreach ($t in $targets) {
            $ext2 = ([string]$t.Extension).ToLowerInvariant()
            $converted = $null
            try {
                if ($ext2 -eq '.evtx') {
                    $ctx = Get-UlsOutputContext -InputPath $t.FullName -WorkDir $WorkDir -InputRoot $inputRoot -CabExtractionRoots @($cabExtractionRoots.ToArray())
                    $key = (Get-SafeDerivedPath -InputPath $t.FullName -OutDir $ctx.OutDir -BasePath $ctx.BasePath -Suffix '.evtx.events.txt').ToLowerInvariant()
                    $outTxt = Get-SafeDerivedPath -InputPath $t.FullName -OutDir $ctx.OutDir -BasePath $ctx.BasePath -Suffix '.evtx.events.txt' -UseHash:($conversionNameCounts[$key] -gt 1)
                    [void](ConvertFrom-EvtxToEventXmlText -EvtxPath $t.FullName -OutText $outTxt)
                    if (Test-Path -LiteralPath $outTxt) { $converted = Get-Item -LiteralPath $outTxt; $evtxConverted = $true; $convertedFileCount++ }
                }
                elseif ($ext2 -eq '.evt') {
                    $ctx = Get-UlsOutputContext -InputPath $t.FullName -WorkDir $WorkDir -InputRoot $inputRoot -CabExtractionRoots @($cabExtractionRoots.ToArray())
                    $key = (Get-SafeDerivedPath -InputPath $t.FullName -OutDir $ctx.OutDir -BasePath $ctx.BasePath -Suffix '.evt.events.txt').ToLowerInvariant()
                    $outTxt = Get-SafeDerivedPath -InputPath $t.FullName -OutDir $ctx.OutDir -BasePath $ctx.BasePath -Suffix '.evt.events.txt' -UseHash:($conversionNameCounts[$key] -gt 1)
                    [void](ConvertFrom-EvtxToEventXmlText -EvtxPath $t.FullName -OutText $outTxt)
                    if (Test-Path -LiteralPath $outTxt) { $converted = Get-Item -LiteralPath $outTxt; $evtxConverted = $true; $convertedFileCount++ }
                }
                elseif ($ext2 -eq '.etl') {
                    if (-not $ConvertEtl) {
                        throw "ETL file '$($t.Name)' requires -ConvertEtl to run local EventLogReader conversion, or convert the ETL to XML/text yourself and scrub the converted output."
                    }
                    $ctx = Get-UlsOutputContext -InputPath $t.FullName -WorkDir $WorkDir -InputRoot $inputRoot -CabExtractionRoots @($cabExtractionRoots.ToArray())
                    $key = (Get-SafeDerivedPath -InputPath $t.FullName -OutDir $ctx.OutDir -BasePath $ctx.BasePath -Suffix '.etl.events.txt').ToLowerInvariant()
                    $outTxt = Get-SafeDerivedPath -InputPath $t.FullName -OutDir $ctx.OutDir -BasePath $ctx.BasePath -Suffix '.etl.events.txt' -UseHash:($conversionNameCounts[$key] -gt 1)
                    [void](ConvertFrom-EtlToEventXmlText -EtlPath $t.FullName -OutText $outTxt)
                    if (Test-Path -LiteralPath $outTxt) { $converted = Get-Item -LiteralPath $outTxt; $evtxConverted = $true; $convertedFileCount++ }
                }
                elseif ($ext2 -eq '.xlsx') {
                    $ctx = Get-UlsOutputContext -InputPath $t.FullName -WorkDir $WorkDir -InputRoot $inputRoot -CabExtractionRoots @($cabExtractionRoots.ToArray())
                    $key = (Get-SafeDerivedPath -InputPath $t.FullName -OutDir $ctx.OutDir -BasePath $ctx.BasePath -Suffix '.xlsx.csv').ToLowerInvariant()
                    $outCsv = Get-SafeDerivedPath -InputPath $t.FullName -OutDir $ctx.OutDir -BasePath $ctx.BasePath -Suffix '.xlsx.csv' -UseHash:($conversionNameCounts[$key] -gt 1)
                    [void](ConvertFrom-XlsxToCsv -XlsxPath $t.FullName -OutCsv $outCsv)
                    if (Test-Path -LiteralPath $outCsv) { $converted = Get-Item -LiteralPath $outCsv; $convertedFileCount++ }
                }
                elseif ($ext2 -eq '.docx') {
                    $ctx = Get-UlsOutputContext -InputPath $t.FullName -WorkDir $WorkDir -InputRoot $inputRoot -CabExtractionRoots @($cabExtractionRoots.ToArray())
                    $key = (Get-SafeDerivedPath -InputPath $t.FullName -OutDir $ctx.OutDir -BasePath $ctx.BasePath -Suffix '.docx.txt').ToLowerInvariant()
                    $outTxt = Get-SafeDerivedPath -InputPath $t.FullName -OutDir $ctx.OutDir -BasePath $ctx.BasePath -Suffix '.docx.txt' -UseHash:($conversionNameCounts[$key] -gt 1)
                    [void](ConvertFrom-DocxToText -DocxPath $t.FullName -OutText $outTxt)
                    if (Test-Path -LiteralPath $outTxt) { $converted = Get-Item -LiteralPath $outTxt; $convertedFileCount++ }
                }
                elseif ($ext2 -eq '.pptx') {
                    $ctx = Get-UlsOutputContext -InputPath $t.FullName -WorkDir $WorkDir -InputRoot $inputRoot -CabExtractionRoots @($cabExtractionRoots.ToArray())
                    $key = (Get-SafeDerivedPath -InputPath $t.FullName -OutDir $ctx.OutDir -BasePath $ctx.BasePath -Suffix '.pptx.txt').ToLowerInvariant()
                    $outTxt = Get-SafeDerivedPath -InputPath $t.FullName -OutDir $ctx.OutDir -BasePath $ctx.BasePath -Suffix '.pptx.txt' -UseHash:($conversionNameCounts[$key] -gt 1)
                    [void](ConvertFrom-PptxToText -PptxPath $t.FullName -OutText $outTxt)
                    if (Test-Path -LiteralPath $outTxt) { $converted = Get-Item -LiteralPath $outTxt; $convertedFileCount++ }
                }
                elseif ($ext2 -in @('.doc','.ppt')) {
                    throw "Legacy Office file '$($t.Name)' is not parsed natively. Export it to .docx/.pptx or plain text, then scrub the exported file."
                }
                elseif ($ext2 -eq '.log' -and $Profile -ine 'IntuneDiagnostics') {
                    $head = @(Get-Content -LiteralPath $t.FullName -TotalCount 20 -ErrorAction SilentlyContinue)
                    if ($head -match '^#Fields:') {
                        $key = ($t.BaseName + '.w3c.csv').ToLowerInvariant()
                        $ctx = Get-UlsOutputContext -InputPath $t.FullName -WorkDir $WorkDir -InputRoot $inputRoot -CabExtractionRoots @($cabExtractionRoots.ToArray())
                        $key = (Get-SafeDerivedPath -InputPath $t.FullName -OutDir $ctx.OutDir -BasePath $ctx.BasePath -Suffix '.w3c.csv').ToLowerInvariant()
                        $outCsv = Get-SafeDerivedPath -InputPath $t.FullName -OutDir $ctx.OutDir -BasePath $ctx.BasePath -Suffix '.w3c.csv' -UseHash:($conversionNameCounts[$key] -gt 1)
                        [void](ConvertFrom-W3CToCsv -LogPath $t.FullName -OutCsv $outCsv)
                        if (Test-Path -LiteralPath $outCsv) { $converted = Get-Item -LiteralPath $outCsv; $iisConverted = $true; $convertedFileCount++ }
                    }
                }
            }
            catch {
                Write-Fail "Conversion failed for $($t.Name): $($_.Exception.Message)"
                if ($ext2 -in @('.doc','.ppt','.etl')) { throw }
            }
            if ($converted) { $newTargets += $converted; $intermediateTargets += $converted } else { $newTargets += $t }
        }
        $targets = @($newTargets)
        if ($targets.Count -eq 0) { throw "No inputs left to scrub after conversion." }
    }

    # --- Salt (prompt securely if still unknown) ---
    Write-Host ""
    Write-Step "Salt"
    if ($NonInteractive -and [string]::IsNullOrWhiteSpace($script:Salt)) {
        throw "Salt is required in -NonInteractive mode. Pass -Salt, -SaltFromEnv, or -SaltFile."
    }
    [void](Get-SessionSalt)
    Write-Ok "Salt set (fingerprint $(Get-SaltFingerprint))."

    # --- Profile ---
    Write-Host ""
    Write-Step "Choose a profile (how fields are interpreted)"
    $prof = $null
    if ($ProfileFile) {
        $prof = Import-ScrubProfileFile -Path $ProfileFile
    }
    elseif ($Profile -and (Test-Path $Profile -PathType Leaf) -and ($Profile -match '\.(json|psd1)$')) {
        $prof = Import-ScrubProfileFile -Path $Profile
    }
    elseif ($Profile) {
        $prof = Get-ScrubProfile -Name $Profile
        if (-not $prof) { throw "Unknown profile: $Profile" }
    }
    else {
        $suggest = 'Generic'
        $firstCsv = $targets | Where-Object { $_.Extension -ieq '.csv' } | Select-Object -First 1
        $anyJson  = @($targets | Where-Object { $_.Extension -imatch '^\.(json|ndjson|jsonl)$' }).Count -gt 0
        $anyTsv   = @($targets | Where-Object { $_.Extension -ieq '.tsv' }).Count -gt 0
        if ($iisConverted) { $suggest = 'IIS' }
        elseif ($firstCsv) {
            try {
                $hdr = (Get-Content -Path $firstCsv.FullName -TotalCount 1 -ErrorAction SilentlyContinue)
                if ($hdr -match 'RequestID|CertificateTemplate|ESC\d|PkiObjectType|StrongCertificateBindingEnforcement') { $suggest = 'CA' }
                elseif ($evtxConverted -or ($hdr -match 'ProviderName|LevelDisplayName|RecordId')) { $suggest = 'WindowsEventCsv' }
            } catch { }
        }
        elseif ($anyJson) { $suggest = 'Generic' }
        elseif ($anyTsv) { $suggest = 'Tsv' }
        else { $suggest = 'Text' }

        if ($NonInteractive) { $prof = Get-ScrubProfile -Name $suggest }
        else {
            $opts = @()
            foreach ($p in (Get-ScrubProfile)) {
                $label = $p.Name; if ($p.Name -eq $suggest) { $label += "   (suggested)" }
                $opts += @{ Key = $p.Name; Label = $label; Detail = $p.Description }
            }
            $opts += @{ Key = '__file'; Label = 'Custom -- load from a profile file (.json/.psd1)'; Detail = 'Bring your own column rules.' }
            $defIdx = 1
            for ($i = 0; $i -lt $opts.Count; $i++) { if ($opts[$i].Key -eq $suggest) { $defIdx = $i + 1 } }
            $choice = Read-Choice -Prompt "Profile number" -Options $opts -DefaultIndex $defIdx
            if ($choice -eq '__file') {
                $pf = Read-DefaultString -Prompt "Path to a profile file (.json or .psd1)"
                $prof = Import-ScrubProfileFile -Path $pf
            }
            else { $prof = Get-ScrubProfile -Name $choice }
        }
    }
    if (-not $prof) { throw "No profile resolved." }
    if ($ProfileExtensionFile -and $ProfileExtensionFile.Count -gt 0) {
        $prof = Merge-ScrubProfileExtension -Profile $prof -Path $ProfileExtensionFile
    }
    Write-Ok "Profile: $($prof.Name) -- $($prof.Description)"
    $eventXmlTextTargets = @($targets | Where-Object { $_.Name -match '(?i)\.events\.txt$' })
    if ($eventXmlTextTargets.Count -gt 0) {
        Write-Ok "Detected format: Windows Event XML text -- field-aware discovery/scrub."
    }

    # --- Sensitive seed terms ---
    if (-not $PSBoundParameters.ContainsKey('SensitiveTerms')) {
        if ($NonInteractive) { $SensitiveTerms = @() }
        else {
            Write-Host ""
            Write-Step "Sensitive terms (optional)"
            Write-Detail "Shapeless secrets the detectors can't recognise on their own:"
            Write-Detail "your org name, internal host prefixes, project codenames, vendor names."
            $raw = Read-DefaultString -Prompt "Comma-separated terms (blank for none)" -Default ""
            $SensitiveTerms = @()
            if (-not [string]::IsNullOrWhiteSpace($raw)) { $SensitiveTerms = @($raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
        }
    }
    $profileSeedTerms = @()
    try { if ($prof.SeedTerms) { $profileSeedTerms += @($prof.SeedTerms) } } catch { }
    $seedFilesCombined = @()
    if ($SensitiveTermsFile) { $seedFilesCombined += @($SensitiveTermsFile) }
    if ($SeedFile) { $seedFilesCombined += @($SeedFile) }
    try { if ($prof.SeedFiles) { $seedFilesCombined += @($prof.SeedFiles) } } catch { }
    $SensitiveTerms = Merge-ScrubTerms -Terms (@($SensitiveTerms) + $profileSeedTerms) -Files $seedFilesCombined -BasePath $prof.ProfileRoot
    if ($SensitiveTerms.Count -gt 0) { Write-Ok "$($SensitiveTerms.Count) sensitive term(s) will be redacted." }
    Initialize-ScrubProfileRuntime -Profile $prof -AllowlistFiles $AllowlistFile
    $resolvedProfileName = ''
    try { $resolvedProfileName = [string]$prof.Name } catch { }
    if ($resolvedProfileName -ieq 'IntuneDiagnostics') {
        if (-not $PSBoundParameters.ContainsKey('LargeFileThresholdMB') -and $LargeFileThresholdMB -gt 25) {
            $LargeFileThresholdMB = 25
            Write-Detail "IntuneDiagnostics large-file auto threshold adjusted to 25 MB."
        }
        $beforeIntuneFilter = $skippedFiles.Count
        $intuneTargets = New-Object System.Collections.Generic.List[object]
        foreach ($it in @($targets | Sort-Object FullName)) {
            if (Test-UlsIntuneDiagnosticsTextFile -File $it) {
                [void]$intuneTargets.Add($it)
            }
            else {
                [void]$skippedFiles.Add((New-UlsSkippedFileRecord -File $it -Reason 'Unsupported IntuneDiagnostics file type' -ActionRequired 'Extract or convert locally, or scrub with an appropriate profile.'))
            }
        }
        $targets = @($intuneTargets.ToArray() | Sort-Object FullName)
        $newSkipped = $skippedFiles.Count - $beforeIntuneFilter
        if ($newSkipped -gt 0) { Write-Info "IntuneDiagnostics target filter skipped $newSkipped unsupported file(s)." }
        if ($targets.Count -eq 0) { throw "No supported IntuneDiagnostics text files remain to scrub." }
    }

    # --- Map source ---
    Write-Host ""
    Write-Step "Where should the token map come from?"
    if (-not $MapSource) {
        if ($NonInteractive) { $MapSource = if ($TokenMapCsv) { 'ExistingMap' } else { 'Discover' } }
        else {
            $opts = @(
                @{ Key='Discover';    Label='Build it from these log(s)  (no AD needed)'; Detail='Scans the files, tokenizes every identifier it finds. The universal default.' },
                @{ Key='ExistingMap'; Label='Use an existing token map';                  Detail='Reuse a map you built earlier (keeps tokens consistent across runs).' },
                @{ Key='AD';          Label='Build from Active Directory  (optional)';     Detail='Authoritative: collapses every alias of one identity to one token. Needs domain rights.' }
            )
            $MapSource = Read-Choice -Prompt "Map source number" -Options $opts -DefaultIndex 1
        }
    }
    Write-Info "Map source: $MapSource"

    if (-not $TokenMapCsv) { $TokenMapCsv = Join-Path $WorkDir "scrub_token_map_DO_NOT_UPLOAD.csv" }

    if ($DryRun) {
        # Dry run writes nothing -- no map is built. Load an existing map read-only
        # if one was chosen; otherwise the preview uses on-the-fly (deterministic) tokens.
        Write-Info "[DRY RUN] No token map will be built or written."
        if ($MapSource -eq 'ExistingMap') {
            if (-not (Test-Path $TokenMapCsv) -and -not $NonInteractive) { $TokenMapCsv = Read-DefaultString -Prompt "Path to the existing token map CSV" }
            if (Test-Path $TokenMapCsv) { [void](Import-ScrubTokenMap -TokenMapCsv $TokenMapCsv) }
        }
        else { Write-Detail "Preview uses on-the-fly tokens (deterministic for your salt)." }
    }
    else {
        switch ($MapSource) {
            'Discover' {
                [void](New-ScrubTokenMap -InputPath @($targets | ForEach-Object { $_.FullName }) -TokenMapCsv $TokenMapCsv -SeedTerms $SensitiveTerms -NoCorrelate:$NoCorrelate -TokenMapMode $TokenMapMode -ScrubPolicy $script:ScrubPolicy -ProfileName $prof.Name -WorkDir $WorkDir -AllowlistFile $AllowlistFile -ThrottleLimit $ThrottleLimit -LargeFileThresholdMB $LargeFileThresholdMB -KeepIntermediate:$KeepIntermediate)
            }
            'AD' {
                $ulsPerfAd = New-UlsPerfStopwatch
                $res = New-ScrubTokenMapFromAD -TokenMapCsv $TokenMapCsv -SeedTerms $SensitiveTerms
                Add-UlsPerfPhase -Phase 'Build map' -Stopwatch $ulsPerfAd -File ([System.IO.Path]::GetFileName($TokenMapCsv)) -Notes 'AD map build'
                if (-not $res) {
                    Write-Warn "Falling back to discovery (AD was unavailable)."
                    [void](New-ScrubTokenMap -InputPath @($targets | ForEach-Object { $_.FullName }) -TokenMapCsv $TokenMapCsv -SeedTerms $SensitiveTerms -NoCorrelate:$NoCorrelate -TokenMapMode $TokenMapMode -ScrubPolicy $script:ScrubPolicy -ProfileName $prof.Name -WorkDir $WorkDir -AllowlistFile $AllowlistFile -ThrottleLimit $ThrottleLimit -LargeFileThresholdMB $LargeFileThresholdMB -KeepIntermediate:$KeepIntermediate)
                }
            }
            'ExistingMap' {
                if (-not (Test-Path $TokenMapCsv)) {
                    if ($NonInteractive) { throw "Token map not found: $TokenMapCsv" }
                    $TokenMapCsv = Read-DefaultString -Prompt "Path to the existing token map CSV"
                }
                $ulsPerfImportMap = New-UlsPerfStopwatch
                [void](Import-ScrubTokenMap -TokenMapCsv $TokenMapCsv)
                Add-UlsPerfPhase -Phase 'Build map' -Stopwatch $ulsPerfImportMap -File ([System.IO.Path]::GetFileName($TokenMapCsv)) -Notes 'ExistingMap import'
            }
        }
    }

    if ($DiscoveryOnly) {
        Write-Ok "Discovery-only complete. Token map written: $TokenMapCsv"
        if ($PassThru) { return [pscustomobject]@{ DiscoveryOnly = $true; TokenMapCsv = $TokenMapCsv } }
        return
    }

    # --- Scrub every target ---
    Write-Host ""
    Write-Rule "Scrubbing"
    Reset-UlsCSharpMapOnlyScrubberCache
    Write-UlsProgress -Activity 'Prepare scrub outputs' -RowsDone 0 -RowsTotal $targets.Count -Force
    $scrubNameCounts = @{}
    $scrubPrepIndex = 0
    foreach ($st in $targets) {
        $scrubPrepIndex++
        if ($scrubPrepIndex -eq 1 -or ($scrubPrepIndex % 250) -eq 0 -or $scrubPrepIndex -eq $targets.Count) {
            Write-UlsProgress -Activity 'Prepare scrub outputs' -RowsDone $scrubPrepIndex -RowsTotal $targets.Count -Force
        }
        $ctx = Get-UlsOutputContext -InputPath $st.FullName -WorkDir $WorkDir -InputRoot $inputRoot -CabExtractionRoots @($cabExtractionRoots.ToArray())
        $candidate = Get-ScrubbedOutPath -InputPath $st.FullName -OutDir $ctx.OutDir -BasePath $ctx.BasePath
        $key = $candidate.ToLowerInvariant()
        if (-not $scrubNameCounts.ContainsKey($key)) { $scrubNameCounts[$key] = 0 }
        $scrubNameCounts[$key] = [int]$scrubNameCounts[$key] + 1
    }
    Write-UlsProgress -Activity 'Prepare scrub outputs' -Completed
    $results = @()
    $i = 0
    $parallelScrubCompletedPaths = @{}
    $folderJob = $false
    try { $folderJob = (Test-Path $Path -PathType Container) } catch { $folderJob = $false }
    if (-not $DryRun -and $ThrottleLimit -gt 1 -and (Test-Path -LiteralPath $TokenMapCsv)) {
        $acceleratorScrubJobs = New-Object System.Collections.Generic.List[object]
        Write-UlsProgress -Activity 'Prepare CSharp scrub batch' -RowsDone 0 -RowsTotal $targets.Count -Force
        $acceleratorPrepIndex = 0
        foreach ($pt in @($targets)) {
            $acceleratorPrepIndex++
            if ($acceleratorPrepIndex -eq 1 -or ($acceleratorPrepIndex % 250) -eq 0 -or $acceleratorPrepIndex -eq $targets.Count) {
                Write-UlsProgress -Activity 'Prepare CSharp scrub batch' -RowsDone $acceleratorPrepIndex -RowsTotal $targets.Count -Force
            }
            $extForAccelerator = ([string]$pt.Extension).ToLowerInvariant()
            if ($extForAccelerator -notin @('.log','.txt','.reg','.html','.htm','.xml','.log_')) { continue }
            $ctx = Get-UlsOutputContext -InputPath $pt.FullName -WorkDir $WorkDir -InputRoot $inputRoot -CabExtractionRoots @($cabExtractionRoots.ToArray())
            $candidatePathForAccelerator = Get-ScrubbedOutPath -InputPath $pt.FullName -OutDir $ctx.OutDir -BasePath $ctx.BasePath
            $outForAccelerator = Get-ScrubbedOutPath -InputPath $pt.FullName -OutDir $ctx.OutDir -BasePath $ctx.BasePath -UseHash:($scrubNameCounts[$candidatePathForAccelerator.ToLowerInvariant()] -gt 1)
            $isEventXmlForAccelerator = $false
            try { $isEventXmlForAccelerator = Test-UlsWindowsEventXmlTextFile -Path $pt.FullName } catch { $isEventXmlForAccelerator = $false }
            [void]$acceleratorScrubJobs.Add([pscustomobject]@{
                InputPath    = $pt.FullName
                OutputPath   = $outForAccelerator
                Length       = [int64]$pt.Length
                Name         = $pt.Name
                Format       = 'Text'
                Delimiter    = ','
                eventXmlText = [bool]$isEventXmlForAccelerator
            })
        }
        Write-UlsProgress -Activity 'Prepare CSharp scrub batch' -Completed
        $remainingAcceleratorJobs = @($acceleratorScrubJobs.ToArray())
        if ($remainingAcceleratorJobs.Count -gt 0) {
            try {
                Write-Info ("Scrubbing {0} text/report file(s) with {1} CSharp worker(s)." -f $remainingAcceleratorJobs.Count, ([Math]::Min($ThrottleLimit, $remainingAcceleratorJobs.Count)))
                $csharpBatchResults = @(Invoke-UlsCSharpScrubFilesParallel -Jobs ([object[]]$remainingAcceleratorJobs) -Profile $prof -TokenMapCsv $TokenMapCsv -SensitiveTerms $SensitiveTerms -ThrottleLimit $ThrottleLimit)
                $csharpBatchSuccess = @($csharpBatchResults | Where-Object { $_.Clean })
                $csharpBatchFailed = @($csharpBatchResults | Where-Object { -not $_.Clean })
                $results += $csharpBatchSuccess
                if ($csharpBatchSuccess.Count -gt 0) {
                    foreach ($cbs in @($csharpBatchSuccess)) {
                        try { $parallelScrubCompletedPaths[[System.IO.Path]::GetFullPath([string]$cbs.Input).ToLowerInvariant()] = $true } catch { $parallelScrubCompletedPaths[[string]$cbs.Input] = $true }
                    }
                }
                if ($csharpBatchFailed.Count -gt 0) {
                    $results += $csharpBatchFailed
                    foreach ($cbr in @($csharpBatchFailed)) {
                        try { $parallelScrubCompletedPaths[[System.IO.Path]::GetFullPath([string]$cbr.Input).ToLowerInvariant()] = $true } catch { $parallelScrubCompletedPaths[[string]$cbr.Input] = $true }
                    }
                }
            }
            catch {
                throw
            }
        }
    }

    $scrubTotalBytes = 0L
    foreach ($tb in @($targets)) { try { $scrubTotalBytes += [int64]$tb.Length } catch { } }
    $scrubDoneBytes = 0L
    foreach ($t in $targets) {
        $i++
        $scrubFullKey = ''
        try { $scrubFullKey = [System.IO.Path]::GetFullPath($t.FullName).ToLowerInvariant() } catch { $scrubFullKey = [string]$t.FullName }
        if ($parallelScrubCompletedPaths.ContainsKey($scrubFullKey)) { try { $scrubDoneBytes += [int64]$t.Length } catch { }; continue }
        Write-UlsProgress -Activity 'Scrub files' -File $t.Name -RowsDone $i -RowsTotal $targets.Count -BytesDone $scrubDoneBytes -BytesTotal $scrubTotalBytes
        $ctx = Get-UlsOutputContext -InputPath $t.FullName -WorkDir $WorkDir -InputRoot $inputRoot -CabExtractionRoots @($cabExtractionRoots.ToArray())
        $candidatePath = Get-ScrubbedOutPath -InputPath $t.FullName -OutDir $ctx.OutDir -BasePath $ctx.BasePath
        $outPath = Get-ScrubbedOutPath -InputPath $t.FullName -OutDir $ctx.OutDir -BasePath $ctx.BasePath -UseHash:($scrubNameCounts[$candidatePath.ToLowerInvariant()] -gt 1)
        try {
            $parallelFormat = $prof.Format
            if ($parallelFormat -eq 'Auto') {
                $parallelExt = [System.IO.Path]::GetExtension($t.FullName).ToLowerInvariant()
                if ($parallelExt -eq '.csv') { $parallelFormat = 'Csv' }
                elseif ($parallelExt -eq '.tsv') { $parallelFormat = 'Tsv' }
                elseif ($parallelExt -eq '.psv') { $parallelFormat = 'Psv' }
            }
            $parallelDelim = ','
            try { if ($prof.Delimiter) { $parallelDelim = [string]$prof.Delimiter } } catch { }
            if ($parallelFormat -eq 'Tsv') { $parallelDelim = "`t" }
            elseif ($parallelFormat -eq 'Psv') { $parallelDelim = '|' }

            $isIntermediateForEngine = $false
            foreach ($mid in @($intermediateTargets)) {
                try {
                    if ([string]::Equals([string]$mid.FullName, [string]$t.FullName, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $isIntermediateForEngine = $true
                        break
                    }
                } catch { }
            }
            $csharpResult = Invoke-UlsCSharpScrubIfSelected `
                -InputPath $t.FullName `
                -OutputPath $outPath `
                -Profile $prof `
                -Format $parallelFormat `
                -TokenMapCsv $TokenMapCsv `
                -SensitiveTerms $SensitiveTerms `
                -DryRun:$DryRun `
                -ExplainDetections:$ExplainDetections
            if ($csharpResult) {
                $results += $csharpResult
                continue
            }
            if (-not $DryRun -and (Test-Path -LiteralPath $TokenMapCsv) -and $parallelFormat -in @('Text','Kv','Csv','Tsv','Psv','Json')) {
                throw "CSharp scrub is required for $parallelFormat inputs in v1 but was not selected for '$($t.Name)'."
            }
            $results += Invoke-ScrubFile -InputPath $t.FullName -OutputPath $outPath -Profile $prof -SensitiveTerms $SensitiveTerms -AllowlistFile $AllowlistFile -ScrubPolicy $script:ScrubPolicy -ExplainDetections:$ExplainDetections -DryRun:$DryRun
        }
        catch {
            Write-Fail "Failed on $($t.Name): $($_.Exception.Message)"
            Write-Detail "type: $($_.Exception.GetType().FullName)"
            foreach ($frame in (@($_.ScriptStackTrace -split "`r?`n") | Select-Object -First 5)) { if ($frame -and $frame.Trim()) { Write-Detail $frame.Trim() } }
            $results += [pscustomobject]@{ Input = $t.FullName; Output = $null; Clean = $false; Error = $_.Exception.Message }
        }
        finally {
            try { $scrubDoneBytes += [int64]$t.Length } catch { }
        }
    }
    Write-UlsProgress -Activity 'Scrub files' -Completed
    $finalizeSw = New-UlsPerfStopwatch

    # --- Manifest + summary ---
    if ($DryRun) {
        Write-Host ""
        Write-Rule "Summary"
        $tot = (@($results | ForEach-Object { $_.ChangeCount }) | Measure-Object -Sum).Sum
        if ($script:FalsePositiveReport) { [void](Write-DetectionReport -Path $script:FalsePositiveReport) }
        if ($script:DetectionSummaryReport) { [void](Write-DetectionSummaryReport -Path $script:DetectionSummaryReport) }
        Write-Ok "[DRY RUN] Complete. $tot value(s) across $($results.Count) file(s) would be tokenized."
        Write-Info "Nothing was written. Re-run without -DryRun to produce scrubbed files."
        if ($script:PerfReportEnabled) { [void](Write-UlsPerfReport -WorkDir $WorkDir) }
        Write-Host ""
        if ($PassThru) { return $results }
        return
    }
    Write-Host ""
    Write-Step "Finalizing run"
    Write-Host ""
    Write-Rule "Summary"
    Write-Info "Building summary and manifest..."
    [void](Write-RunManifest -WorkDir $WorkDir -Results $results -TokenMapCsv $TokenMapCsv -TokenMapMode $TokenMapMode -SkippedFiles @($skippedFiles.ToArray()) -InputRoot $inputRoot -OutputRoot $WorkDir -ConvertedFiles $convertedFileCount)
    Add-UlsPerfPhase -Phase 'Finalize run' -Stopwatch $finalizeSw -Rows @($results).Count -Notes 'summary, manifest, reports, cleanup'
    if ($script:FalsePositiveReport) { [void](Write-DetectionReport -Path $script:FalsePositiveReport) }
    if ($script:DetectionSummaryReport) { [void](Write-DetectionSummaryReport -Path $script:DetectionSummaryReport) }
    if (-not $KeepIntermediate -and ($intermediateTargets.Count -gt 0 -or $cabExtractionRoots.Count -gt 0)) {
        $cleanupSw = New-UlsPerfStopwatch
        $cleanInputs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $failedInputs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($res in @($results)) {
            if (-not $res -or -not $res.Input) { continue }
            try { $rf = [System.IO.Path]::GetFullPath([string]$res.Input) } catch { $rf = [string]$res.Input }
            if ($res.Clean) { [void]$cleanInputs.Add($rf) } else { [void]$failedInputs.Add($rf) }
        }

        $deletedRootCount = 0
        $deletedIntermediateCount = 0
        $cleanupFailures = New-Object System.Collections.Generic.List[string]
        $deletedRoots = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        foreach ($root in @($cabExtractionRoots.ToArray() | Sort-Object -Unique)) {
            if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path -LiteralPath $root)) { continue }
            try { $rootFull = [System.IO.Path]::GetFullPath($root).TrimEnd([char[]]@('\','/')) } catch { $rootFull = [string]$root }
            $rootPrefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
            $rootHadSelected = $false
            $rootHadFailure = $false
            foreach ($res in @($results)) {
                if (-not $res -or -not $res.Input) { continue }
                try { $inputFull = [System.IO.Path]::GetFullPath([string]$res.Input) } catch { $inputFull = [string]$res.Input }
                if ($inputFull.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $rootHadSelected = $true
                    if (-not $res.Clean) { $rootHadFailure = $true; break }
                }
            }
            if ($rootHadSelected -and -not $rootHadFailure) {
                try {
                    Remove-Item -LiteralPath $rootFull -Recurse -Force -ErrorAction Stop
                    [void]$deletedRoots.Add($rootFull)
                    $deletedRootCount++
                }
                catch { [void]$cleanupFailures.Add(("CAB extraction workspace '{0}': {1}" -f $rootFull, $_.Exception.Message)) }
            }
            elseif ($rootHadFailure) {
                Write-Warn "Kept CAB extraction workspace for review: $rootFull"
            }
        }

        $cleanupIndex = 0
        $standaloneIntermediates = @($intermediateTargets | Sort-Object FullName -Unique)
        foreach ($mid in $standaloneIntermediates) {
            $cleanupIndex++
            if ($cleanupIndex % 250 -eq 0) {
                Write-UlsProgress -Activity 'Cleanup' -RowsDone $cleanupIndex -RowsTotal $standaloneIntermediates.Count -Force
            }
            if (-not $mid -or -not $mid.FullName) { continue }
            try { $midFull = [System.IO.Path]::GetFullPath([string]$mid.FullName) } catch { $midFull = [string]$mid.FullName }
            $underDeletedRoot = $false
            foreach ($dr in @($deletedRoots)) {
                if ($midFull.StartsWith($dr + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) { $underDeletedRoot = $true; break }
            }
            if ($underDeletedRoot -or -not $cleanInputs.Contains($midFull) -or $failedInputs.Contains($midFull) -or -not (Test-Path -LiteralPath $midFull)) { continue }
            try {
                Remove-Item -LiteralPath $midFull -Force -ErrorAction Stop
                $deletedIntermediateCount++
            }
            catch { [void]$cleanupFailures.Add(("Intermediate '{0}': {1}" -f $midFull, $_.Exception.Message)) }
        }
        Write-UlsProgress -Activity 'Cleanup' -Completed
        if ($deletedRootCount -gt 0 -or $deletedIntermediateCount -gt 0) {
            Write-Info ("Deleted unsafe intermediate workspace(s): {0}; standalone file(s): {1}." -f $deletedRootCount, $deletedIntermediateCount)
        }
        if ($cleanupFailures.Count -gt 0) {
            foreach ($failure in @($cleanupFailures | Select-Object -First 5)) { Write-Warn "Could not delete unsafe intermediate: $failure" }
            if ($cleanupFailures.Count -gt 5) { Write-Warn ("{0} additional cleanup failure(s) omitted." -f ($cleanupFailures.Count - 5)) }
        }
        Add-UlsPerfPhase -Phase 'Cleanup intermediates' -Stopwatch $cleanupSw -Rows ($deletedRootCount + $deletedIntermediateCount) -Notes ("roots={0}; files={1}; failures={2}" -f $deletedRootCount,$deletedIntermediateCount,$cleanupFailures.Count)
    }
    $okCount = @($results | Where-Object { $_.Clean }).Count
    $badCount = @($results | Where-Object { -not $_.Clean }).Count
    foreach ($r in @($results | Where-Object { -not $_.Clean } | Select-Object -First 20)) {
        $rn = if ($r.Output) { [System.IO.Path]::GetFileName($r.Output) } else { [System.IO.Path]::GetFileName($r.Input) }
        Write-Fail ($rn + "  (scrub failed -- review)")
    }
    if ($badCount -gt 20) { Write-Warn ("{0} additional failed file(s) omitted from the console summary; see scrub_run_manifest.json." -f ($badCount - 20)) }
    Write-Host ""
    if ($badCount -eq 0) { Write-Ok "$okCount file(s) scrubbed successfully." }
    else { Write-Warn "$okCount clean, $badCount need review before upload." }
    if ($SafeBundleOut) {
        try { [void](New-SafeScrubBundle -Results $results -OutputPath $SafeBundleOut -WorkDir $WorkDir -Force:$Force) }
        catch { Write-Warn "Safe bundle was not created: $($_.Exception.Message)" }
    }
    Write-Host ""
    Write-Warn "NEVER upload: $TokenMapCsv"
    if ($badCount -eq 0) {
        Write-Ok  "Safe to upload: the *_scrubbed.* files in $WorkDir"
    }
    else {
        Write-Warn "Do NOT upload failed scrubbed files until the failures are resolved."
    }
    if ($script:PerfReportEnabled) { [void](Write-UlsPerfReport -WorkDir $WorkDir) }
    Write-Host ""
    if ($PassThru) { return $results }
    return
}

# BEGIN detection review and artifact filtering

# Override: broader generated/local artifact exclusion used by recommendations and folder scrubs.
function Test-GeneratedScrubArtifactName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Name -match '(?i)(_scrubbed|\.scrubbed\.|token_map|DO_NOT_UPLOAD|false_positive|detection_report|detection_review|scrub_run_manifest|manifest\.json|profile_build_report|generated-profile|profile-template)') { return $true }
    if ([System.IO.Path]::GetExtension($Name) -ieq '.zip') { return $true }
    return $false
}

function Resolve-LogRecommendationTargets {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Recurse,
        [string[]]$Include,
        [string[]]$Exclude
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'Path is required.' }
    $targets = @()
    if (Test-Path -LiteralPath $Path -PathType Container) {
        $targets = @(Get-ChildItem -LiteralPath $Path -File -Recurse:$Recurse -ErrorAction SilentlyContinue)
    }
    elseif (Test-Path -LiteralPath $Path -PathType Leaf) {
        $targets = @(Get-Item -LiteralPath $Path)
    }
    else { throw "Path not found: $Path" }

    $targets = @($targets | Where-Object { -not (Test-GeneratedScrubArtifactName -Name $_.Name) })
    if ($Include -and $Include.Count -gt 0) {
        $targets = @($targets | Where-Object {
            $ok = $false
            foreach ($pat in $Include) { if ($_.Name -like $pat) { $ok = $true; break } }
            $ok
        })
    }
    if ($Exclude -and $Exclude.Count -gt 0) {
        $targets = @($targets | Where-Object {
            $skip = $false
            foreach ($pat in $Exclude) { if ($_.Name -like $pat) { $skip = $true; break } }
            -not $skip
        })
    }
    return @($targets | Sort-Object FullName)
}

# END detection review and artifact filtering

# BEGIN positive detection review rows
# Current-version bugfix only: no version/banner/schema bump.

# Base identifier discovery with detector/reason metadata for dry-run review rows.
function Find-UlsIdentifiersCore {
    param([Parameter(Mandatory)][string]$Text)

    $found = @{}   # normalizedKey -> identifier object

    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }

    function _AddFoundIdentifier {
        param(
            [string]$Raw,
            [string]$Prefix,
            [string]$Detector,
            [string]$Reason,
            [int]$Index = -1,
            [int]$Length = 0,
            [string]$ColumnName = ''
        )

        if ([string]::IsNullOrWhiteSpace($Raw)) { return }
        if ([string]::IsNullOrWhiteSpace($Prefix)) { return }

        $norm = Normalize-TokenKey -Value $Raw
        if (-not $norm -or $found.ContainsKey($norm)) { return }

        $tokenPreview = ''
        try { $tokenPreview = Get-Token -Value $Raw -Prefix $Prefix } catch { $tokenPreview = '' }

        Add-DetectionTrace `
            -Detector $Detector `
            -Action 'Tokenized' `
            -Value $Raw `
            -Token $tokenPreview `
            -Reason $Reason `
            -ColumnName $ColumnName `
            -Context (Get-DetectionContext -Text $Text -Index $Index -Length $Length)

        $found[$norm] = [pscustomobject]@{
            Raw      = $Raw
            Prefix   = $Prefix
            Detector = $Detector
            Reason   = $Reason
        }
    }

    foreach ($id in (Find-UniversalLabeledIdentifiers -Text $Text)) {
        $reason = if ($id.Rule) { [string]$id.Rule } else { 'Universal label rule' }
        _AddFoundIdentifier -Raw $id.Raw -Prefix $id.Prefix -Detector 'UniversalLabel' -Reason $reason -ColumnName '(label)'
    }

    foreach ($id in (Find-CustomRegexIdentifiers -Text $Text)) {
        $reason = if ($id.Rule) { [string]$id.Rule } else { 'Custom regex rule' }
        _AddFoundIdentifier -Raw $id.Raw -Prefix $id.Prefix -Detector 'CustomRegex' -Reason $reason -ColumnName '(custom-regex)'
    }

    foreach ($id in (Find-SecretIdentifiers -Text $Text)) {
        $reason = switch ($id.Prefix) {
            'PEM'     { 'Private key block' }
            'CONNSTR' { 'Connection string pattern' }
            'APIKEY'  { 'API key/token pattern' }
            default   { 'Secret pattern' }
        }
        _AddFoundIdentifier -Raw $id.Raw -Prefix $id.Prefix -Detector 'Secret' -Reason $reason -ColumnName '(secret)'
    }

    foreach ($d in $script:ShapeDetectors) {
        # ULS perf patch 6: skip a shape detector when its required literal is absent (the same
        # Sentinel guard the scrub path uses), so discovery short-circuits like the scrub.
        if ($d.Sentinel -and ($Text.IndexOf([string]$d.Sentinel, [System.StringComparison]::OrdinalIgnoreCase) -lt 0)) { continue }
        foreach ($m in [regex]::Matches($Text, $d.Rx)) {
            $raw = $m.Value

            if ([string]::IsNullOrWhiteSpace($raw)) { continue }
            if (Is-AlreadyToken -Value $raw) { continue }
            if (Test-PreserveDottedDecimal -Value $raw) { continue }
            if ($d.Skip -and ($raw -match $d.Skip)) { continue }

            # Keep well-known public domains readable. They are intentionally not
            # positive detections because they are allowlisted public diagnostics.
            if (($d.Prefix -eq 'DNS' -or $d.Prefix -eq 'UNMAPPED_UPN') -and (Test-AllowedDomain -Value $raw)) { continue }

            if (Test-PreserveDetectedValue -Value $raw -Detector $d.Name -Prefix $d.Prefix -Text $Text -Index $m.Index -Length $m.Length) {
                Add-DetectionTrace `
                    -Detector $d.Name `
                    -Action 'Preserved' `
                    -Value $raw `
                    -Token '' `
                    -Reason 'Discovery preserve' `
                    -Context (Get-DetectionContext -Text $Text -Index $m.Index -Length $m.Length)
                continue
            }

            _AddFoundIdentifier `
                -Raw $raw `
                -Prefix $d.Prefix `
                -Detector $d.Name `
                -Reason 'Shape detector' `
                -Index $m.Index `
                -Length $m.Length `
                -ColumnName '(shape)'
        }
    }

    return @($found.Values)
}

# END positive detection review rows


# BEGIN OpenSSH log hardening
# Addresses common sshd/syslog free-text forms that are not label:value pairs:
#   - syslog emitter hostname after timestamp (for example: "Dec 10 06:55:46 LabSZ sshd[...]")
#   - OpenSSH authentication usernames in prose (Invalid user, Failed password for ...)
#   - reverse-DNS hostnames before IPv4 hardening can split numeric-leading FQDNs
# This is heuristic/contextual matching, not a static allowlist or static denylist.

if (-not (Get-Variable -Name __ULS_FindIdentifiers_BeforeOpenSsh -Scope Script -ErrorAction SilentlyContinue)) {
    $script:__ULS_FindIdentifiers_BeforeOpenSsh = ${function:Find-UlsIdentifiersCore}
}
if (-not (Get-Variable -Name __ULS_InvokeFreeTextHardening_BeforeOpenSsh -Scope Script -ErrorAction SilentlyContinue)) {
    $script:__ULS_InvokeFreeTextHardening_BeforeOpenSsh = ${function:Invoke-UlsFreeTextHardeningCore}
}
if (-not (Get-Variable -Name __ULS_InvokeLeakHardeningText_BeforeOpenSsh -Scope Script -ErrorAction SilentlyContinue)) {
    $script:__ULS_InvokeLeakHardeningText_BeforeOpenSsh = ${function:Invoke-UlsLeakHardeningTextCore}
}

function Test-UlsOpenSshLogText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    return ($Text -match '(?im)^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+sshd(?:\[\d+\])?:')
}

function Get-UlsOpenSshValuePrefix {
    param([string]$Value, [string]$DefaultPrefix = 'HOST')
    if ([string]::IsNullOrWhiteSpace($Value)) { return $DefaultPrefix }
    $v = $Value.Trim()
    if ($v -match '^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$') { return 'IP' }
    if ($v -match '^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}$') { return 'DNS' }
    return $DefaultPrefix
}

function Add-UlsOpenSshIdentifier {
    param(
        [Parameter(Mandatory)]$List,
        [Parameter(Mandatory)][hashtable]$Seen,
        [string]$Raw,
        [string]$Prefix,
        [string]$Detector = 'OpenSSHAuth',
        [string]$Reason = 'OpenSSH auth context',
        [int]$Index = -1,
        [int]$Length = 0
    )

    if ([string]::IsNullOrWhiteSpace($Raw)) { return }
    $v = ([string]$Raw).Trim()
    $v = $v.TrimStart([char[]]@('[','('))
    $v = $v.TrimEnd([char[]]@('.', ',', ';', ':', ']', ')'))
    if ([string]::IsNullOrWhiteSpace($v)) { return }
    if (Is-AlreadyToken -Value $v) { return }
    if ($v -match '^(?:-|unknown|none|null|\(null\))$') { return }

    $p = if ([string]::IsNullOrWhiteSpace($Prefix)) { Get-UlsOpenSshValuePrefix -Value $v } else { $Prefix }
    $norm = Normalize-TokenKey -Value $v
    if (-not $norm) { return }
    if ($Seen.ContainsKey($norm)) { return }
    $Seen[$norm] = $true

    [void]$List.Add([pscustomobject]@{
        Raw      = $v
        Prefix   = $p
        Detector = $Detector
        Reason   = $Reason
        Index    = $Index
        Length   = $(if ($Length -gt 0) { $Length } else { $v.Length })
    })
}

function Find-OpenSshAuthIdentifiers {
    param([Parameter(Mandatory)][string]$Text)

    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    if (-not (Test-UlsOpenSshLogText -Text $Text)) { return @() }

    $patterns = @(
        [pscustomobject]@{ Pattern='(?m)^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+)([A-Za-z][A-Za-z0-9_.-]{1,127})(?=\s+sshd(?:\[\d+\])?:)'; Group=2; Prefix=''; Reason='Syslog emitter hostname' },
        [pscustomobject]@{ Pattern='(?i)\bgetaddrinfo\s+for\s+([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})(?=\s+\[)'; Group=1; Prefix='DNS'; Reason='OpenSSH reverse-DNS hostname' },
        [pscustomobject]@{ Pattern='(?i)\brhost=([^\s]+)'; Group=1; Prefix=''; Reason='OpenSSH rhost value' },
        [pscustomobject]@{ Pattern='(?i)\bfrom\s+([A-Za-z0-9][A-Za-z0-9_.-]*)(?=\s+(?:port\b|ssh2\b|\[preauth\]|$))'; Group=1; Prefix=''; Reason='OpenSSH remote endpoint' },
        [pscustomobject]@{ Pattern='(?i)\bInvalid user\s+([^\s]+)(?=\s+from\b)'; Group=1; Prefix='PRINCIPAL'; Reason='OpenSSH invalid username' },
        [pscustomobject]@{ Pattern='(?i)\binput_userauth_request:\s+invalid user\s+([^\s\[]+)'; Group=1; Prefix='PRINCIPAL'; Reason='OpenSSH invalid username' },
        [pscustomobject]@{ Pattern='(?i)\bFailed password for invalid user\s+([^\s]+)(?=\s+from\b)'; Group=1; Prefix='PRINCIPAL'; Reason='OpenSSH failed-password username' },
        [pscustomobject]@{ Pattern='(?i)\bFailed password for\s+([^\s]+)(?=\s+from\b)'; Group=1; Prefix='PRINCIPAL'; Reason='OpenSSH failed-password username' },
        [pscustomobject]@{ Pattern='(?i)\bToo many authentication failures for\s+([^\s\[]+)'; Group=1; Prefix='PRINCIPAL'; Reason='OpenSSH auth-failure username' },
        [pscustomobject]@{ Pattern='(?i)\buser=([^\s]+)'; Group=1; Prefix='PRINCIPAL'; Reason='OpenSSH user field' }
    )

    foreach ($spec in $patterns) {
        $rx = New-ScrubRegex -Pattern ([string]$spec.Pattern) -Context "OpenSSH auth detector '$($spec.Reason)'"
        foreach ($m in $rx.Matches($Text)) {
            $g = $m.Groups[[int]$spec.Group]
            if (-not $g.Success) { continue }
            $raw = $g.Value
            $prefix = [string]$spec.Prefix
            if ([string]::IsNullOrWhiteSpace($prefix)) { $prefix = Get-UlsOpenSshValuePrefix -Value $raw }
            Add-UlsOpenSshIdentifier -List $out -Seen $seen -Raw $raw -Prefix $prefix -Reason ([string]$spec.Reason) -Index $g.Index -Length $g.Length
        }
    }

    return @($out.ToArray())
}

function Invoke-OpenSshAuthHardening {
    param([Parameter(Mandatory)][string]$Text, [string]$ColumnName = '')
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    if (-not (Test-UlsOpenSshLogText -Text $Text)) { return $Text }

    $out = $Text

    function _ReplaceOpenSshGroup {
        param(
            [Parameter(Mandatory)][string]$InputText,
            [Parameter(Mandatory)][string]$Pattern,
            [int]$GroupNumber = 1,
            [string]$Prefix = '',
            [string]$Reason = 'OpenSSH auth context'
        )

        $rx = New-ScrubRegex -Pattern $Pattern -Context "OpenSSH hardening '$Reason'"
        return $rx.Replace($InputText, {
            param($m)
            $g = $m.Groups[$GroupNumber]
            if (-not $g.Success) { return $m.Value }

            $raw = $g.Value.Trim()
            $clean = $raw.TrimStart([char[]]@('[','(')).TrimEnd([char[]]@('.', ',', ';', ':', ']', ')'))
            if ([string]::IsNullOrWhiteSpace($clean)) { return $m.Value }
            if (Is-AlreadyToken -Value $clean) { return $m.Value }
            if ($clean -match '^(?:-|unknown|none|null|\(null\))$') { return $m.Value }

            $p = if ([string]::IsNullOrWhiteSpace($Prefix)) { Get-UlsOpenSshValuePrefix -Value $clean } else { $Prefix }
            $tok = Get-Token -Value $clean -Prefix $p
            Add-DetectionTrace -Detector 'OpenSSHAuth' -Action 'Tokenized' -Value $clean -Token $tok -Reason $Reason -ColumnName $ColumnName -Context (Get-DetectionContext -Text $InputText -Index $g.Index -Length $g.Length)

            $rel = $g.Index - $m.Index
            if ($rel -lt 0) { return $m.Value }
            $before = $m.Value.Substring(0, $rel)
            $afterStart = $rel + $g.Length
            $after = if ($afterStart -lt $m.Value.Length) { $m.Value.Substring($afterStart) } else { '' }
            return $before + $tok + $after
        })
    }

    # Do DNS-like OpenSSH fields before the generic IPv4 detector to avoid split tokens
    # such as IP_x.DNS_y for numeric-leading reverse-DNS hostnames.
    $out = _ReplaceOpenSshGroup -InputText $out -Pattern '(?m)^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+)([A-Za-z][A-Za-z0-9_.-]{1,127})(?=\s+sshd(?:\[\d+\])?:)' -GroupNumber 2 -Prefix '' -Reason 'Syslog emitter hostname'
    $out = _ReplaceOpenSshGroup -InputText $out -Pattern '(?i)(\bgetaddrinfo\s+for\s+)([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})(?=\s+\[)' -GroupNumber 2 -Prefix 'DNS' -Reason 'OpenSSH reverse-DNS hostname'
    $out = _ReplaceOpenSshGroup -InputText $out -Pattern '(?i)(\brhost=)([^\s]+)' -GroupNumber 2 -Prefix '' -Reason 'OpenSSH rhost value'
    $out = _ReplaceOpenSshGroup -InputText $out -Pattern '(?i)(\bfrom\s+)([A-Za-z0-9][A-Za-z0-9_.-]*)(?=\s+(?:port\b|ssh2\b|\[preauth\]|$))' -GroupNumber 2 -Prefix '' -Reason 'OpenSSH remote endpoint'

    # Then handle auth usernames expressed in prose rather than label:value form.
    $out = _ReplaceOpenSshGroup -InputText $out -Pattern '(?i)(\bInvalid user\s+)([^\s]+)(?=\s+from\b)' -GroupNumber 2 -Prefix 'PRINCIPAL' -Reason 'OpenSSH invalid username'
    $out = _ReplaceOpenSshGroup -InputText $out -Pattern '(?i)(\binput_userauth_request:\s+invalid user\s+)([^\s\[]+)' -GroupNumber 2 -Prefix 'PRINCIPAL' -Reason 'OpenSSH invalid username'
    $out = _ReplaceOpenSshGroup -InputText $out -Pattern '(?i)(\bFailed password for invalid user\s+)([^\s]+)(?=\s+from\b)' -GroupNumber 2 -Prefix 'PRINCIPAL' -Reason 'OpenSSH failed-password username'
    $out = _ReplaceOpenSshGroup -InputText $out -Pattern '(?i)(\bFailed password for\s+)([^\s]+)(?=\s+from\b)' -GroupNumber 2 -Prefix 'PRINCIPAL' -Reason 'OpenSSH failed-password username'
    $out = _ReplaceOpenSshGroup -InputText $out -Pattern '(?i)(\bToo many authentication failures for\s+)([^\s\[]+)' -GroupNumber 2 -Prefix 'PRINCIPAL' -Reason 'OpenSSH auth-failure username'
    $out = _ReplaceOpenSshGroup -InputText $out -Pattern '(?i)(\buser=)([^\s]+)' -GroupNumber 2 -Prefix 'PRINCIPAL' -Reason 'OpenSSH user field'

    return $out
}

function Find-Identifiers {
    param([Parameter(Mandatory)][string]$Text)

    $base = @(& $script:__ULS_FindIdentifiers_BeforeOpenSsh -Text $Text)
    $seen = @{}
    foreach ($id in $base) {
        if ($id -and $id.Raw) {
            $norm = Normalize-TokenKey -Value ([string]$id.Raw)
            if ($norm) { $seen[$norm] = $true }
        }
    }

    $extra = New-Object System.Collections.Generic.List[object]
    foreach ($id in (Find-OpenSshAuthIdentifiers -Text $Text)) {
        if (-not $id -or [string]::IsNullOrWhiteSpace([string]$id.Raw)) { continue }
        $norm = Normalize-TokenKey -Value ([string]$id.Raw)
        if (-not $norm -or $seen.ContainsKey($norm)) { continue }
        $seen[$norm] = $true
        $tok = Get-Token -Value ([string]$id.Raw) -Prefix ([string]$id.Prefix)
        Add-DetectionTrace -Detector 'OpenSSHAuth' -Action 'Tokenized' -Value ([string]$id.Raw) -Token $tok -Reason ([string]$id.Reason) -ColumnName '(openssh)' -Context (Get-DetectionContext -Text $Text -Index ([int]$id.Index) -Length ([int]$id.Length))
        [void]$extra.Add([pscustomobject]@{
            Raw      = [string]$id.Raw
            Prefix   = [string]$id.Prefix
            Detector = 'OpenSSHAuth'
            Reason   = [string]$id.Reason
        })
    }

    return @($base + @($extra.ToArray()))
}

function Invoke-FreeTextHardening {
    param([string]$ColumnName, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    $exactNorm = Normalize-TokenKey -Value $Value
    if ($exactNorm -and $script:TokenByNorm -and $script:TokenByNorm.ContainsKey($exactNorm)) {
        return [string]$script:TokenByNorm[$exactNorm]
    }
    $pre = Invoke-OpenSshAuthHardening -Text $Value -ColumnName $ColumnName
    $pre = Invoke-UlsConnectionHostHardening -Text $pre -ColumnName $ColumnName
    return [string](& $script:__ULS_InvokeFreeTextHardening_BeforeOpenSsh -ColumnName $ColumnName -Value $pre)
}

function Invoke-LeakHardeningText {
    param([Parameter(Mandatory)][string]$Text)
    $pre = Invoke-OpenSshAuthHardening -Text $Text -ColumnName ''
    $pre = Invoke-UlsConnectionHostHardening -Text $pre -ColumnName ''
    return [string](& $script:__ULS_InvokeLeakHardeningText_BeforeOpenSsh -Text $pre)
}

# END OpenSSH log hardening

# BEGIN broad dotted/label false-positive preservation
# Current-version bugfix only: no version/banner/schema bump.
#
# Purpose:
#   Preserve common non-sensitive diagnostic identifiers that look like DNS/FQDNs,
#   URLs, secrets, or base64 only because of their shape:
#     - Android/Java package/class/action names
#     - Hadoop/Spark/OpenStack logger/config namespaces
#     - local artifact filenames (.jar, .map, .rts, .app in app-path context, etc.)
#     - ACPI/kernel/device diagnostic names
#     - harmless label-rule captures such as "Auth", "Starting", "/dev/sda", and port "80"
#
# Guardrails:
#   - Strict policy still tokenizes.
#   - Network/identity/path forms are not globally preserved here.
#   - Real rhost/reverse-DNS/proxy destination domains remain tokenized unless existing allowlists preserve them.

function Test-UlsCommonPublicNetworkDomain {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}').ToLowerInvariant()

    # Values in these domains are usually real web/proxy/reverse-DNS destinations.
    # Do not blanket-preserve them as software/package namespaces.
    if ($v -match '(^|\.)((com|net|org|edu|gov|mil|io|cn|jp|de|nl|uk|br|mx|tw|hk|at|eu|ru|in|fr|au|ca|us|info|biz|asia)$)') {
        return $true
    }

    return $false
}

function Test-UlsLikelyCodeOrConfigNamespace {
    param([string]$Value, [string]$Text)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')

    # Android package/action/component symbols from Android/HealthApp logs.
    if ($v -match '^(android|vnd\.android|Intent)\.[A-Za-z0-9_.-]+$') { return $true }
    if ($v -match '^(com\.(tencent|qqgame|amap|example|huawei|android)|com\.google\.(Chrome|Keystone)|com\.apple|org\.apache)\.[A-Za-z0-9_.-]+$') { return $true }
    if ($v -match '^(activity|business|cooperation|plugin|system|recents|record|state|tr|ui)\.[A-Za-z0-9_.-]+$') { return $true }
    if ($v -match '^(H|Stub|PowerManagerService|mVisiblity|mVisibility)\.(handleMessage|onTransact|WakeLocks|getValue)$') { return $true }

    # Java/system/config/ZooKeeper property names.
    if ($v -match '^(java|javax|sun|kotlin|scala|zookeeper|autopurge|os|user|host)\.[A-Za-z0-9_.-]+$') { return $true }
    if ($v -match '^(n)\.[A-Za-z_][A-Za-z0-9_]*$') { return $true }

    # Hadoop/HDFS/Spark/OpenStack logger/config namespaces.
    if ($v -match '^(dfs|NameSystem|DefaultSpeculator|maps|mapred|mapreduce|yarn|hadoop|spark|storage|executor|broadcast|output|python|rdd|netty|akka|slf4j|Configuration|util|nova|compute|http\.requests)\.[A-Za-z0-9_.-]+$') { return $true }
    if ($v -match '^SecurityLogger\.org\.apache\.[A-Za-z0-9_.-]+$') { return $true }
    if ($v -match '^org\.(mortbay|apache)\.[A-Za-z0-9_.-]+$') { return $true }

    # BGL/HPC local event-category and source/artifact namespaces.
    if ($v -match '^(SPaSM|XL|mpi|partad|raptor|fdmn|clusterfilesystem|change|unix|net\.niff|home)\.[A-Za-z0-9_.-]+$') { return $true }

    # macOS diagnostic/component symbols.
    if ($v -match '^(DiskStore|EC|ImportBailout|KSOutOfProcessFetcher|Keystone|dispatcher|subject)\.[A-Za-z0-9_.-]+$') { return $true }

    return $false
}

function Test-PreserveNonSensitiveDottedArtifactName {
    param([string]$Value, [string]$Text, [int]$Index = -1, [int]$Length = 0)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }

    $v = $Value.Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')
    if ($v -notmatch '\.') { return $false }

    # Do not preserve obvious identity/URL/path forms here.
    if ($v -match '@|://|\\|/') { return $false }

    # Local diagnostic/source/package artifact extensions. This intentionally runs
    # before the leading-digit guard so names like 8x4x4.map and 1.jhist survive.
    if ($v -match '(?i)\.(properties|conf|cfg|ini|yaml|yml|toml|xml|json|log|txt|pid|lock|policy|rules|template|templates|jar|jhist|map|mapfile|rts|trace|out|cpp|cc|cxx|h|hpp|pcap|pcapng|plist|bundle|framework|dylib|qlgenerator|db|sqlite|bin|sqm)$') {
        return $true
    }

    # macOS .app can also be a public suffix. Preserve only bundle-looking app names
    # or values in app-bundle context.
    if ($v -match '(?i)^[A-Za-z0-9 _-]+\.app$') {
        if (($Value -cmatch '^[A-Z]') -or ($Text -match '(?i)(/Applications/|/System/Library/|CoreServices|PlugIns|\.app/Contents|LaunchServices)')) { return $true }
    }

    # Linux kernel/initrd image names.
    if ($v -match '(?i)^(vmlinuz|initrd)-\d+(?:[.\w-]+)+$') { return $true }

    # Thunderbird/BGL/HPC timestamp-ish local identifiers like 200511091901.jA.
    if ($v -match '^\d{10,}\.[A-Za-z]{1,3}$') { return $true }

    # If it begins with a digit and is not a known local artifact/timestamp above,
    # keep the conservative behavior.
    if ($v -match '^\d') { return $false }

    # ACPI / PCI route symbols.
    if ($v -match '^[A-Z0-9_]+(?:\.[A-Z0-9_]+){1,8}$') {
        if ($Text -match '(?i)(ACPI|PCI Interrupt|_PRT|BOOT_IMAGE|kernel command line|Thunderbird|BGL|HPC)') { return $true }
    }

    # Explicit package/config/logger namespace families from broad false-positive testing.
    if (Test-UlsLikelyCodeOrConfigNamespace -Value $v -Text $Text) { return $true }

    # Class/method/logger shapes. Avoid obvious public network domains.
    $parts = @($v -split '\.')
    if ($parts.Count -ge 2 -and -not (Test-UlsCommonPublicNetworkDomain -Value $v)) {
        $last = [string]$parts[-1]

        # CamelCase or Java-style method/class symbol in any segment.
        if ($v -cmatch '[a-z][A-Z]' -or $last -cmatch '^[A-Z][A-Za-z0-9_]*$') { return $true }

        # Common short logger/method words.
        if ($last -match '^(?i)(init|start|stop|run|load|save|open|close|read|write|parse|build|handle|process|worker|factory|service|manager|env|activity|isEmpty|baseline|new|rel|old|panic|full|down|up|hw|ticketstore|arpc|OU|Normal|SleepTimer|Error)$') { return $true }
    }

    return $false
}

function Test-PreserveLikelyBenignUniversalLabelValue {
    param(
        [string]$Value,
        [string]$Detector,
        [string]$Prefix,
        [string]$Text,
        [int]$Index = -1,
        [int]$Length = 0
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }
    if ($Detector -ne 'UniversalLabel') { return $false }

    $v = $Value.Trim().Trim('"', "'", ',', ';', ')', ']', '}')

    if ($Prefix -eq 'DNS') {
        if ($v -match '^(?i)(Auth|IPC|Starting|Connection|routing|type|nginx|no|\[?ContainerId:?)$') { return $true }
        if ($v -match '^/dev/[A-Za-z0-9._/-]+$') { return $true }
        if ($v -match '^<KSOmahaServer:0x[0-9a-fA-F]+$') { return $true }
        if (Test-PreserveNonSensitiveDottedArtifactName -Value $v -Text $Text -Index $Index -Length $Length) { return $true }
    }

    if ($Prefix -eq 'PRINCIPAL') {
        # Preserve only the obvious Android zero singleton. Keep real Linux/OpenSSH
        # usernames like root, test, git, mysql tokenized.
        if ($v -eq '0') { return $true }
    }

    if ($Prefix -eq 'X500') {
        if ($v -match '^\d{1,5}$') { return $true }
        if ($v -match '^(NS[A-Za-z0-9]+ErrorDomain|kCFErrorDomain[A-Za-z0-9]+|[A-Z][A-Za-z0-9]+ErrorDomain|com\.apple\.[A-Za-z0-9_.-]+|type)$') { return $true }
    }

    return $false
}

function Test-PreserveLikelyBenignSecretValue {
    param([string]$Value, [string]$Text, [int]$Index = -1, [int]$Length = 0)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }

    $v = $Value.Trim().Trim('"', "'", ',', ';', ')', ']', '}')

    # Java/Android exception class names and Apple XPC activity diagnostics are not secrets.
    if ($v -match '^(android|java|javax|org|com)\.[A-Za-z0-9_.]+Exception$') { return $true }
    if ($v -match '^com\.apple\.xpc\.activity/\d+$') { return $true }

    return $false
}

function Test-PreserveLikelyBenignBase64FalsePositive {
    param([string]$Value, [string]$Text, [int]$Index = -1, [int]$Length = 0)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }

    $v = $Value.Trim().Trim('"', "'", ',', ';', ')', ']', '}')

    # macOS framework/class names can be long mixed-case alphabetic strings and
    # accidentally trip base64-ish shape detectors.
    if ($v -match '^[A-Za-z]{24,120}$' -and $v -cmatch '[a-z][A-Z]' -and $v -match '(Action|Transport|Controller|Constraint|Constraints|Layout|Bluetooth|Visualize|Server|Manager|Domain|Display|Power|Notification|Controller|Service)') { return $true }

    return $false
}

function Test-UlsPreserveDetectedValueBeforeLowSignalFilters {
    param(
        [string]$Value,
        [string]$Detector,
        [string]$Prefix,
        [string]$Text,
        [int]$Index = -1,
        [int]$Length = 0
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    if (Test-ScrubAllowlist -Value $Value) { return $true }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }

    $v = $Value.Trim()
    if (Is-AlreadyToken -Value $v) { return $true }

    # Additional broad false-positive reducers.
    if (Test-PreserveLikelyBenignUniversalLabelValue -Value $v -Detector $Detector -Prefix $Prefix -Text $Text -Index $Index -Length $Length) { return $true }
    if ($Prefix -eq 'SECRET' -and (Test-PreserveLikelyBenignSecretValue -Value $v -Text $Text -Index $Index -Length $Length)) { return $true }
    if ($Prefix -eq 'BLOB' -and (Test-PreserveLikelyBenignBase64FalsePositive -Value $v -Text $Text -Index $Index -Length $Length)) { return $true }

    # Base preservation behavior retained.
    if (Test-PreserveDottedDecimal -Value $v) { return $true }
    if (($Prefix -eq 'IP' -or $Prefix -eq 'IP6') -and (Test-PreserveIpAddress -Value $v)) { return $true }
    if ($Prefix -eq 'GUID' -and (Test-PreserveGuid -Value $v)) { return $true }
    if ($Detector -eq 'DOMAIN\user' -or $Prefix -eq 'PRINCIPAL') {
        if (Test-WindowsPathLikeDomainUser -Value $v -Text $Text -Index $Index -Length $Length) { return $true }
    }
    if ($Prefix -eq 'DNS') {
        if (Test-AllowedDomain -Value $v) { return $true }
        if (Test-WindowsDiagnosticDottedName -Value $v) { return $true }
        if (Test-PreserveNonSensitiveDottedArtifactName -Value $v -Text $Text -Index $Index -Length $Length) { return $true }
        if ($script:ScrubPolicy -eq 'Readable' -and (Test-KnownFileOrDiagnosticName -Value $v)) { return $true }
    }
    if ($Prefix -eq 'BLOB' -and -not (Test-LooksLikeBase64Blob -Value $v)) { return $true }
    if (($Prefix -eq 'GUID' -or $Prefix -eq 'CERT') -and (Test-DiagnosticContext -Text $Text -Index $Index -Length $Length)) { return $true }

    return $false
}

function Get-ValueShapePrefix {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = $Value.Trim().Trim('"', "'", ',', ';', ')', ']', '}')

    if ($v -match '^S-1-\d+-')                                                     { return 'SID' }
    if ($v -match '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$')  { return 'GUID' }
    if ($v -match '^[0-9a-fA-F]{32,}$')                                            { return 'CERT' }
    if ($v -match '^[^@\s]+@[^@\s]+\.[^@\s]+$')                                    { return 'UNMAPPED_UPN' }
    if ($v -match '^\d{1,3}(\.\d{1,3}){3}$')                                       { return 'IP' }
    if ($v -match '^[A-Za-z0-9_.-]+\\[A-Za-z0-9_.\-$]+$')                          { return 'PRINCIPAL' }
    if ($v -match '^(CN|OU|DC|O|L|ST|C)=')                                         { return 'X500' }

    if ($v -match '^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}$') {
        if (Test-PreserveNonSensitiveDottedArtifactName -Value $v) { return $null }
        return 'DNS'
    }

    return $null
}

# END broad false-positive preservation bootstrap

# BEGIN broad false-positive preservation filters
# Current-version hardening only: no version/banner/schema bump.
# This layer suppresses low-signal false positives found after the Java/ZooKeeper
# and broad dotted-artifact preservation passes, while keeping real network/identity
# identifiers tokenized.

if (-not (Get-Variable -Name __ULS_TestPreserveDetectedValue_BeforeLowSignalFilters -Scope Script -ErrorAction SilentlyContinue)) {
    $script:__ULS_TestPreserveDetectedValue_BeforeLowSignalFilters = ${function:Test-UlsPreserveDetectedValueBeforeLowSignalFilters}
}
if (-not (Get-Variable -Name __ULS_FindUniversalLabeledIdentifiers_BeforeLowSignalFilters -Scope Script -ErrorAction SilentlyContinue)) {
    $script:__ULS_FindUniversalLabeledIdentifiers_BeforeLowSignalFilters = ${function:Find-UlsUniversalLabeledIdentifiersCore}
}
if (-not (Get-Variable -Name __ULS_FindSecretIdentifiers_BeforeLowSignalFilters -Scope Script -ErrorAction SilentlyContinue)) {
    $script:__ULS_FindSecretIdentifiers_BeforeLowSignalFilters = ${function:Find-UlsSecretIdentifiersCore}
}

function Test-UlsLowSignalUniversalLabelValue {
    param(
        [string]$Value,
        [string]$Rule
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }

    $v = ([string]$Value).Trim()
    $r = ([string]$Rule).Trim()

    # Numeric/word fragments commonly captured by broad "label" rules in prose.
    if ($v -match '^(?:0|80|no|Starting|IPC|Auth|Connection|routing|type|nginx)$') { return $true }
    if ($v -match '^\[?ContainerId:?$') { return $true }

    # Local Unix/Linux device names are useful diagnostics, not hosts.
    if ($v -match '(?i)^/dev/[A-Za-z0-9_.-]+$') { return $true }

    # Apple/macOS diagnostic error domains and service names can look tenant-like.
    if ($v -match '(?i)^(ABAddressBookErrorDomain|kCFErrorDomainCFNetwork|NSURLErrorDomain|NSOSStatusErrorDomain|CoreDAVHTTPStatusErrorDomain)$') { return $true }
    if ($v -match '(?i)^com\.apple\.(?:security\.sos\.error|xpc\.activity)(?:/\d+)?$') { return $true }

    # Objective-C object/debug pointer forms are local diagnostic artifacts.
    if ($v -match '(?i)^<?[A-Za-z][A-Za-z0-9_.$-]*:0x[0-9a-f]+$') { return $true }

    # android/java exception/class symbols may be captured by broad principal/secret-ish rules.
    if ($v -match '(?i)^(?:android|java|javax|org|com)\.[A-Za-z0-9_.$]+(?:Exception|Error|RuntimeException)$') { return $true }

    # ULS patch 9 (high-confidence label capture): a value after a label is only an identity if it
    # LOOKS like one. Suppress common status/enum words, bare numbers, hex status codes, dotted
    # version numbers, single chars, and capture artifacts (a match that ran across a newline). A real
    # word-like identity (e.g. an account literally named "Test") should be caught by a BYOP seed term,
    # not by tokenizing every dictionary word that follows a label. Shape-y values (@, \, S-1-, dotted
    # host, etc.) and ordinary usernames (jdoe, glides) are unaffected. Privileged names (administrator,
    # admin, guest, root) are deliberately NOT in this list. Strict policy already tokenizes everything.
    $vp = $v.TrimEnd('.', ',', ';', ':', ')', ']', '}', '!', '?')
    if ($vp -match '(?i)^(yes|no|y|n|true|false|none|null|n/?a|nil|enabled|disabled|on|off|success|succeeded|successful|failure|failed|error|errors|warning|warnings|info|information|critical|verbose|started|stopped|stopping|starting|running|complete|completed|pending|active|inactive|present|absent|valid|invalid|allow|allowed|deny|denied|block|blocked|security|application|system|setup|service|services|target|source|test|tests|unknown|default|public|private|local|global|normal|high|low|medium|read|write|create|update|delete|open|close|ok|done)$') { return $true }
    if ($vp -match '^[+\-]?\d+(?:\.\d+)*$') { return $true }     # bare number, RID fragment, or dotted version
    if ($vp -match '^0x[0-9A-Fa-f]+$') { return $true }          # hex status / error code
    if ($v -match '[\r\n]') { return $true }                     # capture crossed a newline -> artifact
    if ($vp.Length -le 2) { return $true }                       # too short to be a meaningful identifier

    return $false
}

function Test-UlsLowSignalSecretValue {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }

    $v = ([string]$Value).Trim()

    # Java/Android exception class names and Apple diagnostic service identifiers are not secrets.
    if ($v -match '(?i)^(?:android|java|javax|org|com)\.[A-Za-z0-9_.$]+(?:Exception|Error|RuntimeException)$') { return $true }
    if ($v -match '(?i)^com\.apple\.xpc\.activity/\d+$') { return $true }

    return $false
}

function Test-UlsPreserveCommonFalsePositiveValue {
    param(
        [string]$Value,
        [string]$Detector,
        [string]$Prefix,
        [string]$Text,
        [int]$Index = -1,
        [int]$Length = 0
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }

    $v = ([string]$Value).Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')
    $ctx = if ($null -ne $Text) { [string]$Text } else { '' }

    if ($Prefix -eq 'DNS') {
        # Local package/archive/app artifacts that are not DNS names.
        if ($v -match '(?i)\.(apk|ipa|app|framework|bundle|dylib|kext|sqm)$') { return $true }

        # Public documentation link in Hadoop sample, not an operational destination.
        if ($v -ieq 'wiki.apache.org' -and $ctx -match '(?i)NoRouteToHost|apache\.org/hadoop|For more details see') { return $true }
    }

    if ($Prefix -eq 'IP') {
        # Non-routable wildcard/bind address: useful to keep readable.
        if ($v -eq '0.0.0.0') { return $true }

        # Windows package/file version strings can look exactly like IPv4 addresses.
        $versionEsc = [regex]::Escape($v)
        if ($ctx -match "(?i)(Package_for_KB|ApplicableState|CurrentState|wcp\.dll version|~~$versionEsc\b)") { return $true }
    }

    if ($Prefix -eq 'IP6') {
        # PCI/ACPI bus/device identifiers and abbreviated status/debug fragments are not IPv6 addresses.
        if ($ctx -match '(?i)\b(PCI|ACPI|GSI|IRQ|Transparent bridge|interrupt|IStorePendingTransaction|coldpatching|onTouchEvent|chip status changed|New ido chip|mLp\()\b') { return $true }

        # Very short :: fragments are almost always parser artifacts in these free-form logs.
        if ($v -match '(?i)^(?:::?[0-9a-f]{1,3}|[0-9a-f]{1,3}::)$') { return $true }

        # A colon-hex value with no "::" and fewer than 8 groups is not a valid IPv6
        # address. Full IPv6 addresses have 8 groups; shorter forms must use "::" to compress.
        # ESENT lgpos triplets, PCI/bus IDs, and similar diagnostics stay readable in Balanced
        # mode, while real compressed or full addresses still tokenize. Strict still tokenizes everything.
        if (($v -notmatch '::') -and ($v -match '^[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})+$') -and ((@($v -split ':')).Count -lt 8)) { return $true }
    }

    return $false
}

function Test-UlsPreserveDetectedValueBeforeScopeOperatorFilter {
    param(
        [string]$Value,
        [string]$Detector,
        [string]$Prefix,
        [string]$Text,
        [int]$Index = -1,
        [int]$Length = 0
    )

    try {
        if (& $script:__ULS_TestPreserveDetectedValue_BeforeLowSignalFilters `
            -Value $Value `
            -Detector $Detector `
            -Prefix $Prefix `
            -Text $Text `
            -Index $Index `
            -Length $Length) {
            return $true
        }
    }
    catch { }

    if (Test-UlsPreserveCommonFalsePositiveValue -Value $Value -Detector $Detector -Prefix $Prefix -Text $Text -Index $Index -Length $Length) {
        return $true
    }

    return $false
}

function Find-UniversalLabeledIdentifiers {
    param([Parameter(Mandatory)][string]$Text)

    $items = @(& $script:__ULS_FindUniversalLabeledIdentifiers_BeforeLowSignalFilters -Text $Text)
    if ($script:ScrubPolicy -eq 'Strict') { return @($items) }

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($id in $items) {
        $raw = ''
        $rule = ''
        try { $raw = [string]$id.Raw } catch { $raw = '' }
        try { $rule = [string]$id.Rule } catch { $rule = '' }

        if (Test-UlsLowSignalUniversalLabelValue -Value $raw -Rule $rule) { continue }
        [void]$out.Add($id)
    }

    return @($out.ToArray())
}

function Find-SecretIdentifiers {
    param([Parameter(Mandatory)][string]$Text)

    $items = @(& $script:__ULS_FindSecretIdentifiers_BeforeLowSignalFilters -Text $Text)
    if ($script:ScrubPolicy -eq 'Strict') { return @($items) }

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($id in $items) {
        $raw = ''
        try { $raw = [string]$id.Raw } catch { $raw = '' }

        if (Test-UlsLowSignalSecretValue -Value $raw) { continue }
        [void]$out.Add($id)
    }

    return @($out.ToArray())
}

# END broad false-positive preservation filters

# BEGIN broad false-positive hardening: C++ scope operator IPv6 fragments
# Current-version bugfix only: no version/banner/schema bump.
#
# Some macOS/corecaptured/kernel lines contain C++/IOKit scope operators such as:
#   CCIOReporterFormatter::addRegistryChildToChannelDictionary
#   AppleThunderboltNHIType2::waitForOk2Go2Sx
#   en0::IO80211Interface::postMessage
#
# A generic IPv6 shape regex can see tiny substrings like "::add", "e2::",
# "0::", "face::", or "::f" inside those symbols. In Balanced/Readable mode,
# preserve those when the match is embedded in an alphanumeric symbol context.
# Real standalone IPv6 addresses continue through the previous detector logic.
if (-not (Get-Variable -Name __ULS_TestPreserveDetectedValue_BeforeScopeOperatorFilter -Scope Script -ErrorAction SilentlyContinue)) {
    $script:__ULS_TestPreserveDetectedValue_BeforeScopeOperatorFilter = ${function:Test-UlsPreserveDetectedValueBeforeScopeOperatorFilter}
}

function Test-UlsScopeOperatorIpv6FalsePositive {
    param(
        [string]$Value,
        [string]$Prefix,
        [string]$Text,
        [int]$Index = -1,
        [int]$Length = 0
    )

    if ($Prefix -ne 'IP6') { return $false }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }

    $v = ([string]$Value).Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')
    if ([string]::IsNullOrWhiteSpace($v)) { return $false }

    # Only target the tiny compressed fragments that commonly arise from
    # language scope operators. Do not preserve full multi-hextet IPv6 values here.
    if ($v -notmatch '^(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{0,4})$') { return $false }
    if ($v -match '^(?i)(?:fe80|2607|2001|fd[0-9a-f]{2}|fc[0-9a-f]{2})') { return $false }

    if ([string]::IsNullOrEmpty($Text) -or $Index -lt 0) { return $false }

    $len = if ($Length -gt 0) { $Length } else { $Value.Length }
    if ($len -lt 2) { return $false }

    $before = ''
    $after = ''
    if ($Index -gt 0) {
        $before = $Text.Substring($Index - 1, 1)
    }
    if (($Index + $len) -lt $Text.Length) {
        $after = $Text.Substring($Index + $len, 1)
    }

    # If the detector match is embedded inside an identifier, it is much more
    # likely to be a C++/Obj-C/IOKit scope-operator fragment than a real IPv6.
    if ($before -match '[A-Za-z0-9_]' -or $after -match '[A-Za-z0-9_]') { return $true }

    # Also preserve when the nearby context visibly contains a scoped method/class.
    $start = [Math]::Max(0, $Index - 48)
    $take = [Math]::Min($Text.Length - $start, $len + 96)
    $ctx = $Text.Substring($start, $take)
    if ($ctx -match '[A-Za-z_][A-Za-z0-9_]{1,80}::[A-Za-z_][A-Za-z0-9_]{1,80}') { return $true }

    return $false
}

function Test-PreserveDetectedValue {
    param(
        [string]$Value,
        [string]$Detector,
        [string]$Prefix,
        [string]$Text,
        [int]$Index = -1,
        [int]$Length = 0
    )

    if (Test-UlsScopeOperatorIpv6FalsePositive -Value $Value -Prefix $Prefix -Text $Text -Index $Index -Length $Length) {
        return $true
    }

    return (& $script:__ULS_TestPreserveDetectedValue_BeforeScopeOperatorFilter `
        -Value $Value `
        -Detector $Detector `
        -Prefix $Prefix `
        -Text $Text `
        -Index $Index `
        -Length $Length)
}

# END broad false-positive hardening: C++ scope operator IPv6 fragments

# BEGIN performance and precision policy layer
if (-not (Get-Variable -Name __ULS_TestPreserveDetectedValue_BeforePolicyLayer -Scope Script -ErrorAction SilentlyContinue)) {
    $script:__ULS_TestPreserveDetectedValue_BeforePolicyLayer = ${function:Test-PreserveDetectedValue}
}
if (-not (Get-Variable -Name __ULS_TestPreserveUniversalLabeledValue_BeforePolicyLayer -Scope Script -ErrorAction SilentlyContinue)) {
    $script:__ULS_TestPreserveUniversalLabeledValue_BeforePolicyLayer = ${function:Test-PreserveUniversalLabeledValue}
}
if (-not (Get-Variable -Name __ULS_FindIdentifiers_BeforePolicyLayer -Scope Script -ErrorAction SilentlyContinue)) {
    $script:__ULS_FindIdentifiers_BeforePolicyLayer = ${function:Find-Identifiers}
}

function Test-UlsHighConfidenceUniversalLabelValue {
    param($Rule, [string]$Label, [string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = ([string]$Value).Trim().Trim('"', "'", '.', ',', ';', ':', '}', ']', ')')
    if ([string]::IsNullOrWhiteSpace($v)) { return $false }
    if ($Rule -and ([string]$Rule.Name -match 'SecretLabels')) { return $true }
    if ($Label -match '(?i)(key|secret|token|password|passwd|pwd|auth|authorization|credential)') { return $true }
    if (Test-UlsWellKnownSid -Value $v) { return $false }
    if (Test-UlsWellKnownWindowsPrincipal -Value $v) { return $false }
    if ($v -match '^S-1-\d+(?:-\d+)+$') { return $true }
    if ($v -match '^[A-Za-z0-9_.-]+\\[A-Za-z0-9_.\-$]+$') { return $true }
    if ($v -match '\$$') { return $true }
    if ($v -match '^[^@\s]+@[^@\s]+\.[^@\s]+$') { return $true }
    if ($v -match '^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$') { return -not (Test-PreserveIpAddress -Value $v) }
    if ($v -match ':' -and (Test-UlsValidIpv6Address -Value $v)) { return -not (Test-PreserveIpAddress -Value $v) }
    if ($v -match '^(CN|OU|DC|O|L|ST|C)=') { return $true }
    if ($v -match '^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}$') {
        if (Test-AllowedDomain -Value $v) { return $false }
        if (Test-WindowsDiagnosticDottedName -Value $v) { return $false }
        return $true
    }
    if ($Label -match '(?i)(host|server|machine|computer|device|workstation|client name|node|instance)') {
        return ($v -match '^[A-Za-z][A-Za-z0-9_-]{2,63}$' -and $v -notmatch '(?i)^(system|security|application|setup|default|unknown|localhost|workgroup)$')
    }
    if ($Label -match '(?i)(serial\s*number|serialnumber|serial|imei|meid)') {
        return ($v -match '^[A-Za-z0-9][A-Za-z0-9._-]{4,63}$')
    }
    if ($Label -match '(?i)(account|user|principal|subject|target|caller|login|identity|domain|tenant|realm)') {
        return ($v.Length -ge 3 -and $v -notmatch '(?i)^(system|security|application|setup|default|unknown|localhost|workgroup|nt authority|builtin|local service|network service|anonymous logon)$')
    }
    if ($Label -match '(?i)(url|uri|endpoint|callback|redirect)') {
        return ($v -match '^(?i)[a-z][a-z0-9+.-]*://')
    }
    if ($Label -match '(?i)(request|correlation|trace|session|transaction|object)') {
        if ($Label -notmatch '(?i)(tenant|device|aad|azure\s*ad|entra|enrollment|managed\s*device|user|principal|serial|imei|meid)') { return $false }
        return ($v -match '^[0-9a-fA-F]{16,}$' -or $v -match '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$')
    }
    return $false
}

function Test-UlsPolicyPreserveUniversalLabeledValue {
    param($Rule, [string]$Label, [string]$Value)

    try {
        if (& $script:__ULS_TestPreserveUniversalLabeledValue_BeforePolicyLayer -Rule $Rule -Label $Label -Value $Value) { return $true }
    }
    catch { }

    if ($script:ScrubPolicy -eq 'Strict') { return $false }
    if (Test-UlsStandaloneTimestampLikeValue -Value $Value) { return $true }
    if (Test-UlsCompositeStatusPayload -Value $Value) { return $true }
    if (Test-UlsXmlStateFragmentValue -Value $Value) { return $true }
    if ($Label -match '(?i)(account|user|principal|subject|target|caller|login|identity)' -and ((Test-UlsLongNaturalLanguagePrincipalNoise -Value $Value) -or (Test-UlsLogonBannerTitleValue -Value $Value))) { return $true }
    if (-not (Test-UlsHighConfidenceUniversalLabelValue -Rule $Rule -Label $Label -Value $Value)) { return $true }
    return $false
}

function Test-UlsPolicyPreserveDetectedValue {
    param(
        [string]$Value,
        [string]$Detector,
        [string]$Prefix,
        [string]$Text,
        [int]$Index = -1,
        [int]$Length = 0
    )

    try {
        if (& $script:__ULS_TestPreserveDetectedValue_BeforePolicyLayer `
            -Value $Value `
            -Detector $Detector `
            -Prefix $Prefix `
            -Text $Text `
            -Index $Index `
            -Length $Length) {
            return $true
        }
    }
    catch { }

    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    if ($script:ScrubPolicy -eq 'Strict') { return $false }

    $v = ([string]$Value).Trim().Trim('"', "'", '.', ',', ';', ':', ')', ']', '}')
    if ([string]::IsNullOrWhiteSpace($v)) { return $true }
    if (Test-UlsStandaloneTimestampLikeValue -Value $v) { return $true }
    if (Test-UlsCompositeStatusPayload -Value $v) { return $true }
    if (Test-UlsXmlStateFragmentValue -Value $v) { return $true }
    if ($Prefix -eq 'PRINCIPAL' -and ((Test-UlsLongNaturalLanguagePrincipalNoise -Value $v) -or (Test-UlsLogonBannerTitleValue -Value $v) -or (Test-UlsRelativeDiagnosticBackslashPathValue -Value $v))) { return $true }

    if (Test-UlsWindowsEventXmlPreserveDetectedValue -Value $v -Detector $Detector -Prefix $Prefix -Text $Text -Index $Index -Length $Length) { return $true }
    if ($Prefix -eq 'SID' -and (Test-UlsWellKnownSid -Value $v)) { return $true }
    if ($Prefix -eq 'PRINCIPAL' -and (Test-UlsWellKnownWindowsPrincipal -Value $v)) { return $true }
    if ($Prefix -eq 'PRINCIPAL' -and (Test-WindowsPathLikeDomainUser -Value $v -Text $Text -Index $Index -Length $Length)) { return $true }
    if ($Prefix -eq 'X500' -and $v -match '(?i)^CN=\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$') { return $true }
    if ($Prefix -eq 'URI') {
        if (Test-UlsDiagnosticPathOnlyUri -Value $v) { return $true }
        $hasScheme = ($v -match '^(?i)[a-z][a-z0-9+.-]*://')
        if (-not $hasScheme) {
            if (Test-UlsDiagnosticPathOnlyUri -Value $v) { return $true }
            $ctx = Get-UlsDetectorContext -Text $Text -Index $Index -Length $Length
            if (-not (Test-UlsSensitiveMapContext -Text $ctx) -and -not (Test-UlsContainsEmbeddedSensitiveValue -Value $v)) { return $true }
        }
    }
    if ($Prefix -eq 'DNS' -and (Test-WindowsDiagnosticDottedName -Value $v)) { return $true }
    if ($Prefix -eq 'IP6' -and -not (Test-UlsValidIpv6Address -Value $v)) { return $true }
    if ($Prefix -eq 'GUID') {
        if (Test-PreserveGuid -Value $v) { return $true }
        if (-not (Test-UlsGuidHasSensitiveContext -Text $Text -Index $Index -Length $Length)) { return $true }
    }
    if ($Prefix -eq 'CERT' -and -not (Test-UlsLongHexHasSensitiveContext -Text $Text -Index $Index -Length $Length)) { return $true }
    if ($Prefix -eq 'BLOB') {
        if (-not (Test-LooksLikeBase64Blob -Value $v)) { return $true }
        $blobCtx = Get-UlsDetectorContext -Text $Text -Index $Index -Length $Length
        if ($blobCtx -notmatch '(?i)\b(secret|token|password|passwd|pwd|credential|authorization|bearer|client[_\s-]*secret|api[_\s-]*key|private[_\s-]*key|certificate|cert|thumbprint)\b') { return $true }
    }
    return $false
}

function Find-UlsConnectionHostIdentifiers {
    param([Parameter(Mandatory)][string]$Text)

    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    if ($Text.IndexOf('://') -lt 0 -and $Text -notmatch '(?i)\b(server|host|address|bootstrap\.servers|broker\.list|data source)\s*=') { return @() }

    function _AddConnectionHostId {
        param([string]$Raw, [string]$Reason)
        if ([string]::IsNullOrWhiteSpace($Raw)) { return }
        $v = ([string]$Raw).Trim().Trim('[',']')
        if ([string]::IsNullOrWhiteSpace($v)) { return }
        if ((Is-AlreadyToken -Value $v) -or (Test-ScrubAllowlist -Value $v) -or (Test-AllowedDomain -Value $v)) { return }
        $prefix = Get-UlsConnectionHostPrefix -HostValue $v
        if (-not $prefix) { return }
        if ($prefix -eq 'IP6' -and -not (Test-UlsValidIpv6Address -Value $v)) { return }
        $norm = Normalize-TokenKey -Value $v
        if (-not $norm -or $seen.ContainsKey($norm)) { return }
        $seen[$norm] = $true
        [void]$out.Add([pscustomobject]@{ Raw = $v; Prefix = $prefix; Detector = 'ConnectionHost'; Reason = $Reason })
    }

    foreach ($m in [regex]::Matches($Text, '(?i)\b(?:jdbc:[a-z0-9+.-]+:)?(?:postgres(?:ql)?|mysql|mariadb|sqlserver|oracle|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|kafka|zookeeper|ws|wss|http|https)://(?:[^@\s/;,?]+@)?(?<host>\[[^\]\s]+\]|[A-Za-z0-9][A-Za-z0-9_.-]{0,252}|\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?')) {
        _AddConnectionHostId -Raw $m.Groups['host'].Value -Reason 'URL/connection string host'
    }
    foreach ($m in [regex]::Matches($Text, '(?i)\b(?:server|host|address|bootstrap\.servers|broker\.list|data source)\s*=\s*(?<host>[A-Za-z0-9][A-Za-z0-9_.-]{1,252}|\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?')) {
        _AddConnectionHostId -Raw $m.Groups['host'].Value -Reason 'Connection string host key'
    }

    return @($out.ToArray())
}

function Find-UlsWindowsEventCsvTextIdentifiersFast {
    param([Parameter(Mandatory)][string]$Text)

    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }

    function _AddFastWindowsEventId {
        param([string]$Raw, [string]$Prefix, [string]$Detector, [string]$Reason)
        if ([string]::IsNullOrWhiteSpace($Raw) -or [string]::IsNullOrWhiteSpace($Prefix)) { return }
        $v = ([string]$Raw).Trim().Trim('"', "'", '.', ',', ';', ':', '}', ']', ')')
        if ([string]::IsNullOrWhiteSpace($v)) { return }
        if ((Is-AlreadyToken -Value $v) -or (Test-ScrubAllowlist -Value $v)) { return }
        if (Test-PreserveDetectedValue -Value $v -Detector $Detector -Prefix $Prefix -Text $Reason -Index 0 -Length $v.Length) { return }
        $norm = Normalize-TokenKey -Value $v
        if (-not $norm -or $seen.ContainsKey($norm)) { return }
        $seen[$norm] = $true
        [void]$out.Add([pscustomobject]@{ Raw = $v; Prefix = $Prefix; Detector = $Detector; Reason = $Reason })
    }

    foreach ($m in [regex]::Matches($Text, '(?m)^(?:"[^"]*",){6}"(?<machine>[^"]+)"')) {
        _AddFastWindowsEventId -Raw $m.Groups['machine'].Value -Prefix 'COMPUTER' -Detector 'WindowsEventCsvColumn' -Reason 'MachineName'
    }
    foreach ($m in [regex]::Matches($Text, '(?m)^(?:"[^"]*",){7}"(?<userid>S-1-\d+(?:-\d+)*)"')) {
        _AddFastWindowsEventId -Raw $m.Groups['userid'].Value -Prefix 'SID' -Detector 'WindowsEventCsvColumn' -Reason 'UserId'
    }
    foreach ($m in [regex]::Matches($Text, '""(?<key>EventData_[^""]+)""\s*:\s*""(?<value>[^""]*)""')) {
        $key = $m.Groups['key'].Value
        $value = $m.Groups['value'].Value
        $prefix = Get-UlsWindowsEventKeyPrefix -KeyName $key -Value $value
        if ($prefix) { _AddFastWindowsEventId -Raw $value -Prefix $prefix -Detector 'WindowsEventJsonKey' -Reason $key }
    }
    foreach ($m in [regex]::Matches($Text, '(?i)\b(?:Security ID|TargetSid|SubjectUserSid)\s*:\s*(?<value>S-1-\d+(?:-\d+)+)')) {
        _AddFastWindowsEventId -Raw $m.Groups['value'].Value -Prefix 'SID' -Detector 'WindowsEventMessageLabel' -Reason 'Security ID'
    }
    foreach ($m in [regex]::Matches($Text, '(?i)\b(?:Account Name|Target User Name|Subject User Name|TargetUserName|SubjectUserName)\s*:\s*(?<value>[^\s,;]+)')) {
        _AddFastWindowsEventId -Raw $m.Groups['value'].Value -Prefix 'PRINCIPAL' -Detector 'WindowsEventMessageLabel' -Reason 'Account/User Name'
    }
    foreach ($m in [regex]::Matches($Text, '(?i)\b(?:Account Domain|Target Domain Name|Subject Domain Name|TargetDomainName|SubjectDomainName|Workstation Name|WorkstationName|Computer Name)\s*:\s*(?<value>[^\s,;]+)')) {
        _AddFastWindowsEventId -Raw $m.Groups['value'].Value -Prefix 'COMPUTER' -Detector 'WindowsEventMessageLabel' -Reason 'Domain/Workstation'
    }
    foreach ($m in [regex]::Matches($Text, '(?i)\b(?:Source Network Address|Client Address|IP Address|IpAddress)\s*:\s*(?<value>[^\s,;]+)')) {
        $rawIp = $m.Groups['value'].Value
        $p = if ($rawIp -match ':' -and (Test-UlsValidIpv6Address -Value $rawIp)) { 'IP6' } else { 'IP' }
        _AddFastWindowsEventId -Raw $rawIp -Prefix $p -Detector 'WindowsEventMessageLabel' -Reason 'Network Address'
    }
    foreach ($m in [regex]::Matches($Text, 'S-1-\d+(?:-\d+)+')) {
        _AddFastWindowsEventId -Raw $m.Value -Prefix 'SID' -Detector 'WindowsEventSid' -Reason 'SID shape'
    }
    foreach ($m in [regex]::Matches($Text, '(?<!\d)(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)(?!\.\d)')) {
        _AddFastWindowsEventId -Raw $m.Value -Prefix 'IP' -Detector 'WindowsEventIPv4' -Reason 'IPv4 shape'
    }
    foreach ($id in (Find-UlsConnectionHostIdentifiers -Text $Text)) {
        _AddFastWindowsEventId -Raw ([string]$id.Raw) -Prefix ([string]$id.Prefix) -Detector 'ConnectionHost' -Reason ([string]$id.Reason)
    }
    foreach ($id in (Find-SecretIdentifiers -Text $Text)) {
        _AddFastWindowsEventId -Raw ([string]$id.Raw) -Prefix ([string]$id.Prefix) -Detector 'Secret' -Reason 'Secret pattern'
    }

    return @($out.ToArray())
}

function Find-UlsPolicyIdentifiers {
    param([Parameter(Mandatory)][string]$Text)

    if (Test-UlsWindowsEventXmlText -Text $Text) {
        return @(Find-UlsWindowsEventXmlTextIdentifiers -Text $Text)
    }

    if ($Text.Length -gt 1MB -and $Text -match 'EventDataJson' -and $Text -match 'ProviderName' -and $Text -match 'MachineName') {
        return @(Find-UlsWindowsEventCsvTextIdentifiersFast -Text $Text)
    }

    $base = @(& $script:__ULS_FindIdentifiers_BeforePolicyLayer -Text $Text)
    $seen = @{}
    foreach ($id in $base) {
        try {
            $norm = Normalize-TokenKey -Value ([string]$id.Raw)
            if ($norm) { $seen[$norm] = $true }
        }
        catch { }
    }

    $extra = New-Object System.Collections.Generic.List[object]
    foreach ($id in (Find-UlsConnectionHostIdentifiers -Text $Text)) {
        $norm = Normalize-TokenKey -Value ([string]$id.Raw)
        if (-not $norm -or $seen.ContainsKey($norm)) { continue }
        $seen[$norm] = $true
        try {
            Add-DetectionTrace -Detector 'ConnectionHost' -Action 'Tokenized' -Value ([string]$id.Raw) -Token (Get-Token -Value ([string]$id.Raw) -Prefix ([string]$id.Prefix)) -Reason ([string]$id.Reason) -ColumnName '(connection)' -Context ''
        }
        catch { }
        [void]$extra.Add($id)
    }

    return @($base + @($extra.ToArray()))
}

${function:Test-PreserveUniversalLabeledValue} = ${function:Test-UlsPolicyPreserveUniversalLabeledValue}
${function:Test-PreserveDetectedValue} = ${function:Test-UlsPolicyPreserveDetectedValue}
${function:Find-Identifiers} = ${function:Find-UlsPolicyIdentifiers}

# END performance and precision policy layer

Set-Alias -Name Invoke-UniversalLogScrubber -Value Invoke-UniversalScrubber
Set-Alias -Name Test-ULSLogFormat -Value Test-LogFormat

Export-ModuleMember -Function `
    Invoke-UniversalScrubber, Test-LogFormat, New-ScrubTokenMap, New-ScrubTokenMapFromAD, `
    Import-ScrubTokenMap, Invoke-ScrubFile, Get-ScrubProfile, `
    Invoke-UlsCSharpDiscoveryWorkerShard, Invoke-UlsCSharpDiscoverRangeBatch, Invoke-UlsCSharpScrubFileBatch, `
    ConvertFrom-EvtxToEventXmlText, ConvertFrom-EtlToEventXmlText, ConvertFrom-W3CToCsv, ConvertFrom-XlsxToCsv, ConvertFrom-DocxToText, ConvertFrom-PptxToText, `
    Import-ScrubProfileFile, Import-ScrubProfileExtensionFile, Test-ScrubProfile, New-ScrubProfileTemplate, New-ScrubProfileFromSample, `
    Restore-ScrubbedFile, New-SyntheticLog `
    -Alias `
    Invoke-UniversalLogScrubber, Test-ULSLogFormat

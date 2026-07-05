# Universal Log Scrubber Usage Guide

This guide covers the public `1.1.0` workflow for running Universal Log Scrubber against files, folders, diagnostic bundles, and common enterprise log exports.

## 1. Start interactive mode

The easiest way to start is now the interactive command console:

```powershell
Import-Module .\UniversalLogScrubber\UniversalLogScrubber.psd1 -Force
Invoke-UniversalScrubber
```

The launcher script does the same thing when run without arguments:

```powershell
.\scripts\Run-UniversalScrubber.ps1
```

Inside the console, commands use the `(ULS) >` prompt:

```text
(ULS) > help
(ULS) > set path ".\samples\logs"
(ULS) > set workdir ".\samples\out\quickstart"
(ULS) > set saltfile ".\salt.txt"
(ULS) > set recurse true
(ULS) > plan
(ULS) > scrub
(ULS) > last
(ULS) > exit
```

Useful commands:

| Command | Purpose |
|---|---|
| `help` | Show interactive help. Use `help scrub`, `help set`, or `help profile` for command-specific help. |
| `profile` | List built-in profiles or inspect one profile. Use `profile .\docs\profiles\kv-log-profile.json` for BYOP files. |
| `validate` | Validate a built-in or BYOP profile before scrubbing. Use `validate profile .\docs\profiles\kv-log-profile.json`. |
| `set` | Show or set session defaults such as `path`, `workdir`, `profile`, `saltfile`, and `recurse`. |
| `plan` | Preview the command that will run without running it. Literal salts are hidden. |
| `scrub` | Run a guided or session-based scrub job. |
| `last` | Show the most recent interactive run, manifest, skipped files, failed files, or command. |
| `version` | Show version/runtime details. Use `version full` for synopsis, description, and notes. |
| `doctor` | Check the local host, PowerShell version, paths, optional tools, and common readiness items. |

## 2. Scripted command pattern

Scripted and automation workflows still use the normal PowerShell command style:

```powershell
Invoke-UniversalScrubber `
  -Path <file-or-folder> `
  -WorkDir <output-folder> `
  -MapSource Discover `
  -TokenMapMode Replace `
  -SaltFile .\salt.txt `
  -Recurse `
  -NonInteractive
```

Use `-Profile <profile-name>` when you want to force one profile for the whole run. If `-Profile` is omitted, the scrubber uses its normal format-aware workflow.

For a repository checkout, the launcher script is usually the easiest entry point:

```powershell
.\scripts\Run-UniversalScrubber.ps1 `
  -Path .\samples\logs `
  -WorkDir .\samples\out\quickstart `
  -Recurse `
  -MapSource Discover `
  -TokenMapMode Replace `
  -SaltFile .\salt.txt `
  -NonInteractive
```

## 3. Auto, profiles, and BYOP

In the interactive console, `Auto` is the default. Auto does **not** force a single profile. It means the scrubber will use its existing format-aware defaults and conversion workflows. This is useful for mixed folders.

Use a specific profile when you know the source:

| Profile | Best for |
|---|---|
| `Generic` | Unknown files where broad detection is preferred. |
| `Text` | Free-form text where every line should be scanned. |
| `WindowsEventXml` | Windows Event logs converted locally to event XML text. |
| `IntuneDiagnostics` | Intune diagnostic bundles, MDM reports, registry exports, XML/HTML reports, `.log_` files, and converted event text. |
| `Intune` | Intune/Endpoint Manager CSV exports such as managed devices, app, enrollment, policy, and compliance reports. |
| `ServiceNow` | Incident, change, task, CMDB, caller, assignment, CI, notes, and URL exports. |
| `Nexthink` | Device, user, binary, campaign, destination, experience, and remote-action exports. |
| `Sccm` | SCCM/MECM inventory, deployment, collection, compliance, and client exports. |
| `SccmText` | SCCM/MECM/ConfigMgr CMTrace-style client and management-point logs. |
| `Firewall`, `FirewallText`, `FirewallCsv` | Firewall, VPN, network security, syslog, key-value, and CSV exports. |
| `Vpn` | VPN and remote-access authentication gateway logs. |
| `CloudAudit` | Cloud activity/audit exports. |
| `IdentityProvider` | Entra, Okta, SSO, MFA, and directory sign-in logs. |
| `Edr` | EDR/XDR alert exports. |
| `Kubernetes` | Kubernetes audit and workload logs. |
| `Database` | Database audit/query logs. |

For BYOP profiles:

```powershell
Invoke-UniversalScrubber `
  -Path .\samples\logs\gateway-kv.log `
  -ProfileFile .\docs\profiles\kv-log-profile.json `
  -WorkDir .\samples\out\kv `
  -SaltFile .\salt.txt `
  -MapSource Discover `
  -TokenMapMode Replace `
  -NonInteractive
```

Inside interactive mode:

```text
(ULS) > profile .\docs\profiles\kv-log-profile.json
(ULS) > validate profile .\docs\profiles\kv-log-profile.json
(ULS) > set profilefile .\docs\profiles\kv-log-profile.json
(ULS) > plan
```

`-AutoProfile` is still available for strict noninteractive use, but it requires one high-confidence profile for all selected files. For mixed folders, omit `-Profile` or use the interactive Auto default.

### Validate profiles before use

For noninteractive checks, use the PowerShell command:

```powershell
Test-UniversalScrubberProfile -Profile Generic
Test-UniversalScrubberProfile -ProfileFile .\docs\profiles\kv-log-profile.json -Detailed
Test-UniversalScrubberProfile -ProfileFile .\docs\profiles\kv-log-profile.json -Quiet
```

`Test-UniversalScrubberProfile` validates that the profile can be loaded by the scrubber runtime, checks required profile shape, compiles regex rules, counts rules, warns about unknown profile properties, and checks referenced seed/allowlist files. `-Quiet` returns `$true` or `$false` for scripts and CI.

Inside interactive mode:

```text
(ULS) > validate profile
(ULS) > validate profile Generic
(ULS) > validate profile .\docs\profiles\kv-log-profile.json
(ULS) > validate profile .\docs\profiles\kv-log-profile.json -Detailed
```

When no target is supplied, `validate profile` uses the current interactive session profile. If the current profile is `Auto`, the console explains that Auto is a workflow default rather than a profile file.

## 4. Salt handling

Use one of these:

```powershell
-SaltFile .\salt.txt
-SaltFromEnv SCRUB_SALT
-Salt "temporary-value"
```

Prefer `-SaltFile` or `-SaltFromEnv` for repeatable workflows. Literal salts are accepted, but the interactive `plan` and `scrub` previews hide them and show `$global:UlsInteractiveSalt` instead.

Never upload salts or token maps.

## 5. Dry runs and recommendation runs

Recommendation-only mode does not require a salt:

```powershell
Invoke-UniversalScrubber -Path .\samples\logs -RecommendOnly -Recurse -NonInteractive
```

Dry-run mode previews detections and does not write scrubbed output:

```powershell
Invoke-UniversalScrubber `
  -Path .\samples\logs `
  -WorkDir .\samples\out\dryrun `
  -DryRun `
  -SaltFile .\salt.txt `
  -MapSource Discover `
  -Recurse `
  -NonInteractive
```

For first-time use, `-SafeFirstRun` is a conservative local review workflow.

## 6. Windows Event, EVTX, and ETL workflows

Native `.evtx` and `.evt` files are converted locally to event XML text before scrubbing:

```powershell
Invoke-UniversalScrubber `
  -Path .\logs\win-events `
  -WorkDir .\out\win-events `
  -SaltFile .\salt.txt `
  -MapSource Discover `
  -TokenMapMode Replace `
  -Recurse `
  -NonInteractive
```

`.etl` files are skipped with a warning unless `-ConvertEtl` is supplied:

```powershell
Invoke-UniversalScrubber `
  -Path .\logs\traces `
  -WorkDir .\out\traces `
  -ConvertEtl `
  -SaltFile .\salt.txt `
  -MapSource Discover `
  -NonInteractive
```

ETL conversion depends on Windows-local event tooling. If conversion is not available, convert locally on a Windows host and scrub the resulting `.events.txt` output.

## 7. Intune diagnostics

```powershell
Invoke-UniversalScrubber `
  -Path "C:\Path\To\DiagLogs" `
  -WorkDir "C:\Path\To\ScrubbedOutput" `
  -Profile IntuneDiagnostics `
  -Recurse `
  -MapSource Discover `
  -TokenMapMode Replace `
  -SaltFile .\salt.txt `
  -ExtractCab `
  -NonInteractive
```

Review skipped files and output before sharing. Upload only scrubbed files or a reviewed safe bundle.

## 8. Safe upload bundles

```powershell
Invoke-UniversalScrubber `
  -Path .\logs `
  -WorkDir .\out `
  -SaltFile .\salt.txt `
  -MapSource Discover `
  -TokenMapMode Replace `
  -SafeBundleOut .\out\safe-upload.zip `
  -Recurse `
  -NonInteractive
```

Safe bundles include successful scrubbed outputs and exclude private token maps, salts, raw inputs, converted intermediates, detailed reports, manifests, and local-only evidence.

## 9. Restore findings locally

Use the private token map only inside the secure environment:

```powershell
Restore-ScrubbedFile `
  -Path .\out\example.scrubbed.log `
  -TokenMapCsv .\out\scrub_token_map_DO_NOT_UPLOAD.csv `
  -OutPath .\out\example.restored.local-only.log
```

Do not upload restored files.

## 10. Help and version commands

```powershell
Invoke-UniversalScrubber -Help
Invoke-UniversalScrubber -Version
Invoke-UniversalScrubber -Interactive
Get-Help Invoke-UniversalScrubber -Full
```

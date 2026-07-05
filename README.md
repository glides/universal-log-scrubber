# Universal Log Scrubber v1.1.0

**Share the logs, not the exposure.**

Universal Log Scrubber is a local-first PowerShell module for preparing logs, diagnostic bundles, exports, and evidence files before they are shared with vendors, outside reviewers, support teams, or approved analysis tools.

It replaces sensitive values with deterministic typed tokens while keeping the surrounding log structure readable. Reviewers can still follow events, counts, timelines, users, devices, and relationships without receiving the original identifiers.

## Latest updates

**v1.1.0** is the interactive workflow release.

- Added the default interactive command console. Running `Invoke-UniversalScrubber` with no arguments now opens the ULS console.
- Added `-Interactive`, `-Help`, and improved `-Version` output.
- Added interactive commands for `help`, `profile`, `validate`, `set`, `plan`, `scrub`, `last`, `version`, `doctor`, `examples`, and `exit`.
- Added session defaults so operators can set `path`, `workdir`, `profile`, `saltfile`, `recurse`, and other options once, then preview or run jobs.
- Added safe command previews with `plan`. Literal salts are hidden and represented as `$global:UlsInteractiveSalt` instead of being printed in the console.
- Made `Auto` the interactive default. Auto does not force a single profile; it lets the existing format-aware workflow handle mixed inputs unless the operator explicitly sets a profile.
- Added BYOP profile inspection and validation from the interactive console with `profile .\path\to\profile.json` and `validate profile .\path\to\profile.json`.
- Improved ETL handling so `.etl` files are skipped with clear guidance unless `-ConvertEtl` is supplied.
- Updated Windows Event wording to the current converted event XML text workflow.

## What it helps protect

Universal Log Scrubber is designed to reduce exposure from common log content such as:

- Users, UPNs, email addresses, service accounts, and domain principals.
- Hostnames, computer names, device names, serial-like identifiers, and asset labels.
- Private IP addresses, IPv6 addresses, MAC addresses, SSIDs, and network identifiers.
- SIDs, GUIDs, object IDs, tenant IDs, cloud account IDs, and X.500-style names.
- URLs, URIs, UNC paths, user-profile paths, and connection strings.
- Bearer tokens, API keys, client secrets, passwords, JWTs, private-key material, and other secret-shaped values.
- Client names, project names, internal code names, tenant display names, and other sensitive words supplied as seed terms.

## What it does

- Scrubs common structured, semi-structured, and text log formats.
- Creates a private token map so local reviewers can re-identify findings when needed.
- Uses deterministic tokens so the same value stays correlated across files when the same salt and map are used.
- Supports dry-run review before producing scrubbed output.
- Supports built-in profiles for common log families and BYOP profiles for local formats.
- Can extract CAB diagnostics, convert supported event files locally, and scrub the converted output.
- Can create a safe upload zip that excludes private maps, salts, raw files, intermediates, and local-only evidence.

## Common inputs

Supported workflows include CSV, TSV, PSV, JSON, JSONL/NDJSON, key-value logs, free text, syslog-style text, CEF/LEEF-like events, IIS/W3C logs, web access logs, registry exports, XML/HTML reports, Windows Event exports, EVTX/ETL-derived event text, Intune diagnostics, Office-derived text, firewall/VPN exports, cloud audit logs, identity-provider logs, EDR alerts, database audit logs, Kubernetes/container logs, ServiceNow exports, Nexthink exports, SCCM/MECM logs, and AD CS audit exports.

## Quick start

Import the module and start the interactive console:

```powershell
Import-Module .\UniversalLogScrubber\UniversalLogScrubber.psd1 -Force
Invoke-UniversalScrubber
```

Useful interactive commands:

```text
help
set path ".\samples\logs"
set workdir ".\samples\out\quickstart"
set saltfile ".\salt.txt"
set recurse true
validate profile
plan
scrub
last
exit
```

Scripted runs still work normally:

```powershell
Invoke-UniversalScrubber `
  -Path .\samples\logs `
  -WorkDir .\samples\out\quickstart `
  -MapSource Discover `
  -TokenMapMode Replace `
  -SaltFile .\salt.txt `
  -Recurse `
  -NonInteractive
```

Validate built-in or BYOP profiles before a run:

```powershell
Test-UniversalScrubberProfile -Profile Generic
Test-UniversalScrubberProfile -ProfileFile .\docs\profiles\kv-log-profile.json -Detailed
```

For Intune diagnostic bundles:

```powershell
.\scripts\Run-UniversalScrubber.ps1 `
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

## Recommended workflow

1. Run the interactive console with `Invoke-UniversalScrubber`, or run `-RecommendOnly`, `-SafeFirstRun`, or `-DryRun` first.
2. Use the default Auto behavior for mixed folders, or choose a built-in profile when the source is known.
3. Use a BYOP `-ProfileFile` or profile extension when local fields, asset patterns, tenant aliases, or vendor-specific labels need extra handling.
4. Build a fresh token map with `-MapSource Discover` and `-TokenMapMode Replace`, or reuse a trusted existing map with `-MapSource ExistingMap`.
5. Scrub into a local work directory.
6. Review skipped files, failed files, and representative scrubbed output.
7. Upload only reviewed scrubbed files or a reviewed safe bundle.

## Important files

| File | Purpose | Upload? |
|---|---|---|
| `*_scrubbed.*` | Scrubbed output files. Review before sharing. | Usually safe after review |
| `safe-upload.zip` | Optional bundle containing scrubbed outputs intended for handoff. | Usually safe after review |
| `scrub_token_map_DO_NOT_UPLOAD.csv` | Private lookup table from original values to tokens. | Never |
| `scrub_run_manifest.json` | Local run summary, skipped files, failed files, and workflow evidence. | Treat as local-only unless reviewed and explicitly approved |
| salts / salt files | Secret input used to keep tokens deterministic. | Never |
| converted intermediates | Local conversion artifacts created before scrub. | Never unless separately scrubbed and reviewed |

## Profiles and tuning

The interactive default is `Auto`, which means no single profile is forced. This is useful for mixed folders because the scrubber can use format-aware defaults and special conversion workflows. Use source-specific profiles such as `IntuneDiagnostics`, `WindowsEventXml`, `ServiceNow`, `Nexthink`, `SccmText`, `Firewall`, `CloudAudit`, `IdentityProvider`, `Edr`, `Kubernetes`, or `Database` when the log source is known.

Native Windows Event files are converted locally to event XML text and scrubbed as part of that workflow. BYOP profiles and profile extensions are available when your environment has local field names, asset patterns, tenant aliases, project names, or vendor-specific labels that generic detection cannot safely infer.

## Safety notes

Universal Log Scrubber is a defensive safe-sharing aid, not a formal anonymization guarantee. Review output before anything leaves the secure environment.

Never upload salts, token maps, raw logs, converted intermediates, detailed detection reports, profile-build reports, run manifests unless approved, or files marked `DO_NOT_UPLOAD`.

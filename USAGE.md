# Universal Log Scrubber Usage Guide

This guide covers the public `1.0.2` workflow for running Universal Log Scrubber against files, folders, diagnostic bundles, and common enterprise log exports.

## 1. Basic command pattern

```powershell
Invoke-UniversalScrubber `
  -Path <file-or-folder> `
  -WorkDir <output-folder> `
  -Profile <profile-name> `
  -MapSource Discover `
  -TokenMapMode Replace `
  -SaltFile .\salt.txt `
  -NonInteractive
```

Use `-Recurse` for nested folders.

For a repository checkout, the launcher script is usually the easiest entry point:

```powershell
.\scripts\Run-UniversalScrubber.ps1 `
  -Path .\samples\logs `
  -WorkDir .\samples\out\quickstart `
  -Profile Generic `
  -Recurse `
  -MapSource Discover `
  -TokenMapMode Replace `
  -SaltFile .\salt.txt `
  -NonInteractive
```

## 2. Choose a profile

Profiles tell the scrubber how to interpret a source. Use a specific profile when you know the source. Use `Generic` when you do not.

| Profile | Best for |
|---|---|
| `Generic` | Unknown mixed files, quick starts, and broad folder runs. |
| `Text` | Free-form text where every line should be scanned. |
| Windows Event files | Use the local event conversion workflow. Converted `.events.txt` output is scrubbed as event text. |
| `IntuneDiagnostics` | Intune diagnostic bundles, MDM reports, registry exports, XML/HTML reports, `.log_` files, and converted event text. |
| `Intune` | Intune/Endpoint Manager CSV exports such as managed devices, app, enrollment, policy, and compliance reports. |
| `ServiceNow` | Incident, change, task, CMDB, caller, assignment, CI, notes, and URL exports. |
| `Nexthink` | Device, user, binary, campaign, destination, experience, and remote-action exports. |
| `Sccm` | SCCM/MECM inventory, deployment, collection, compliance, and client exports. |
| `SccmText` | SCCM/MECM/ConfigMgr CMTrace-style client and management-point logs. |
| `Firewall`, `FirewallText`, `FirewallCsv` | Firewall, VPN, network security, syslog, key-value, and CSV exports. |
| `Vpn` | VPN and remote-access authentication gateway logs. |
| `Proxy` | Proxy, SWG, and web filtering exports. |
| `IIS` | IIS/W3C logs with `#Fields` headers. |
| `WebAccess`, `Apache` | Reverse proxy, Nginx, Apache, CDN, and web access logs. |
| `Syslog` | Syslog and syslog-like line logs. |
| `Cef`, `Logfmt` | CEF/LEEF-like key-value events and logfmt application logs. |
| `CloudAudit` | Cloud audit/activity logs with principals, tenants, resources, IPs, and request IDs. |
| `IdentityProvider` | Entra, Okta, SSO, MFA, and directory sign-in logs. |
| `Edr` | EDR/XDR alert exports with users, devices, network destinations, commands, and evidence. |
| `AppJson` | Application JSON/NDJSON logs. |
| `Database` | Database audit/query logs with users, clients, hosts, SQL text, and connection strings. |
| `Container`, `Kubernetes` | Container runtime, Docker, orchestrator, and Kubernetes audit logs. |
| `CA` | AD CS / certificate authority audit exports. |
| `Tsv`, `Psv` | Tab-separated or pipe-separated tables. |

## 3. Pick a token-map source

| Map source | Use when |
|---|---|
| `Discover` | Normal workflow. Build a map from the supplied files. |
| `ExistingMap` | Re-run against related files and keep token correlation with an earlier run. |
| `AD` | Build an identity-aware map from Active Directory before scrubbing. Requires a domain-joined session with read access. |

For most public examples and first runs, use:

```powershell
-MapSource Discover -TokenMapMode Replace
```

Use `Replace` for fresh jobs. Use `Merge` only when you intentionally want to preserve existing map rows.

## 4. Salt handling

A salt is required for deterministic tokens. Keep it private.

Recommended automation pattern:

```powershell
$env:SCRUB_SALT = 'use-a-long-random-secret-value'

Invoke-UniversalScrubber `
  -Path .\logs `
  -WorkDir .\out `
  -Profile Generic `
  -MapSource Discover `
  -SaltFromEnv SCRUB_SALT `
  -NonInteractive
```

A salt file is also supported:

```powershell
-SaltFile .\salt.txt
```

Avoid typing salts directly into shared scripts, screenshots, tickets, or command history.

## 5. Preview before scrubbing

Use recommendation modes when you are not sure what profile or workflow to use:

```powershell
Invoke-UniversalScrubber -Path .\logs -RecommendOnly -Recurse
Invoke-UniversalScrubber -Path .\logs -SafeFirstRun -Recurse
```

Use dry run when you want to inspect detection behavior before writing scrubbed outputs:

```powershell
Invoke-UniversalScrubber `
  -Path .\logs `
  -WorkDir .\out-preview `
  -Profile Generic `
  -MapSource Discover `
  -DryRun `
  -ExplainDetections `
  -SaltFile .\salt.txt `
  -NonInteractive
```

Dry-run evidence is local-only. Review it, tune profiles/seeds/allowlists if needed, then run the real scrub.

## 6. Intune diagnostic bundles

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

Notes:

- CAB extraction is explicit. Without `-ExtractCab`, CAB files are skipped and listed in the manifest.
- `.evtx` files are converted locally before scrub when supported.
- `.etl` conversion is explicit with `-ConvertEtl`.
- Converted files and extracted workspaces are local intermediates until scrubbed and reviewed.
- Use a fresh work directory for each full run.

## 7. Reuse an existing map

Use this when files belong to the same case and token correlation must stay stable:

```powershell
Invoke-UniversalScrubber `
  -Path .\more-logs `
  -WorkDir .\out-rerun `
  -Profile Generic `
  -MapSource ExistingMap `
  -TokenMapCsv .\out\scrub_token_map_DO_NOT_UPLOAD.csv `
  -SaltFile .\salt.txt `
  -NonInteractive
```

The existing map and salt must stay private.

## 8. BYOP profiles and extensions

Use `-ProfileFile` when a source needs its own profile:

```powershell
Invoke-UniversalScrubber `
  -Path .\samples\logs\kubernetes-audit.jsonl `
  -ProfileFile .\docs\profiles\examples\kubernetes-audit-profile.json `
  -WorkDir .\samples\out\kubernetes `
  -MapSource Discover `
  -SaltFile .\salt.txt `
  -NonInteractive
```

Use `-ProfileExtensionFile` when a built-in profile is close but needs local tuning:

```powershell
Invoke-UniversalScrubber `
  -Path .\samples\logs\aws-cloudtrail-management.jsonl `
  -Profile CloudAudit `
  -ProfileExtensionFile .\docs\profiles\examples\aws-cloudtrail-extension.json `
  -WorkDir .\samples\out\cloudtrail `
  -MapSource Discover `
  -SaltFile .\salt.txt `
  -NonInteractive
```

Use profile extensions for local field names, tenant aliases, application labels, asset naming patterns, project names, or known safe allowlist values.

## 9. Seeds and allowlists

Use seed terms for sensitive values that have no reliable pattern:

```powershell
Invoke-UniversalScrubber `
  -Path .\logs `
  -WorkDir .\out `
  -Profile Generic `
  -SeedFile .\seeds.txt `
  -SaltFile .\salt.txt `
  -MapSource Discover `
  -NonInteractive
```

Use allowlists for public or harmless values that should stay readable:

```powershell
-AllowlistFile .\allowlist.txt
```

Seed files and allowlists should contain only approved values. Do not publish local seed files if they contain client names, tenant names, project names, or private identifiers.

## 10. Safe upload bundles

```powershell
Invoke-UniversalScrubber `
  -Path .\logs `
  -WorkDir .\out `
  -Profile Generic `
  -MapSource Discover `
  -SaltFile .\salt.txt `
  -SafeBundleOut .\out\safe-upload.zip `
  -Force `
  -NonInteractive
```

Safe bundles are intended to include successful scrubbed outputs and a safe readme. They should exclude token maps, salts, raw inputs, converted intermediates, local-only reports, manifests, and files marked `DO_NOT_UPLOAD`.

Always inspect the zip before upload.

## 11. Review checklist

Before anything leaves the secure environment:

- Confirm the run completed without scrub or conversion failures.
- Review skipped files in `scrub_run_manifest.json`.
- Review representative scrubbed rows from each source type.
- Search scrubbed outputs for known sensitive seed terms, known usernames, known hostnames, tenant names, and case-specific identifiers.
- Upload only reviewed scrubbed files or a reviewed safe bundle.
- Keep token maps, salts, raw files, detailed reports, and local manifests private.

## 12. Troubleshooting quick notes

| Symptom | What to check |
|---|---|
| CAB files are skipped | Add `-ExtractCab` if local extraction is intended. |
| ETL files are skipped | Add `-ConvertEtl` and run on a system that can read the trace. |
| Output is missing | Review `scrub_run_manifest.json` for skipped or failed files. |
| Too many false positives | Try `Balanced` or `Readable`, add allowlists, or tune a profile extension. |
| Missed local values | Add seed terms, profile rules, or a profile extension. |
| Tokens do not correlate across runs | Reuse the same salt and trusted token map with `ExistingMap`. |

# BYOP profile examples

Universal Log Scrubber supports two profile patterns:

1. **Full BYOP profiles** with `-ProfileFile`, used when a log source needs its own schema.
2. **Profile extensions** with `-ProfileExtensionFile`, used when a built-in profile is close but needs a local overlay.

Use these examples as starting points. Tune them with dry runs before using them on sensitive logs.

## Top-level examples

| File | Type | Best used with | Purpose |
|---|---|---|---|
| `csv-schema-profile.json` | Full profile | `-ProfileFile` | CSV exports where specific columns should pass through, scan, or scrub. |
| `json-app-profile.json` | Full profile | `-ProfileFile` or compare with `AppJson` | Application JSON/NDJSON logs with user, host, tenant, request, and secret fields. |
| `kv-log-profile.json` | Full profile | `-ProfileFile` or compare with `Logfmt`/`Firewall` | key=value application, gateway, or network logs. |
| `webaccess-profile.json` | Full profile | `-ProfileFile` or compare with `WebAccess` | Web access logs with users, hosts, client IPs, URLs, referrers, and query data. |
| `profile-extension-example.json` | Extension | Any close built-in profile | Minimal starter overlay showing common extension fields. |
| `servicenow-local-extension.json` | Extension | `ServiceNow` | Local ServiceNow requester, assignment, CI, vendor-ticket, work-note, and URL fields. |
| `endpoint-management-extension.json` | Extension | `Intune`, `IntuneDiagnostics`, `Sccm`, `SccmText`, `Nexthink` | Local asset IDs, owners, device names, collection names, deployment rings, and endpoint labels. |
| `security-audit-extension.json` | Extension | `CloudAudit`, `IdentityProvider`, `Edr`, `CA`, event-text workflows | Incident, alert, tenant, identity, investigation, and audit labels. |
| `network-edge-extension.json` | Extension | `Firewall`, `FirewallCsv`, `Proxy`, `Vpn`, `WebAccess`, `IIS` | Network edge users, hosts, NAT fields, tunnel IDs, policy/rule owners, and URL labels. |
| `seed.example.txt` | Seed list | `-SeedFile` or profile `SeedFiles` | Example sensitive terms that do not have reliable patterns. |
| `allowlist.example.txt` | Allowlist | `-AllowlistFile` or profile allowlist settings | Example safe values that should remain readable. |

## Additional examples folder

| File | Type | Best used with | Purpose |
|---|---|---|---|
| `examples/aws-cloudtrail-extension.json` | Extension | `CloudAudit` | AWS ARNs, account IDs, access-key IDs, assumed-role sessions, and nested resources. |
| `examples/entra-signin-extension.json` | Extension | `IdentityProvider` | Microsoft Entra sign-in fields and nested JSON values. |
| `examples/okta-system-log-extension.json` | Extension | `IdentityProvider` or `CloudAudit` | Okta actor, client, target, and debug context values. |
| `examples/kubernetes-audit-profile.json` | Full profile | `-ProfileFile` | Kubernetes audit JSONL records. |
| `examples/paloalto-traffic-csv-profile.json` | Full profile | `-ProfileFile` or compare with `FirewallCsv` | PAN-OS traffic log CSV exports. |
| `examples/webaccess-query-token-extension.json` | Extension | `WebAccess`, `Apache`, `IIS` | Query-string secrets and URL-encoded identities. |
| `examples/database-audit-profile.json` | Full profile | `-ProfileFile` or compare with `Database` | SQL/PostgreSQL-style audit rows. |
| `examples/strict-workstation-paths-extension.json` | Extension | `Text`, `IntuneDiagnostics`, `SccmText`, event-text workflows | Stricter workstation, UNC, profile path, and local script-output handling. |

## Interactive profile inspection

In v1.1.0, the interactive console can inspect built-in profiles and BYOP profile files before you run a job:

```text
profile
profile SccmText
profile .\docs\profiles\kv-log-profile.json
validate profile .\docs\profiles\kv-log-profile.json
set profilefile .\docs\profiles\kv-log-profile.json
plan
```

This is useful when validating local profile files in secure environments without opening a separate editor or running a full scrub job.

For scripted validation or CI, use:

```powershell
Test-UniversalScrubberProfile -ProfileFile .\docs\profiles\kv-log-profile.json -Detailed
Test-UniversalScrubberProfile -ProfileFile .\docs\profiles\kv-log-profile.json -Quiet
```

## Example commands

### Extend a built-in cloud/audit profile

```powershell
Invoke-UniversalScrubber `
  -Path .\samples\logs\aws-cloudtrail-management.jsonl `
  -Profile CloudAudit `
  -ProfileExtensionFile .\docs\profiles\examples\aws-cloudtrail-extension.json `
  -WorkDir .\samples\out\cloudtrail `
  -SaltFile .\salt.txt `
  -MapSource Discover `
  -TokenMapMode Replace `
  -NonInteractive
```

### Use a full BYOP profile

```powershell
Invoke-UniversalScrubber `
  -Path .\samples\logs\kubernetes-audit.jsonl `
  -ProfileFile .\docs\profiles\examples\kubernetes-audit-profile.json `
  -WorkDir .\samples\out\kubernetes `
  -SaltFile .\salt.txt `
  -MapSource Discover `
  -TokenMapMode Replace `
  -NonInteractive
```

### Add stricter handling for a source

```powershell
Invoke-UniversalScrubber `
  -Path .\samples\logs\sysmon-event-xml.txt `
  -Profile Text `
  -ProfileExtensionFile .\docs\profiles\examples\strict-workstation-paths-extension.json `
  -WorkDir .\samples\out\sysmon-strict `
  -SaltFile .\salt.txt `
  -MapSource Discover `
  -TokenMapMode Replace `
  -NonInteractive
```

## Guidance

- Prefer a focused extension over changing broad detector behavior.
- Keep profiles generic enough to share; keep client-specific values in local seed files or local-only reviewer notes.
- Use synthetic values in examples and tests.
- Validate profiles before publishing or using them in repeatable workflows.

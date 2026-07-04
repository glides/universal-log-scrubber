# Synthetic sample logs

These files are fictional but shaped after common enterprise log exports. They are intentionally not trivial: many entries include nested JSON, values embedded in messages, URLs with query-string identities, Windows paths, account IDs, GUIDs, SIDs, MACs, private IPs, public documentation domains, and product/version noise.

## Suggested profiles

| File | Entries | Suggested profile | Notes |
|---|---:|---|---|
| `app-auth.ndjson` | sample | `AppJson` or `Generic` | Application authentication events with users, hosts, IPs, tokens, request IDs, and nested attributes. |
| `aws-cloudtrail-management.jsonl` | sample | `CloudAudit` + `docs/profiles/examples/aws-cloudtrail-extension.json` | CloudTrail-style management events with ARNs, request IDs, assumed-role sessions, access-key shapes, and nested resources. |
| `cloud-audit.jsonl` | sample | `CloudAudit` | Generic cloud audit/activity events. |
| `edr-process-alerts.jsonl` | sample | `Edr` | EDR alert-style nested process/user/device/network/file evidence. |
| `edr_alerts.jsonl` | sample | `Edr` | Additional EDR/XDR alert examples. |
| `entra-signin-logs.csv` | sample | `IdentityProvider` + `docs/profiles/examples/entra-signin-extension.json` | Microsoft Entra SigninLogs-style export with nested JSON columns. |
| `firewall_vpn_syslog.log` | sample | `Firewall` or `Vpn` | Firewall/VPN syslog-style messages. |
| `gateway-kv.log` | sample | `Logfmt`, `Firewall`, or `docs/profiles/kv-log-profile.json` | key=value gateway/application events. |
| `intune_managed_devices.csv` | sample | `Intune` + `docs/profiles/endpoint-management-extension.json` | Intune managed-device export shape. |
| `intune_mdm_report.html` | sample | `IntuneDiagnostics` | MDM diagnostic report-style HTML. |
| `intune_policy_report.xml` | sample | `IntuneDiagnostics` | Policy/report XML with users, devices, and tenant-like values. |
| `intune_registry_export.reg` | sample | `IntuneDiagnostics` | Registry export-style text with user/device paths. |
| `kubernetes-audit.jsonl` | sample | `docs/profiles/examples/kubernetes-audit-profile.json` | Kubernetes audit events with users, source IPs, request URIs, objectRefs, RBAC annotations, and requestObject secrets. |
| `m365_unified_audit_log.csv` | sample | `CloudAudit` or `IdentityProvider` | Microsoft 365 audit-style CSV rows. |
| `nexthink_devices_executions.csv` | sample | `Nexthink` + `docs/profiles/endpoint-management-extension.json` | Nexthink device/execution export shape. |
| `nginx-reverse-proxy-access.log` | sample | `WebAccess` + `docs/profiles/examples/webaccess-query-token-extension.json` | Combined/reverse-proxy access lines with upstreams, referrers, encoded emails, and request IDs. |
| `okta-system-log.jsonl` | sample | `IdentityProvider` or `CloudAudit` + `docs/profiles/examples/okta-system-log-extension.json` | Okta System Log-style events with actor/client/target/debugContext data. |
| `paloalto-traffic.csv` | sample | `docs/profiles/examples/paloalto-traffic-csv-profile.json` or built-in `FirewallCsv` | PAN-OS traffic-export style columns with source/destination users, hosts, UUIDs, session IDs, HIP tags, and NAT fields. |
| `postgresql-audit.csv` | sample | `docs/profiles/examples/database-audit-profile.json` or built-in `Database` | Database audit rows with users, client IPs, statements, UNC paths, API-key-like strings, and SIDs. |
| `sccm_cmtrace_client.log` | sample | `SccmText` + `docs/profiles/endpoint-management-extension.json` | CMTrace-style client log lines. |
| `sentinel_incidents_alerts.jsonl` | sample | `CloudAudit`, `Edr`, or `docs/profiles/security-audit-extension.json` | Incident/alert records with users, hosts, entities, and investigation fields. |
| `servicenow_incidents.csv` | sample | `ServiceNow` + `docs/profiles/servicenow-local-extension.json` | ServiceNow incident/task export shape. |
| `sysmon-event-xml.txt` | sample | `Text`, `IntuneDiagnostics`, or strict workstation extension depending on workflow | Sysmon event XML-text style records with process, network, DNS, path, SID, and command-line data. |
| `vpn-firewall.log` | sample | `Firewall` or `Vpn` | VPN/firewall text log examples. |
| `web-access.log` | sample | `WebAccess` | Web access log examples. |
| `windows-event-sample.csv` | sample | `Generic` or a BYOP profile if you still receive event data as a table | Legacy event-table sample rows. Native event files are usually converted locally to `.events.txt` before scrub. |

All values are synthetic. Do not reuse these salts, IDs, or token-looking strings in production.

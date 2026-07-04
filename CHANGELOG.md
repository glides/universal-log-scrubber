# Changelog

## v1.0.0

Initial public release of Universal Log Scrubber.

### Highlights

- Local-first log scrubbing for security, support, diagnostic, and evidence-sharing workflows.
- Deterministic typed tokens that preserve useful correlation across related files.
- Private token maps for local re-identification of findings.
- Built-in profiles for common enterprise log families, including Windows events, Intune diagnostics, cloud audit logs, identity-provider logs, firewall/VPN/proxy logs, ServiceNow, Nexthink, SCCM/MECM, EDR, Kubernetes/container logs, database audit logs, IIS/W3C, web access logs, and AD CS audit exports.
- BYOP profiles and profile extensions for local field names, vendor-specific labels, asset patterns, tenant aliases, seed terms, and allowlists.
- Dry-run and recommendation workflows for safer review before producing shareable output.
- Local conversion workflows for supported event, web, Office-derived, and diagnostic inputs.
- Optional safe upload bundles that exclude private maps, salts, raw inputs, converted intermediates, and local-only evidence.
- Sample logs, example profiles, and contributor guidance using synthetic data only.

### Safety posture

- Token maps, salts, raw logs, converted intermediates, detailed detection reports, profile-build reports, and files marked `DO_NOT_UPLOAD` are local-only.
- Scrubbed output should be reviewed before sharing.
- The tool is a safe-sharing aid, not a substitute for human approval or formal anonymization review.

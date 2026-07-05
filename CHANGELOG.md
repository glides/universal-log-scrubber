# Changelog

## v1.1.0

Interactive workflow release focused on making Universal Log Scrubber easier to run safely from a terminal while preserving existing scripted behavior.

### Highlights

- Added the default interactive command console. Running `Invoke-UniversalScrubber` with no arguments now opens the ULS console.
- Added `Start-UniversalScrubberInteractive` and `Invoke-UniversalScrubber -Interactive`.
- Added `Invoke-UniversalScrubber -Help` and expanded `-Version`/interactive `version full` details.
- Added interactive commands for `help`, `profile`, `validate`, `set`, `plan`, `scrub`, `last`, `version`, `doctor`, `examples`, `clear`, and `exit`.
- Added session defaults so operators can set common values once and reuse them across `plan` and `scrub`.
- Added safer command previews: literal salts are hidden and represented as `$global:UlsInteractiveSalt` instead of being printed.
- Made interactive `Auto` the default profile behavior. Auto does not force one profile; it lets normal format-aware defaults handle mixed folders unless the user explicitly sets a profile.
- Added BYOP profile inspection and validation from the interactive console.
- Added `Test-UniversalScrubberProfile` for noninteractive validation of built-in and BYOP profiles before scrubbing.
- Improved ETL behavior so `.etl` files are skipped with a clear warning unless `-ConvertEtl` is supplied.
- Updated Windows Event workflow language to `WindowsEventXml` and converted event XML text.
- Added/updated maintainer checks for the 1.1.0 module version and interactive command export.

### Notes

- Existing scripted commands continue to work.
- Strict single-profile recommendation behavior remains available with `-AutoProfile`.
- Token maps, salts, raw logs, converted intermediates, detailed detection reports, profile-build reports, and files marked `DO_NOT_UPLOAD` remain local-only.

## v1.0.2

Public maintenance release focused on compatibility, Windows Event log readability, and large diagnostic bundle handling.

### Highlights

- Improved Windows PowerShell 5.1 compatibility while retaining PowerShell 7 support.
- Improved Windows Event log output readability by preserving common built-in Windows groups, setup/OOBE placeholder accounts, and known Windows driver/service names when they are not client-specific.
- Improved correlation for repeated user, device, hostname, SID, MAC, and cloud/device identifiers across converted event text and large diagnostic bundles.
- Improved map-based scrubbing consistency for large converted event outputs and diagnostic packages.
- Added status timestamps to console progress messages to make long-running jobs easier to review.
- Continued safe-bundle behavior that keeps private token maps, salts, raw logs, converted intermediates, and local-only evidence out of upload packages.

### Notes

- Token maps, salts, raw logs, converted intermediates, detailed detection reports, profile-build reports, and files marked `DO_NOT_UPLOAD` remain local-only.
- Scrubbed output should still be reviewed before sharing, especially for regulated or high-sensitivity environments.
- This release remains a defensive safe-sharing aid, not a formal anonymization guarantee.

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

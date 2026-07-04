# Security Policy

Universal Log Scrubber is designed for local preparation of sensitive logs before external analysis. Security reports are welcome, especially if the issue could cause sensitive data to remain in output that appears safe.

## Supported versions

The current supported version is the latest version on the `main` branch.

## What to report

Please report:

- Sensitive values that remain in scrubbed output after the leak check passes.
- Token map, salt, manifest, or local-only report files accidentally included in a safe bundle.
- Crashes that prevent fail-closed behavior.
- Profile parsing behavior that silently ignores unsafe rules.
- Restore behavior that re-identifies values outside the intended local workflow.
- CI/test issues that hide failures or skip important safety checks.

## What not to include

Do not send raw client logs, production secrets, salts, token maps, `DO_NOT_UPLOAD` reports, private tenant names, internal hostnames, or real credentials in public issues.

Use synthetic reproduction data whenever possible. If the issue requires real data to explain, reduce it to the smallest fictionalized example that still reproduces the behavior.

## Public issue guidance

Public issues are appropriate for:

- Documentation problems.
- Synthetic reproductions.
- False positives using public/sample values.
- Feature requests.
- Questions about usage that do not require private data.

For anything involving real data exposure or bypass behavior, avoid posting details publicly until the maintainer has a safe way to review the report.

## Local validation before reporting

When possible, reproduce the issue with fictional data and run the sample smoke tests locally before opening a report. Do not attach token maps, salts, local-only reports, or raw repro artifacts.

## Safe reproduction pattern

```text
Original private value: do not post
Synthetic equivalent: svc-aurora-sync@northstar.example
Expected behavior: tokenized as PRINCIPAL_...
Actual behavior: left unchanged in sample output
```

## Maintainer response

The maintainer will try to confirm reports, determine severity, fix the issue, and document safer usage guidance where needed.

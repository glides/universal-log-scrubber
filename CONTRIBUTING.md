# Contributing

Thanks for helping improve Universal Log Scrubber.

This project supports security-sensitive workflows. The most important contribution rule is: **do not include real secrets, raw client logs, salts, token maps, local-only reports, private screenshots, tenant IDs, usernames, hostnames, or customer data in issues, pull requests, examples, tests, or documentation.**

## Good first contributions

- Improve documentation or examples.
- Add synthetic sample logs.
- Add or tune BYOP profile examples.
- Improve false-positive handling using public or synthetic diagnostics.
- Add tests for a detector, profile rule, or edge case.
- Improve error messages and troubleshooting guidance.

## Before opening a pull request

1. Run the sample log smoke tests.
2. Validate example profiles.
3. Confirm that no generated artifacts marked `DO_NOT_UPLOAD` are committed.
4. Confirm that no raw customer/client data is present.

```powershell
.\scripts\Test-SampleLogs.ps1

Import-Module .\UniversalLogScrubber\UniversalLogScrubber.psd1 -Force
Get-ChildItem .\docs\profiles\*.json, .\docs\profiles\examples\*.json | ForEach-Object {
  if (-not (Test-ScrubProfile -Path $_.FullName -Quiet)) {
    throw "Profile failed validation: $($_.FullName)"
  }
}
```

## Repository script layout

`scripts/` contains user-facing helpers such as the launcher and sample-log smoke test. Keep examples and documentation focused on supported public commands and safe synthetic data.

## Development workflow

```powershell
git checkout -b feature/my-change
# edit code, docs, tests, or profiles
.\scripts\Test-SampleLogs.ps1
git status
git add .
git commit -m "Describe the change"
git push
```

## Test data rules

Use fictional but realistic-looking data. Prefer values like:

- `naomi.rivera@northstar.example`
- `CN=svc-aurora-sync,OU=Lab Users,DC=example,DC=local`
- `10.44.18.27`
- `vpn-edge-03.branch.example`
- `sk-test-...`
- `PROJECT-ORCHID`

Do not use real organization names, real tenant IDs, real access keys, real usernames, real URLs from private environments, real screenshots, or real security event exports.

## Pull request expectations

A good PR should explain:

- What changed.
- Why it changed.
- How it was tested.
- Any safety or compatibility impact.
- Whether new sample data is synthetic.

## Coding style

- Keep PowerShell compatible with Windows PowerShell 5.1 and PowerShell 7 where possible.
- Prefer clear fail-closed behavior over silent best-effort behavior.
- Preserve diagnostic readability unless a value is sensitive.
- Treat token maps, salts, detailed reports, manifests, and profile-build evidence as local-only.
- Add comments when code exists to prevent a leak, false positive, or dangerous upload path.

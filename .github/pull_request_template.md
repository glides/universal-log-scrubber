## Summary

Describe what changed and why.

## Type of change

- [ ] Bug fix
- [ ] Detector/profile improvement
- [ ] Documentation
- [ ] Sample log or test fixture
- [ ] CI/test improvement
- [ ] Other

## Safety checklist

- [ ] I did not include real client/customer logs.
- [ ] I did not include secrets, salts, token maps, or `DO_NOT_UPLOAD` files.
- [ ] Any sample data is synthetic/fictitious.
- [ ] I considered whether this change could increase false negatives.
- [ ] I considered whether this change could over-scrub useful diagnostics.

## Testing

Paste the commands you ran:

```powershell
Import-Module .\UniversalLogScrubber\UniversalLogScrubber.psd1 -Force
Invoke-ScrubSelfTest
.\scripts\Test-SampleLogs.ps1
```

## Notes for reviewers

Mention any edge cases, compatibility concerns, or follow-up work.

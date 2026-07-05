# Samples

`logs/` contains synthetic, realistic sample inputs for smoke testing and demos.

Run the smoke test from the repository root:

```powershell
.\scripts\Test-SampleLogs.ps1
```

The smoke test writes to `samples/out/smoke-test` by default.

The sample inputs are fictional, but generated outputs still include token maps and local review artifacts. Treat generated token maps, detection reviews, reports, and manifests as local-only so the sample workflow matches production habits.

For an interactive sample walkthrough, run `Invoke-UniversalScrubber`, then use `set path .\samples\logs`, `set workdir .\samples\out\interactive`, `set saltfile .\salt.txt`, `set recurse true`, `plan`, and `scrub`.

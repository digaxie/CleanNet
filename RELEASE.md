# Release Guide

This repository is source-first. End-user binaries should normally be uploaded to GitHub Releases, not committed to the main branch.

## Public Release Requirements

- `config.json` contains only the Discord default site.
- Runtime files are not committed:
  - `stats.json`
  - `strategy_cache.json`
  - `ai_strategy.json`
  - `proxy_state.json`
  - `bypass.log`
- `.gitignore` excludes local cache/build output.
- `README.md`, `SECURITY.md`, and `PRIVACY.md` explain EXE and source/BAT usage.
- Release assets include SHA-256 hashes.

## Build Portable ZIP

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_release.ps1
```

Output:

- `dist\CleanNet-2.0\`
- `dist\CleanNet-2.0-portable.zip`

## Build EXE

```powershell
python -m pip install pyinstaller --user
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_exe.ps1
```

Output:

- `dist\CleanNet.exe`

## Full Quality Gate

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify_release.ps1
```

This checks:

- Python compilation.
- Unit tests.
- Portable ZIP contents.
- PyInstaller EXE build.
- EXE smoke test for dashboard/API endpoints.
- Cache/build cleanup.

## Generate Release Hashes

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\generate_checksums.ps1
```

Output:

- `dist\SHA256SUMS.txt`

Upload these files to GitHub Releases:

- `dist\CleanNet.exe`
- `dist\CleanNet-2.0-portable.zip`
- `dist\SHA256SUMS.txt`

## Suggested GitHub Release Text

```text
CleanNet v2.0

Install options:
1. CleanNet.exe - fastest path for normal users.
2. CleanNet-2.0-portable.zip - readable source/BAT path for users who do not trust EXE files.

Default public configuration includes Discord only.

Verify downloads with SHA256SUMS.txt.
Dashboard: http://127.0.0.1:8888
Proxy: 127.0.0.1:8080
```

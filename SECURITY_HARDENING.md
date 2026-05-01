# Security Hardening Notes

This file records implementation-level hardening decisions so public reviewers can audit what changed and why.

## Local-Only Bindings

CleanNet binds runtime services to `127.0.0.1`:

- Proxy: `127.0.0.1:8080`
- Dashboard: `127.0.0.1:8888`

The dashboard must not be exposed with port forwarding or reverse proxying.

## Windows Proxy Ownership

CleanNet uses the current-user Windows proxy settings only:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
```

Hardening behavior:

- Before enabling CleanNet proxy, the previous proxy state is saved to `proxy_state.json`.
- While running, a watchdog checks that Windows proxy still points to CleanNet.
- If another process disables or changes CleanNet-owned proxy settings, CleanNet repairs ownership.
- On normal exit, CleanNet restores the previous proxy state.

## Disk Log Minimization

Disk logs are warning/error focused by default. Verbose operational events are available in the dashboard memory buffer during the current session.

Relevant environment variables:

| Variable | Effect |
|---|---|
| `DPI_BYPASS_LOG_LEVEL=DEBUG` | Enables verbose disk logging for debugging. |
| `DPI_BYPASS_NO_DISK_LOG=1` | Disables disk logging. |
| `DPI_BYPASS_LOG_HOSTS=1` | Writes real hostnames to disk logs instead of hashes. |

Default public behavior does not require these variables.

## Hostname Handling

Warning/error disk logs hash hostnames by default. This reduces accidental browsing-history leakage if log files are shared.

The dashboard may show real hostnames because it is a local operator tool bound to `127.0.0.1`.

## Runtime Files

These files are generated locally and ignored by Git:

- `stats.json`
- `strategy_cache.json`
- `ai_strategy.json`
- `proxy_state.json`
- `bypass.log`
- `bypass.log.*`

They should not be committed to the public repository.

## Public Config Policy

The public `config.json` must include only the Discord default site. User-added sites belong to local user config and must not be published.

Before publishing, run a private local grep for any personal/custom site names you do not want in the public repository. The public package should not contain private browsing targets, custom test domains, generated strategy state, or generated statistics.

Also verify that root `config.json` has exactly one site key: `discord`.

## Release Verification

Run the full release gate:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify_release.ps1
```

Then generate hashes:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\generate_checksums.ps1
```

Upload `CleanNet.exe`, the portable ZIP, and `SHA256SUMS.txt` to GitHub Releases.

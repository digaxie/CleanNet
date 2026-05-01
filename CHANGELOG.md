# Changelog

## 2.0 Public GitHub Package - 2026-05-01

- Prepared a clean public repository package in a separate publishing folder.
- Replaced the GitHub README with a full Turkish, English, and German end-user guide.
- Rewrote security and privacy documentation with explicit local-only behavior, EXE trust notes, registry scope, and verification steps.
- Added `.gitignore` rules for runtime state, logs, Python caches, and build output.
- Added `scripts/generate_checksums.ps1` for release SHA-256 verification files.
- Sanitized the public default `config.json` so only Discord is included.
- Changed public default privacy settings to enable DNS/SNI privacy mode by default.
- Fixed EXE startup proxy ownership so CleanNet enables Windows proxy only after its local proxy server is ready.
- Hardened duplicate EXE launch handling so a second launch exits without disabling the active proxy.
- Synced Windows 11 LAN connection settings so the Settings app shows manual proxy as enabled.
- Kept both user paths documented: `CleanNet.exe` for convenience and `CleanNet_Launcher.bat` / Python source for users who prefer auditable files.

## 2.0 - 2026-04-29

- Removed the retired third-party network integration and its obsolete config keys.
- Split core runtime helpers into the `cleannet` package.
- Added config, stats, diagnostics, strategy advisor, Windows proxy, and single-instance modules.
- Added Windows proxy backup/restore behavior around CleanNet proxy ownership.
- Added live connection tracking and strategy advice to the dashboard.
- Added diagnostics export endpoint and dashboard action.
- Added stdlib `unittest` coverage for config migration, Windows helpers, strategy advice, and diagnostics.
- Added portable release and optional PyInstaller packaging scripts.
- Moved dashboard HTML/JS into `assets/dashboard.html`.
- Moved strategy catalog/training profiles and proxy parsing helpers into dedicated modules.
- Moved strategy cache and adaptive AI engine into `cleannet/ai_engine.py`.
- Moved the async proxy runtime into `cleannet/proxy_engine.py`.
- Moved dashboard API routing into `cleannet/dashboard.py`.
- Moved dashboard config/site mutation rules into `cleannet/config_service.py`.
- Moved strategy training and self-training orchestration into `cleannet/training.py`.
- Moved TLS fragmentation/desync strategy functions into `cleannet/strategies.py`.
- Moved system tray and user-triggered lifecycle actions into `cleannet/tray.py`.
- Moved background health, ping, site-test, and strategy-retest tasks into `cleannet/background_tasks.py`.
- Moved DoH DNS resolution and privacy DNS cache management into `cleannet/dns_resolver.py`.
- Moved application startup, server lifecycle, single-instance lock, and shutdown handlers into `cleannet/app.py`.
- Added `RuntimeState` to centralize mutable runtime/config-derived state in `cleannet/runtime.py`.
- Moved default config and bypass preset constants into `cleannet/config_defaults.py`.
- Moved privacy-aware logging setup and dashboard log buffering into `cleannet/logging_setup.py`.
- Moved application paths and static runtime tunables into `cleannet/settings.py`.
- Moved runtime bootstrap/context wiring into `cleannet/bootstrap.py`; `bypass_silent.pyw` is now a thin launcher.
- Added dashboard Performance controls for low-latency mode, background AI training, ping target, and refresh intervals.
- Added live Windows network flow diagnostics and generic proxy exception helpers for visible remote endpoints.
- Added per-site strategy lock APIs and dashboard controls for Auto, AI best, and manual strategy selection.
- Expanded dashboard localization coverage so visible controls, empty states, diagnostics, presets, and helper overlays support Turkish, English, and German.

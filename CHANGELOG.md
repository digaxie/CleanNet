# Changelog

## 2.2.0 - Beta (not yet released)

- **Verified strategy success.** Training, self-training and the site test now complete a real TLS handshake (certificate, hostname and Finished checks) through each strategy. DPI block pages that answer with their own certificate are reported as "DPI intercepted" instead of success, and live connections the browser rejects right after a "successful" strategy are re-counted as failures. The dashboard shows a verification badge per site.
- **New dashboard.** Rebuilt around what users need: an Overview that answers "am I protected?" and lists what needs attention with one-click fixes, a Sites page with an add-site wizard and a detail panel per site (verification, test, strategy, domains, CDN finder), Activity (live connections, latency, results, logs, per-app exclusions), the Smart engine and Settings. Light, dark and system themes, mobile layout with bottom navigation, deep links, keyboard focus states, and complete English, Turkish (now with proper characters) and German text. Still a single local file with no external resources.
- **Strategy AI rewritten (engine v4).** A discounted Beta bandit per site replaces the neural network, linear score and drift detector. The network had been trained with the outcome leaking into its inputs, and live connections paid for random exploration. Live traffic now always uses the best known order; exploration happens in background probes. The dashboard reports first-try success and average connect time instead of the old "accuracy". Existing models migrate automatically.
- **Strategies.** Added `sni_multi_record`, `sni_tcp_drip`, `tls_record_tcp_split` and `tls_record_long_delay`. Retired `sni_padding`, `dot_shuffle`, `reverse_frag`, `tls_frag_overlap` and `tls_interleaved_ccs` from automatic selection: they either change ClientHello content (the server replies but the handshake fails) or can never be accepted. They still work when a site is locked to them.
- **One codebase for Windows and Linux.** The `linux/` copy is gone; `cleannet/` selects `windows_integration` / `linux_integration`, the netstat / ss network monitor and the pystray / Qt tray at runtime. Linux docs moved to `docs/LINUX.md`; the Linux launcher and release scripts now live at the repository root and `scripts/`.
- **CI.** GitHub Actions runs the test suite on Windows and Linux (Python 3.10 and 3.13) and builds and verifies the Linux release archive.

## 2.1.5 - 2026-11-18

Security and reliability fix release.

- **Security:** the local dashboard API now rejects requests from other websites (cross-site requests) and DNS-rebinding hosts. Previously any website open in the browser could change CleanNet's settings, remove sites or start the administrator prompt of the Xbox/Store fix. The Xbox/Store fix script is now written to a unique temporary file, and values shown in the dashboard are escaped.
- Strategies now receive the complete TLS ClientHello even when it arrives in several pieces (common with post-quantum key exchange in current browsers); before, split greetings were re-framed incorrectly and the connection failed.
- Large HTTP request headers, IPv6 connection targets and keep-alive requests through the plain HTTP proxy are handled correctly.
- The dashboard no longer pauses all proxied traffic every few seconds while the network-connections list refreshes.
- Settings files are saved atomically; a config file saved with a UTF-8 BOM (Notepad, PowerShell) is accepted, and a damaged config is kept as a backup instead of being overwritten.
- Adding a site whose name already exists merges domains instead of replacing the site; addresses like `https://www.example.com/path` are cleaned up; imported configs are validated.
- Background health checks keep running after an unexpected error; autostart from the packaged EXE uses the correct command.

## 2.1.4 - 2026-07-09

- Fixed non-configured (passthrough) sites such as YouTube and Kick failing with "connection timed out" errors on networks that advertise IPv6 but cannot actually route it — a common state on half-configured ISP modems. CleanNet connected to such hosts by hostname, the operating system offered the IPv6 address first, and the connection hung on the dead IPv6 route until CleanNet's 10-second connect timeout expired, so the IPv4 address was never tried. Browsers hide this network condition with their own Happy Eyeballs logic, which is why the same sites opened fine without the proxy. Upstream connections now use Happy Eyeballs (RFC 8305): IPv6 and IPv4 are attempted with a 250 ms stagger and the first one to connect wins. Sites that only publish IPv4 addresses were never affected, and nothing changes on networks with working IPv6.
- The dashboard ping monitor uses the same dual-stack connect, so a hostname ping target no longer shows -1 on such networks.

## 2.1.3 - 2026-06-20

- Reworked the built-in "Fix Xbox / Store Apps" tool so it reliably restores Microsoft Store / UWP apps (for example the Xbox app and Game Pass) that show blank pages or fail to load while the proxy is on. Windows isolates Store/UWP apps from local network services, so they could not reach CleanNet's local proxy. The tool now grants a per-app loopback exemption for the apps that need it (Xbox, Game Pass, Store, Xbox sign-in, and any installed Xbox/Gaming/Store package) instead of relying only on the generic exemption that Windows frequently ignores.
- The fix now runs in a visible, elevated console that lists exactly which packages it updates, and the dashboard shows a confirmation first explaining that it requires Administrator (UAC), what it changes, and that it is reversible.
- Made the tool easier to find: it is now its own clearly labeled card in Settings instead of a small button under Config Management.

## 2.1.2 - 2026-06-19

- Fixed a connectivity regression in privacy (DoH) mode. Plain-HTTP passthrough traffic was being DNS-resolved over DoH and blocked when resolution failed, so applications whose HTTP client ignores the Windows system-proxy bypass list (for example the Epic Games and Xbox launchers, which contact local/loopback and vendor endpoints) could not connect and reported their services as unavailable while CleanNet was running with privacy mode on. Privacy/DoH now applies only to configured bypass sites; all passthrough traffic uses the system resolver and is never blocked. There is no privacy change for configured sites.

## 2.1.1 - 2026-06-15

- Fixed a startup issue where enabling autostart could leave the machine without internet after a reboot. CleanNet took over the Windows system proxy before the network stack (DHCP/DNS) was ready, routing all traffic through the local engine while it could not yet reach upstream, so connections were blackholed until CleanNet was manually restarted. CleanNet now waits for confirmed connectivity (DNS resolution plus a live TCP connection to a public endpoint, up to 120 seconds) before activating the system proxy at startup.
- Added a Windows session-end safeguard: on logoff, restart, or shutdown — even without choosing Exit first — CleanNet restores the user's original proxy settings before the process terminates, so a stale proxy never affects the next boot.

## 2.1 Linux Compatibility Release - 2026-05-28

- Added native Linux compatibility and DPI-bypass support (`python -m cleannet`).
- Created a dedicated `linux/` subdirectory containing a completely Windows-free, native Linux codebase package.
- Implemented Linux proxy backend selection in `os_integration.py` supporting KDE (`kwriteconfig/kreadconfig`), GNOME (`gsettings`), and system `env-file` fallback (`~/.config/cleannet/proxy.env`).
- Added robust system proxy backup and restore using `linux_proxy_state.json` to prevent orphaned settings.
- Rewrote `network_monitor.py` for Linux using a robust `ss`-based active connection parser with standard process lookup fallbacks.
- Updated the local system tray (`cleannet/tray.py`) with native PyQt6 QSystemTrayIcon and explicit 22x22 pixel smooth scaling to prevent rendering issues on GNOME/Cinnamon/MATE system panels.
- Handled tray menu popup bugs by manually capturing `ActivationReason.Context` (right clicks) on all Linux environments.
- Added optional `pystray` fallback tray.
- Added full Linux quality gate shell scripts: `run_tests.sh`, `scripts/build_linux_release.sh`, and `scripts/verify_linux_release.sh`.
- Excluded Windows-specific scripts, batch files, and installers from the Linux directory.

## 2.0 Public GitHub Package - 2026-05-01

- Fixed Turkish/German documentation encoding so GitHub renders non-ASCII text correctly.
- Added OpenAI/ChatGPT/VS Code developer endpoints to the built-in proxy bypass list.
- Changed non-configured passthrough domains to use a plain tunnel instead of DNS/SNI privacy shielding, avoiding breakage in apps such as VS Code extensions.
- Fixed Performance dashboard toggles so Low Latency Mode and Background AI Training preserve user changes while live stats refresh.
- Added a classic per-user Inno Setup installer script with a pre-install trust explanation, default install path, runtime data path, optional desktop shortcut, and safe uninstall proxy cleanup.
- Changed the setup installer to install a PyInstaller `onedir` app bundle instead of launching the packed one-file EXE, reducing first-launch antivirus lockups.
- Added first-run onboarding so a fresh EXE shows a local setup screen and waits for user confirmation before enabling Windows proxy.
- Moved standalone EXE runtime data to a visible `%LOCALAPPDATA%\CleanNet` folder while keeping source/dev builds local to the project folder.
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

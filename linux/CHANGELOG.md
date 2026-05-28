# Changelog

## Linux cleanup

- Converted runtime entrypoint to `python -m cleannet`.
- Split source assets from XDG user data.
- Added Linux proxy backends for KDE, GNOME-compatible desktops, and manual env-file fallback.
- Added Linux proxy backup/restore through `linux_proxy_state.json`.
- Replaced network diagnostics with an `ss` based Linux flow parser.
- Removed Windows build, installer, runtime integration, and UWP-specific behavior from this Linux package.

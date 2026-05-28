# Security

CleanNet Linux is a local-only user-space proxy.

It does not:

- install kernel drivers;
- install certificates;
- decrypt HTTPS traffic;
- require sudo for normal use;
- change system-wide proxy settings.

It can write user-level desktop proxy settings through GNOME or KDE tools. Before changing them, it stores a temporary backup in `linux_proxy_state.json` under the CleanNet data directory and restores that state when CleanNet stops normally.

If no supported desktop proxy backend is available, CleanNet writes `~/.config/cleannet/proxy.env` for manual use instead of modifying shell startup files.

Run verification before release:

```bash
scripts/verify_linux_release.sh
```

# CleanNet Linux

CleanNet is a local Linux DPI bypass proxy. It listens on `127.0.0.1`, routes selected HTTPS connections through a local proxy, and can fragment TLS ClientHello traffic for configured sites.

## What Works

- Core proxy, DNS over HTTPS, strategy selection, AI strategy cache, and dashboard work on Linux with Python 3.10+.
- GNOME-compatible desktops are managed through `gsettings` when `org.gnome.system.proxy` is available.
- KDE Plasma is managed through `kwriteconfig6/5` and `kreadconfig6/5`.
- Other desktops or headless environments get a manual env file at `~/.config/cleannet/proxy.env`.
- Network-flow diagnostics use `ss` from `iproute2`; if `ss` is missing, only that dashboard feature is disabled.

## Install And Run

```bash
tar -xzf cleannet-linux-<version>.tar.gz
cd cleannet-linux-<version>
./cleannet-launcher.sh
```

Then open:

```text
http://127.0.0.1:8888
```

On Debian/Ubuntu, install venv support first if needed:

```bash
sudo apt install python3-venv
```

Manual run:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m cleannet
```

## Data Locations

CleanNet stores runtime data under:

```text
${CLEANNET_DATA_DIR}
${XDG_DATA_HOME:-~/.local/share}/cleannet
```

Typical files:

| File | Purpose |
|---|---|
| `config.json` | Sites, ports, privacy/performance settings |
| `bypass.log` | Warning/error disk log |
| `linux_proxy_state.json` | Previous user proxy state while CleanNet owns proxy settings |
| `strategy_cache.json` | Learned strategy cache |
| `ai_strategy.json` | Adaptive strategy learning data |
| `stats.json` | Runtime counters |

## Proxy Behavior

CleanNet never uses sudo and never writes system-wide proxy settings. It only manages user-level desktop proxy settings when supported.

Backend selection order:

1. KDE Plasma proxy settings.
2. GNOME-compatible `gsettings` proxy schema.
3. Manual env file fallback.

For env-file fallback, run this in a shell that should use CleanNet:

```bash
source ~/.config/cleannet/proxy.env
```

CleanNet does not edit `.bashrc`, `.profile`, or other shell startup files.

## Tray Notes

Tray support is optional. PyQt6/PyQt5 is used when available; otherwise CleanNet tries `pystray` and Pillow. GNOME 44+ may require an AppIndicator extension for tray icons. If no tray is available, CleanNet keeps running and the dashboard remains available.

## Build And Verify

Run tests:

```bash
./run_tests.sh
```

Build a clean tarball:

```bash
scripts/build_linux_release.sh
```

Full verification:

```bash
scripts/verify_linux_release.sh
```

## Türkçe Kısa Not

CleanNet Linux sürümü `python -m cleannet` ile çalışır. GNOME ve KDE kullanıcı proxy ayarlarını yönetir; diğer masaüstlerinde `~/.config/cleannet/proxy.env` dosyası üretir. Debian/Ubuntu üzerinde sanal ortam hatası alırsanız `sudo apt install python3-venv` kurun.

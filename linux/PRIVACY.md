# Privacy

CleanNet runs locally. It does not send telemetry, analytics, crash reports, or update checks.

Runtime data is stored in `${CLEANNET_DATA_DIR}` or `${XDG_DATA_HOME:-~/.local/share}/cleannet`.

| File | Purpose |
|---|---|
| `config.json` | User configuration |
| `bypass.log` | Warning/error log |
| `linux_proxy_state.json` | Temporary backup of previous user proxy settings |
| `strategy_cache.json` | Learned strategy cache |
| `ai_strategy.json` | Adaptive strategy learning data |
| `stats.json` | Aggregate runtime counters |

The env-file fallback writes `~/.config/cleannet/proxy.env`. CleanNet does not edit shell profile files automatically.

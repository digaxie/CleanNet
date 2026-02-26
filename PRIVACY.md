# Privacy Policy

CleanNet is designed with a **zero-telemetry, local-only** architecture. This document explains exactly what data the tool collects, stores, and transmits.

## Data Collection Summary

| Category | Collected? | Details |
|----------|-----------|---------|
| Personal information | No | No names, emails, accounts, or identifiers |
| Browsing history | No | CleanNet does not record which sites you visit |
| Analytics / Telemetry | No | No data is sent to any analytics service |
| Crash reports | No | Errors are logged locally only |
| Update checks | No | CleanNet never contacts any server for updates |

## Network Connections

CleanNet makes exactly **three types** of outbound connections:

### 1. DNS over HTTPS (DoH)

| Provider | URL | When | Purpose |
|----------|-----|------|---------|
| Google DNS | `https://dns.google/resolve` | On startup, then every 30 minutes | Resolve domain IPs for bypass-enabled sites |
| Cloudflare DNS | `https://cloudflare-dns.com/dns-query` | When Google DNS fails | Fallback DNS resolution |

**What is sent:** The domain names you have configured in your site list (e.g., `discord.com`).
**What is NOT sent:** Your browsing activity, the pages you visit, or any content.

### 2. Ping Measurement

| Destination | When | Purpose |
|-------------|------|---------|
| `1.1.1.1:443` | Every 60 seconds | Measure network latency for the dashboard ping chart |

This is a simple TCP connection test. No data is sent or received beyond the TCP handshake.

### 3. Bypass Connections

When you browse a bypass-enabled site through the proxy, CleanNet opens a TCP connection to that site's IP on port 443 and forwards your browser's TLS handshake (with fragmentation applied). CleanNet **never decrypts** the TLS traffic — it only splits the initial handshake packets.

## Local Data Storage

All data is stored in the application directory (where `bypass_silent.pyw` is located):

### config.json
- **Contains:** Your site list, port settings, proxy bypass rules
- **Created by:** You (via dashboard or manual editing)
- **Sensitive?** Contains the site names you chose to add

### strategy_cache.json
- **Contains:** Which bypass strategy works for each site, success/failure counts, timing data
- **Created by:** Auto-generated during operation
- **Sensitive?** Contains site names and connection timing data
- **Safe to delete?** Yes — strategies will be re-discovered automatically

### stats.json
- **Contains:** Aggregate connection counts per site (connections, successes, failures, average latency)
- **Created by:** Auto-generated, saved every 60 seconds
- **Sensitive?** Contains site names and aggregate numbers
- **Safe to delete?** Yes — counters will reset to zero

### bypass.log
- **Contains:** Timestamped connection logs (domain names, IPs, strategies used, success/failure)
- **Created by:** Auto-generated during operation
- **Sensitive?** Yes — contains a record of domains you connected to through the proxy
- **Safe to delete?** Yes — a new log file will be created on next run
- **Rotation:** Automatically rotated at 5MB, keeps last 3 files

## Windows Registry

CleanNet writes to two registry keys:

| Key | Value | Purpose | When |
|-----|-------|---------|------|
| `HKCU\...\Internet Settings\ProxyEnable` | `0` or `1` | Enable/disable system proxy | On startup and shutdown |
| `HKCU\...\Internet Settings\ProxyServer` | `127.0.0.1:8080` | Set proxy address | On startup |
| `HKCU\...\Run\CleanNetDPIBypass` | Path to `bypass_silent.pyw` | Auto-start on login | Only if you enable auto-start |

On shutdown, CleanNet **removes the proxy settings** (sets ProxyEnable to 0 and deletes ProxyServer) to restore your original network configuration.

## Third-Party Services

CleanNet uses **no third-party services** beyond the two DNS providers listed above (Google DNS and Cloudflare DNS). There are:

- No analytics (no Google Analytics, Mixpanel, etc.)
- No error tracking (no Sentry, Bugsnag, etc.)
- No CDNs for dashboard assets (everything is embedded in the Python file)
- No external JavaScript or CSS loaded from the internet
- No feature flags or A/B testing services

## How to Verify

CleanNet is a single Python file. You can verify all of the above by:

1. **Reading the source code** — `bypass_silent.pyw` is ~2500 lines of unobfuscated Python
2. **Monitoring network traffic** — use Wireshark or `netstat` to confirm only the connections listed above
3. **Checking the registry** — run `reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"` before and after running CleanNet
4. **Inspecting local files** — all JSON files are human-readable

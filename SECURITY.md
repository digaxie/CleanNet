# Security Policy

## Scope

CleanNet is a local-only tool. It runs two services bound exclusively to `127.0.0.1`:

| Service | Port | Purpose |
|---------|------|---------|
| HTTP Proxy | 8080 | Handles browser CONNECT/HTTP requests locally |
| Web Dashboard | 8888 | Monitoring UI with SSE event stream |

Both services **only listen on localhost** and are **not accessible from other machines** on your network.

## What CleanNet Has Access To

- **Your browser traffic** (only what passes through the proxy on port 8080)
- **DNS resolution** via HTTPS to `dns.google` and `cloudflare-dns.com`
- **Windows proxy settings** (registry key `HKCU\...\Internet Settings`) — to set/clear the system proxy
- **Windows startup registry** (optional, only if you enable auto-start)
- **Local filesystem** — reads/writes `config.json`, `strategy_cache.json`, `stats.json`, `bypass.log` in the application directory

## What CleanNet Does NOT Have Access To

- No admin/root privileges required
- No kernel drivers or packet capture (unlike tools like GoodbyeDPI or Zapret)
- No network interfaces beyond localhost binding
- No TLS certificate generation or MITM — the tool never decrypts your HTTPS traffic
- No access to decrypted page content, passwords, cookies, or form data

## Attack Surface

Since both services are bound to `127.0.0.1`, the attack surface is limited to:

1. **Local processes** on your machine can connect to ports 8080/8888
2. **Malicious web pages** could potentially send requests to `http://127.0.0.1:8888/api/*` (CSRF). Mitigation: the dashboard API only modifies local configuration files and does not expose sensitive data.
3. **Config file manipulation** — if another process modifies `config.json`, CleanNet will load the changed configuration. Mitigation: the config validator checks structure and rejects malformed data.

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do NOT open a public issue** for security vulnerabilities
2. Email: Open a private security advisory on GitHub via the "Security" tab
3. Include: steps to reproduce, affected version, potential impact

I will respond within 48 hours and work on a fix.

## Dependencies

CleanNet uses only two third-party packages:

| Package | Purpose | Why It's Needed |
|---------|---------|-----------------|
| `pystray` | System tray icon | Provides the tray icon for background operation |
| `Pillow` | Image processing | Required by pystray for icon rendering |

All other functionality uses Python standard library modules (`asyncio`, `ssl`, `socket`, `json`, `logging`, etc.).

## Code Transparency

CleanNet is a **single Python file** (`bypass_silent.pyw`). There is no compiled code, no obfuscation, no binary blobs, and no minified JavaScript loaded from external sources. The entire dashboard UI (HTML/CSS/JS) is embedded as a string literal in the Python file — you can read and audit every line.

# Privacy Policy

Languages: [English](#english) | [TÃ¼rkÃ§e](#tÃ¼rkÃ§e) | [Deutsch](#deutsch)

## English

CleanNet is designed as a zero-telemetry, local-first tool.

### Data Collection Summary

| Category | Collected | Notes |
|---|---|---|
| Personal information | No | No account, email, name, or device ID collection |
| Analytics | No | No analytics SDK or beacon |
| Crash reports | No | Errors are logged locally only |
| Update checks | No | No background update server |
| Configured domains | Locally | Stored in your local `config.json` |
| Strategy results | Locally | Stored in local cache files |

### Network Connections

CleanNet makes these outbound connections during normal operation:

| Destination | Purpose |
|---|---|
| `dns.google` | DNS over HTTPS lookup for configured domains |
| `cloudflare-dns.com` | DNS over HTTPS fallback |
| Ping target, default `1.1.1.1:443` | Latency measurement |
| Configured site IPs | Forwarding your own proxied HTTPS connection |

CleanNet does not send telemetry to the project author.

### Local Files

| File | Contains |
|---|---|
| `config.json` | Sites, ports, privacy/performance settings, proxy bypass entries |
| `strategy_cache.json` | Learned working strategy data |
| `ai_strategy.json` | Adaptive strategy learning data |
| `stats.json` | Aggregate counters |
| `bypass.log` | Warning/error disk log |
| `proxy_state.json` | Previous Windows proxy state backup |

You can delete generated runtime files when CleanNet is not running. `config.json` deletion resets your settings.

### Logs

Disk logging is minimized by default. Real hostnames are hashed in warning/error disk logs unless `DPI_BYPASS_LOG_HOSTS=1` is set. The dashboard keeps more detailed logs in memory so the user can troubleshoot the current session.

### Windows Registry

CleanNet writes user-level proxy settings while running:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
```

Optional autostart writes:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\CleanNetDPIBypass
```

## TÃ¼rkÃ§e

CleanNet telemetrisiz ve yerel Ã¶ncelikli olacak ÅŸekilde tasarlanmÄ±ÅŸtÄ±r.

### Veri Toplama Ã–zeti

| Kategori | ToplanÄ±r mÄ± | Not |
|---|---|---|
| KiÅŸisel bilgi | HayÄ±r | Hesap, email, ad veya cihaz ID toplanmaz |
| Analitik | HayÄ±r | Analitik SDK veya beacon yok |
| Crash report | HayÄ±r | Hatalar yalnÄ±zca yerel loglanÄ±r |
| Update check | HayÄ±r | Arka planda update sunucusu yok |
| Ayarlanan domainler | Yerel | Yerel `config.json` iÃ§inde tutulur |
| Strateji sonuÃ§larÄ± | Yerel | Yerel cache dosyalarÄ±nda tutulur |

### AÄŸ BaÄŸlantÄ±larÄ±

Normal kullanÄ±mda CleanNet ÅŸu dÄ±ÅŸ baÄŸlantÄ±larÄ± yapar:

| Hedef | AmaÃ§ |
|---|---|
| `dns.google` | AyarlÄ± domainler iÃ§in DNS over HTTPS |
| `cloudflare-dns.com` | DNS over HTTPS fallback |
| Ping hedefi, varsayÄ±lan `1.1.1.1:443` | Gecikme Ã¶lÃ§Ã¼mÃ¼ |
| AyarlanmÄ±ÅŸ site IPleri | KullanÄ±cÄ±nÄ±n proxy Ã¼zerinden geÃ§en HTTPS baÄŸlantÄ±sÄ± |

CleanNet proje sahibine telemetri gÃ¶ndermez.

### Yerel Dosyalar

| Dosya | Ä°Ã§erik |
|---|---|
| `config.json` | Siteler, portlar, privacy/performance ayarlarÄ±, proxy bypass girdileri |
| `strategy_cache.json` | Ã–ÄŸrenilen Ã§alÄ±ÅŸan strateji verisi |
| `ai_strategy.json` | Adaptif strateji Ã¶ÄŸrenme verisi |
| `stats.json` | Toplam sayaÃ§lar |
| `bypass.log` | Warning/error disk logu |
| `proxy_state.json` | Ã–nceki Windows proxy yedeÄŸi |

CleanNet Ã§alÄ±ÅŸmÄ±yorken runtime dosyalarÄ±nÄ± silebilirsiniz. `config.json` silinirse ayarlar sÄ±fÄ±rlanÄ±r.

### Loglar

Disk loglarÄ± varsayÄ±lan olarak azaltÄ±lmÄ±ÅŸtÄ±r. `DPI_BYPASS_LOG_HOSTS=1` ayarlanmadÄ±ÄŸÄ± sÃ¼rece warning/error disk loglarÄ±nda gerÃ§ek hostname yerine hash kullanÄ±lÄ±r. Dashboard, mevcut oturum sorunlarÄ±nÄ± Ã§Ã¶zebilmeniz iÃ§in daha detaylÄ± loglarÄ± bellekte tutar.

### Windows Registry

CleanNet Ã§alÄ±ÅŸÄ±rken kullanÄ±cÄ± seviyesinde proxy ayarlarÄ±nÄ± yazar:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
```

Opsiyonel autostart ÅŸuraya yazÄ±lÄ±r:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\CleanNetDPIBypass
```

## Deutsch

CleanNet ist als telemetrieloses, lokal orientiertes Tool konzipiert.

### Datenerfassung

| Kategorie | Erfasst | Hinweis |
|---|---|---|
| PersÃ¶nliche Daten | Nein | Kein Account, keine E-Mail, kein Name, keine GerÃ¤te-ID |
| Analytik | Nein | Kein Analytics SDK oder Beacon |
| Crash Reports | Nein | Fehler werden nur lokal geloggt |
| Update Checks | Nein | Kein Hintergrund-Update-Server |
| Konfigurierte Domains | Lokal | In `config.json` gespeichert |
| Strategieergebnisse | Lokal | In lokalen Cache-Dateien gespeichert |

### Netzwerkverbindungen

Normale ausgehende Verbindungen:

| Ziel | Zweck |
|---|---|
| `dns.google` | DNS over HTTPS fÃ¼r konfigurierte Domains |
| `cloudflare-dns.com` | DNS over HTTPS Fallback |
| Ping-Ziel, Standard `1.1.1.1:443` | Latenzmessung |
| Konfigurierte Website-IPs | Weiterleitung Ihrer eigenen HTTPS-Verbindung |

CleanNet sendet keine Telemetrie an den Projektbetreiber.

### Lokale Dateien

| Datei | Inhalt |
|---|---|
| `config.json` | Websites, Ports, Privacy/Performance, Proxy Bypass |
| `strategy_cache.json` | Gelernte Strategiedaten |
| `ai_strategy.json` | Adaptive Strategiedaten |
| `stats.json` | Aggregierte ZÃ¤hler |
| `bypass.log` | Warning/Error Disk-Log |
| `proxy_state.json` | Backup des vorherigen Windows Proxy-Zustands |

Generierte Runtime-Dateien kÃ¶nnen gelÃ¶scht werden, wenn CleanNet nicht lÃ¤uft. Das LÃ¶schen von `config.json` setzt Einstellungen zurÃ¼ck.

### Logs

Disk-Logs sind standardmÃ¤ÃŸig minimiert. Echte Hostnamen werden in Warning/Error-Disk-Logs gehasht, auÃŸer `DPI_BYPASS_LOG_HOSTS=1` ist gesetzt. Das Dashboard hÃ¤lt detailliertere Logs nur im Speicher fÃ¼r die aktuelle Sitzung.

### Windows Registry

CleanNet schreibt wÃ¤hrend der Laufzeit Benutzer-Proxy-Einstellungen:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
```

Optionaler Autostart:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\CleanNetDPIBypass
```

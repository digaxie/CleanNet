# Privacy Policy

Languages: [English](#english) | [Türkçe](#türkçe) | [Deutsch](#deutsch)

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

## Türkçe

CleanNet telemetrisiz ve yerel öncelikli olacak şekilde tasarlanmıştır.

### Veri Toplama Özeti

| Kategori | Toplanır mı | Not |
|---|---|---|
| Kişisel bilgi | Hayır | Hesap, email, ad veya cihaz ID toplanmaz |
| Analitik | Hayır | Analitik SDK veya beacon yok |
| Crash report | Hayır | Hatalar yalnızca yerel loglanır |
| Update check | Hayır | Arka planda update sunucusu yok |
| Ayarlanan domainler | Yerel | Yerel `config.json` içinde tutulur |
| Strateji sonuçları | Yerel | Yerel cache dosyalarında tutulur |

### Ağ Bağlantıları

Normal kullanımda CleanNet şu dış bağlantıları yapar:

| Hedef | Amaç |
|---|---|
| `dns.google` | Ayarlı domainler için DNS over HTTPS |
| `cloudflare-dns.com` | DNS over HTTPS fallback |
| Ping hedefi, varsayılan `1.1.1.1:443` | Gecikme ölçümü |
| Ayarlanmış site IPleri | Kullanıcının proxy üzerinden geçen HTTPS bağlantısı |

CleanNet proje sahibine telemetri göndermez.

### Yerel Dosyalar

| Dosya | İçerik |
|---|---|
| `config.json` | Siteler, portlar, privacy/performance ayarları, proxy bypass girdileri |
| `strategy_cache.json` | Öğrenilen çalışan strateji verisi |
| `ai_strategy.json` | Adaptif strateji öğrenme verisi |
| `stats.json` | Toplam sayaçlar |
| `bypass.log` | Warning/error disk logu |
| `proxy_state.json` | Önceki Windows proxy yedeği |

CleanNet çalışmıyorken runtime dosyalarını silebilirsiniz. `config.json` silinirse ayarlar sıfırlanır.

### Loglar

Disk logları varsayılan olarak azaltılmıştır. `DPI_BYPASS_LOG_HOSTS=1` ayarlanmadığı sürece warning/error disk loglarında gerçek hostname yerine hash kullanılır. Dashboard, mevcut oturum sorunlarını çözebilmeniz için daha detaylı logları bellekte tutar.

### Windows Registry

CleanNet çalışırken kullanıcı seviyesinde proxy ayarlarını yazar:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
```

Opsiyonel autostart şuraya yazılır:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\CleanNetDPIBypass
```

## Deutsch

CleanNet ist als telemetrieloses, lokal orientiertes Tool konzipiert.

### Datenerfassung

| Kategorie | Erfasst | Hinweis |
|---|---|---|
| Persönliche Daten | Nein | Kein Account, keine E-Mail, kein Name, keine Geräte-ID |
| Analytik | Nein | Kein Analytics SDK oder Beacon |
| Crash Reports | Nein | Fehler werden nur lokal geloggt |
| Update Checks | Nein | Kein Hintergrund-Update-Server |
| Konfigurierte Domains | Lokal | In `config.json` gespeichert |
| Strategieergebnisse | Lokal | In lokalen Cache-Dateien gespeichert |

### Netzwerkverbindungen

Normale ausgehende Verbindungen:

| Ziel | Zweck |
|---|---|
| `dns.google` | DNS over HTTPS für konfigurierte Domains |
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
| `stats.json` | Aggregierte Zähler |
| `bypass.log` | Warning/Error Disk-Log |
| `proxy_state.json` | Backup des vorherigen Windows Proxy-Zustands |

Generierte Runtime-Dateien können gelöscht werden, wenn CleanNet nicht läuft. Das Löschen von `config.json` setzt Einstellungen zurück.

### Logs

Disk-Logs sind standardmäßig minimiert. Echte Hostnamen werden in Warning/Error-Disk-Logs gehasht, außer `DPI_BYPASS_LOG_HOSTS=1` ist gesetzt. Das Dashboard hält detailliertere Logs nur im Speicher für die aktuelle Sitzung.

### Windows Registry

CleanNet schreibt während der Laufzeit Benutzer-Proxy-Einstellungen:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
```

Optionaler Autostart:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\CleanNetDPIBypass
```

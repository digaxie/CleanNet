# CleanNet — DPI Bypass Engine

> **🇬🇧 English** | [🇹🇷 Türkçe](#türkçe) | [🇩🇪 Deutsch](#deutsch)

A lightweight, single-file Python tool that bypasses ISP-level Deep Packet Inspection (DPI) by fragmenting TLS ClientHello packets. It runs entirely on your machine as a local HTTP proxy (`127.0.0.1:8080`) with a web dashboard and system tray icon.

## How It Works

When you visit a blocked website, your ISP inspects the **TLS ClientHello** packet to read the **SNI (Server Name Indication)** field — the domain name sent in plaintext during the TLS handshake. If the domain is on their blocklist, they inject a TCP RST packet to kill your connection.

CleanNet sits between your browser and the internet as a local proxy. When it detects a connection to a bypass-enabled domain, it **fragments the TLS ClientHello** into multiple smaller TCP segments. Each fragment alone is too small for the DPI system to reconstruct the full SNI, so the connection passes through. The destination server reassembles the fragments normally and completes the TLS handshake.

```
Browser ──CONNECT──▶ CleanNet (127.0.0.1:8080) ──fragmented TLS──▶ ISP DPI ──passes──▶ Server
                         │
                         ├─ Reads SNI from ClientHello
                         ├─ Looks up best strategy for this domain
                         ├─ Fragments the packet using that strategy
                         └─ Forwards fragments to the real server
```

**What CleanNet does NOT do:**
- It does **not** encrypt or hide your traffic (use a VPN for that)
- It does **not** change your IP address
- It does **not** modify any website content
- It does **not** send your data to any third party
- It does **not** require admin/root privileges

## Features

- **8 Bypass Strategies** — Automatically discovers the best method for each site (see [Strategies](#bypass-strategies))
- **Strategy Cache** — Learns and remembers working strategies; first visit may take 15–30s, subsequent visits are instant (~250ms)
- **Web Dashboard** — Real-time monitoring at `http://127.0.0.1:8888` with live stats, ping chart, strategy timeline, and log viewer
- **Site Wizard** — Add sites from the dashboard with DNS resolution preview before adding
- **CDN Finder** — Built-in tool to discover CDN domains that a site uses
- **DNS over HTTPS (DoH)** — Resolves IPs via Google DNS (`dns.google`) and Cloudflare (`cloudflare-dns.com`) to avoid DNS-level blocking
- **System Tray** — Runs silently in the background; right-click for dashboard or exit
- **Auto CDN Detection** — Automatically associates CDN subdomains that contain the site name
- **Proxy Bypass (Exclude)** — Exclude gaming, streaming, or custom domains from going through the proxy
- **Config Export/Import** — Backup and restore your configuration from the dashboard
- **Multi-language** — Dashboard and launcher support English, Turkish, and German
- **Connection Stats** — Persistent per-site statistics saved across restarts
- **Auto-start** — Optional Windows startup integration

## Requirements

- **OS:** Windows 10 / 11
- **Python:** 3.8 or newer
- **Dependencies:** `pystray`, `Pillow` (installed automatically by the launcher)

## Setup

### Option 1: Launcher (Recommended)

1. Clone the repository:
   ```bash
   git clone https://github.com/digaxie/CleanNet.git
   cd CleanNet
   ```

2. Run the launcher:
   ```
   CleanNet_Launcher.bat
   ```

   The launcher will:
   - Clear any old system proxy settings
   - Install Python dependencies (`pystray`, `Pillow`)
   - On first run: ask you to choose a proxy bypass preset (Gaming / Streaming / All / None)
   - On first run: ask if you want to add CleanNet to Windows startup
   - Start the bypass proxy on `127.0.0.1:8080`
   - Open the web dashboard at `http://127.0.0.1:8888`

### Option 2: Manual

```bash
pip install -r requirements.txt
pythonw bypass_silent.pyw
```

Then open `http://127.0.0.1:8888` in your browser.

### Configuring Your Browser

Set your browser's HTTP proxy to `127.0.0.1:8080`. The launcher sets this as the system proxy automatically.

- **Firefox:** Settings → Network Settings → Manual proxy → HTTP Proxy: `127.0.0.1`, Port: `8080`
- **Chrome/Edge:** Uses system proxy settings (set automatically by CleanNet)

## Adding Sites

1. Open the **Web Dashboard** (`http://127.0.0.1:8888`)
2. Enter a domain in the **"Add Site"** field (e.g., `example.com`)
3. Click **Resolve** — the engine will show you the resolved IPs
4. Click **Confirm & Add** — the site is added and bypass begins

The engine will automatically:
- Resolve IPs via DNS over HTTPS
- Detect CDN subdomains containing the site name
- Test all 8 strategies and cache the fastest working one

> **Note:** The first page load after adding a site may take **15–30 seconds** while the engine discovers the best strategy. All subsequent connections will be near-instant.

### Adding CDN Domains

Some sites serve assets (images, videos, scripts) from CDN domains that don't contain the site name. These won't be auto-detected. To find them:

1. Open the target site in your browser
2. Press **F12** → Console tab
3. Paste this snippet and press Enter:
   ```js
   [...new Set(performance.getEntriesByType('resource').map(r=>new URL(r.name).hostname))].filter(h=>h!==location.hostname).sort().forEach(d=>console.log(d))
   ```
4. Copy the domains and add them in the dashboard's **CDN Finder** section

## Configuration

All settings are stored in `config.json`:

```json
{
    "sites": {
        "discord": {
            "enabled": true,
            "domains": ["discord.com", "discordapp.com", "discord.gg", "..."],
            "dns_resolve": ["discord.com", "gateway.discord.gg"],
            "ips": ["162.159.128.233"]
        }
    },
    "proxy_port": 8080,
    "dashboard_port": 8888,
    "proxy_bypass": ["*.steampowered.com", "*.riotgames.com"]
}
```

| Field | Description |
|-------|-------------|
| `sites` | Domains to bypass. Each site has its own domain list, DNS resolution targets, and resolved IPs. |
| `proxy_port` | Local proxy port (default: `8080`). Your browser connects here. |
| `dashboard_port` | Web dashboard port (default: `8888`). |
| `proxy_bypass` | Wildcard patterns for domains that should **not** go through the proxy (e.g., gaming servers). These connections pass through directly without any modification. |

### Auto-generated Files

These files are created automatically at runtime and are excluded from version control (`.gitignore`):

| File | Purpose |
|------|---------|
| `strategy_cache.json` | Stores discovered bypass strategies per site. Auto-populated, safe to delete (strategies will be re-discovered). |
| `stats.json` | Persistent connection statistics. Auto-populated, safe to delete. |
| `bypass.log` | Application log. Rotated automatically, safe to delete. |

## Bypass Strategies

CleanNet tests these 8 strategies in order and caches the fastest one that works:

| # | Strategy | How It Works |
|---|----------|--------------|
| 1 | `direct` | No modification — sends the ClientHello as-is. Used as a baseline to check if the site is actually blocked. |
| 2 | `host_split` | Splits the TCP stream at the SNI extension boundary. The first segment contains the TLS header, the second contains the SNI. |
| 3 | `fragment_light` | Splits the ClientHello into 2 equal halves at the TCP level. Simple but effective against basic DPI. |
| 4 | `tls_record_frag` | Fragments at the **TLS record layer** — wraps the ClientHello in multiple TLS records (each ≤100 bytes). The DPI sees multiple small TLS records instead of one large one. |
| 5 | `fragment_burst` | Enables `TCP_NODELAY` and sends fragments in rapid succession without Nagle buffering. Works against DPI that reassembles based on timing. |
| 6 | `desync` | Sends the first fragment, waits 200ms, then sends the rest with TLS record fragmentation. The delay causes the DPI to timeout its reassembly buffer. |
| 7 | `fragment_heavy` | Byte-level fragmentation — sends the ClientHello one byte at a time. Most aggressive, highest overhead, but works against the most sophisticated DPI. |
| 8 | `sni_shuffle` | Splits the TLS record at the midpoint of the SNI field specifically, ensuring the domain name is split across two TLS records. |

### Strategy Selection Logic

1. If a **cached best strategy** exists for the site → use it immediately
2. If not → try all strategies in order, with multiple IPs
3. On success → cache the strategy and its latency
4. On failure → record the failure and try the next strategy
5. Failed strategies are **retried after 30 minutes** in case network conditions change

## Network & Privacy Details

### What This Tool Accesses

| Destination | Port | Purpose | When |
|------------|------|---------|------|
| `dns.google` | 443 | DNS over HTTPS resolution | On startup + every 30 minutes |
| `cloudflare-dns.com` | 443 | DNS over HTTPS resolution (fallback) | When Google DNS fails |
| `1.1.1.1` | 443 | Ping measurement | Every 60 seconds |
| Your configured site IPs | 443 | TLS connections through bypass | When you browse bypass-enabled sites |

### What This Tool Does NOT Access

- No telemetry, analytics, or crash reporting
- No update checks or phone-home requests
- No third-party APIs or services beyond DoH DNS
- No data leaves your machine except the connections listed above

### Local-Only Services

| Service | Address | Purpose |
|---------|---------|---------|
| HTTP Proxy | `127.0.0.1:8080` | Browser connects here; all traffic is handled locally |
| Web Dashboard | `127.0.0.1:8888` | Monitoring UI; only accessible from your machine |

### Data Stored Locally

| File | Contains | Sensitive? |
|------|----------|------------|
| `config.json` | Your site list, ports, bypass rules | Site names you configured |
| `strategy_cache.json` | Which strategy works for which site | Site names + timing data |
| `stats.json` | Connection counts per site | Aggregate numbers only |
| `bypass.log` | Connection logs with timestamps | Domain names + IPs you connected to |

All data is stored in the application directory. Nothing is written to the registry (except the optional auto-start entry) or sent anywhere.

## Known Limitations

- **CDN detection is best-effort.** Domains containing the site name are auto-detected (e.g., `cdn.discord.com` → detected). Generic CDN domains (e.g., `akamai.net`) are not — use the CDN Finder to add them manually.
- **Windows only.** The proxy settings, system tray, and launcher are Windows-specific. The core bypass logic is platform-independent, but the surrounding tooling is not.
- **Not a VPN.** This tool only fragments TLS handshakes. Your ISP can still see which IPs you connect to (just not the SNI in the handshake). For full privacy, use a VPN.
- **Strategy effectiveness varies.** Different ISPs use different DPI systems. A strategy that works on one ISP may not work on another. The auto-discovery system handles this automatically.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Site not loading after adding | Wait 15–30 seconds for strategy discovery. Check the dashboard log for progress. |
| Images/videos not loading | The site uses CDN domains not yet added. Use CDN Finder (F12 → Console snippet) to discover and add them. |
| All strategies failing | Your ISP may use advanced DPI. Try again after a few minutes — the engine retries failed strategies periodically. |
| Dashboard not opening | Check if port 8888 is already in use. Change `dashboard_port` in `config.json`. |
| Proxy not working | Check if port 8080 is already in use. Check your browser's proxy settings point to `127.0.0.1:8080`. |
| Games lagging | Add the game's domains to Proxy Bypass (Exclude) list in the dashboard. Use the Gaming preset on first launch. |

## License

MIT License — see [LICENSE](LICENSE)

## Contributing

Contributions are welcome! Please open an issue first to discuss what you'd like to change.

## Disclaimer

This tool is provided for **educational and personal use** to access content that may be restricted by network-level filtering. The user is solely responsible for compliance with local laws and regulations. The author does not endorse or encourage accessing illegal content.

---

<a id="türkçe"></a>
## 🇹🇷 Türkçe

### CleanNet — DPI Bypass Motoru

ISP düzeyindeki Derin Paket İnceleme (DPI) engellemelerini, TLS ClientHello paketlerini parçalayarak aşan hafif, tek dosyalı bir Python aracı. Tamamen yerel olarak çalışır — bilgisayarınızda `127.0.0.1:8080` adresinde HTTP proxy olarak hizmet verir, web dashboard ve sistem tepsisi ikonu ile birlikte gelir.

### Nasıl Çalışır

Engelli bir siteye bağlanmaya çalıştığınızda, ISP'niz TLS handshake sırasında gönderilen **SNI (Server Name Indication)** alanını okur. Bu alan domain adını düz metin olarak içerir. Domain engel listesindeyse, ISP bağlantınızı kesmek için TCP RST paketi enjekte eder.

CleanNet, tarayıcınız ile internet arasında yerel bir proxy olarak durur. Bypass-etkin bir domaine bağlantı algıladığında, TLS ClientHello paketini birden fazla küçük TCP segmentine **parçalar**. Her bir parça tek başına DPI sisteminin tam SNI'yi yeniden oluşturması için çok küçüktür, bu yüzden bağlantı geçer. Hedef sunucu parçaları normal şekilde birleştirir ve TLS handshake'i tamamlar.

**CleanNet'in yapmadığı şeyler:**
- Trafiğinizi **şifrelemez** veya gizlemez (bunun için VPN kullanın)
- IP adresinizi **değiştirmez**
- Hiçbir web sitesi içeriğini **değiştirmez**
- Verilerinizi üçüncü taraflara **göndermez**
- Yönetici/root yetkisi **gerektirmez**

### Özellikler

- **8 Bypass Stratejisi** — Her site için otomatik olarak en iyi yöntemi keşfeder
- **Strateji Önbelleği** — Çalışan stratejileri öğrenir ve hatırlar; ilk ziyaret 15–30s sürebilir, sonrakiler anlık (~250ms)
- **Web Dashboard** — `http://127.0.0.1:8888` adresinde canlı istatistikler, ping grafiği, strateji zaman çizelgesi ve log görüntüleyici
- **Site Sihirbazı** — Dashboard'dan DNS çözümleme önizlemesi ile site ekleyin
- **CDN Bulucu** — Bir sitenin kullandığı CDN domainlerini keşfetmek için dahili araç
- **DNS over HTTPS (DoH)** — DNS seviyesindeki engellemeleri aşmak için Google DNS ve Cloudflare üzerinden IP çözümlemesi
- **Sistem Tepsisi** — Arka planda sessizce çalışır
- **Proxy Bypass (Haric Tutma)** — Oyun, streaming veya özel domainleri proxy'den geçirmeden doğrudan iletir
- **Config Dışa/İçe Aktarma** — Yapılandırmanızı yedekleyin ve geri yükleyin
- **Çok Dilli** — İngilizce, Türkçe ve Almanca desteği
- **Otomatik Başlatma** — Opsiyonel Windows başlangıç entegrasyonu

### Kurulum

1. Repoyu klonlayın:
   ```bash
   git clone https://github.com/digaxie/CleanNet.git
   cd CleanNet
   ```

2. **Launcher'ı çalıştırın** (önerilen):
   ```
   CleanNet_Launcher.bat
   ```
   Launcher bağımlılıkları kurar, ilk çalıştırmada bypass preset'i ve otomatik başlatma seçeneklerini sorar, ardından proxy'yi başlatır ve dashboard'u açar.

3. Veya manuel:
   ```bash
   pip install -r requirements.txt
   pythonw bypass_silent.pyw
   ```

4. Dashboard: **http://127.0.0.1:8888**

### Site Ekleme

1. Web Dashboard'u açın
2. **"Add Site"** alanına domain girin (örn. `example.com`)
3. **Resolve** butonuna tıklayın — motor IP'leri gösterecek
4. **Confirm & Add** — site eklenir ve bypass başlar

### CDN Domainleri Ekleme

Bazı siteler, site adını içermeyen CDN domainlerinden içerik sunar. Bunları bulmak için:

1. Hedef siteyi tarayıcınızda açın
2. **F12** → Console sekmesi
3. Bu snippet'ı yapıştırın:
   ```js
   [...new Set(performance.getEntriesByType('resource').map(r=>new URL(r.name).hostname))].filter(h=>h!==location.hostname).sort().forEach(d=>console.log(d))
   ```
4. Domainleri dashboard'daki **CDN Bulucu** bölümünden ekleyin

### Ağ ve Gizlilik

| Hedef | Amaç |
|-------|------|
| `dns.google` / `cloudflare-dns.com` | DNS over HTTPS çözümlemesi |
| `1.1.1.1` | Ping ölçümü |
| Yapılandırılmış site IP'leri | Bypass üzerinden TLS bağlantıları |

- Telemetri, analitik veya çökme raporlaması **yoktur**
- Güncelleme kontrolü veya sunucuya bağlanma **yoktur**
- Tüm veriler uygulama dizininde yerel olarak saklanır

### Bilinen Sınırlamalar

- **CDN algılama en iyi çaba şeklindedir.** Site adını içeren domainler otomatik algılanır. Genel CDN domainleri için CDN Bulucu'yu kullanın.
- **Sadece Windows.** Proxy ayarları, sistem tepsisi ve launcher Windows'a özeldir.
- **VPN değildir.** Bu araç yalnızca TLS handshake'lerini parçalar. ISP'niz hangi IP'lere bağlandığınızı görebilir.

### Sorun Giderme

| Sorun | Çözüm |
|-------|-------|
| Site ekledikten sonra yüklenmiyor | Strateji keşfi için 15–30 saniye bekleyin. Dashboard loglarını kontrol edin. |
| Görseller/videolar yüklenmiyor | Site, eklenmemiş CDN domainleri kullanıyor. CDN Bulucu ile keşfedip ekleyin. |
| Oyunlarda gecikme | Oyun domainlerini dashboard'daki Proxy Bypass (Hariç Tutma) listesine ekleyin. |

---

<a id="deutsch"></a>
## 🇩🇪 Deutsch

### CleanNet — DPI-Bypass-Engine

Ein leichtgewichtiges, Python-basiertes Einzeldatei-Tool, das ISP-Level Deep Packet Inspection (DPI) umgeht, indem es TLS-ClientHello-Pakete fragmentiert. Es läuft vollständig lokal als HTTP-Proxy (`127.0.0.1:8080`) mit Web-Dashboard und System-Tray-Symbol.

### Funktionsweise

Wenn Sie eine gesperrte Website besuchen, liest Ihr ISP das **SNI-Feld (Server Name Indication)** im TLS-Handshake — den Domainnamen, der im Klartext gesendet wird. Steht die Domain auf der Sperrliste, wird Ihre Verbindung durch ein eingeschleustes TCP-RST-Paket unterbrochen.

CleanNet sitzt als lokaler Proxy zwischen Ihrem Browser und dem Internet. Bei einer Verbindung zu einer Bypass-aktivierten Domain **fragmentiert** es das TLS-ClientHello in mehrere kleine TCP-Segmente. Jedes Fragment ist zu klein für das DPI-System, um das vollständige SNI zu rekonstruieren — die Verbindung kommt durch. Der Zielserver setzt die Fragmente normal zusammen.

**Was CleanNet NICHT tut:**
- Es **verschlüsselt** Ihren Datenverkehr **nicht** (verwenden Sie dafür ein VPN)
- Es **ändert** Ihre IP-Adresse **nicht**
- Es **modifiziert** keine Website-Inhalte
- Es **sendet** keine Daten an Dritte
- Es **benötigt** keine Administrator-Rechte

### Funktionen

- **8 Bypass-Strategien** — Findet automatisch die beste Methode für jede Website
- **Strategie-Cache** — Lernt und speichert funktionierende Strategien; erster Besuch kann 15–30s dauern, danach sofort (~250ms)
- **Web-Dashboard** — Echtzeitüberwachung unter `http://127.0.0.1:8888`
- **Website-Assistent** — Websites mit DNS-Auflösungsvorschau hinzufügen
- **CDN-Finder** — Integriertes Tool zur Erkennung von CDN-Domains
- **DNS over HTTPS (DoH)** — IP-Auflösung über Google DNS und Cloudflare
- **System-Tray** — Läuft im Hintergrund
- **Proxy-Bypass (Ausschluss)** — Gaming-, Streaming- oder benutzerdefinierte Domains vom Proxy ausschließen
- **Config Export/Import** — Konfiguration sichern und wiederherstellen
- **Mehrsprachig** — Englisch, Türkisch und Deutsch

### Installation

1. Repository klonen:
   ```bash
   git clone https://github.com/digaxie/CleanNet.git
   cd CleanNet
   ```

2. **Launcher starten** (empfohlen):
   ```
   CleanNet_Launcher.bat
   ```
   Der Launcher installiert Abhängigkeiten, fragt beim ersten Start nach Bypass-Voreinstellungen und Autostart-Option, startet dann den Proxy und öffnet das Dashboard.

3. Oder manuell:
   ```bash
   pip install -r requirements.txt
   pythonw bypass_silent.pyw
   ```

4. Dashboard: **http://127.0.0.1:8888**

### Websites hinzufügen

1. Web-Dashboard öffnen
2. Domain im Feld **"Add Site"** eingeben (z.B. `example.com`)
3. **Resolve** klicken — die Engine zeigt aufgelöste IPs
4. **Confirm & Add** — die Website wird hinzugefügt

### CDN-Domains hinzufügen

Einige Websites liefern Assets über CDN-Domains, die den Seitennamen nicht enthalten. Um diese zu finden:

1. Zielseite im Browser öffnen
2. **F12** → Console-Tab
3. Dieses Snippet einfügen:
   ```js
   [...new Set(performance.getEntriesByType('resource').map(r=>new URL(r.name).hostname))].filter(h=>h!==location.hostname).sort().forEach(d=>console.log(d))
   ```
4. Domains im Dashboard unter **CDN Finder** hinzufügen

### Netzwerk & Datenschutz

| Ziel | Zweck |
|------|-------|
| `dns.google` / `cloudflare-dns.com` | DNS-over-HTTPS-Auflösung |
| `1.1.1.1` | Ping-Messung |
| Konfigurierte Website-IPs | TLS-Verbindungen über Bypass |

- Keine Telemetrie, Analytik oder Absturzberichte
- Keine Update-Prüfungen oder Verbindungen zu externen Servern
- Alle Daten werden lokal im Anwendungsverzeichnis gespeichert

### Bekannte Einschränkungen

- **CDN-Erkennung ist Best-Effort.** Domains mit dem Seitennamen werden automatisch erkannt. Für generische CDN-Domains verwenden Sie den CDN-Finder.
- **Nur Windows.** Proxy-Einstellungen, System-Tray und Launcher sind Windows-spezifisch.
- **Kein VPN.** Dieses Tool fragmentiert nur TLS-Handshakes. Ihr ISP kann weiterhin sehen, mit welchen IPs Sie sich verbinden.

### Fehlerbehebung

| Problem | Lösung |
|---------|--------|
| Website lädt nach Hinzufügen nicht | 15–30 Sekunden für Strategie-Erkennung warten. Dashboard-Logs prüfen. |
| Bilder/Videos laden nicht | Website nutzt nicht hinzugefügte CDN-Domains. Mit CDN-Finder entdecken und hinzufügen. |
| Spiele laggen | Spiel-Domains zur Proxy-Bypass-Liste (Ausschluss) im Dashboard hinzufügen. |

# Security Policy

Languages: [English](#english) | [TÃ¼rkÃ§e](#tÃ¼rkÃ§e) | [Deutsch](#deutsch)

## English

### Supported Version

Only the latest public release is supported for security fixes.

| Version | Supported |
|---|---|
| `2.1.x` | Yes |
| Older versions | No |

### Security Model

CleanNet is a local-only Windows tool.

| Component | Address | Exposure |
|---|---|---|
| HTTP proxy | `127.0.0.1:8080` | Local machine only |
| Web dashboard | `127.0.0.1:8888` | Local machine only |

CleanNet does not install drivers, does not decrypt HTTPS, and does not require administrator privileges for normal use.

### What CleanNet Can Touch

- Browser/application traffic that is explicitly sent to the local proxy.
- DNS over HTTPS requests for domains configured in `config.json`.
- User-level Windows proxy settings under `HKCU`.
- Optional user-level autostart registry entry.
- Local files in the application directory.

### What CleanNet Does Not Do

- No telemetry.
- No analytics.
- No crash reporting.
- No update checks.
- No remote dashboard.
- No kernel driver.
- No certificate authority installation.
- No HTTPS man-in-the-middle decryption.

### EXE Trust Notes

The EXE is built with PyInstaller from the same Python source in this repository. Some antivirus or SmartScreen tools may warn about unsigned PyInstaller applications. If you do not trust the EXE, use the portable ZIP or clone the repository and run:

```powershell
python -m pip install -r requirements.txt --user
pythonw bypass_silent.pyw
```

Verify release files with:

```powershell
Get-FileHash .\CleanNet.exe -Algorithm SHA256
Get-FileHash .\CleanNet-2.0-portable.zip -Algorithm SHA256
```

Compare hashes with `SHA256SUMS.txt` from the release.

### Reporting a Vulnerability

Please do not open a public issue for security vulnerabilities.

Use GitHub Security Advisories if available. Include:

- Affected version.
- Reproduction steps.
- Expected and actual behavior.
- Impact.
- Any relevant logs with private domains removed.

### Local Risk Notes

Any local process can attempt to connect to `127.0.0.1:8888`. Do not expose the dashboard through port forwarding or a reverse proxy. Keep CleanNet bound to localhost.

## TÃ¼rkÃ§e

### Desteklenen SÃ¼rÃ¼m

GÃ¼venlik dÃ¼zeltmeleri yalnÄ±zca en gÃ¼ncel public release iÃ§in desteklenir.

| SÃ¼rÃ¼m | Destek |
|---|---|
| `2.1.x` | Evet |
| Eski sÃ¼rÃ¼mler | HayÄ±r |

### GÃ¼venlik Modeli

CleanNet yalnÄ±zca yerel Ã§alÄ±ÅŸan bir Windows aracÄ±dÄ±r.

| BileÅŸen | Adres | EriÅŸim |
|---|---|---|
| HTTP proxy | `127.0.0.1:8080` | Sadece yerel makine |
| Web dashboard | `127.0.0.1:8888` | Sadece yerel makine |

CleanNet driver kurmaz, HTTPS trafiÄŸini Ã§Ã¶zmez ve normal kullanÄ±m iÃ§in yÃ¶netici izni istemez.

### CleanNet Neye EriÅŸebilir

- Yerel proxyye gÃ¶nderilen tarayÄ±cÄ±/uygulama trafiÄŸi.
- `config.json` iÃ§indeki domainler iÃ§in DNS over HTTPS istekleri.
- KullanÄ±cÄ± seviyesindeki Windows proxy ayarlarÄ±.
- Ä°steÄŸe baÄŸlÄ± kullanÄ±cÄ± seviyesinde autostart registry girdisi.
- Uygulama klasÃ¶rÃ¼ndeki yerel dosyalar.

### CleanNet Ne Yapmaz

- Telemetri yok.
- Analitik yok.
- Crash report yok.
- Update check yok.
- Uzak dashboard yok.
- Kernel driver yok.
- Sertifika otoritesi kurulumu yok.
- HTTPS MITM/decryption yok.

### EXE GÃ¼ven Notu

EXE, bu repodaki aynÄ± Python kaynak kodundan PyInstaller ile Ã¼retilir. BazÄ± antivirÃ¼s veya SmartScreen araÃ§larÄ± imzasÄ±z PyInstaller uygulamalarÄ±na uyarÄ± verebilir. EXEâ€™ye gÃ¼venmiyorsanÄ±z portable ZIP kullanÄ±n veya repoyu klonlayÄ±p ÅŸunu Ã§alÄ±ÅŸtÄ±rÄ±n:

```powershell
python -m pip install -r requirements.txt --user
pythonw bypass_silent.pyw
```

Release dosyalarÄ±nÄ± ÅŸu komutla doÄŸrulayÄ±n:

```powershell
Get-FileHash .\CleanNet.exe -Algorithm SHA256
Get-FileHash .\CleanNet-2.0-portable.zip -Algorithm SHA256
```

Hash Ã§Ä±ktÄ±sÄ±nÄ± release iÃ§indeki `SHA256SUMS.txt` ile karÅŸÄ±laÅŸtÄ±rÄ±n.

### GÃ¼venlik AÃ§Ä±ÄŸÄ± Bildirme

GÃ¼venlik aÃ§Ä±klarÄ± iÃ§in public issue aÃ§mayÄ±n.

MÃ¼mkÃ¼nse GitHub Security Advisories kullanÄ±n. ÅžunlarÄ± ekleyin:

- Etkilenen sÃ¼rÃ¼m.
- Tekrar Ã¼retme adÄ±mlarÄ±.
- Beklenen ve gerÃ§ek davranÄ±ÅŸ.
- Etki.
- Ã–zel domainler temizlenmiÅŸ ilgili loglar.

### Yerel Risk NotlarÄ±

Her yerel process `127.0.0.1:8888` adresine baÄŸlanmayÄ± deneyebilir. Dashboardu port forwarding veya reverse proxy ile dÄ±ÅŸ aÄŸa aÃ§mayÄ±n. CleanNet localhostâ€™a baÄŸlÄ± kalmalÄ±dÄ±r.

## Deutsch

### UnterstÃ¼tzte Version

Sicherheitsfixes werden nur fÃ¼r das aktuelle Ã¶ffentliche Release unterstÃ¼tzt.

| Version | UnterstÃ¼tzt |
|---|---|
| `2.1.x` | Ja |
| Ã„ltere Versionen | Nein |

### Sicherheitsmodell

CleanNet ist ein lokal laufendes Windows-Tool.

| Komponente | Adresse | Zugriff |
|---|---|---|
| HTTP Proxy | `127.0.0.1:8080` | Nur lokaler Rechner |
| Web Dashboard | `127.0.0.1:8888` | Nur lokaler Rechner |

CleanNet installiert keine Treiber, entschlÃ¼sselt kein HTTPS und benÃ¶tigt fÃ¼r normale Nutzung keine Administratorrechte.

### Worauf CleanNet Zugriff Hat

- Browser/App-Verkehr, der explizit an den lokalen Proxy gesendet wird.
- DNS-over-HTTPS-Anfragen fÃ¼r Domains in `config.json`.
- Benutzerbezogene Windows Proxy-Einstellungen.
- Optionale Autostart-Registry-EintrÃ¤ge im Benutzerkontext.
- Lokale Dateien im Anwendungsverzeichnis.

### Was CleanNet Nicht Macht

- Keine Telemetrie.
- Keine Analytik.
- Keine Crash Reports.
- Keine Update Checks.
- Kein Remote Dashboard.
- Kein Kernel-Treiber.
- Keine Zertifizierungsstelle.
- Keine HTTPS-MITM-EntschlÃ¼sselung.

### EXE-Vertrauen

Die EXE wird mit PyInstaller aus demselben Python-Quellcode in diesem Repository gebaut. Antivirus oder SmartScreen kÃ¶nnen bei unsignierten PyInstaller-Apps warnen. Wenn Sie der EXE nicht vertrauen, verwenden Sie das portable ZIP oder klonen Sie das Repository und starten:

```powershell
python -m pip install -r requirements.txt --user
pythonw bypass_silent.pyw
```

Release-Dateien prÃ¼fen:

```powershell
Get-FileHash .\CleanNet.exe -Algorithm SHA256
Get-FileHash .\CleanNet-2.0-portable.zip -Algorithm SHA256
```

Vergleichen Sie die Hashes mit `SHA256SUMS.txt` im Release.

### SicherheitslÃ¼cke Melden

Bitte keine Ã¶ffentlichen Issues fÃ¼r SicherheitslÃ¼cken Ã¶ffnen.

Nutzen Sie GitHub Security Advisories, falls verfÃ¼gbar. Bitte angeben:

- Betroffene Version.
- Schritte zur Reproduktion.
- Erwartetes und tatsÃ¤chliches Verhalten.
- Auswirkungen.
- Relevante Logs ohne private Domains.

### Lokale Risiken

Jeder lokale Prozess kann versuchen, `127.0.0.1:8888` zu erreichen. VerÃ¶ffentlichen Sie das Dashboard nicht Ã¼ber Port Forwarding oder Reverse Proxy. CleanNet sollte an localhost gebunden bleiben.

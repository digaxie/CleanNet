# Security Policy

Languages: [English](#english) | [Türkçe](#türkçe) | [Deutsch](#deutsch)

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

## Türkçe

### Desteklenen Sürüm

Güvenlik düzeltmeleri yalnızca en güncel public release için desteklenir.

| Sürüm | Destek |
|---|---|
| `2.1.x` | Evet |
| Eski sürümler | Hayır |

### Güvenlik Modeli

CleanNet yalnızca yerel çalışan bir Windows aracıdır.

| Bileşen | Adres | Erişim |
|---|---|---|
| HTTP proxy | `127.0.0.1:8080` | Sadece yerel makine |
| Web dashboard | `127.0.0.1:8888` | Sadece yerel makine |

CleanNet driver kurmaz, HTTPS trafiğini çözmez ve normal kullanım için yönetici izni istemez.

### CleanNet Neye Erişebilir

- Yerel proxyye gönderilen tarayıcı/uygulama trafiği.
- `config.json` içindeki domainler için DNS over HTTPS istekleri.
- Kullanıcı seviyesindeki Windows proxy ayarları.
- İsteğe bağlı kullanıcı seviyesinde autostart registry girdisi.
- Uygulama klasöründeki yerel dosyalar.

### CleanNet Ne Yapmaz

- Telemetri yok.
- Analitik yok.
- Crash report yok.
- Update check yok.
- Uzak dashboard yok.
- Kernel driver yok.
- Sertifika otoritesi kurulumu yok.
- HTTPS MITM/decryption yok.

### EXE Güven Notu

EXE, bu repodaki aynı Python kaynak kodundan PyInstaller ile üretilir. Bazı antivirüs veya SmartScreen araçları imzasız PyInstaller uygulamalarına uyarı verebilir. EXE’ye güvenmiyorsanız portable ZIP kullanın veya repoyu klonlayıp şunu çalıştırın:

```powershell
python -m pip install -r requirements.txt --user
pythonw bypass_silent.pyw
```

Release dosyalarını şu komutla doğrulayın:

```powershell
Get-FileHash .\CleanNet.exe -Algorithm SHA256
Get-FileHash .\CleanNet-2.0-portable.zip -Algorithm SHA256
```

Hash çıktısını release içindeki `SHA256SUMS.txt` ile karşılaştırın.

### Güvenlik Açığı Bildirme

Güvenlik açıkları için public issue açmayın.

Mümkünse GitHub Security Advisories kullanın. Şunları ekleyin:

- Etkilenen sürüm.
- Tekrar üretme adımları.
- Beklenen ve gerçek davranış.
- Etki.
- Özel domainler temizlenmiş ilgili loglar.

### Yerel Risk Notları

Her yerel process `127.0.0.1:8888` adresine bağlanmayı deneyebilir. Dashboardu port forwarding veya reverse proxy ile dış ağa açmayın. CleanNet localhost’a bağlı kalmalıdır.

## Deutsch

### Unterstützte Version

Sicherheitsfixes werden nur für das aktuelle öffentliche Release unterstützt.

| Version | Unterstützt |
|---|---|
| `2.1.x` | Ja |
| Ältere Versionen | Nein |

### Sicherheitsmodell

CleanNet ist ein lokal laufendes Windows-Tool.

| Komponente | Adresse | Zugriff |
|---|---|---|
| HTTP Proxy | `127.0.0.1:8080` | Nur lokaler Rechner |
| Web Dashboard | `127.0.0.1:8888` | Nur lokaler Rechner |

CleanNet installiert keine Treiber, entschlüsselt kein HTTPS und benötigt für normale Nutzung keine Administratorrechte.

### Worauf CleanNet Zugriff Hat

- Browser/App-Verkehr, der explizit an den lokalen Proxy gesendet wird.
- DNS-over-HTTPS-Anfragen für Domains in `config.json`.
- Benutzerbezogene Windows Proxy-Einstellungen.
- Optionale Autostart-Registry-Einträge im Benutzerkontext.
- Lokale Dateien im Anwendungsverzeichnis.

### Was CleanNet Nicht Macht

- Keine Telemetrie.
- Keine Analytik.
- Keine Crash Reports.
- Keine Update Checks.
- Kein Remote Dashboard.
- Kein Kernel-Treiber.
- Keine Zertifizierungsstelle.
- Keine HTTPS-MITM-Entschlüsselung.

### EXE-Vertrauen

Die EXE wird mit PyInstaller aus demselben Python-Quellcode in diesem Repository gebaut. Antivirus oder SmartScreen können bei unsignierten PyInstaller-Apps warnen. Wenn Sie der EXE nicht vertrauen, verwenden Sie das portable ZIP oder klonen Sie das Repository und starten:

```powershell
python -m pip install -r requirements.txt --user
pythonw bypass_silent.pyw
```

Release-Dateien prüfen:

```powershell
Get-FileHash .\CleanNet.exe -Algorithm SHA256
Get-FileHash .\CleanNet-2.0-portable.zip -Algorithm SHA256
```

Vergleichen Sie die Hashes mit `SHA256SUMS.txt` im Release.

### Sicherheitslücke Melden

Bitte keine öffentlichen Issues für Sicherheitslücken öffnen.

Nutzen Sie GitHub Security Advisories, falls verfügbar. Bitte angeben:

- Betroffene Version.
- Schritte zur Reproduktion.
- Erwartetes und tatsächliches Verhalten.
- Auswirkungen.
- Relevante Logs ohne private Domains.

### Lokale Risiken

Jeder lokale Prozess kann versuchen, `127.0.0.1:8888` zu erreichen. Veröffentlichen Sie das Dashboard nicht über Port Forwarding oder Reverse Proxy. CleanNet sollte an localhost gebunden bleiben.

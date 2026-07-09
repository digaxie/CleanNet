# CleanNet

CleanNet is a local, Windows-focused DPI bypass tool for people who want a transparent alternative to opaque VPN-like utilities. It runs on your own computer, listens only on `127.0.0.1`, and routes selected HTTPS connections through a local proxy that can fragment TLS ClientHello traffic.

Languages: [English](#english) | [Türkçe](#türkçe) | [Deutsch](#deutsch)

Current version: `v2.1.4`

Public default site list: Discord only. No personal/custom site list is included in this public package.

**Linux:** A native Linux port (GNOME/KDE/desktop proxy integration, PyQt6 tray, `python -m cleannet`) lives in the [`linux/`](linux/) folder — see [`linux/README.md`](linux/README.md). The instructions below cover the Windows build.

## English

### What CleanNet Does

CleanNet helps with ISP-level SNI/DPI filtering by acting as a local HTTP proxy:

```text
Browser or app -> CleanNet proxy 127.0.0.1:8080 -> fragmented TLS ClientHello -> destination server
Dashboard      -> http://127.0.0.1:8888
```

It can:

- Set the Windows user-level system proxy while CleanNet is running.
- Restore the previous proxy state on exit.
- Resolve configured domains with DNS over HTTPS.
- Hide DNS/SNI handling as much as this technique allows.
- Learn which bypass strategy works best per site.
- Show live status, latency, logs, diagnostics, and network-flow based exception helpers in the dashboard.
- Let you add/remove sites and proxy exceptions from the dashboard.
- Run from a ready EXE or directly from readable Python source.

It does not:

- Work as a VPN.
- Change your public IP address.
- Decrypt HTTPS traffic.
- Install drivers.
- Require administrator privileges for normal use.
- Send telemetry, analytics, crash reports, or update checks.

### Download and Install

Use the method that matches your trust preference.

| Option | Best for | What you run |
|---|---|---|
| Setup installer | Recommended for normal users | `CleanNet-2.1.4-setup.exe` |
| Standalone EXE | Portable/no-install use | `CleanNet.exe` from GitHub Releases |
| Portable source ZIP | Users who want readable files | `CleanNet_Launcher.bat` |
| Manual Python | Developers and auditors | `pythonw bypass_silent.pyw` |

#### Option 1: Setup Installer

1. Open the GitHub Releases page.
2. Download `CleanNet-2.1.4-setup.exe`.
3. Run the installer.
4. Read the setup information screen before continuing.
5. Choose whether to create a desktop shortcut.
6. Launch CleanNet from the final setup page or the Start Menu.

Default install paths:

```text
Application files: %LOCALAPPDATA%\Programs\CleanNet
Runtime data:      %LOCALAPPDATA%\CleanNet
Dashboard:         http://127.0.0.1:8888
Proxy:             127.0.0.1:8080
```

The installer is per-user and does not require administrator privileges. It does not install drivers, services, root certificates, browser extensions, telemetry, or system-wide hooks.

The setup installer installs an expanded app folder instead of launching a packed one-file EXE. This reduces first-launch antivirus friction compared with self-extracting executables. Unsigned files may still be scanned by Windows Defender, SmartScreen, Avast, or similar products the first time they run.

#### Option 2: Standalone EXE

1. Open the GitHub Releases page.
2. Download `CleanNet.exe`.
3. Run it.
4. Open `http://127.0.0.1:8888` if the dashboard does not open automatically.

Windows SmartScreen may warn about unsigned open-source executables. That warning means the file is not code-signed by a commercial certificate. It does not prove the file is malicious. If you do not trust the EXE, use the setup installer, portable source ZIP, or manual Python path.

#### Option 3: Portable Source ZIP

1. Download `CleanNet-2.1.4-portable.zip` from GitHub Releases.
2. Extract it to a normal folder, for example `C:\Tools\CleanNet`.
3. Run:

```bat
CleanNet_Launcher.bat
```

The launcher installs Python dependencies with `pip --user`, starts `pythonw bypass_silent.pyw`, and opens the dashboard.

#### Option 4: Manual Python

```powershell
python -m pip install -r requirements.txt --user
pythonw bypass_silent.pyw
```

Then open:

```text
http://127.0.0.1:8888
```

### Verify What You Downloaded

For release files, compare SHA-256 hashes:

```powershell
Get-FileHash .\CleanNet.exe -Algorithm SHA256
Get-FileHash .\CleanNet-2.1.4-portable.zip -Algorithm SHA256
Get-FileHash .\CleanNet-2.1.4-setup.exe -Algorithm SHA256
```

Compare the output with the `SHA256SUMS.txt` file attached to the release.

If you want maximum transparency, use the portable ZIP or clone the repository and run the Python source. The source path uses the same runtime modules as the EXE.

### First Run

The recommended setup installer explains the exact install path, data path, local proxy address, and Windows proxy behavior before CleanNet is launched.

For standalone EXE and portable-source users, CleanNet opens a local first-run setup screen before it enables Windows proxy settings.

The setup screen shows:

- The local data folder used for config, logs, stats, and AI cache.
- The exact local proxy address: `127.0.0.1:8080`.
- A clear note that CleanNet does not install drivers, services, certificates, or system-wide hooks.

Windows proxy stays off until the installer launches CleanNet, or until standalone/portable users press **Start CleanNet** on the first-run screen.

CleanNet uses this public default:

- Site: Discord
- Proxy: `127.0.0.1:8080`
- Dashboard: `127.0.0.1:8888`
- Low latency mode: on
- Background AI training: off
- DNS/SNI privacy mode: on

You can add other sites yourself from the dashboard. Added sites stay in your local `config.json`.

### Dashboard

The dashboard is local-only and available at:

```text
http://127.0.0.1:8888
```

Main areas:

- Overview: status, ping, proxy ownership, current runtime health.
- Sites: enabled sites, domains, strategy lock, test action.
- Performance: low latency mode, ping target, refresh intervals, live PC connections, proxy exceptions.
- AI Engine: strategy learning status and training controls.
- Settings: proxy bypass presets, import/export, autostart, diagnostics.
- Logs: in-memory operational log for the current session.

### Adding a Site

1. Open the dashboard.
2. Go to Sites.
3. Enter a domain.
4. Resolve it.
5. Confirm and add.
6. Test the site.

The first connection may take longer while CleanNet discovers a working strategy. After that, the selected strategy is cached locally.

### Gaming and Low Latency Use

Games, launchers, voice apps, anti-cheat services, and latency-sensitive apps should normally bypass CleanNet.

Use Performance -> Live PC Connections:

1. Find the process or remote endpoint.
2. Click Add Exception for one endpoint, or Add All For Process for visible endpoints.
3. CleanNet writes the entry to `proxy_bypass`.
4. Windows proxy override is refreshed.

CleanNet cannot create true per-process Windows proxy exceptions. Windows proxy bypass rules are host/IP/domain based. The dashboard helps you create those rules from live network flows.

### Security Model

CleanNet is local-first:

| Surface | Value |
|---|---|
| Proxy bind address | `127.0.0.1` |
| Dashboard bind address | `127.0.0.1` |
| Normal admin requirement | No |
| Driver install | No |
| HTTPS decryption | No |
| Telemetry | No |
| External UI assets | No |

CleanNet writes only user-level Windows proxy settings under:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
```

It stores a backup in `proxy_state.json` and restores the previous proxy state when the app exits — including when you log off, restart, or shut down Windows without choosing Exit first. This means that even if you keep autostart off and just open CleanNet when you need it, a reboot will not leave your system proxy pointing at the stopped local engine. A proxy watchdog keeps Windows proxy ownership correct while CleanNet is running.

### Privacy

CleanNet stores runtime data locally:

| File | Purpose | Safe to delete |
|---|---|---|
| `config.json` | Sites, ports, privacy/performance settings, proxy bypass entries | Yes, but settings reset |
| `strategy_cache.json` | Learned working strategy data | Yes |
| `ai_strategy.json` | Adaptive strategy learning data | Yes |
| `stats.json` | Aggregate counters | Yes |
| `bypass.log` | Warning/error disk log | Yes |
| `proxy_state.json` | Previous Windows proxy backup | Usually no while running |

Disk logs are privacy-minimized by default. Verbose logs are kept in memory for the dashboard and are lost when the process exits.

### Build From Source

Run tests:

```powershell
.\run_tests.ps1
```

Build portable ZIP:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_release.ps1
```

Build EXE:

```powershell
python -m pip install pyinstaller --user
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_exe.ps1
```

Build classic installer:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_installer.ps1
```

The installer build requires Inno Setup 6.

Full release quality gate:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify_release.ps1
```

### Troubleshooting

| Problem | What to check |
|---|---|
| Dashboard does not open | Check `127.0.0.1:8888`, then check if another app uses port `8888`. |
| Site does not open | Run site test from dashboard, wait for strategy discovery, check logs. |
| Discord still does not route | Confirm Windows proxy is owned by CleanNet in Overview/Diagnostics. |
| Games lag | Add the game endpoint or process endpoints to proxy exceptions. |
| Internet breaks after force-closing | Run `CleanTraces.ps1` or disable Windows proxy manually. |
| EXE is not trusted | Read the setup installer explanation, use the portable ZIP, or clone the source and run `CleanNet_Launcher.bat`. |
| Xbox / Microsoft Store apps show blank pages or will not sign in | Windows isolates Store/UWP apps from local services, so they cannot reach CleanNet's proxy. In the dashboard open **Settings → Fix Xbox / Store Apps**, accept the Administrator (UAC) prompt, then fully close and reopen the app. This is a built-in, reversible Windows setting. |

### Legal Notice

Use CleanNet only where you are allowed to do so. The project is provided for education, interoperability, and personal network troubleshooting. You are responsible for local laws, policies, and terms of service.

---

## Türkçe

### CleanNet Ne Yapar

CleanNet, Windows üzerinde yerel çalışan bir DPI bypass aracıdır. Seçili HTTPS bağlantılarında TLS ClientHello paketini parçalayarak SNI/DPI filtrelerine karşı çalışır.

```text
Tarayıcı veya uygulama -> CleanNet proxy 127.0.0.1:8080 -> parçalanmış TLS ClientHello -> hedef sunucu
Dashboard              -> http://127.0.0.1:8888
```

Yapabildikleri:

- CleanNet çalışırken Windows kullanıcı proxy ayarını yönetir.
- Kapanırken önceki proxy durumunu geri yükler.
- Ayarlı domainleri DNS over HTTPS ile çözümler.
- DNS/SNI gizliliğini bu tekniğin izin verdiği ölçüde korur.
- Site başına en iyi bypass stratejisini öğrenir.
- Dashboard üzerinde canlı durum, ping, log, diagnostics ve ağ akışı tablosu gösterir.
- Kullanıcının dashboarddan site ve proxy exception eklemesine izin verir.
- Hazır installer, standalone EXE veya okunabilir Python kaynak dosyalarıyla çalışır.

Yapmadıkları:

- VPN değildir.
- IP adresinizi değiştirmez.
- HTTPS trafiğini çözmez.
- Driver kurmaz.
- Windows servisi kurmaz.
- Kök sertifika kurmaz.
- Normal kullanımda yönetici izni istemez.
- Telemetri, analitik, crash report veya update check göndermez.

### İndirme ve Kurulum

Güven tercihinize göre dört yol var.

| Seçenek | Kimler için | Çalıştırılacak dosya |
|---|---|---|
| Klasik setup installer | Normal kullanıcılar için önerilir | `CleanNet-2.1.4-setup.exe` |
| Standalone EXE | Kurulumsuz/taşınabilir kullanım | GitHub Releases içindeki `CleanNet.exe` |
| Portable kaynak ZIP | Dosyaları görmek isteyen kullanıcı | `CleanNet_Launcher.bat` |
| Manuel Python | Geliştirici ve denetleyen kullanıcı | `pythonw bypass_silent.pyw` |

#### Seçenek 1: Klasik Setup Installer

1. GitHub Releases sayfasını açın.
2. `CleanNet-2.1.4-setup.exe` dosyasını indirin.
3. Installer'ı çalıştırın.
4. Devam etmeden önce kurulum bilgilendirme ekranını okuyun.
5. Masaüstü kısayolu isteyip istemediğinizi seçin.
6. Son ekrandan veya Başlat Menüsü'nden CleanNet'i başlatın.

Varsayılan kurulum yolları:

```text
Uygulama dosyaları: %LOCALAPPDATA%\Programs\CleanNet
Çalışma verileri:   %LOCALAPPDATA%\CleanNet
Dashboard:          http://127.0.0.1:8888
Proxy:              127.0.0.1:8080
```

Installer kullanıcı bazlıdır ve yönetici izni gerektirmez. Driver, servis, kök sertifika, tarayıcı eklentisi, telemetri veya sistem geneli hook kurmaz.

Setup installer, tek dosyalı self-extracting EXE başlatmak yerine genişletilmiş uygulama klasörü kurar. Bu, ilk çalıştırmada antivirüslerin dosyayı kilitleme riskini azaltır. Yine de imzasız dosyalar ilk açılışta Windows Defender, SmartScreen, Avast veya benzeri güvenlik ürünleri tarafından taranabilir.

#### Seçenek 2: Standalone EXE

1. GitHub Releases sayfasını açın.
2. `CleanNet.exe` dosyasını indirin.
3. Çalıştırın.
4. Dashboard otomatik açılmazsa `http://127.0.0.1:8888` adresini açın.

Windows SmartScreen imzasız açık kaynak EXE dosyaları için uyarı gösterebilir. Bu uyarı dosyanın ticari code-signing sertifikası olmadığını belirtir; tek başına zararlı olduğu anlamına gelmez. EXE dosyasına güvenmiyorsanız setup installer, portable kaynak ZIP veya manuel Python yolunu kullanın.

#### Seçenek 3: Portable Kaynak ZIP

1. GitHub Releases içinden `CleanNet-2.1.4-portable.zip` dosyasını indirin.
2. Normal bir klasöre çıkarın, örnek: `C:\Tools\CleanNet`.
3. Çalıştırın:

```bat
CleanNet_Launcher.bat
```

Launcher Python bağımlılıklarını `pip --user` ile kurar, `pythonw bypass_silent.pyw` başlatır ve dashboardu açar.

#### Seçenek 4: Manuel Python

```powershell
python -m pip install -r requirements.txt --user
pythonw bypass_silent.pyw
```

Sonra şu adresi açın:

```text
http://127.0.0.1:8888
```

### İndirdiğiniz Dosyayı Doğrulama

Release dosyaları için SHA-256 kontrolü yapın:

```powershell
Get-FileHash .\CleanNet.exe -Algorithm SHA256
Get-FileHash .\CleanNet-2.1.4-portable.zip -Algorithm SHA256
Get-FileHash .\CleanNet-2.1.4-setup.exe -Algorithm SHA256
```

Çıktıyı release ekindeki `SHA256SUMS.txt` ile karşılaştırın.

Maksimum şeffaflık istiyorsanız portable ZIP veya kaynak kodu klonlama yolunu kullanın. Kaynak yolu ile EXE aynı runtime modüllerini kullanır.

### İlk Çalıştırma

Önerilen setup installer, CleanNet başlamadan önce kurulum yolu, veri yolu, yerel proxy adresi ve Windows proxy davranışını açıklar.

Standalone EXE ve portable kaynak yolunda CleanNet, Windows proxy ayarlarını açmadan önce yerel ilk kurulum ekranını gösterir.

Setup/ilk kurulum ekranında şunları görürsünüz:

- Config, log, stats ve AI cache için kullanılan yerel veri klasörü.
- Net yerel proxy adresi: `127.0.0.1:8080`.
- CleanNet'in driver, servis, sertifika veya sistem geneli hook kurmadığı bilgisi.

Windows proxy, installer CleanNet'i başlatana kadar veya standalone/portable kullanıcı ilk kurulum ekranında **Start CleanNet** düğmesine basana kadar kapalı kalır.

Public varsayılanlar:

- Site: Discord
- Proxy: `127.0.0.1:8080`
- Dashboard: `127.0.0.1:8888`
- Düşük gecikme modu: açık
- Arka plan AI eğitimi: kapalı
- DNS/SNI privacy modu: açık

Başka siteleri dashboarddan kendiniz ekleyebilirsiniz. Eklenen siteler yerel `config.json` içinde kalır.

### Dashboard

Dashboard yalnızca yereldir ve şu adreste açılır:

```text
http://127.0.0.1:8888
```

Ana bölümler:

- Overview: durum, ping, proxy sahipliği ve anlık çalışma sağlığı.
- Sites: etkin siteler, domainler, strateji kilidi, test işlemi.
- Performance: düşük gecikme modu, ping hedefi, yenileme aralıkları, canlı PC bağlantıları, proxy istisnaları.
- AI Engine: strateji öğrenme durumu ve eğitim kontrolleri.
- Settings: proxy bypass hazır ayarları, içe/dışa aktarma, autostart, diagnostics.
- Logs: mevcut oturuma ait bellek içi işlem logu.

### Site Ekleme

1. Dashboardu açın.
2. Sites bölümüne gidin.
3. Bir domain girin.
4. Çözümleyin (Resolve).
5. Onaylayıp ekleyin.
6. Siteyi test edin.

İlk bağlantı, CleanNet çalışan bir strateji bulurken daha uzun sürebilir. Sonrasında seçilen strateji yerel olarak önbelleğe alınır.

### Oyun ve Düşük Gecikme

Oyunlar, launcherlar, sesli konuşma uygulamaları, anti-cheat servisleri ve düşük gecikme isteyen uygulamalar genelde CleanNet dışında kalmalıdır.

Dashboard içinde Performance -> Live PC Connections bölümünü kullanın:

1. Process veya remote endpoint satırını bulun.
2. Tek endpoint için Add Exception, görünen tüm process endpointleri için Add All For Process seçin.
3. CleanNet girdiyi `proxy_bypass` içine yazar.
4. Windows proxy override güncellenir.

CleanNet gerçek process-level Windows proxy exception oluşturamaz. Windows proxy bypass kuralları host/IP/domain bazlıdır. Dashboard canlı ağ akışlarından bu kuralları oluşturmanıza yardım eder.

### Güvenlik Modeli

CleanNet yerel önceliklidir:

| Alan | Değer |
|---|---|
| Proxy bind adresi | `127.0.0.1` |
| Dashboard bind adresi | `127.0.0.1` |
| Normal admin gereksinimi | Yok |
| Driver kurulumu | Yok |
| HTTPS çözme | Yok |
| Telemetri | Yok |
| Harici UI asset | Yok |

CleanNet yalnızca şu registry alanındaki kullanıcı bazlı Windows proxy ayarlarını yazar:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
```

Önceki proxy durumu `proxy_state.json` içinde saklanır ve çıkışta — Exit'e basmadan Windows oturumunu kapatsanız, yeniden başlatsanız veya bilgisayarı kapatsanız bile — geri yüklenir. Böylece autostart'ı kapalı tutup CleanNet'i sadece ihtiyaç duyduğunuzda açsanız dahi, yeniden başlatma sistem proxy'sini durmuş yerel motora bağlı bırakmaz. Uygulama kapanmadan zorla öldürülürse Windows proxy ayarını manuel kapatabilir veya `CleanTraces.ps1` kullanabilirsiniz.

### Gizlilik

CleanNet çalışma verilerini yerel olarak saklar:

| Dosya | Amaç | Silinebilir mi |
|---|---|---|
| `config.json` | Siteler, portlar, privacy/performance ayarları, proxy bypass girdileri | Evet, ama ayarlar sıfırlanır |
| `strategy_cache.json` | Öğrenilmiş çalışan strateji verisi | Evet |
| `ai_strategy.json` | Uyarlanabilir strateji öğrenme verisi | Evet |
| `stats.json` | Toplu sayaçlar | Evet |
| `bypass.log` | Warning/error disk logu | Evet |
| `proxy_state.json` | Önceki Windows proxy yedeği | Çalışırken genelde hayır |

Disk logları varsayılan olarak gizlilik açısından minimize edilmiştir. Ayrıntılı loglar dashboard için yalnızca bellekte tutulur ve işlem kapanınca kaybolur.

### Kaynaktan Derleme

Testleri çalıştırın:

```powershell
.\run_tests.ps1
```

Portable ZIP oluşturun:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_release.ps1
```

EXE oluşturun:

```powershell
python -m pip install pyinstaller --user
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_exe.ps1
```

Klasik installer oluşturun:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_installer.ps1
```

Installer build için Inno Setup 6 gerekir.

Tam release kalite kapısı:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify_release.ps1
```

### Sorun Giderme

| Sorun | Kontrol edilecek şey |
|---|---|
| Dashboard açılmıyor | `127.0.0.1:8888` adresini ve `8888` portunu kullanan başka uygulama olup olmadığını kontrol edin. |
| Site açılmıyor | Dashboarddan site testi çalıştırın, strateji keşfini bekleyin, loglara bakın. |
| Discord hâlâ route olmuyor | Overview/Diagnostics içinde Windows proxy'nin CleanNet'e ait olduğunu doğrulayın. |
| Oyunlarda ping artıyor | Oyunun endpointlerini veya process endpointlerini proxy exception listesine ekleyin. |
| İnternet zorla kapatma sonrası bozuldu | `CleanTraces.ps1` çalıştırın veya Windows proxy ayarını manuel kapatın. |
| EXE'ye güvenmiyorsunuz | Setup installer açıklamalarını okuyun veya portable ZIP / kaynak kod yolunu kullanın. |
| Xbox / Microsoft Store uygulamaları boş açılıyor veya giriş yapılamıyor | Windows, Store/UWP uygulamalarını yerel servislerden yalıtır; bu yüzden CleanNet proxy'sine ulaşamazlar. Dashboard'da **Ayarlar → Xbox / Store Uygulamalarını Düzelt**'i açın, Yönetici (UAC) iznini onaylayın, ardından uygulamayı tamamen kapatıp yeniden açın. Bu, Windows'un yerleşik ve geri alınabilir bir ayarıdır. |

### Yasal Not

CleanNet'i yalnızca kullanmanızın izinli olduğu yerlerde kullanın. Proje eğitim, birlikte çalışabilirlik ve kişisel ağ tanılama amacıyla sunulur. Yerel kanunlar, kurum politikaları ve hizmet şartlarından kullanıcı sorumludur.

---

## Deutsch

### Was CleanNet Macht

CleanNet ist ein lokal laufendes DPI-Bypass-Tool für Windows. Für ausgewählte HTTPS-Verbindungen fragmentiert es den TLS ClientHello, um SNI/DPI-Filter zu umgehen.

```text
Browser oder App -> CleanNet Proxy 127.0.0.1:8080 -> fragmentierter TLS ClientHello -> Zielserver
Dashboard        -> http://127.0.0.1:8888
```

CleanNet kann:

- Während der Laufzeit den Windows-Benutzerproxy setzen.
- Beim Beenden den vorherigen Proxyzustand wiederherstellen.
- Konfigurierte Domains per DNS over HTTPS auflösen.
- DNS/SNI-Verarbeitung soweit möglich verbergen.
- Pro Website die beste Bypass-Strategie lernen.
- Status, Latenz, Logs, Diagnosen und Live-Netzwerkflüsse im Dashboard zeigen.
- Websites und Proxy-Ausnahmen über das Dashboard verwalten.
- Als fertige EXE oder direkt aus lesbarem Python-Quellcode laufen.

CleanNet kann nicht:

- Als VPN arbeiten.
- Die öffentliche IP-Adresse ändern.
- HTTPS-Verkehr entschlüsseln.
- Treiber installieren.
- Für normale Nutzung Administratorrechte verlangen.
- Telemetrie, Analytik, Crash Reports oder Update Checks senden.

### Download und Installation

Wählen Sie den Weg, dem Sie vertrauen.

| Option | Geeignet für | Ausführen |
|---|---|---|
| Setup Installer | Empfohlen für normale Nutzer | `CleanNet-2.1.4-setup.exe` |
| Standalone EXE | Portable Nutzung ohne Installation | `CleanNet.exe` aus GitHub Releases |
| Portable Source ZIP | Nutzer, die Dateien prüfen möchten | `CleanNet_Launcher.bat` |
| Manuelles Python | Entwickler und Auditoren | `pythonw bypass_silent.pyw` |

#### Option 1: Setup Installer

1. Öffnen Sie die GitHub Releases Seite.
2. Laden Sie `CleanNet-2.1.4-setup.exe` herunter.
3. Starten Sie den Installer.
4. Lesen Sie die Setup-Informationen, bevor Sie fortfahren.
5. Wählen Sie optional eine Desktop-Verknüpfung.
6. Starten Sie CleanNet vom letzten Setup-Bildschirm oder aus dem Startmenü.

Standardpfade:

```text
Programmdateien: %LOCALAPPDATA%\Programs\CleanNet
Laufzeitdaten:   %LOCALAPPDATA%\CleanNet
Dashboard:       http://127.0.0.1:8888
Proxy:           127.0.0.1:8080
```

Der Installer ist benutzerbasiert und benötigt keine Administratorrechte. Er installiert keine Treiber, Dienste, Root-Zertifikate, Browser-Erweiterungen, Telemetrie oder systemweiten Hooks.

Der Setup Installer installiert einen entpackten App-Ordner, statt eine gepackte One-File-EXE direkt zu starten. Das reduziert Antivirus-Probleme beim ersten Start. Unsigned Dateien können beim ersten Start trotzdem von Windows Defender, SmartScreen, Avast oder ähnlichen Produkten geprüft werden.

#### Option 2: Standalone EXE

1. Öffnen Sie die GitHub Releases Seite.
2. Laden Sie `CleanNet.exe` herunter.
3. Starten Sie die Datei.
4. Falls das Dashboard nicht automatisch öffnet, öffnen Sie `http://127.0.0.1:8888`.

Windows SmartScreen kann bei unsignierten Open-Source-EXE-Dateien warnen. Diese Warnung bedeutet, dass keine kommerzielle Code-Signing-Signatur vorhanden ist. Wenn Sie der EXE nicht vertrauen, verwenden Sie den Setup Installer, das portable ZIP oder den manuellen Python-Weg.

#### Option 3: Portable Source ZIP

1. Laden Sie `CleanNet-2.1.4-portable.zip` aus GitHub Releases herunter.
2. Entpacken Sie es in einen normalen Ordner, zum Beispiel `C:\Tools\CleanNet`.
3. Starten Sie:

```bat
CleanNet_Launcher.bat
```

Der Launcher installiert Python-Abhängigkeiten mit `pip --user`, startet `pythonw bypass_silent.pyw` und öffnet das Dashboard.

#### Option 4: Manuelles Python

```powershell
python -m pip install -r requirements.txt --user
pythonw bypass_silent.pyw
```

Dann öffnen:

```text
http://127.0.0.1:8888
```

### Download Prüfen

Prüfen Sie SHA-256 Hashes:

```powershell
Get-FileHash .\CleanNet.exe -Algorithm SHA256
Get-FileHash .\CleanNet-2.1.4-portable.zip -Algorithm SHA256
Get-FileHash .\CleanNet-2.1.4-setup.exe -Algorithm SHA256
```

Vergleichen Sie die Ausgabe mit `SHA256SUMS.txt` im Release.

Für maximale Transparenz verwenden Sie das portable ZIP oder klonen Sie den Quellcode und starten die Python-Version. Die Quellcode-Version verwendet dieselben Runtime-Module wie die EXE.

### Erster Start

Der empfohlene Setup Installer erklärt Installationspfad, Datenpfad, lokale Proxy-Adresse und Windows-Proxy-Verhalten, bevor CleanNet gestartet wird.

Bei Standalone-EXE und portablem Quellcode zeigt CleanNet zuerst einen lokalen Setup-Bildschirm, bevor Windows-Proxy-Einstellungen aktiviert werden.

Der Setup-Bildschirm zeigt:

- Den lokalen Datenordner fuer Config, Logs, Statistiken und AI-Cache.
- Die lokale Proxy-Adresse: `127.0.0.1:8080`.
- Einen klaren Hinweis, dass CleanNet keine Treiber, Dienste, Zertifikate oder systemweiten Hooks installiert.

Der Windows-Proxy bleibt aus, bis der Installer CleanNet startet oder bis Standalone-/Portable-Nutzer **CleanNet starten** drücken.

Öffentliche Standardkonfiguration:

- Website: Discord
- Proxy: `127.0.0.1:8080`
- Dashboard: `127.0.0.1:8888`
- Low latency mode: an
- Background AI training: aus
- DNS/SNI privacy mode: an

Weitere Websites können Sie selbst im Dashboard hinzufügen. Diese werden lokal in `config.json` gespeichert.

### Dashboard

Das Dashboard ist nur lokal erreichbar:

```text
http://127.0.0.1:8888
```

Bereiche:

- Overview: Status, Ping, Proxy-Eigentum und Runtime-Zustand.
- Sites: Websites, Domains, Strategy Lock und Testaktion.
- Performance: Low latency, Ping Target, Refresh Interval, Live PC Connections, Proxy Exceptions.
- AI Engine: Strategie-Lernen und Trainingssteuerung.
- Settings: Proxy-Bypass-Presets, Import/Export, Autostart, Diagnostics.
- Logs: In-Memory-Log der aktuellen Sitzung.

### Website Hinzufügen

1. Dashboard öffnen.
2. Sites öffnen.
3. Domain eingeben.
4. Resolve ausführen.
5. Confirm and Add wählen.
6. Website-Test starten.

Die erste Verbindung kann wegen Strategie-Erkennung länger dauern. Danach wird die funktionierende Strategie lokal gespeichert.

### Gaming und Niedrige Latenz

Spiele, Launcher, Voice Apps, Anti-Cheat-Dienste und latenzkritische Apps sollten normalerweise CleanNet umgehen.

Nutzen Sie Performance -> Live PC Connections:

1. Prozess oder Remote Endpoint finden.
2. Add Exception für einen Endpoint oder Add All For Process für sichtbare Endpoints wählen.
3. CleanNet schreibt den Eintrag in `proxy_bypass`.
4. Windows Proxy Override wird aktualisiert.

CleanNet kann keine echten process-level Windows Proxy Exceptions erstellen. Windows Proxy Bypass Regeln sind host/IP/domain-basiert. Das Dashboard hilft, diese Regeln aus Live-Netzwerkflüssen zu erzeugen.

### Sicherheitsmodell

| Bereich | Wert |
|---|---|
| Proxy Bind-Adresse | `127.0.0.1` |
| Dashboard Bind-Adresse | `127.0.0.1` |
| Adminrechte normal nötig | Nein |
| Treiberinstallation | Nein |
| HTTPS Entschlüsselung | Nein |
| Telemetrie | Nein |
| Externe UI Assets | Nein |

CleanNet schreibt nur Benutzer-Proxy-Einstellungen:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
```

Der vorherige Proxyzustand wird in `proxy_state.json` gesichert und beim Beenden wiederhergestellt — auch wenn Sie Windows abmelden, neu starten oder herunterfahren, ohne vorher Exit zu wählen. Selbst wenn Sie den Autostart deaktiviert lassen und CleanNet nur bei Bedarf öffnen, zeigt der System-Proxy nach einem Neustart also nie auf die gestoppte lokale Engine. Ein Watchdog korrigiert das Proxy-Eigentum während CleanNet läuft.

### Datenschutz

| Datei | Zweck | Löschbar |
|---|---|---|
| `config.json` | Websites, Ports, Privacy/Performance, Proxy Bypass | Ja, Einstellungen werden zurückgesetzt |
| `strategy_cache.json` | Gelernte Strategiedaten | Ja |
| `ai_strategy.json` | Adaptive Strategiedaten | Ja |
| `stats.json` | Aggregierte Zähler | Ja |
| `bypass.log` | Warning/Error Disk-Log | Ja |
| `proxy_state.json` | Vorheriger Windows Proxy Backup | Während der Laufzeit eher nein |

Disk-Logs sind standardmäßig minimiert. Detaillierte Logs bleiben nur im Speicher für das Dashboard und verschwinden beim Beenden.

### Aus Quellcode Bauen

```powershell
.\run_tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_release.ps1
python -m pip install pyinstaller --user
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_exe.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_installer.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify_release.ps1
```

Der Installer-Build benötigt Inno Setup 6.

### Fehlerbehebung

| Problem | Prüfung |
|---|---|
| Dashboard öffnet nicht | `127.0.0.1:8888` und Portkonflikt prüfen. |
| Website öffnet nicht | Website-Test im Dashboard starten, Strategie-Erkennung abwarten, Logs prüfen. |
| Discord routet nicht | In Overview/Diagnostics prüfen, ob Windows Proxy CleanNet gehört. |
| Spiele haben hohe Latenz | Spiel-Endpoint oder Prozess-Endpoints zu Proxy Exceptions hinzufügen. |
| Internet nach Force-Close defekt | `CleanTraces.ps1` ausführen oder Windows Proxy manuell deaktivieren. |
| EXE nicht vertrauenswürdig | Setup-Erklärung lesen oder Portable ZIP / Quellcode + `CleanNet_Launcher.bat` verwenden. |
| Xbox / Microsoft Store-Apps bleiben leer oder Anmeldung schlägt fehl | Windows isoliert Store/UWP-Apps von lokalen Diensten, sodass sie den CleanNet-Proxy nicht erreichen. Im Dashboard **Einstellungen → Xbox / Store-Apps reparieren** öffnen, die Administrator-Abfrage (UAC) bestätigen und die App anschließend vollständig schließen und neu öffnen. Dies ist eine integrierte, umkehrbare Windows-Einstellung. |

### Rechtlicher Hinweis

Verwenden Sie CleanNet nur dort, wo dies erlaubt ist. Das Projekt dient Bildung, Interoperabilität und persönlicher Netzwerkdiagnose. Nutzer sind selbst für lokale Gesetze, Richtlinien und Nutzungsbedingungen verantwortlich.

---

## Repository Notes

- Default public `config.json` contains only Discord.
- Runtime files are ignored by `.gitignore`.
- Setup installer, standalone EXE, portable ZIP, and SHA256SUMS should be attached to GitHub Releases.
- Main branch should stay source-first and auditable.

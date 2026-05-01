#requires -Version 5.1
<#
 CleanTraces.ps1
 -----------------------------------------------------------------------------
 Cihaz uzerindeki gezinme/uygulama izlerini temizler. ISS/operator loglarina
 ERISEMEZ; bu script sadece yerel (bu bilgisayardaki) izleri siler.

 KATEGORILER
   1) DNS cache (Windows)
   2) Tarayici verisi (Chrome, Edge, Firefox, Brave, Opera, Vivaldi)
   3) Windows Temp / Prefetch / Recent / Jump Lists / Thumb cache
   4) Registry gezinme/yaziri MRU (TypedURLs, RunMRU, RecentDocs)
   5) Proje loglari (bypass.log*, privacy_sites*.txt, strategy_cache.json,
      stats.json, ai_strategy.json, __pycache__)
   6) Geri donusum kutusu
   7) (Opsiyonel) Shadow copies / system restore points

 KULLANIM
   Sag tik > Run with PowerShell   VEYA   yaninda CleanTraces.bat'i calistir.
   Admin yetkisi gerekir (1 ve 7 icin sart, digerleri kullanici bazinda caliisir).

 UYARILAR
   - Gidiyor, geri donmuyor.
   - Tarayicilar kapatilir (force-kill). Acik sekmeler/kayitli sifreler disinda
     session verisi kayboldar.
   - Proje klasoru varsayilan olarak bu scriptin bulundugu dizindir.
#>

[CmdletBinding()]
param(
    [switch]$IncludeShadowCopies,
    [string]$ProjectRoot = $PSScriptRoot,
    [switch]$DryRun
)

$ErrorActionPreference = 'Continue'
$sw = [System.Diagnostics.Stopwatch]::StartNew()

function Write-Step($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Done($msg) { Write-Host "    $msg" -ForegroundColor DarkGray }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err ($msg) { Write-Host "[X] $msg" -ForegroundColor Red }

function Test-Admin {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Remove-PathSafe {
    param([Parameter(Mandatory)][string]$Path, [switch]$File)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    if ($DryRun) { Write-Done "DRYRUN sil: $Path"; return }
    try {
        if ($File) { Remove-Item -LiteralPath $Path -Force -ErrorAction Stop }
        else       { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop }
        Write-Done "silindi: $Path"
    } catch { Write-Done "atlandi (kilitli?): $Path" }
}

function Clear-DirContents {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-PathSafe -Path $_.FullName
    }
}

$isAdmin = Test-Admin
Write-Host ""
Write-Host "=== CleanTraces.ps1 ===" -ForegroundColor Green
Write-Host "Admin  : $isAdmin"
Write-Host "DryRun : $DryRun"
Write-Host "Project: $ProjectRoot"
Write-Host ""

# ---------- 0) Tarayicilari kapat ----------
Write-Step "Tarayicilar kapatiliyor (kilitlenmis dosyalar acilsin diye)"
$browsers = @('chrome','msedge','firefox','brave','opera','vivaldi','iexplore')
foreach ($b in $browsers) {
    if ($DryRun) { continue }
    Get-Process -Name $b -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Milliseconds 400

# ---------- 1) DNS cache ----------
Write-Step "Windows DNS resolver cache"
if ($DryRun) { Write-Done "DRYRUN ipconfig /flushdns" }
else { ipconfig /flushdns | Out-Null; Write-Done "flushdns tamam" }

# ---------- 2) Tarayici verisi ----------
Write-Step "Tarayici profilleri temizleniyor"

$local = $env:LOCALAPPDATA
$roam  = $env:APPDATA

# Chromium tabanli (Chrome, Edge, Brave, Opera, Vivaldi)
$chromiumProfiles = @(
    "$local\Google\Chrome\User Data",
    "$local\Microsoft\Edge\User Data",
    "$local\BraveSoftware\Brave-Browser\User Data",
    "$roam\Opera Software\Opera Stable",
    "$local\Vivaldi\User Data"
)
# Bu profil altinda silinecek klasor/dosya isimleri (her profile tekrar uygulanir)
$chromiumTargets = @(
    'History','History-journal','Cookies','Cookies-journal',
    'Login Data','Login Data-journal','Web Data','Web Data-journal',
    'Shortcuts','Top Sites','Top Sites-journal','Visited Links',
    'Network\Cookies','Network\Cookies-journal',
    'Network Action Predictor','Network Action Predictor-journal',
    'Sessions','Session Storage','Local Storage','IndexedDB',
    'Service Worker','Cache','Code Cache','GPUCache',
    'Media Cache','Application Cache','DawnCache',
    'QuotaManager','QuotaManager-journal'
)

foreach ($root in $chromiumProfiles) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    # Default profil + Profile 1,2,...
    $profiles = Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^(Default|Profile \d+|Guest Profile)$' }
    foreach ($prof in $profiles) {
        foreach ($t in $chromiumTargets) {
            $full = Join-Path $prof.FullName $t
            if (Test-Path -LiteralPath $full) {
                if ((Get-Item -LiteralPath $full).PSIsContainer) { Remove-PathSafe -Path $full }
                else { Remove-PathSafe -Path $full -File }
            }
        }
    }
}

# Firefox
$ffRoot = "$roam\Mozilla\Firefox\Profiles"
if (Test-Path -LiteralPath $ffRoot) {
    $ffTargets = @(
        'places.sqlite','places.sqlite-wal','places.sqlite-shm',
        'cookies.sqlite','cookies.sqlite-wal','cookies.sqlite-shm',
        'formhistory.sqlite','downloads.sqlite',
        'sessionstore.jsonlz4','sessionstore-backups',
        'cache2','startupCache','thumbnails','offlineCache',
        'storage\default','storage\temporary','webappsstore.sqlite'
    )
    Get-ChildItem -LiteralPath $ffRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        foreach ($t in $ffTargets) {
            $full = Join-Path $_.FullName $t
            if (Test-Path -LiteralPath $full) {
                if ((Get-Item -LiteralPath $full).PSIsContainer) { Remove-PathSafe -Path $full }
                else { Remove-PathSafe -Path $full -File }
            }
        }
    }
}

# ---------- 3) Windows sistem izleri ----------
Write-Step "Windows Temp / Prefetch / Recent / Jump Lists"

Clear-DirContents "$env:TEMP"
Clear-DirContents "$env:LOCALAPPDATA\Temp"
Clear-DirContents "$env:APPDATA\Microsoft\Windows\Recent"
Clear-DirContents "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations"
Clear-DirContents "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations"
Remove-PathSafe "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db"
Remove-PathSafe "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\iconcache_*.db"
Remove-PathSafe "$env:LOCALAPPDATA\IconCache.db"

if ($isAdmin) {
    Clear-DirContents "$env:SystemRoot\Temp"
    Clear-DirContents "$env:SystemRoot\Prefetch"
} else {
    Write-Warn "Admin degil, Prefetch ve C:\Windows\Temp atlaniyor"
}

# PowerShell / CMD history
Remove-PathSafe "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -File
# Not: cmd history RAM'de, zaten kalici degil

# ---------- 4) Registry MRU ----------
Write-Step "Registry gezinme/calistirma MRU"
$regPaths = @(
    'HKCU:\Software\Microsoft\Internet Explorer\TypedURLs',
    'HKCU:\Software\Microsoft\Internet Explorer\TypedURLsTime',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
)
foreach ($r in $regPaths) {
    if (Test-Path $r) {
        if ($DryRun) { Write-Done "DRYRUN reg del: $r" }
        else {
            try {
                Get-ChildItem -Path $r -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                Get-Item -Path $r -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty Property -ErrorAction SilentlyContinue |
                    ForEach-Object { Remove-ItemProperty -Path $r -Name $_ -ErrorAction SilentlyContinue }
                Write-Done "temizlendi: $r"
            } catch { Write-Done "atlandi: $r" }
        }
    }
}

# ---------- 5) Proje loglari ----------
Write-Step "Proje loglari (bypass/privacy/cache)"
# NOT: ai_strategy.json KORUNUR (kullanici istegi) - silme listesinde yok.
$projectTargets = @(
    'bypass.log','bypass.log.1','bypass.log.2','bypass.log.3','bypass.log.*',
    'privacy_sites.txt','privacy_sites_last100_analysis.txt',
    'strategy_cache.json','stats.json'
)
foreach ($pat in $projectTargets) {
    Get-ChildItem -LiteralPath $ProjectRoot -Filter $pat -File -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-PathSafe -Path $_.FullName -File }
}
# __pycache__ klasorleri
Get-ChildItem -LiteralPath $ProjectRoot -Directory -Recurse -Filter '__pycache__' -ErrorAction SilentlyContinue |
    ForEach-Object { Remove-PathSafe -Path $_.FullName }

# ---------- 6) Geri donusum kutusu ----------
Write-Step "Geri donusum kutusu"
if ($DryRun) { Write-Done "DRYRUN Clear-RecycleBin" }
else {
    try { Clear-RecycleBin -Force -ErrorAction Stop; Write-Done "bosaltildi" }
    catch { Write-Done "atlandi: $($_.Exception.Message)" }
}

# ---------- 7) (opsiyonel) Shadow copies ----------
if ($IncludeShadowCopies) {
    Write-Step "Shadow copies / System Restore points"
    if (-not $isAdmin) {
        Write-Warn "Admin degil, shadow copy temizlenemez"
    } elseif ($DryRun) {
        Write-Done "DRYRUN vssadmin delete shadows /all /quiet"
    } else {
        try {
            & vssadmin delete shadows /all /quiet | Out-Null
            Write-Done "shadow copies silindi"
        } catch { Write-Err $_.Exception.Message }
    }
}

$sw.Stop()
Write-Host ""
Write-Host "=== Bitti ($([int]$sw.Elapsed.TotalSeconds) sn) ===" -ForegroundColor Green
Write-Host ""
Write-Host "UNUTMA:" -ForegroundColor Yellow
Write-Host "  - ISS taraftaki metadata loglari BU SCRIPT ILE SILINMEZ (sizin kontrolunuzde degil)."
Write-Host "  - Derin temizlik icin: reboot + pagefile sifirlama + disk bos alan wipe (sdelete -z)."
Write-Host "  - Script'i tekrar calistirmak isterseniz, tarayicilar tekrar kapatilacak."

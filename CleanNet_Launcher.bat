@echo off

REM ==================== AUTO-ELEVATE TO ADMIN ====================
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

setlocal enabledelayedexpansion
chcp 65001 >nul 2>&1
title CleanNet - DPI Bypass Launcher
color 0A

REM ==================== LANGUAGE DETECTION ====================
set "LANG=en"

REM Check user locale (regional settings)
for /f "tokens=3" %%a in ('reg query "HKCU\Control Panel\International" /v LocaleName 2^>nul ^| find "LocaleName"') do set "LOCALE=%%a"

if defined LOCALE (
    echo !LOCALE! | find /i "tr" >nul 2>&1 && set "LANG=tr"
    echo !LOCALE! | find /i "de" >nul 2>&1 && set "LANG=de"
)

REM ==================== STRINGS ====================
if "!LANG!"=="tr" (
    set "STR_HEADER=      CleanNet - DPI Bypass Motoru"
    set "STR_KILL_ASK=[?] Calisan pythonw.exe islemleri kapatilsin mi? (E/H): "
    set "STR_KILL_YES=E"
    set "STR_KILL_DONE=[OK] pythonw islemleri kapatildi"
    set "STR_KILL_SKIP=[*] Mevcut islemler korunuyor"
    set "STR_PROXY_CLEAR=[OK] Eski proxy ayarlari temizlendi"
    set "STR_DEP_CHECK=[*] Bagimliliklar kontrol ediliyor..."
    set "STR_DEP_OK=[OK] Bagimliliklar kuruldu"
    set "STR_DEP_FAIL=[!] Bazi bagimliliklar kurulamadi"
    set "STR_STARTING=[*] DPI Bypass baslatiliyor..."
    set "STR_DASH_OPEN=[*] Dashboard aciliyor..."
    set "STR_RUNNING=  CleanNet DPI Bypass calisiyor."
    set "STR_PRESET_TITLE=[?] Proxy bypass on ayarlari:"
    set "STR_PRESET_1=    1 - Oyun (Gaming)"
    set "STR_PRESET_2=    2 - Streaming"
    set "STR_PRESET_3=    3 - Tumu"
    set "STR_PRESET_4=    4 - Hicbiri (sonradan dashboard'dan eklenebilir)"
    set "STR_PRESET_ASK=[?] Seciminiz (1/2/3/4): "
    set "STR_PRESET_DONE=[OK] Bypass ayarlari kaydedildi"
    set "STR_AUTO_ASK=[?] Windows baslangicina eklensin mi? (E/H): "
    set "STR_AUTO_YES=E"
    set "STR_AUTO_DONE=[OK] Baslangica eklendi"
    set "STR_AUTO_SKIP=[*] Baslangica eklenmedi"
) else if "!LANG!"=="de" (
    set "STR_HEADER=      CleanNet - DPI-Bypass-Engine"
    set "STR_KILL_ASK=[?] Laufende pythonw.exe-Prozesse beenden? (J/N): "
    set "STR_KILL_YES=J"
    set "STR_KILL_DONE=[OK] pythonw-Prozesse beendet"
    set "STR_KILL_SKIP=[*] Bestehende Prozesse beibehalten"
    set "STR_PROXY_CLEAR=[OK] Alte Proxy-Einstellungen entfernt"
    set "STR_DEP_CHECK=[*] Abhangigkeiten werden gepruft..."
    set "STR_DEP_OK=[OK] Abhangigkeiten installiert"
    set "STR_DEP_FAIL=[!] Einige Abhangigkeiten konnten nicht installiert werden"
    set "STR_STARTING=[*] DPI-Bypass wird gestartet..."
    set "STR_DASH_OPEN=[*] Dashboard wird geoeffnet..."
    set "STR_RUNNING=  CleanNet DPI-Bypass laeuft."
    set "STR_PRESET_TITLE=[?] Proxy-Bypass-Voreinstellungen:"
    set "STR_PRESET_1=    1 - Gaming"
    set "STR_PRESET_2=    2 - Streaming"
    set "STR_PRESET_3=    3 - Alle"
    set "STR_PRESET_4=    4 - Keine (spaeter ueber Dashboard aenderbar)"
    set "STR_PRESET_ASK=[?] Ihre Wahl (1/2/3/4): "
    set "STR_PRESET_DONE=[OK] Bypass-Einstellungen gespeichert"
    set "STR_AUTO_ASK=[?] Zum Windows-Autostart hinzufuegen? (J/N): "
    set "STR_AUTO_YES=J"
    set "STR_AUTO_DONE=[OK] Zum Autostart hinzugefuegt"
    set "STR_AUTO_SKIP=[*] Nicht zum Autostart hinzugefuegt"
) else (
    set "STR_HEADER=      CleanNet - DPI Bypass Engine"
    set "STR_KILL_ASK=[?] Kill running pythonw.exe processes? (Y/N): "
    set "STR_KILL_YES=Y"
    set "STR_KILL_DONE=[OK] pythonw processes killed"
    set "STR_KILL_SKIP=[*] Keeping existing processes"
    set "STR_PROXY_CLEAR=[OK] Old proxy settings cleared"
    set "STR_DEP_CHECK=[*] Checking dependencies..."
    set "STR_DEP_OK=[OK] Dependencies installed"
    set "STR_DEP_FAIL=[!] Some dependencies could not be installed"
    set "STR_STARTING=[*] Starting DPI Bypass..."
    set "STR_DASH_OPEN=[*] Opening dashboard..."
    set "STR_RUNNING=  CleanNet DPI Bypass is running."
    set "STR_PRESET_TITLE=[?] Proxy bypass presets:"
    set "STR_PRESET_1=    1 - Gaming"
    set "STR_PRESET_2=    2 - Streaming"
    set "STR_PRESET_3=    3 - All"
    set "STR_PRESET_4=    4 - None (can be added later from dashboard)"
    set "STR_PRESET_ASK=[?] Your choice (1/2/3/4): "
    set "STR_PRESET_DONE=[OK] Bypass settings saved"
    set "STR_AUTO_ASK=[?] Add to Windows startup? (Y/N): "
    set "STR_AUTO_YES=Y"
    set "STR_AUTO_DONE=[OK] Added to startup"
    set "STR_AUTO_SKIP=[*] Not added to startup"
)

REM ==================== START ====================
echo ========================================================
echo !STR_HEADER!
echo ========================================================
echo.

REM Clear old proxy settings
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul 2>&1
echo !STR_PROXY_CLEAR!

REM Enable UWP loopback access (required for Microsoft Store, Mail, etc. to work with local proxy)
CheckNetIsolation LoopbackExempt -a -p=S-1-15-2-1 >nul 2>&1

REM Check if pythonw.exe is running before asking
tasklist /fi "imagename eq pythonw.exe" 2>nul | find /i "pythonw.exe" >nul 2>&1
if !errorlevel! equ 0 (
    echo.
    set /p "KILL_CHOICE=!STR_KILL_ASK!"
    if /i "!KILL_CHOICE!"=="!STR_KILL_YES!" (
        taskkill /f /im pythonw.exe >nul 2>&1
        timeout /t 1 /nobreak >nul
        echo !STR_KILL_DONE!
    ) else (
        echo !STR_KILL_SKIP!
    )
)
echo.

REM Install dependencies
echo !STR_DEP_CHECK!
python -m pip install -r "%~dp0requirements.txt" --quiet >nul 2>&1
if !errorlevel! equ 0 (
    echo !STR_DEP_OK!
) else (
    echo !STR_DEP_FAIL!
)
echo.

REM ==================== FIRST RUN: PRESET SELECTION ====================
findstr /c:"proxy_bypass" "%~dp0config.json" >nul 2>&1
if !errorlevel! neq 0 (
    echo !STR_PRESET_TITLE!
    echo !STR_PRESET_1!
    echo !STR_PRESET_2!
    echo !STR_PRESET_3!
    echo !STR_PRESET_4!
    echo.
    set /p "PRESET_CHOICE=!STR_PRESET_ASK!"

    set "CFG_PATH=%~dp0config.json"
    set "CFG_PATH=!CFG_PATH:\=/!"

    set "GAMING_LIST='*.riotgames.com','*.leagueoflegends.com','*.pvp.net','*.riotcdn.net','*.lolesports.com','*.playvalorant.com','*.epicgames.com','*.epicgames.dev','*.unrealengine.com','*.fortnite.com','*.easyanticheat.net','*.steampowered.com','*.steamcommunity.com','*.steamcontent.com','*.steamstatic.com','*.valvesoftware.com','*.steamgames.com','*.ea.com','*.origin.com','*.dice.se','*.bioware.com','*.ubisoft.com','*.ubi.com','*.uplay.com','*.ubisoft.fr','*.ubisoft.org','*.ubisoft-dns.com','*.cdn.ubi.com','*.abtasty.com','*.akamaized.net','*.amazonaws.com','*.blizzard.com','*.battle.net','*.blizzard.cn','*.xbox.com','*.xboxlive.com','*.playfabapi.com','*.playfab.com','*.halowaypoint.com','*.playstation.com','*.playstation.net','*.playstationnetwork.com','*.sonyentertainmentnetwork.com','*.nintendo.com','*.nintendo.net','*.nintendo.co.jp','*.gog.com','*.cdprojektred.com','*.rockstargames.com','*.rsg.sc','*.bethesda.net','*.bethsoft.com','*.square-enix.com','*.square-enix-games.com','*.finalfantasyxiv.com','*.playonline.com','*.bandainamcoent.com','*.bandainamco.net','*.sega.com','*.wargaming.net','*.worldoftanks.com','*.worldoftanks.eu','*.worldofwarships.com','*.wg.gg','*.gaijin.net','*.warthunder.com','*.enlisted.net','*.garena.com','*.garena.sg','*.nexon.com','*.nexon.net','*.ncsoft.com','*.plaync.com','*.hoyoverse.com','*.mihoyo.com','*.genshinimpact.com','*.honkaiimpact3.com','*.kurogames.com','*.krafton.com','*.pubg.com','*.supercell.com','*.supercell.net','*.brawlstars.com','*.clashofclans.com','*.roblox.com','*.minecraft.net','*.mojang.com','*.minecraftservices.com','*.battleye.com','*.xigncode.com','*.nprotect.com','*.unity3d.com','*.photonengine.com','*.faceit.com','*.mod.io','*.nexusmods.com','*.akamaihd.net','*.cloudflare.com','*.fastly.net','*.cloudfront.net'"
    set "STREAMING_LIST='*.netflix.com','*.spotify.com','*.twitch.tv','*.akamaihd.net','*.cloudflare.com','*.fastly.net','*.cloudfront.net'"

    if "!PRESET_CHOICE!"=="1" (
        python -c "import json,sys;p=sys.argv[1];c=json.load(open(p,'r',encoding='utf-8'));c['proxy_bypass']=[!GAMING_LIST!];json.dump(c,open(p,'w',encoding='utf-8'),indent=4)" "!CFG_PATH!"
    ) else if "!PRESET_CHOICE!"=="2" (
        python -c "import json,sys;p=sys.argv[1];c=json.load(open(p,'r',encoding='utf-8'));c['proxy_bypass']=[!STREAMING_LIST!];json.dump(c,open(p,'w',encoding='utf-8'),indent=4)" "!CFG_PATH!"
    ) else if "!PRESET_CHOICE!"=="3" (
        python -c "import json,sys;p=sys.argv[1];c=json.load(open(p,'r',encoding='utf-8'));c['proxy_bypass']=[!GAMING_LIST!,'*.netflix.com','*.spotify.com','*.twitch.tv'];json.dump(c,open(p,'w',encoding='utf-8'),indent=4)" "!CFG_PATH!"
    ) else (
        python -c "import json,sys;p=sys.argv[1];c=json.load(open(p,'r',encoding='utf-8'));c['proxy_bypass']=[];json.dump(c,open(p,'w',encoding='utf-8'),indent=4)" "!CFG_PATH!"
    )
    echo !STR_PRESET_DONE!
    echo.
)

REM ==================== FIRST RUN: AUTOSTART ====================
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v CleanNetDPIBypass >nul 2>&1
if !errorlevel! neq 0 (
    set /p "AUTO_CHOICE=!STR_AUTO_ASK!"
    if /i "!AUTO_CHOICE!"=="!STR_AUTO_YES!" (
        for %%P in (pythonw.exe) do set "PW_PATH=%%~$PATH:P"
        if defined PW_PATH (
            reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v CleanNetDPIBypass /t REG_SZ /d "\"!PW_PATH!\" \"%~dp0bypass_silent.pyw\"" /f >nul 2>&1
            echo !STR_AUTO_DONE!
        ) else (
            echo [!] pythonw.exe not found in PATH
        )
    ) else (
        echo !STR_AUTO_SKIP!
    )
    echo.
)

REM ==================== START PROXY ====================
echo !STR_STARTING!
cd /d "%~dp0"
start /min "" pythonw bypass_silent.pyw

timeout /t 3 /nobreak >nul

echo [OK] Proxy: 127.0.0.1:8080
echo [OK] Dashboard: http://127.0.0.1:8888
echo.
echo !STR_DASH_OPEN!
timeout /t 2 /nobreak >nul
start http://127.0.0.1:8888

echo.
echo ========================================================
echo !STR_RUNNING!
echo   Dashboard: http://127.0.0.1:8888
echo   Log: bypass.log
echo ========================================================
echo.
timeout /t 5

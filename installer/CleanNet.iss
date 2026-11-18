#define MyAppName "CleanNet"
#define MyAppVersion "2.1.6"
#define MyAppPublisher "CleanNet"
#define MyAppURL "https://github.com/digaxie/CleanNet"
#define MyAppExeName "CleanNet.exe"

[Setup]
AppId={{8A6E54DF-A28B-49F8-8DFB-C1EA44E72000}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={localappdata}\Programs\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableDirPage=no
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=..\dist
OutputBaseFilename=CleanNet-{#MyAppVersion}-setup
SetupIconFile=..\assets\cleannet_app.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
VersionInfoVersion=2.1.6.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=CleanNet local proxy setup
VersionInfoProductName={#MyAppName}
LicenseFile=..\LICENSE
InfoBeforeFile=SETUP_INFO.txt
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "turkish"; MessagesFile: "compiler:Languages\Turkish.isl"
Name: "german"; MessagesFile: "compiler:Languages\German.isl"

[CustomMessages]
english.desktopicon=Create a desktop shortcut
turkish.desktopicon=Masaustunde kisayol olustur
german.desktopicon=Desktop-Verknuepfung erstellen
english.additionalshortcuts=Additional shortcuts:
turkish.additionalshortcuts=Ek kisayollar:
german.additionalshortcuts=Zusaetzliche Verknuepfungen:
english.launchCleanNet=Launch CleanNet
turkish.launchCleanNet=CleanNet'i baslat
german.launchCleanNet=CleanNet starten

[Tasks]
Name: "desktopicon"; Description: "{cm:desktopicon}"; GroupDescription: "{cm:additionalshortcuts}"; Flags: unchecked

[Dirs]
Name: "{localappdata}\CleanNet"

[Files]
Source: "..\dist\installer_app\CleanNet\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\PRIVACY.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\SECURITY.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\VERSION"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\CHANGELOG.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "SETUP_INFO.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "default-config.installed.json"; DestDir: "{localappdata}\CleanNet"; DestName: "config.json"; Flags: onlyifdoesntexist uninsneveruninstall

[Icons]
Name: "{group}\CleanNet"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\CleanNet README"; Filename: "{app}\README.md"
Name: "{autodesktop}\CleanNet"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:launchCleanNet}"; Flags: nowait postinstall skipifsilent unchecked; Check: not CleanNetWasRunning

[Code]
const
  InternetSettingsKey = 'Software\Microsoft\Windows\CurrentVersion\Internet Settings';
  RunKey = 'Software\Microsoft\Windows\CurrentVersion\Run';
  AutostartValue = 'CleanNetDPIBypass';

var
  WasRunning: Boolean;
  CleanupDone: Boolean;

function CleanNetWasRunning: Boolean;
begin
  Result := WasRunning;
end;

{ Stops the CleanNet that runs from ExePath (a portable copy elsewhere is left alone).
  Returns True when one was running. }
function StopCleanNet(const ExePath: String): Boolean;
var
  QuotedPath, Params: String;
  ResultCode: Integer;
begin
  Result := False;
  if not FileExists(ExePath) then
    exit;
  QuotedPath := ExePath;
  StringChangeEx(QuotedPath, '''', '''''', True);
  Params := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' +
    '$p = @(Get-Process -Name CleanNet -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq ''' + QuotedPath + ''' }); ' +
    'if ($p.Count -eq 0) { exit 0 }; ' +
    '$p | Stop-Process -Force -ErrorAction SilentlyContinue; ' +
    '$p | Wait-Process -Timeout 15 -ErrorAction SilentlyContinue; exit 10"';
  // Setup is 32-bit; the 32-bit PowerShell cannot read the path of a 64-bit process.
  if Exec(ExpandConstant('{sysnative}\WindowsPowerShell\v1.0\powershell.exe'), Params, '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode) then
    Result := ResultCode = 10;
end;

{ Runs the installed CleanNet with --cleanup or --restore-proxy and waits for it. }
function RunCleanNetCleanup(const Flag: String): Boolean;
var
  ResultCode: Integer;
begin
  Result := False;
  if FileExists(ExpandConstant('{app}\{#MyAppExeName}')) then
    Result := Exec(ExpandConstant('{app}\{#MyAppExeName}'), Flag, '', SW_HIDE,
      ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;

{ Last resort when the cleanup command could not run: switch off a proxy that still
  points at CleanNet. }
procedure DisableLeftoverProxy;
var
  ProxyServer: String;
  ProxyEnable: Cardinal;
begin
  if not RegQueryDWordValue(HKCU, InternetSettingsKey, 'ProxyEnable', ProxyEnable) then
    exit;
  if (ProxyEnable <> 0) and RegQueryStringValue(HKCU, InternetSettingsKey, 'ProxyServer', ProxyServer) then
    if CompareText(ProxyServer, '127.0.0.1:8080') = 0 then
      RegWriteDWordValue(HKCU, InternetSettingsKey, 'ProxyEnable', 0);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  { An upgrade must not replace files under a running CleanNet. It is started again
    after setup, and restores the proxy from its backup when it starts. }
  WasRunning := StopCleanNet(ExpandConstant('{app}\{#MyAppExeName}'));
  Result := '';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    if WasRunning then
      ExecAsOriginalUser(ExpandConstant('{app}\{#MyAppExeName}'), '', '', SW_SHOWNORMAL, ewNoWait, ResultCode)
    else
      { Also repairs a proxy that an older CleanNet uninstaller left pointing at CleanNet. }
      RunCleanNetCleanup('--restore-proxy');
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    { Before the files are removed: stop CleanNet, then let it restore the proxy the user
      had before and remove autostart. }
    StopCleanNet(ExpandConstant('{app}\{#MyAppExeName}'));
    CleanupDone := RunCleanNetCleanup('--cleanup');
  end;
  if CurUninstallStep = usPostUninstall then
  begin
    RegDeleteValue(HKCU, RunKey, AutostartValue);
    if not CleanupDone then
      DisableLeftoverProxy;
  end;
end;
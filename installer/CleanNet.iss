#define MyAppName "CleanNet"
#define MyAppVersion "2.1.2"
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
VersionInfoVersion=2.1.2.0
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
Source: "default-config.installed.json"; DestDir: "{localappdata}\CleanNet"; DestName: "config.json"; Flags: ignoreversion onlyifdoesntexist

[Icons]
Name: "{group}\CleanNet"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\CleanNet README"; Filename: "{app}\README.md"
Name: "{autodesktop}\CleanNet"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:launchCleanNet}"; Flags: nowait postinstall skipifsilent unchecked

[Code]
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ProxyServer: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    if RegQueryStringValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 'ProxyServer', ProxyServer) then
    begin
      if CompareText(ProxyServer, '127.0.0.1:8080') = 0 then
      begin
        RegWriteDWordValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 'ProxyEnable', 0);
        RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 'ProxyServer');
        RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 'ProxyOverride');
      end;
    end;
  end;
end;

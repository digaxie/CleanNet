$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$version = (Get-Content -LiteralPath (Join-Path $root "VERSION") -Raw).Trim()
$distRoot = Join-Path $root "dist"
$installerDistRoot = Join-Path $distRoot "installer_app"
$installerAppDir = Join-Path $installerDistRoot "CleanNet"
$exePath = Join-Path $installerAppDir "CleanNet.exe"
$issPath = Join-Path $root "installer\CleanNet.iss"
$setupPath = Join-Path $distRoot "CleanNet-$version-setup.exe"

function Find-InnoSetupCompiler {
    $cmd = Get-Command iscc.exe -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    $candidates = @(
        "${env:LOCALAPPDATA}\Programs\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles}\Inno Setup 6\ISCC.exe"
    )

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            return $candidate
        }
    }

    return $null
}

Push-Location $root
try {
    $pyFiles = @("bypass_silent.pyw") + (Get-ChildItem -LiteralPath (Join-Path $root "cleannet") -Filter "*.py" | ForEach-Object { $_.FullName })
    python -m py_compile @pyFiles
    Get-ChildItem -LiteralPath (Join-Path $root "cleannet") -Recurse -Directory -Filter "__pycache__" -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force
    Get-ChildItem -LiteralPath (Join-Path $root "cleannet") -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in @(".pyc", ".pyo") } |
        Remove-Item -Force

    $pyinstaller = python -m PyInstaller --version 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller is not installed. Run: python -m pip install pyinstaller --user"
    }

    $running = @(Get-CimInstance Win32_Process -Filter "name = 'CleanNet.exe'")
    foreach ($proc in $running) {
        Stop-Process -Id $proc.ProcessId -Force
    }
    Start-Sleep -Seconds 2

    $iconIco = Join-Path $root "assets\cleannet_app.ico"
    $iconPng = Join-Path $root "assets\cleannet_app.png"
    if (-not (Test-Path -LiteralPath $iconIco) -and (Test-Path -LiteralPath $iconPng)) {
        python -c "from PIL import Image; img=Image.open(r'$iconPng').convert('RGBA'); img.save(r'$iconIco', sizes=[(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)])"
    }

    if (Test-Path -LiteralPath $installerDistRoot) {
        Remove-Item -LiteralPath $installerDistRoot -Recurse -Force
    }

    $workPath = Join-Path $root "build\installer"
    $specPath = Join-Path $root "build\installer-spec"
    $cleannetData = "$(Join-Path $root 'cleannet');cleannet"
    $assetsData = "$(Join-Path $root 'assets');assets"
    $pyinstallerArgs = @(
        "--noconfirm",
        "--onedir",
        "--windowed",
        "--name", "CleanNet",
        "--distpath", $installerDistRoot,
        "--workpath", $workPath,
        "--specpath", $specPath,
        "--add-data", $cleannetData,
        "--add-data", $assetsData
    )
    if (Test-Path -LiteralPath $iconIco) {
        $pyinstallerArgs += @("--icon", $iconIco)
    }
    $pyinstallerArgs += @("bypass_silent.pyw")

    python -m PyInstaller @pyinstallerArgs

    if (-not (Test-Path -LiteralPath $exePath)) {
        throw "Installer app build did not create expected EXE: $exePath"
    }
    Get-ChildItem -LiteralPath $installerAppDir -Recurse -Directory -Filter "__pycache__" -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force
    Get-ChildItem -LiteralPath $installerAppDir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in @(".pyc", ".pyo") } |
        Remove-Item -Force

    if (-not (Test-Path -LiteralPath $issPath)) {
        throw "Missing installer script: $issPath"
    }

    $iscc = Find-InnoSetupCompiler
    if (-not $iscc) {
        throw "Inno Setup Compiler was not found. Install Inno Setup 6, then run this script again: https://jrsoftware.org/isdl.php"
    }

    & $iscc $issPath
    if ($LASTEXITCODE -ne 0) {
        throw "Inno Setup failed with exit code $LASTEXITCODE"
    }

    if (-not (Test-Path -LiteralPath $setupPath)) {
        throw "Installer build did not create expected file: $setupPath"
    }

    Write-Host "[OK] Installer: $setupPath"
} finally {
    Pop-Location
}

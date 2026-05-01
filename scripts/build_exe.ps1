$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
Push-Location $root
try {
    $pyFiles = @("bypass_silent.pyw") + (Get-ChildItem -LiteralPath (Join-Path $root "cleannet") -Filter "*.py" | ForEach-Object { $_.FullName })
    python -m py_compile @pyFiles
    .\run_tests.ps1

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
    $iconArgs = @()
    if (Test-Path -LiteralPath $iconIco) {
        $iconArgs = @("--icon", $iconIco)
    }

    python -m PyInstaller `
        --noconfirm `
        --onefile `
        --windowed `
        --name CleanNet `
        @iconArgs `
        --add-data "cleannet;cleannet" `
        --add-data "assets;assets" `
        bypass_silent.pyw

    Write-Host "[OK] EXE build: $(Join-Path $root 'dist\CleanNet.exe')"
} finally {
    Pop-Location
}

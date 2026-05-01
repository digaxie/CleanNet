$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$version = (Get-Content (Join-Path $root "VERSION") -Raw).Trim()
$distRoot = Join-Path $root "dist"
$outDir = Join-Path $distRoot "CleanNet-$version"
$zipPath = Join-Path $distRoot "CleanNet-$version-portable.zip"

Push-Location $root
try {
    $pyFiles = @("bypass_silent.pyw") + (Get-ChildItem -LiteralPath (Join-Path $root "cleannet") -Filter "*.py" | ForEach-Object { $_.FullName })
    python -m py_compile @pyFiles
    .\run_tests.ps1

    if (Test-Path $outDir) {
        Remove-Item -LiteralPath $outDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $outDir | Out-Null

    $files = @(
        "bypass_silent.pyw",
        "CleanNet_Launcher.bat",
        "CleanTraces.ps1",
        "requirements.txt",
        "config.json",
        "README.md",
        "PRIVACY.md",
        "SECURITY.md",
        "SECURITY_HARDENING.md",
        "LICENSE",
        "VERSION",
        "CHANGELOG.md",
        "RELEASE.md"
    )

    foreach ($file in $files) {
        Copy-Item -LiteralPath (Join-Path $root $file) -Destination (Join-Path $outDir $file) -Force
    }
    Copy-Item -LiteralPath (Join-Path $root "cleannet") -Destination (Join-Path $outDir "cleannet") -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $root "assets") -Destination (Join-Path $outDir "assets") -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $root "scripts") -Destination (Join-Path $outDir "scripts") -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $root "installer") -Destination (Join-Path $outDir "installer") -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $root "tests") -Destination (Join-Path $outDir "tests") -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $root "run_tests.ps1") -Destination (Join-Path $outDir "run_tests.ps1") -Force

    Get-ChildItem -LiteralPath $outDir -Recurse -Directory -Filter "__pycache__" |
        Remove-Item -Recurse -Force
    Get-ChildItem -LiteralPath $outDir -Recurse -File |
        Where-Object { $_.Extension -in @(".pyc", ".pyo") } |
        Remove-Item -Force

    if (Test-Path $zipPath) {
        Remove-Item -LiteralPath $zipPath -Force
    }
    Compress-Archive -Path (Join-Path $outDir "*") -DestinationPath $zipPath -Force

    Write-Host "[OK] Portable release: $zipPath"
} finally {
    Pop-Location
}

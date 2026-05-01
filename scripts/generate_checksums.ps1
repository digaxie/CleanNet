$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$distRoot = Join-Path $root "dist"
$checksumPath = Join-Path $distRoot "SHA256SUMS.txt"

if (-not (Test-Path -LiteralPath $distRoot)) {
    throw "Missing dist directory: $distRoot"
}

$targets = @(
    "CleanNet.exe",
    "CleanNet-2.1.0-portable.zip"
)

$lines = New-Object System.Collections.Generic.List[string]
foreach ($name in $targets) {
    $path = Join-Path $distRoot $name
    if (Test-Path -LiteralPath $path) {
        $hash = Get-FileHash -LiteralPath $path -Algorithm SHA256
        $lines.Add("$($hash.Hash.ToLowerInvariant())  $name")
    }
}

if ($lines.Count -eq 0) {
    throw "No release artifacts found in $distRoot"
}

$lines | Set-Content -LiteralPath $checksumPath -Encoding UTF8
Write-Host "[OK] Checksums: $checksumPath"

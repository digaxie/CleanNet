$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$version = (Get-Content -LiteralPath (Join-Path $root "VERSION") -Raw).Trim()
$distRoot = Join-Path $root "dist"
$outDir = Join-Path $distRoot "CleanNet-$version"
$zipPath = Join-Path $distRoot "CleanNet-$version-portable.zip"
$exePath = Join-Path $distRoot "CleanNet.exe"
$reportPath = Join-Path $distRoot "release_verification_report.txt"
$baseUrl = "http://127.0.0.1:8888"

$checks = New-Object System.Collections.Generic.List[object]
$scriptError = $null

function Add-Check {
    param(
        [string]$Name,
        [bool]$Passed,
        [string]$Detail = ""
    )
    $script:checks.Add([pscustomobject]@{
        Name = $Name
        Passed = $Passed
        Detail = $Detail
    }) | Out-Null
    if ($Passed) {
        Write-Host "[OK] $Name $Detail"
    } else {
        Write-Host "[FAIL] $Name $Detail"
    }
}

function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Action,
        [switch]$UseResultAsDetail
    )
    try {
        $result = & $Action
        $detail = if ($UseResultAsDetail -and $null -ne $result) { [string]$result } else { "" }
        Add-Check $Name $true $detail
    } catch {
        Add-Check $Name $false $_.Exception.Message
        throw
    }
}

function Stop-CleanNetProcesses {
    $pythonw = @(Get-CimInstance Win32_Process -Filter "name = 'pythonw.exe'" |
        Where-Object { $_.CommandLine -like "*bypass_silent.pyw*" })
    foreach ($proc in $pythonw) {
        Stop-Process -Id $proc.ProcessId -Force
    }

    $cleanNet = @(Get-CimInstance Win32_Process -Filter "name = 'CleanNet.exe'")
    foreach ($proc in $cleanNet) {
        Stop-Process -Id $proc.ProcessId -Force
    }
}

function Test-HttpEndpoint {
    param([string]$Path)
    $response = Invoke-WebRequest -Uri ($baseUrl + $Path) -UseBasicParsing -TimeoutSec 10
    if ($response.StatusCode -ne 200) {
        throw "$Path returned HTTP $($response.StatusCode)"
    }
    return $response.Content.Length
}

function Assert-ZipContents {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $zipPath))
    try {
        $entries = @($zip.Entries | ForEach-Object { $_.FullName -replace "\\", "/" })
        $required = @(
            "bypass_silent.pyw",
            "cleannet/bootstrap.py",
            "cleannet/settings.py",
            "cleannet/logging_setup.py",
            "cleannet/config_defaults.py",
            "cleannet/network_monitor.py",
            "cleannet/proxy_engine.py",
            "cleannet/dns_resolver.py",
            "assets/dashboard.html",
            "scripts/build_release.ps1",
            "scripts/build_exe.ps1",
            "scripts/verify_release.ps1",
            "scripts/generate_checksums.ps1",
            "tests/test_bootstrap.py",
            "tests/test_network_monitor.py",
            "tests/test_settings.py",
            "tests/test_logging_setup.py",
            "run_tests.ps1",
            "VERSION"
        )
        $missing = @($required | Where-Object { $_ -notin $entries })
        if ($missing.Count -gt 0) {
            throw "Missing ZIP entries: $($missing -join ', ')"
        }

        $bad = @($entries | Where-Object { $_ -match "(^|/)__pycache__(/|$)" -or $_ -match "\.(pyc|pyo)$" })
        if ($bad.Count -gt 0) {
            throw "Bytecode/cache entries in ZIP: $($bad -join ', ')"
        }

        $launcher = ($zip.Entries | Where-Object { ($_.FullName -replace "\\", "/") -eq "bypass_silent.pyw" })
        $reader = New-Object System.IO.StreamReader($launcher.Open())
        try {
            $launcherText = $reader.ReadToEnd()
        } finally {
            $reader.Dispose()
        }
        if ($launcherText -notmatch "from cleannet\.bootstrap import create_app" -or
            $launcherText -notmatch "create_app\(__file__\)") {
            throw "Launcher does not use create_app(__file__)"
        }
    } finally {
        $zip.Dispose()
    }
}

function Assert-PublicConfig {
    param([string]$ConfigPath)
    $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    $siteNames = @($config.sites.PSObject.Properties.Name)
    if ($siteNames.Count -ne 1 -or $siteNames[0] -ne "discord") {
        throw "Public config must contain only discord; found: $($siteNames -join ', ')"
    }
    if (-not $config.privacy.hide_dns -or -not $config.privacy.hide_sni) {
        throw "Public config must enable DNS/SNI privacy defaults"
    }
}

function Invoke-ExeSmoke {
    Stop-CleanNetProcesses
    Start-Sleep -Seconds 2

    try {
        $started = Start-Process -FilePath $exePath -WindowStyle Hidden -PassThru
        Start-Sleep -Seconds 10

        $statsBytes = Test-HttpEndpoint "/api/stats"
        $diagnosticsBytes = Test-HttpEndpoint "/api/diagnostics"
        $aiBytes = Test-HttpEndpoint "/api/ai-stats"
        $trainBytes = Test-HttpEndpoint "/api/train-status"
        $performanceBytes = Test-HttpEndpoint "/api/performance-settings"
        $flowsBytes = Test-HttpEndpoint "/api/network-flows"
        $strategyCatalogBytes = Test-HttpEndpoint "/api/strategy-catalog"

        $dashboard = Invoke-WebRequest -Uri $baseUrl -UseBasicParsing -TimeoutSec 10
        if ($dashboard.StatusCode -ne 200) {
            throw "Dashboard returned HTTP $($dashboard.StatusCode)"
        }
        if ($dashboard.Content -notmatch "v$version") {
            throw "Dashboard version marker v$version not found"
        }

        $processes = @(Get-CimInstance Win32_Process -Filter "name = 'CleanNet.exe'")
        if ($processes.Count -lt 1) {
            throw "CleanNet.exe process is not running after smoke test"
        }

        return "PID=$($started.Id); active=$($processes.ProcessId -join ','); stats=$statsBytes; diagnostics=$diagnosticsBytes; ai=$aiBytes; train=$trainBytes; performance=$performanceBytes; flows=$flowsBytes; strategy=$strategyCatalogBytes"
    } finally {
        Stop-CleanNetProcesses
        Start-Sleep -Seconds 2
    }
}

function Remove-GeneratedCaches {
    $workspace = (Resolve-Path -LiteralPath $root).Path
    $targets = @()
    $targets += Get-ChildItem -LiteralPath $root -Recurse -Directory -Filter "__pycache__"
    foreach ($path in @("build", "CleanNet.spec")) {
        $fullPath = Join-Path $root $path
        if (Test-Path -LiteralPath $fullPath) {
            $targets += Get-Item -LiteralPath $fullPath
        }
    }
    foreach ($item in $targets) {
        $full = (Resolve-Path -LiteralPath $item.FullName).Path
        if (-not $full.StartsWith($workspace, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to remove outside workspace: $full"
        }
        Remove-Item -LiteralPath $full -Recurse -Force
    }
}

Push-Location $root
try {
    Invoke-Step "Compile all Python files" {
        $pyFiles = @()
        $pyFiles += Join-Path $root "bypass_silent.pyw"
        $pyFiles += Get-ChildItem -LiteralPath (Join-Path $root "cleannet") -File -Filter "*.py" |
            ForEach-Object { $_.FullName }
        $pyFiles += Get-ChildItem -LiteralPath (Join-Path $root "tests") -File -Filter "*.py" |
            ForEach-Object { $_.FullName }
        python -m py_compile @pyFiles
    }

    Invoke-Step "Run unit tests" {
        .\run_tests.ps1
    }

    Invoke-Step "Validate public config" {
        Assert-PublicConfig (Join-Path $root "config.json")
    }

    Invoke-Step "Build portable ZIP" {
        powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_release.ps1
    }

    Invoke-Step "Validate portable ZIP contents" {
        if (-not (Test-Path -LiteralPath $zipPath)) {
            throw "Missing ZIP: $zipPath"
        }
        Assert-ZipContents
        Assert-PublicConfig (Join-Path $outDir "config.json")
    }

    Invoke-Step "Build PyInstaller EXE" {
        Stop-CleanNetProcesses
        Start-Sleep -Seconds 2
        powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_exe.ps1
        if (-not (Test-Path -LiteralPath $exePath)) {
            throw "Missing EXE: $exePath"
        }
    }

    Invoke-Step "Smoke test EXE dashboard and APIs" { Invoke-ExeSmoke } -UseResultAsDetail

    Invoke-Step "Clean generated caches" {
        Remove-GeneratedCaches
        $badBytecode = @(Get-ChildItem -LiteralPath $root -Recurse -File |
            Where-Object { $_.Extension -in @(".pyc", ".pyo") -and $_.FullName -notmatch "\\dist\\" })
        if ($badBytecode.Count -gt 0) {
            throw "Bytecode files remain: $($badBytecode.FullName -join ', ')"
        }
    }

    Invoke-Step "Generate release checksums" {
        powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\generate_checksums.ps1
    }
} catch {
    $scriptError = $_
    $currentFailures = @($checks | Where-Object { -not $_.Passed })
    if ($currentFailures.Count -eq 0) {
        Add-Check "Unexpected verification failure" $false $_.Exception.Message
    }
} finally {
    Stop-CleanNetProcesses
    Pop-Location
}

$failed = @($checks | Where-Object { -not $_.Passed })
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("CleanNet Release Verification")
$lines.Add("Version: $version")
$lines.Add("Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$lines.Add("ZIP: $zipPath")
$lines.Add("EXE: $exePath")
$lines.Add("")
foreach ($check in $checks) {
    $status = if ($check.Passed) { "OK" } else { "FAIL" }
    $detail = if ($check.Detail) { " - $($check.Detail)" } else { "" }
    $lines.Add("[$status] $($check.Name)$detail")
}
$lines.Add("")
$lines.Add("Result: $(if ($failed.Count -eq 0) { 'PASS' } else { 'FAIL' })")
New-Item -ItemType Directory -Path $distRoot -Force | Out-Null
$lines | Set-Content -LiteralPath $reportPath -Encoding UTF8

if ($failed.Count -gt 0) {
    throw "Release verification failed. See $reportPath"
}

if ($null -ne $scriptError) {
    throw "Release verification failed. See $reportPath"
}

Write-Host "[OK] Release verification passed: $reportPath"

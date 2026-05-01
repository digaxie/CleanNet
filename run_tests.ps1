$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root
try {
    $env:PYTHONDONTWRITEBYTECODE = "1"
    python -B -m unittest discover -s tests -p "test_*.py"
} finally {
    Pop-Location
}

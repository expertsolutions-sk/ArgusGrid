<#
.SYNOPSIS  Play the hybrid attack scenario against the running application (demo package only).
           It posts signed sensor events to the real ingestion API, so incidents appear on the map and in the
           incident list. The application must be running (start.bat) and the demo data must be loaded.
#>
[CmdletBinding()]
param(
    [double]$Speed = 10,
    [int]$Port = 8000,
    [switch]$Loop
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Backend = Join-Path $Root 'backend'
$Py = Join-Path $Root '.venv\Scripts\python.exe'
$Bootstrap = Join-Path $Root 'bootstrap.ps1'
if (Test-Path $Bootstrap) {
    . $Bootstrap
    if (-not (Test-Path $Py) -and (Test-Path (Get-EmbeddedPython $Root))) { $Py = Get-EmbeddedPython $Root }
}
if (-not (Test-Path $Py)) { throw 'The application is not set up. Run setup.bat first.' }
if (-not (Test-Path (Join-Path $Backend 'app\simulator'))) { throw 'This package has no simulator (production package).' }
$creds = Join-Path $Backend 'data\demo-devices.txt'
if (-not (Test-Path $creds)) { throw 'The demo data is not loaded (backend\data\demo-devices.txt is missing). Run: python -m app.tools.demo_data create' }

$url = "http://127.0.0.1:$Port"
try {
    $r = Invoke-RestMethod "$url/api/v1/health" -TimeoutSec 3
    if ($r.status -ne 'ok') { throw 'not ok' }
} catch {
    throw "The application does not answer on $url. Run start.bat first (or give -Port)."
}

$env:PYTHONDONTWRITEBYTECODE = '1'
$argList = @('-m', 'app.simulator', '--speed', [string]$Speed, '--base-url', $url)
if ($Loop) { $argList += '--loop' }
Write-Host "Open $url and follow the Operational map and Incidents. Press Ctrl+C to stop."
Push-Location $Backend
try {
    & $Py @argList
    exit $LASTEXITCODE
} finally { Pop-Location }

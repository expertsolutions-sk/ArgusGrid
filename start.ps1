<#
.SYNOPSIS  Start ArgusGrid (DEP-040): prepare the database, start the server, wait for it, open the browser.
#>
[CmdletBinding()]
param([switch]$NoBrowser, [int]$Port = 8000, [switch]$NoSimulator, [double]$SimulatorSpeed = 2)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Backend = Join-Path $Root 'backend'
$Py = Join-Path $Root '.venv\Scripts\python.exe'
$Bootstrap = Join-Path $Root 'bootstrap.ps1'
$ownDatabase = $false
if (Test-Path $Bootstrap) {
    . $Bootstrap
    if (-not (Test-Path $Py) -and (Test-Path (Get-EmbeddedPython $Root))) { $Py = Get-EmbeddedPython $Root }
    $ownDatabase = Test-BundledCluster $Root
}
$DataDir = Join-Path $Backend 'data'
$PidFile = Join-Path $DataDir 'server.pid'
if (-not (Test-Path $Py)) { throw 'The application is not set up. Run setup.bat first.' }

# configuration: backend\config\app.env (KEY=VALUE), already set environment variables win
$envFile = Join-Path $Backend 'config\app.env'
if (Test-Path $envFile) {
    foreach ($line in Get-Content $envFile) {
        if ($line -match '^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$' -and -not (Test-Path ('Env:' + $Matches[1]))) {
            Set-Item -Path ('Env:' + $Matches[1]) -Value $Matches[2]
        }
    }
}
$env:PYTHONDONTWRITEBYTECODE = '1'
$bind = if ($env:ARGUS_BIND_HOST) { $env:ARGUS_BIND_HOST } else { '127.0.0.1' }

if (Test-Path $PidFile) {
    $existing = [int](Get-Content $PidFile -Raw)
    if (Get-Process -Id $existing -ErrorAction SilentlyContinue) { throw "ArgusGrid already runs (process $existing). Use stop.bat first." }
    Remove-Item $PidFile -Force
}

if ($ownDatabase) {
    # the PostgreSQL cluster that setup installed into this folder (runtime\pgdata)
    Start-Cluster $Root
}

Push-Location $Backend
try {
    & $Py -m app.tools.prepare_database
    if ($LASTEXITCODE -ne 0) { throw 'preparing the database failed' }
} finally { Pop-Location }

$logDir = Join-Path $DataDir 'logs'
New-Item -ItemType Directory -Force $logDir | Out-Null
$server = Start-Process -FilePath $Py -WorkingDirectory $Backend -WindowStyle Hidden -PassThru `
    -ArgumentList @('-m', 'uvicorn', 'app.main:app_factory', '--factory', '--host', $bind, '--port', $Port) `
    -RedirectStandardOutput (Join-Path $logDir 'server.out.log') -RedirectStandardError (Join-Path $logDir 'server.err.log')
[System.IO.File]::WriteAllText($PidFile, [string]$server.Id)

$url = "http://${bind}:$Port"
$ready = $false
for ($i = 0; $i -lt 60; $i++) {
    if ($server.HasExited) { break }
    try {
        $r = Invoke-RestMethod "$url/api/v1/health" -TimeoutSec 2
        if ($r.status -eq 'ok') { $ready = $true; break }
    } catch { Start-Sleep -Milliseconds 500 }
}
if (-not $ready) {
    Write-Host 'The server did not become ready. See backend\data\logs\server.err.log'
    exit 1
}
Write-Host "ArgusGrid is running: $url   (process $($server.Id))"

# demo package: keep the attack simulator running, so incidents are being generated when the operator signs in.
# It plays the scenario in a loop against the real ingestion API; stop.bat ends it with the application.
$simDir = Join-Path $Backend 'app\simulator'
$simCreds = Join-Path $DataDir 'demo-devices.txt'
$SimPidFile = Join-Path $DataDir 'simulator.pid'
if (-not $NoSimulator -and (Test-Path $simDir)) {
    if (-not (Test-Path $simCreds)) {
        Write-Host 'Simulator not started: the demo data is not loaded (backend\data\demo-devices.txt is missing).'
    } else {
        $sim = Start-Process -FilePath $Py -WorkingDirectory $Backend -WindowStyle Hidden -PassThru `
            -ArgumentList @('-m', 'app.simulator', '--loop', '--speed', [string]$SimulatorSpeed, '--base-url', $url) `
            -RedirectStandardOutput (Join-Path $logDir 'simulator.out.log') -RedirectStandardError (Join-Path $logDir 'simulator.err.log')
        [System.IO.File]::WriteAllText($SimPidFile, [string]$sim.Id)
        Write-Host "Attack simulator is running (process $($sim.Id), speed x$SimulatorSpeed, repeats). Use -NoSimulator to skip it."
    }
}
if (-not $NoBrowser) { Start-Process $url }

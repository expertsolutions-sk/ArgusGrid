<#
.SYNOPSIS  Stop ArgusGrid (DEP-041): only the process this package started, found by its recorded process id and
           checked by its command line. An external database server is never touched. The PostgreSQL cluster that
           the setup installed into this folder (runtime\pgdata, demo package) is stopped after the application;
           -KeepDatabase leaves it running.
#>
[CmdletBinding()]
param([switch]$KeepDatabase)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$PidFile = Join-Path $Root 'backend\data\server.pid'
$exitCode = 0

# the attack simulator of the demo package, found by its recorded id and checked by its command line
$SimPidFile = Join-Path $Root 'backend\data\simulator.pid'
if (Test-Path $SimPidFile) {
    $sid = [int](Get-Content $SimPidFile -Raw)
    $sim = Get-CimInstance Win32_Process -Filter "ProcessId = $sid" -ErrorAction SilentlyContinue
    if ($sim -and $sim.CommandLine -like '*app.simulator*' -and $sim.CommandLine -like ('*' + $Root + '*')) {
        & taskkill.exe /PID $sid /T /F | Out-Null
        Write-Host "Attack simulator stopped (process $sid)."
    }
    Remove-Item $SimPidFile -Force
}

if (-not (Test-Path $PidFile)) {
    Write-Host 'ArgusGrid is not running (no process file).'
} else {
    $id = [int](Get-Content $PidFile -Raw)
    $proc = Get-CimInstance Win32_Process -Filter "ProcessId = $id" -ErrorAction SilentlyContinue
    if (-not $proc) {
        Remove-Item $PidFile -Force
        Write-Host 'ArgusGrid was not running; the stale process file was removed.'
    } elseif ($proc.CommandLine -notlike '*app.main:app_factory*' -or $proc.CommandLine -notlike ('*' + $Root + '*')) {
        # narrow filter: our server module AND our own folder in the command line
        Write-Host "Process $id is not the ArgusGrid server of this folder. Nothing was stopped."
        $exitCode = 1
    } else {
        Stop-Process -Id $id -Force
        Remove-Item $PidFile -Force
        Write-Host "ArgusGrid stopped (process $id)."
    }
}

$Bootstrap = Join-Path $Root 'bootstrap.ps1'
if ($exitCode -eq 0 -and -not $KeepDatabase -and (Test-Path $Bootstrap)) {
    . $Bootstrap
    if (Test-BundledCluster $Root) {
        if (Stop-Cluster $Root) { Write-Host 'The bundled PostgreSQL of this folder was stopped.' }
    }
}
exit $exitCode

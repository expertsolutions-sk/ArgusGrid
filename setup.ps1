<#
.SYNOPSIS
  ArgusGrid setup (DEP-030 to DEP-035). Checks prerequisites, installs the runtime into .venv, prepares the
  database and creates the initial administrator with a random password.

.PARAMETER CheckOnly   Report only, change nothing.
.PARAMETER DryRun      Show what would be done, change nothing.
.PARAMETER AssumeYes   Unattended: no questions (the database URL must then be given).
.PARAMETER WithDemo    Load the fictional demonstration site (only offered by the demo package).
.PARAMETER DatabaseUrl PostgreSQL 16 URL of an existing, empty database, for example
                       postgresql+psycopg://argusgrid:<password>@localhost:5432/argusgrid
.PARAMETER EmbeddedPython  Demo package: use the downloaded embedded Python even when Python 3.12 is installed.
.PARAMETER LocalCache  Demo package: folder that already holds the pinned downloads (offline install). The
                       same SHA-256 check applies.

.PARAMETER Ask         Demo package: ask the questions (the default there is to act without questions).
.PARAMETER NoDemo      Demo package: do not load the demonstration site.
.PARAMETER NoStart     Demo package: do not start the application after the setup.
.PARAMETER NoBrowser   Demo package: start, but do not open the browser.
.PARAMETER Port        Demo package: port of the application (default 8000).

  Demo package (bootstrap.ps1 present) acts on its own, without questions: it installs what is missing
  (embedded Python, a PostgreSQL 16 cluster that belongs to this folder in runtime\pgsql and runtime\pgdata,
  127.0.0.1 only, and the Microsoft C++ runtime when Windows lacks it), loads the demonstration site, starts the
  application and opens the browser. Files come from fixed addresses and are checked against pinned SHA-256
  values (the C++ runtime by its Microsoft signature). Windows asks once for approval when that runtime is
  installed; nothing else needs administrator rights.

  After a fully successful setup this script and setup.bat delete themselves. Download the package again to run
  the setup once more. Nothing is deleted after a failed or partial run, -CheckOnly or -DryRun.
#>
[CmdletBinding()]
param(
    [switch]$CheckOnly,
    [switch]$DryRun,
    [switch]$AssumeYes,
    [switch]$WithDemo,
    [switch]$EmbeddedPython,
    [switch]$Ask,
    [switch]$NoDemo,
    [switch]$NoStart,
    [switch]$NoBrowser,
    [int]$Port = 8000,
    [string]$LocalCache = '',
    [string]$DatabaseUrl = ''
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Backend = Join-Path $Root 'backend'
$Venv = Join-Path $Root '.venv'
$VenvPy = Join-Path $Venv 'Scripts\python.exe'
$DataDir = Join-Path $Backend 'data'
$ConfigDir = Join-Path $Backend 'config'
$Marker = Join-Path $Root '.setup-done'
$blockers = New-Object System.Collections.Generic.List[string]

function Say([string]$text) { Write-Host $text }
function Step([string]$text) { Write-Host ('  - ' + $text) }

# -- prerequisites ------------------------------------------------------------------------------------
Say 'ArgusGrid setup'
Say ''
$Bootstrap = Join-Path $Root 'bootstrap.ps1'
$canBootstrap = Test-Path $Bootstrap
if ($canBootstrap) { . $Bootstrap }
# self-acting: the demo package asks nothing unless -Ask is given; the plan is printed before it runs
if ($canBootstrap -and -not $Ask) {
    $AssumeYes = $true
    if (-not $NoDemo -and (Test-Path (Join-Path $Backend 'app\tools\demo_data.py'))) { $WithDemo = $true }
}
if ($LocalCache) { $LocalCache = [System.IO.Path]::GetFullPath($LocalCache) }
$python = $null
$candidates = if ($EmbeddedPython) { @() } else { @(@('py', '-3.12'), @('python'), @('python3')) }
foreach ($candidate in $candidates) {
    try {
        $exe = $candidate[0]
        $extra = @($candidate | Select-Object -Skip 1)
        # one number, no quotes inside the code (Windows PowerShell 5.1 mangles embedded quotes): 312 = 3.12
        $code = & $exe @extra -c 'import sys; print(sys.version_info[0] * 100 + sys.version_info[1])' 2>$null
        if ($LASTEXITCODE -eq 0 -and "$code" -match '^\d+$' -and [int]"$code" -ge 312) {
            $python = @{ Exe = $exe; Args = $extra; Version = ('{0}.{1}' -f [math]::Floor([int]"$code" / 100), ([int]"$code" % 100)) }
            break
        }
    } catch { }
}
$useEmbedded = $false
if ($python) { Step ('Python ' + $python.Version + ' found') }
elseif ($canBootstrap) { $useEmbedded = $true; Step 'Python 3.12 or newer: the embedded Python will be downloaded into runtime\python' }
else { Step 'Python 3.12 or newer: MISSING'; $blockers.Add('Install Python 3.12 or newer from python.org and run setup again.') }

if (-not $DatabaseUrl) { $DatabaseUrl = $env:ARGUS_DATABASE_URL }
$urlFile = Join-Path $DataDir 'database.url'
if (-not $DatabaseUrl -and (Test-Path $urlFile)) { $DatabaseUrl = (Get-Content $urlFile -Raw).Trim() }
$bundled = $false
if (-not $DatabaseUrl -and $canBootstrap) {
    $bundled = $true
    if (-not $CheckOnly -and -not $DryRun -and -not $AssumeYes) {
        Say ''
        Say 'No database was given. This package can install its own PostgreSQL 16 (about 311 MB download, kept in runtime\,'
        Say 'listening on 127.0.0.1 only). Answer n to use an existing PostgreSQL 16 database instead.'
        $answer = Read-Host 'Install the bundled PostgreSQL? (Y/n)'
        if ($answer -match '^(n|no|nie)$') { $bundled = $false }
    }
}
if (-not $DatabaseUrl -and -not $bundled -and -not $CheckOnly -and -not $DryRun -and -not $AssumeYes) {
    Say ''
    Say 'PostgreSQL 16 is required. Create an empty database and a role for it first, then enter the URL.'
    Say 'Example: postgresql+psycopg://argusgrid:<password>@localhost:5432/argusgrid'
    $DatabaseUrl = (Read-Host 'Database URL').Trim()
}
if ($DatabaseUrl -match '^postgresql(\+psycopg)?://') { Step 'Database URL given' }
elseif ($bundled) { Step 'Database: the bundled PostgreSQL 16 will be installed into runtime\pgsql (127.0.0.1 only)' }
else { Step 'Database URL: MISSING or not a PostgreSQL URL'; $blockers.Add('Provide -DatabaseUrl (PostgreSQL 16, existing empty database).') }
if ($DatabaseUrl -match '^postgresql://') { $DatabaseUrl = $DatabaseUrl -replace '^postgresql://', 'postgresql+psycopg://' }

if ($canBootstrap) {
    $needed = @()
    if ($useEmbedded) { $needed += 'python', 'pip' }
    if ($bundled -and -not (Test-Path (Join-Path (Get-PgBin $Root) 'postgres.exe'))) { $needed += 'postgres' }
    foreach ($key in $needed) {
        if (Test-PinnedAvailable $Root $key $LocalCache) { Step ('download source reachable or cached: ' + $script:Pins[$key].File) }
        else { Step ('not available: ' + $script:Pins[$key].File); $blockers.Add('Cannot reach ' + $script:Pins[$key].Url + ' and the file is not in runtime\cache or -LocalCache. Put the file there and run setup again.') }
    }
    if ($needed.Count -gt 0) {
        $free = Get-FreeMb $Root
        if ($free -lt $script:MinFreeMb) { Step ("free disk space: $free MB (needs $($script:MinFreeMb) MB)"); $blockers.Add("Free at least $($script:MinFreeMb) MB on the drive of this folder and run setup again.") }
        else { Step ("free disk space: $free MB") }
    }
    $needsVc = $bundled -and -not (Test-VcRuntime)
    if ($needsVc) { Step 'Microsoft Visual C++ runtime: missing, it will be downloaded and installed (Windows asks once for approval)' }
}

if ($WithDemo -and -not (Test-Path (Join-Path $Backend 'app\tools\demo_data.py'))) { $blockers.Add('-WithDemo: this package has no demonstration data (production package).') }
if (-not (Test-Path (Join-Path $Backend 'app\main.py'))) { $blockers.Add('backend\app is missing: the package is incomplete.') }
if (-not (Test-Path (Join-Path $Root 'frontend\dist\index.html'))) { $blockers.Add('frontend\dist is missing: the package is incomplete.') }

Say ''
if ($blockers.Count -gt 0) {
    Say 'Blocking problems:'
    $blockers | ForEach-Object { Say ('  * ' + $_) }
    if ($CheckOnly -or $DryRun) { exit 1 }
    exit 1
}
if ($CheckOnly) { Say 'Check finished: all prerequisites are present.'; exit 0 }

# -- plan ---------------------------------------------------------------------------------------------
$plan = @()
if ($useEmbedded) {
    $VenvPy = Get-EmbeddedPython $Root
    $plan += 'download the embedded Python 3.12 and pip, check SHA-256, unpack into runtime\python'
} else {
    $pyDisplay = ($python.Exe + ' ' + ($python.Args -join ' ')).Trim()
    $plan += "$pyDisplay -m venv `"$Venv`""
}
$plan += "`"$VenvPy`" -m pip install --disable-pip-version-check -r backend\requirements.txt   (from the Python package index)"
if ($bundled) {
    if ($needsVc) { $plan += 'download the Microsoft Visual C++ runtime (about 25 MB), check the Microsoft signature, install it (one Windows approval)' }
    $plan += 'download PostgreSQL 16 (about 311 MB), check SHA-256, unpack bin, lib and share into runtime\pgsql'
    $plan += 'create the cluster runtime\pgdata (127.0.0.1, free port from 54340), an application role and an empty database'
}
$plan += 'write backend\data\database.url (database URL, not shown again)'
$plan += 'write backend\config\app.env if missing (production defaults)'
$plan += "`"$VenvPy`" -m app.tools.prepare_database   (schema, roles, initial administrator)"
if ($WithDemo) { $plan += "`"$VenvPy`" -m app.tools.demo_data create   (fictional demonstration site)" }
if ($canBootstrap -and -not $NoStart) { $plan += "start the application on http://127.0.0.1:$Port" + $(if ($NoBrowser) { '' } else { ' and open the browser' }) }
Say 'Plan:'
$plan | ForEach-Object { Step $_ }
if ($DryRun) { Say ''; Say 'Dry run: nothing was changed.'; exit 0 }
if (-not $AssumeYes) {
    $answer = Read-Host 'Continue? (y/N)'
    if ($answer -notmatch '^(y|yes|a|ano)$') { Say 'Cancelled. Nothing was changed.'; exit 1 }
}

# -- run ----------------------------------------------------------------------------------------------
try {
    if ($useEmbedded) {
        $VenvPy = Install-EmbeddedPython $Root $LocalCache
    } elseif (-not (Test-Path $VenvPy)) {
        & $python.Exe @($python.Args) -m venv $Venv
        if ($LASTEXITCODE -ne 0) { throw 'creating the virtual environment failed' }
    }
    & $VenvPy -m pip install --disable-pip-version-check --no-warn-script-location -r (Join-Path $Backend 'requirements.txt')
    if ($LASTEXITCODE -ne 0) { throw 'installing the requirements failed' }

    New-Item -ItemType Directory -Force $DataDir, $ConfigDir | Out-Null
    if ($bundled) {
        Install-Postgres $Root $LocalCache | Out-Null
        if (Test-Path $urlFile) {
            # repeated run: the cluster and its URL already exist
            if (-not (Test-BundledCluster $Root)) { throw 'backend\data\database.url exists but runtime\pgdata does not; delete the file to start over' }
            Start-Cluster $Root
        } else {
            $DatabaseUrl = Initialize-Cluster $Root
        }
    } elseif ($canBootstrap -and (Test-BundledCluster $Root)) {
        Start-Cluster $Root   # a repeated run: the bundled cluster of this folder may be stopped
    }
    if (-not (Test-Path $urlFile)) {
        [System.IO.File]::WriteAllText($urlFile, $DatabaseUrl)
        # only the current user may read the file with the database password
        & icacls $urlFile /inheritance:r /grant:r ($env:USERNAME + ':(R,W)') | Out-Null
    }
    $envFile = Join-Path $ConfigDir 'app.env'
    if (-not (Test-Path $envFile)) { Copy-Item (Join-Path $Root 'backend\config\app.env.template') $envFile }

    $env:PYTHONDONTWRITEBYTECODE = '1'
    Push-Location $Backend
    try {
        & $VenvPy -m app.tools.prepare_database
        if ($LASTEXITCODE -ne 0) { throw 'preparing the database failed' }
        if ($WithDemo) {
            & $VenvPy -m app.tools.demo_data create
            if ($LASTEXITCODE -ne 0) { throw 'loading the demonstration data failed' }
        }
    } finally { Pop-Location }
} catch {
    Say ''
    Say ('Setup FAILED: ' + $_.Exception.Message)
    Say 'Nothing was deleted. Fix the problem and run setup again; it is safe to repeat (DEP-035).'
    exit 1
}

Say ''
Say 'Setup finished.'
Say ('The initial administrator (sysadmin) and the generated password are in ' + (Join-Path $DataDir 'accounts.txt'))
Say 'The password must be changed at the first login. Move the file out of the folder after you have read it.'
Say 'This setup script now removes itself (to run it again, download the package again).'
if ($canBootstrap -and -not $NoStart) {
    # a failure to start does not undo the setup: start.bat can be run again
    try {
        $startArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $Root 'start.ps1'), '-Port', [string]$Port)
        if ($NoBrowser) { $startArgs += '-NoBrowser' }
        & powershell @startArgs
        if ($LASTEXITCODE -ne 0) { Say 'The application did not start. Run start.bat to try again.' }
    } catch { Say ('The application did not start (' + $_.Exception.Message + '). Run start.bat to try again.') }
} else {
    Say 'Start the application with start.bat.'
}

# -- self removal (D-13): the marker lets setup.bat remove itself as its last step ----------------------
[System.IO.File]::WriteAllText($Marker, 'ok')
Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force
exit 0

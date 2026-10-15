<#
.SYNOPSIS
  ArgusGrid runtime tools (AG-D-70, demo package only). Pinned downloads, an embedded Python and a bundled
  PostgreSQL 16 cluster that belongs to this folder. Dot-sourced by setup.ps1, start.ps1 and stop.ps1.

  Every download is a fixed https address on a short host list and is checked against a SHA-256 value that is
  written in this file. A file that does not match is deleted and the setup stops. Files may also be put in
  runtime\cache (or the folder given with -LocalCache) in advance: the same check applies, no network is needed.
#>

$script:Pins = [ordered]@{
    python   = @{ File = 'python-3.12.10-embed-amd64.zip'; SizeMb = 11
                  Url = 'https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip'
                  Sha256 = '4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3' }
    pip      = @{ File = 'pip-26.2.1-py3-none-any.whl'; SizeMb = 2
                  Url = 'https://files.pythonhosted.org/packages/f3/6e/1736e5b4ae2b778ef2f81c47d797de9f891d4d8acb047a24ca37a60294dd/pip-26.2.1-py3-none-any.whl'
                  Sha256 = '71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e' }
    postgres = @{ File = 'postgresql-16.13-1-windows-x64-binaries.zip'; SizeMb = 311
                  Url = 'https://get.enterprisedb.com/postgresql/postgresql-16.13-1-windows-x64-binaries.zip'
                  Sha256 = '9b4c7a1bc31147b5b2ba59178d0eef86c16181d54a20177192b387dff20f00a9' }
}
$script:AllowedHosts = @('www.python.org', 'files.pythonhosted.org', 'get.enterprisedb.com')
# The Microsoft C++ runtime has a moving address and no fixed checksum, so it is accepted by its signature.
$script:VcRedist = @{ File = 'vc_redist.x64.exe'; SizeMb = 25; Url = 'https://aka.ms/vs/17/release/vc_redist.x64.exe' }
$script:MinFreeMb = 1500
$script:FirstPort = 54340
$script:LastPort = 54399

function Get-RuntimeDir([string]$Root) { Join-Path $Root 'runtime' }
function Get-EmbeddedPython([string]$Root) { Join-Path (Get-RuntimeDir $Root) 'python\python.exe' }
function Get-PgBin([string]$Root) { Join-Path (Get-RuntimeDir $Root) 'pgsql\bin' }
function Get-PgData([string]$Root) { Join-Path (Get-RuntimeDir $Root) 'pgdata' }
function Test-BundledCluster([string]$Root) { Test-Path (Join-Path (Get-PgData $Root) 'PG_VERSION') }

function Test-Sha256([string]$Path, [string]$Expected) {
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    return ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower() -eq $Expected.ToLower())
}

function New-RandomText([int]$Length = 32) {
    $chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    $bytes = New-Object byte[] $Length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
}

function Protect-File([string]$Path) {
    & icacls $Path /inheritance:r /grant:r ($env:USERNAME + ':(R,W)') | Out-Null
}

# Downloads one address to a file: the system proxy with the current user's credentials, three attempts.
function Receive-File([string]$Url, [string]$Destination) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        if (Test-Path -LiteralPath $Destination) { Remove-Item -LiteralPath $Destination -Force }
        $client = New-Object System.Net.WebClient
        try {
            $client.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
            $client.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
            $client.DownloadFile($Url, $Destination)
            return
        } catch {
            if ($attempt -eq 3) { throw ("download failed: " + $Url + " (" + $_.Exception.Message + ")") }
            Write-Host ('  attempt ' + $attempt + ' failed, retrying in ' + (5 * $attempt) + ' s')
            Start-Sleep -Seconds (5 * $attempt)
        } finally { $client.Dispose() }
    }
}

# Free space on the drive that holds the package folder, in MB.
function Get-FreeMb([string]$Root) {
    $drive = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($Root))
    return [int]((New-Object System.IO.DriveInfo($drive)).AvailableFreeSpace / 1MB)
}

# The runtime the PostgreSQL binaries need (the embedded Python only carries vcruntime140, not msvcp140).
function Test-VcRuntime {
    $sys = Join-Path $env:WINDIR 'System32'
    return ((Test-Path (Join-Path $sys 'vcruntime140.dll')) -and (Test-Path (Join-Path $sys 'msvcp140.dll')))
}

# Downloads Microsoft's installer and returns its path only when the signature is valid and Microsoft's.
function Get-VcRedist([string]$Root) {
    $cache = Join-Path (Get-RuntimeDir $Root) 'cache'
    New-Item -ItemType Directory -Force $cache | Out-Null
    $dest = Join-Path $cache $script:VcRedist.File
    Write-Host ('  downloading ' + $script:VcRedist.File + ' (about ' + $script:VcRedist.SizeMb + ' MB) from aka.ms')
    Receive-File $script:VcRedist.Url $dest
    $sig = Get-AuthenticodeSignature -LiteralPath $dest
    if ($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        Remove-Item -LiteralPath $dest -Force
        throw 'the downloaded Visual C++ runtime installer is not validly signed by Microsoft; it was deleted'
    }
    return $dest
}

# Needs administrator approval (one UAC prompt). 1638 = a newer version is present, 3010 = restart advised.
function Install-VcRuntime([string]$Root) {
    if (Test-VcRuntime) { return }
    $exe = Get-VcRedist $Root
    Write-Host '  installing the Microsoft Visual C++ runtime (approve the Windows prompt)'
    $p = Start-Process -FilePath $exe -ArgumentList @('/install', '/quiet', '/norestart') -Verb RunAs -PassThru
    $null = $p.Handle
    $p.WaitForExit()
    if (@(0, 1638, 3010) -notcontains $p.ExitCode) { throw ('the Visual C++ runtime installer failed (exit ' + $p.ExitCode + ')') }
    if (-not (Test-VcRuntime)) { throw 'the Visual C++ runtime is still missing; restart Windows and run setup again' }
}

# Returns the path of a verified file. Order: runtime\cache, -LocalCache folder, download.
function Get-PinnedFile([string]$Root, [string]$Key, [string]$LocalCache = '') {
    $pin = $script:Pins[$Key]
    if (-not $pin) { throw "unknown tool: $Key" }
    if ($pin.Sha256 -notmatch '^[0-9a-f]{64}$') { throw "the checksum of $($pin.File) is not set in bootstrap.ps1" }
    $cache = Join-Path (Get-RuntimeDir $Root) 'cache'
    New-Item -ItemType Directory -Force $cache | Out-Null
    $dest = Join-Path $cache $pin.File
    if (Test-Sha256 $dest $pin.Sha256) { return $dest }
    if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Force }
    if ($LocalCache) {
        $local = Join-Path $LocalCache $pin.File
        if (Test-Sha256 $local $pin.Sha256) { Copy-Item -LiteralPath $local -Destination $dest; return $dest }
    }
    $uri = [System.Uri]$pin.Url
    if ($uri.Scheme -ne 'https' -or $script:AllowedHosts -notcontains $uri.Host) { throw "address not allowed: $($pin.Url)" }
    Write-Host ('  downloading ' + $pin.File + ' (about ' + $pin.SizeMb + ' MB) from ' + $uri.Host)
    $part = $dest + '.part'
    Receive-File $pin.Url $part
    if (-not (Test-Sha256 $part $pin.Sha256)) {
        Remove-Item -LiteralPath $part -Force
        throw "the checksum of $($pin.File) does not match the value pinned in this package; the file was deleted"
    }
    Move-Item -LiteralPath $part -Destination $dest
    return $dest
}

# Reports whether a pinned file can be had without asking anything: cache, local cache or a reachable address.
function Test-PinnedAvailable([string]$Root, [string]$Key, [string]$LocalCache = '') {
    $pin = $script:Pins[$Key]
    $cached = Join-Path (Join-Path (Get-RuntimeDir $Root) 'cache') $pin.File
    if (Test-Sha256 $cached $pin.Sha256) { return $true }
    if ($LocalCache -and (Test-Sha256 (Join-Path $LocalCache $pin.File) $pin.Sha256)) { return $true }
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $req = [System.Net.WebRequest]::Create($pin.Url)
        $req.Method = 'HEAD'
        $req.Timeout = 15000
        $resp = $req.GetResponse()
        $resp.Close()
        return $true
    } catch { return $false }
}

function Install-EmbeddedPython([string]$Root, [string]$LocalCache = '') {
    $py = Get-EmbeddedPython $Root
    if (Test-Path $py) {
        & $py -m pip --version *> $null
        if ($LASTEXITCODE -eq 0) { return $py }   # a repeated run; a half-installed one is unpacked again
    }
    $dir = Split-Path -Parent $py
    $zip = Get-PinnedFile $Root 'python' $LocalCache
    $pipWheel = Get-PinnedFile $Root 'pip' $LocalCache
    if (Test-Path $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
    Expand-Archive -LiteralPath $zip -DestinationPath $dir -Force
    New-Item -ItemType Directory -Force (Join-Path $dir 'Lib\site-packages') | Out-Null
    # The embedded Python ignores the environment and the current folder when a ._pth file exists, so the
    # list of search paths is written here. ..\..\backend is the application.
    $pth = Get-ChildItem -LiteralPath $dir -Filter 'python*._pth' | Select-Object -First 1
    if (-not $pth) { throw 'the embedded Python has no ._pth file' }
    $zipName = ($pth.BaseName -replace '_pth$', '') + '.zip'
    $lines = @($zipName, '.', 'Lib\site-packages', '..\..\backend', 'import site')
    [System.IO.File]::WriteAllText($pth.FullName, ($lines -join "`r`n") + "`r`n")
    # pip is a pure-Python wheel (a zip file): unpacking it into site-packages is its installation
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($pipWheel, (Join-Path $dir 'Lib\site-packages'))
    & $py -m pip --version *> $null
    if ($LASTEXITCODE -ne 0) { throw 'pip does not start in the embedded Python' }
    return $py
}

# Extracts only bin, lib and share of the vendor archive (about 120 MB); the 690 MB administration tool is skipped.
function Install-Postgres([string]$Root, [string]$LocalCache = '') {
    $bin = Get-PgBin $Root
    if (Test-Path (Join-Path $bin 'postgres.exe')) { return $bin }
    $zip = Get-PinnedFile $Root 'postgres' $LocalCache
    $target = Join-Path (Get-RuntimeDir $Root) 'pgsql'
    if (Test-Path $target) { Remove-Item -LiteralPath $target -Recurse -Force }
    New-Item -ItemType Directory -Force $target | Out-Null
    $targetFull = [System.IO.Path]::GetFullPath($target).TrimEnd('\') + '\'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($zip)
    try {
        foreach ($entry in $archive.Entries) {
            if ($entry.FullName -notmatch '^pgsql/(bin|lib|share)/' -or $entry.FullName.EndsWith('/')) { continue }
            $rel = $entry.FullName.Substring('pgsql/'.Length) -replace '/', '\'
            $out = [System.IO.Path]::GetFullPath((Join-Path $target $rel))
            if (-not $out.StartsWith($targetFull, [System.StringComparison]::OrdinalIgnoreCase)) { throw "unsafe path in archive: $($entry.FullName)" }
            New-Item -ItemType Directory -Force (Split-Path -Parent $out) | Out-Null
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $out, $true)
        }
    } finally { $archive.Dispose() }
    foreach ($tool in 'postgres.exe', 'initdb.exe', 'pg_ctl.exe', 'psql.exe') {
        if (-not (Test-Path (Join-Path $bin $tool))) { throw "the archive does not contain bin\$tool" }
    }
    Install-VcRuntime $Root
    $version = & (Join-Path $bin 'postgres.exe') --version 2>$null
    if ($LASTEXITCODE -ne 0 -or "$version" -notmatch 'PostgreSQL\) 16\.') {
        throw 'the PostgreSQL binaries do not start; install the Microsoft Visual C++ Redistributable 2015-2022 (x64) and run setup again'
    }
    return $bin
}

function Find-FreePort {
    for ($p = $script:FirstPort; $p -le $script:LastPort; $p++) {
        $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $p)
        try { $l.Start(); $l.Stop(); return $p } catch { }
    }
    throw "no free port between $($script:FirstPort) and $($script:LastPort)"
}

function Get-PgPort([string]$Root) {
    $file = Join-Path (Get-RuntimeDir $Root) 'postgres.port'
    if (-not (Test-Path $file)) { throw 'the bundled PostgreSQL has no port file' }
    return [int](Get-Content $file -Raw).Trim()
}

# Start-Process -Wait would also wait for the server that pg_ctl leaves running (it hangs for ever), so this
# waits for the one process only. Output goes to files so no pipe of the caller is kept open.
function Invoke-Tool([string]$File, [string[]]$Arguments, [string]$OutFile, [string]$ErrFile) {
    $p = Start-Process -FilePath $File -ArgumentList $Arguments -NoNewWindow -PassThru `
        -RedirectStandardOutput $OutFile -RedirectStandardError $ErrFile
    $null = $p.Handle
    $p.WaitForExit()
    return $p.ExitCode
}

function Test-ClusterRunning([string]$Root) {
    & (Join-Path (Get-PgBin $Root) 'pg_ctl.exe') -D (Get-PgData $Root) status *> $null
    return ($LASTEXITCODE -eq 0)
}

function Start-Cluster([string]$Root) {
    if (Test-ClusterRunning $Root) { return }
    $logs = Join-Path (Get-RuntimeDir $Root) 'logs'
    New-Item -ItemType Directory -Force $logs | Out-Null
    $port = Get-PgPort $Root
    $opts = "-p $port -c listen_addresses=127.0.0.1"
    # pg_ctl output goes to files so the server does not keep the caller's pipes open
    $argList = @('-D', ('"' + (Get-PgData $Root) + '"'), '-l', ('"' + (Join-Path $logs 'postgres.log') + '"'), '-o', ('"' + $opts + '"'), '-w', 'start')
    $code = Invoke-Tool (Join-Path (Get-PgBin $Root) 'pg_ctl.exe') $argList (Join-Path $logs 'pg_ctl.out.log') (Join-Path $logs 'pg_ctl.err.log')
    if ($code -ne 0) { throw 'the bundled PostgreSQL did not start (see runtime\logs)' }
}

function Stop-Cluster([string]$Root) {
    if (-not (Test-BundledCluster $Root)) { return $false }
    if (-not (Test-ClusterRunning $Root)) { return $false }
    $logs = Join-Path (Get-RuntimeDir $Root) 'logs'
    New-Item -ItemType Directory -Force $logs | Out-Null
    $argList = @('-D', ('"' + (Get-PgData $Root) + '"'), '-m', 'fast', '-w', 'stop')
    $code = Invoke-Tool (Join-Path (Get-PgBin $Root) 'pg_ctl.exe') $argList (Join-Path $logs 'pg_ctl.out.log') (Join-Path $logs 'pg_ctl.err.log')
    return ($code -eq 0)
}

# Creates the cluster, an application role and an empty database. Returns the database URL.
function Initialize-Cluster([string]$Root) {
    $bin = Get-PgBin $Root
    $data = Get-PgData $Root
    $runtime = Get-RuntimeDir $Root
    if (Test-BundledCluster $Root) { throw 'runtime\pgdata already exists but backend\data\database.url does not; delete runtime\pgdata to start over' }
    if (Test-Path $data) { Remove-Item -LiteralPath $data -Recurse -Force }
    $port = Find-FreePort
    [System.IO.File]::WriteAllText((Join-Path $runtime 'postgres.port'), [string]$port)
    $superFile = Join-Path $runtime 'postgres.superuser.pw'
    $super = New-RandomText 32
    [System.IO.File]::WriteAllText($superFile, $super)
    Protect-File $superFile
    $logs = Join-Path $runtime 'logs'
    New-Item -ItemType Directory -Force $logs | Out-Null
    $initArgs = @('-D', ('"' + $data + '"'), '-U', 'argus_super', '--auth=scram-sha-256', '--pwfile', ('"' + $superFile + '"'), '-E', 'UTF8', '--locale=C')
    $code = Invoke-Tool (Join-Path $bin 'initdb.exe') $initArgs (Join-Path $logs 'initdb.out.log') (Join-Path $logs 'initdb.err.log')
    if ($code -ne 0) { throw 'initdb failed (see runtime\logs)' }
    Start-Cluster $Root
    $appRole = 'argusgrid_app'
    $appPw = New-RandomText 32
    $psql = Join-Path $bin 'psql.exe'
    $env:PGPASSWORD = $super
    try {
        $sql1 = "CREATE ROLE $appRole LOGIN PASSWORD '$appPw'"
        $sql2 = "CREATE DATABASE argusgrid OWNER $appRole"
        foreach ($sql in $sql1, $sql2) {
            & $psql -h 127.0.0.1 -p $port -U argus_super -d postgres -v ON_ERROR_STOP=1 -q -c $sql | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'creating the application database failed' }
        }
    } finally { Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue }
    return "postgresql+psycopg://${appRole}:${appPw}@127.0.0.1:${port}/argusgrid"
}

# DARE Agent Security installer (Windows).
#
#   irm https://darelabs.tech/security/install.ps1 | iex
#
# Env overrides:
#   DARE_SECURITY_VERSION      pin a specific release tag (e.g. v1.0.0); default: latest
#   DARE_SECURITY_INSTALL_DIR  install directory; default: $env:LOCALAPPDATA\dare-security\bin
#   DARE_SECURITY_REPO         GitHub "owner/repo"; default: darelabs-tech/dare-agent-security
#
# Fail-closed: any checksum that is missing or does not match aborts the
# install. There is no "warn and continue" path for this tool.

$ErrorActionPreference = "Stop"

$Repo = if ($env:DARE_SECURITY_REPO) { $env:DARE_SECURITY_REPO } else { "darelabs-tech/dare-agent-security" }
$InstallDir = if ($env:DARE_SECURITY_INSTALL_DIR) { $env:DARE_SECURITY_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "dare-security\bin" }
$BinName = "dare-agent-security.exe"
$Platform = "windows-x86_64"

function Write-Info($msg) { Write-Host "[install] $msg" }
function Fail($msg) { Write-Error "[install] ERROR: $msg"; exit 1 }

function Resolve-Version {
    if ($env:DARE_SECURITY_VERSION) {
        Write-Info "using pinned version: $env:DARE_SECURITY_VERSION"
        return $env:DARE_SECURITY_VERSION
    }
    Write-Info "resolving latest release for $Repo"
    $apiUrl = "https://api.github.com/repos/$Repo/releases/latest"
    try {
        $release = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "dare-agent-security-installer" }
    } catch {
        Fail "could not resolve latest release from $apiUrl : $_"
    }
    if (-not $release.tag_name) { Fail "release response had no tag_name" }
    Write-Info "resolved latest version: $($release.tag_name)"
    return $release.tag_name
}

function Get-Release([string]$Version) {
    $versionNoV = $Version.TrimStart("v")
    $asset = "dare-agent-security-v$versionNoV-$Platform.zip"
    $baseUrl = "https://github.com/$Repo/releases/download/$Version"
    $archiveUrl = "$baseUrl/$asset"
    $checksumUrl = "$baseUrl/$asset.sha256"

    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("dare-security-install-" + [System.Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null

    $archivePath = Join-Path $tmpDir $asset
    $checksumPath = Join-Path $tmpDir "$asset.sha256"

    Write-Info "downloading $asset"
    try {
        Invoke-WebRequest -Uri $archiveUrl -OutFile $archivePath -UseBasicParsing
    } catch {
        Fail "download failed: $archiveUrl (target platform may not be published yet)"
    }

    try {
        Invoke-WebRequest -Uri $checksumUrl -OutFile $checksumPath -UseBasicParsing
    } catch {
        Fail "checksum download failed: $checksumUrl - refusing to install without a checksum"
    }

    return [PSCustomObject]@{
        TmpDir       = $tmpDir
        ArchivePath  = $archivePath
        ChecksumPath = $checksumPath
        AssetName    = $asset
        VersionNoV   = $versionNoV
    }
}

function Test-Checksum($release) {
    Write-Info "verifying SHA-256 checksum"
    $line = Get-Content $release.ChecksumPath -Raw
    $expected = ($line -split '\s+')[0].Trim().ToLower()
    if (-not $expected) { Fail "checksum file is empty or malformed: $($release.ChecksumPath)" }

    $actual = (Get-FileHash -Algorithm SHA256 $release.ArchivePath).Hash.ToLower()
    if ($expected -ne $actual) {
        Fail "checksum mismatch for $($release.AssetName): expected $expected, got $actual"
    }
    Write-Info "checksum verified"
}

function Install-Binary($release) {
    Write-Info "extracting archive"
    Expand-Archive -Path $release.ArchivePath -DestinationPath $release.TmpDir -Force

    $extractedDir = Join-Path $release.TmpDir "dare-agent-security-v$($release.VersionNoV)-$Platform"
    $srcBin = Join-Path $extractedDir $BinName
    if (-not (Test-Path $srcBin)) { Fail "expected binary not found in archive: $srcBin" }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item $srcBin (Join-Path $InstallDir $BinName) -Force
    Write-Info "installed $BinName to $InstallDir\$BinName"
}

function Confirm-Install {
    $binPath = Join-Path $InstallDir $BinName
    if (-not (Test-Path $binPath)) { Fail "installed binary not found: $binPath" }
    & $binPath --version
    if ($LASTEXITCODE -ne 0) { Fail "installed binary failed to run --version" }

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$InstallDir*") {
        Write-Info "NOTE: $InstallDir is not on your PATH."
        Write-Info "Add it, e.g.: [Environment]::SetEnvironmentVariable('Path', `$env:Path + ';$InstallDir', 'User')"
    }
}

function Main {
    $version = Resolve-Version
    $release = Get-Release -Version $version
    try {
        Test-Checksum $release
        Install-Binary $release
        Confirm-Install
        Write-Info "done. Run: dare-agent-security doctor"
    } finally {
        Remove-Item -Recurse -Force $release.TmpDir -ErrorAction SilentlyContinue
    }
}

Main

param(
    [string]$Version = "latest",
    [string]$Prefix = $(if ($env:SHELLMIND_GUARD_BIN_DIR) { $env:SHELLMIND_GUARD_BIN_DIR } else { Join-Path $env:LOCALAPPDATA "ShellMind-Guard\bin" }),
    [switch]$FromSource
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ShellMind Guard — 1-Command Windows Installer
$Repo = "qira-dev/ShellMind-Guard"
$Asset = "shellmind-guard-windows-x86_64.zip"
$InstallDir = $Prefix
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

function Install-FromSource {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Write-Error "Rust/cargo not found and no prebuilt release is available. Install Rust from https://rustup.rs"
    }
    $CargoRoot = Join-Path $env:TEMP ("smg-cargo-" + [guid]::NewGuid().ToString("N"))
    try {
        $LocalManifest = if ($PSScriptRoot) { Join-Path $PSScriptRoot "Cargo.toml" } else { "" }
        if ($LocalManifest -and (Test-Path $LocalManifest) -and ((Get-Content $LocalManifest -Raw) -match 'name\s*=\s*"shellmind-guard"')) {
            Write-Host "[ShellMind Guard] Building from local source..."
            cargo install --path $PSScriptRoot --root $CargoRoot --locked
        } else {
            if ($Version -eq "latest") {
                throw "Building from GitHub requires an explicit release tag (-Version vX.Y.Z); refusing unpinned HEAD."
            }
            Write-Host "[ShellMind Guard] Building from GitHub repository tag $Version via cargo..."
            cargo install --git "https://github.com/$Repo.git" --tag $Version --root $CargoRoot --locked
        }
        if ($LASTEXITCODE -ne 0) {
            throw "cargo install exited with code $LASTEXITCODE"
        }
        $BuiltExe = Join-Path $CargoRoot "bin\shellmind-guard.exe"
        Copy-Item -Path $BuiltExe -Destination (Join-Path $InstallDir "shellmind-guard.exe") -Force
        $BuiltSmg = Join-Path $CargoRoot "bin\smg.exe"
        if (Test-Path $BuiltSmg) {
            Copy-Item -Path $BuiltSmg -Destination (Join-Path $InstallDir "smg.exe") -Force
        } else {
            Copy-Item -Path $BuiltExe -Destination (Join-Path $InstallDir "smg.exe") -Force
        }
    } finally {
        Remove-Item -Recurse -Force $CargoRoot -ErrorAction SilentlyContinue
    }
}

if (-not $FromSource) {
    $BaseUrl = if ($Version -eq "latest") {
        "https://github.com/$Repo/releases/latest/download"
    } else {
        "https://github.com/$Repo/releases/download/$Version"
    }
    $TmpDir = Join-Path $env:TEMP ("shellmind-guard-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $TmpDir | Out-Null
    try {
        $ZipPath = Join-Path $TmpDir $Asset
        $SumsPath = Join-Path $TmpDir "SHA256SUMS.txt"
        Write-Host "[ShellMind Guard] Downloading $Asset ($Version)..."
        Invoke-WebRequest -Uri "$BaseUrl/$Asset" -OutFile $ZipPath -UseBasicParsing
        Invoke-WebRequest -Uri "$BaseUrl/SHA256SUMS.txt" -OutFile $SumsPath -UseBasicParsing
        $EscapedAsset = [regex]::Escape($Asset)
        $ExpectedLine = Get-Content $SumsPath | Where-Object { $_ -match "\s+$EscapedAsset`$" } | Select-Object -First 1
        if (-not $ExpectedLine) {
            throw [System.Security.SecurityException]"Checksum for $Asset not found in SHA256SUMS.txt"
        }
        $ExpectedHash = ($ExpectedLine -split "\s+")[0].ToUpperInvariant()
        if ($ExpectedHash -notmatch '^[0-9A-F]{64}$') {
            throw [System.Security.SecurityException]"Malformed SHA256 digest in SHA256SUMS.txt for $Asset"
        }
        $ActualHash = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($ExpectedHash -ne $ActualHash) {
            throw [System.Security.SecurityException]"SHA256 checksum mismatch for $Asset! Expected $ExpectedHash, got $ActualHash"
        }
        $ExtractDir = Join-Path $TmpDir "extract"
        New-Item -ItemType Directory -Force -Path $ExtractDir | Out-Null
        Expand-Archive -Path $ZipPath -DestinationPath $ExtractDir -Force
        $ExtractedAny = $false
        foreach ($BinName in @("smg.exe", "shellmind-guard.exe")) {
            $Candidate = Join-Path $ExtractDir $BinName
            if (Test-Path $Candidate) {
                Copy-Item -Path $Candidate -Destination (Join-Path $InstallDir $BinName) -Force
                $ExtractedAny = $true
            }
        }
        if (-not $ExtractedAny) {
            throw [System.Security.SecurityException]"Archive $Asset did not contain smg.exe or shellmind-guard.exe"
        }
    } catch {
        Write-Error "Prebuilt release verification failed ($($_.Exception.Message)). Aborting (pass -FromSource -Version vX.Y.Z to build from a pinned tag)."
        exit 1
    } finally {
        Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
    }
} else {
    Install-FromSource
}

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
$NormalizedUserPath = if ([string]::IsNullOrWhiteSpace($UserPath)) { "" } else { $UserPath.TrimEnd(';') }
$PathParts = if ($NormalizedUserPath) { $NormalizedUserPath -split ';' } else { @() }
if ($PathParts -notcontains $InstallDir) {
    $NewUserPath = if ($NormalizedUserPath) { "$NormalizedUserPath;$InstallDir" } else { $InstallDir }
    [Environment]::SetEnvironmentVariable("Path", $NewUserPath, "User")
    $env:Path = if ([string]::IsNullOrWhiteSpace($env:Path)) { $InstallDir } else { "$($env:Path.TrimEnd(';'));$InstallDir" }
}

$SmgExePath = Join-Path $InstallDir "smg.exe"
$LegacyExePath = Join-Path $InstallDir "shellmind-guard.exe"
if (-not (Test-Path $SmgExePath) -and (Test-Path $LegacyExePath)) {
    Copy-Item -Path $LegacyExePath -Destination $SmgExePath -Force
}
if (-not (Test-Path $SmgExePath)) {
    Write-Error "Expected installed binary not found at $SmgExePath"
    exit 1
}
& $SmgExePath --version
Write-Host "[ShellMind Guard] Installed 'smg' (and 'shellmind-guard' alias). Run 'smg' for TUI, 'smg scan .', or 'smg mcp'."

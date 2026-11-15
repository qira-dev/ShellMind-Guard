param(
    [string]$Version = "latest",
    [switch]$FromSource
)

$ErrorActionPreference = "Stop"

# ShellMind Guard — 1-Command Windows Installer
$Repo = "qira-dev/ShellMind-Guard"
$Asset = "shellmind-guard-windows-x86_64.zip"
$InstallDir = Join-Path $env:LOCALAPPDATA "ShellMind-Guard\bin"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

function Install-FromSource {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Write-Error "Rust/cargo not found and no prebuilt release is available. Install Rust from https://rustup.rs"
    }
    $CargoRoot = Join-Path $env:TEMP ("smg-cargo-" + [guid]::NewGuid().ToString("N"))
    try {
        Write-Host "[ShellMind Guard] Building from source via cargo..."
        cargo install --git "https://github.com/$Repo.git" --root $CargoRoot --locked
        if ($LASTEXITCODE -ne 0) {
            throw "cargo install exited with code $LASTEXITCODE"
        }
        $BuiltExe = Join-Path $CargoRoot "bin\shellmind-guard.exe"
        Copy-Item -Path $BuiltExe -Destination (Join-Path $InstallDir "shellmind-guard.exe") -Force
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
        $ExpectedLine = Get-Content $SumsPath | Where-Object { $_ -match "\s+$Asset`$" } | Select-Object -First 1
        if (-not $ExpectedLine) {
            throw "Checksum for $Asset not found in SHA256SUMS.txt"
        }
        $ExpectedHash = ($ExpectedLine -split "\s+")[0].ToUpperInvariant()
        $ActualHash = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($ExpectedHash -ne $ActualHash) {
            throw "SHA256 checksum mismatch for $Asset! Expected $ExpectedHash, got $ActualHash"
        }
        Expand-Archive -Path $ZipPath -DestinationPath $InstallDir -Force
    } catch {
        Write-Warning "Prebuilt release verification failed ($_); falling back to source build."
        Install-FromSource
    } finally {
        Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
    }
} else {
    Install-FromSource
}

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
    $env:Path = "$env:Path;$InstallDir"
}

$ExePath = Join-Path $InstallDir "shellmind-guard.exe"
if (Test-Path $ExePath) {
    & $ExePath --version
} else {
    shellmind-guard --version
}
Write-Host "[ShellMind Guard] Installed. Run 'shellmind-guard scan .' or 'shellmind-guard mcp'."

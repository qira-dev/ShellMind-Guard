$ErrorActionPreference = "Stop"

# ShellMind Guard — 1-Command Windows Installer
param(
    [string]$Version = "latest",
    [switch]$FromSource
)

$Repo = "qira-dev/ShellMind-Guard"
$Asset = "shellmind-guard-windows-x86_64.zip"
$InstallDir = Join-Path $env:LOCALAPPDATA "ShellMind-Guard\bin"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

function Install-FromSource {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Write-Error "Rust/cargo not found and no prebuilt release is available. Install Rust from https://rustup.rs"
    }
    Write-Host "[ShellMind Guard] Building from source via cargo..."
    cargo install --git "https://github.com/$Repo.git" --locked
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
        Write-Host "[ShellMind Guard] Downloading $Asset ($Version)..."
        Invoke-WebRequest -Uri "$BaseUrl/$Asset" -OutFile $ZipPath -UseBasicParsing
        Expand-Archive -Path $ZipPath -DestinationPath $InstallDir -Force
    } catch {
        Write-Warning "Prebuilt release download failed; falling back to source build."
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

# Rusty Toolz installer - Windows.
# (On Linux/macOS, run ./install.sh instead.)
#
#   1. clone the repo
#   2. in PowerShell:  powershell -ExecutionPolicy Bypass -File .\install.ps1
#   3. it checks/installs prerequisites, adds a hosts alias, builds, and runs the dashboard.

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

# ---- config -----------------------------------------------------------------
$HostnameAlias = 'rustytoolz.local'
$Port = 80   # so http://rustytoolz.local works with no port; the dashboard stays loopback-only
# Cross-platform tools + dashboard; the Linux-specific tools are built lazily by
# the dashboard on first click (and only work on Linux).
$PortableTools = @('dashboard', 'Portofino', 'FuckAroundFindOut', 'FluShot', 'HumptyDumpty')

function Info($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "!!  $m" -ForegroundColor Yellow }

Info "Rusty Toolz installer (Windows)"

# Put cargo on PATH for this session if it's already installed.
$cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
if (Test-Path (Join-Path $cargoBin 'cargo.exe')) { $env:Path = "$cargoBin;$env:Path" }

# ---- 1. Rust toolchain ------------------------------------------------------
if (Get-Command cargo -ErrorAction SilentlyContinue) {
    Info "Rust present - $(cargo --version)"
} else {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Warn "winget not found. Install 'App Installer' from the Microsoft Store, or install Rust from https://rustup.rs, then re-run."
        exit 1
    }
    Info "Installing Rust via winget (rustup)..."
    winget install --id Rustlang.Rustup -e --accept-package-agreements --accept-source-agreements
    $env:Path = "$cargoBin;$env:Path"
    Info "Installed $(cargo --version)"
}

# ---- 2. MSVC linker (link.exe) via VS C++ Build Tools -----------------------
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$hasVc = $false
if (Test-Path $vswhere) {
    $vc = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if ($vc) { $hasVc = $true }
}
if ((Get-Command link.exe -ErrorAction SilentlyContinue) -or $hasVc) {
    Info "MSVC C++ build tools present (the Rust linker)"
} else {
    Warn "MSVC linker not found - Rust needs it to build on Windows."
    Info "Installing Visual Studio 2022 C++ Build Tools (multi-GB download; accept the UAC prompt)..."
    winget install --id Microsoft.VisualStudio.2022.BuildTools -e --accept-package-agreements --accept-source-agreements `
        --override "--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
}

# ---- 3. hosts alias (needs admin) -------------------------------------------
$hostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$entry = "127.0.0.1`t$HostnameAlias"
if (Select-String -Path $hostsFile -Pattern "\s$([regex]::Escape($HostnameAlias))(\s|$)" -Quiet -ErrorAction SilentlyContinue) {
    Info "hosts entry for $HostnameAlias already present"
} else {
    $ans = Read-Host "Add '$entry' to the hosts file so http://$HostnameAlias`:$Port works? [y/N]"
    if ($ans -match '^[Yy]') {
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if ($isAdmin) {
            Add-Content -Path $hostsFile -Value $entry
            Info "Added hosts entry."
        } else {
            Info "Elevating just to append the hosts line..."
            Start-Process -Verb RunAs -Wait -FilePath 'powershell' -ArgumentList @(
                '-NoProfile', '-Command', "Add-Content -Path '$hostsFile' -Value '$entry'"
            )
            Info "Added hosts entry (if you approved the UAC prompt)."
        }
    } else {
        Warn "Skipped - use http://localhost:$Port instead."
    }
}

# ---- 4. build ---------------------------------------------------------------
Info "Building the cross-platform tools + dashboard (release)..."
$buildArgs = @('build', '--release')
foreach ($t in $PortableTools) { $buildArgs += @('-p', $t) }
& cargo @buildArgs

# ---- 5. run -----------------------------------------------------------------
# Windows has no privileged-port restriction, so binding 80 works without admin
# as long as nothing else (IIS / http.sys) holds it. If it can't bind, the
# dashboard prints how to pick a high port.
$env:RUSTYTOOLZ_PORT = "$Port"
$suffix = if ($Port -eq 80) { '' } else { ":$Port" }
Info "Starting the dashboard: http://localhost$suffix  (and http://$HostnameAlias$suffix if you added the alias)"
Info "Ctrl+C to stop."
& "target\release\dashboard.exe"

<#
.SYNOPSIS
  Build and run the rustls prototype, with the two environment fixes this machine needs.

.DESCRIPTION
  `cargo build` fails here for two reasons that have nothing to do with the code:

  1. The MSVC linker is not on PATH. Visual Studio 2022 Community is installed, so its
     environment is imported first with vcvars64.bat.
  2. cargo's HTTPS goes through Windows schannel, which fails with SEC_E_NO_CREDENTIALS
     when the process cannot obtain a credential handle. That is the restricted-token
     sandbox, not a cargo misconfiguration; the command works when run with the wider
     sandbox mode, which is what -RequireFullAccess records. Python is unaffected because
     it uses OpenSSL.

  If the crates are already in the local registry cache, `-Offline` builds without any
  network access and therefore without the wider mode.

.EXAMPLE
  powershell -File tools\build_rust_prototype.ps1
  powershell -File tools\build_rust_prototype.ps1 -Offline
#>
[CmdletBinding()]
param(
  [switch]$Offline,
  [switch]$BuildOnly
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$crate = Join-Path $projectRoot 'rust-prototype'
$vcvars = 'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat'

if (-not (Test-Path -LiteralPath $crate)) { throw "crate not found: $crate" }
if (-not (Test-Path -LiteralPath $vcvars)) {
  throw "vcvars64.bat not found at $vcvars -- adjust this script for the installed Visual Studio"
}

$cargoCommand = if ($BuildOnly) { 'cargo build --release' } else { 'cargo run --release' }
if ($Offline) { $cargoCommand += ' --offline' }

Write-Host "crate  : $crate"
Write-Host "command: $cargoCommand"
Write-Host ''

Push-Location $crate
try {
  cmd /c "call `"$vcvars`" >nul 2>&1 && $cargoCommand 2>&1"
  $status = $LASTEXITCODE
}
finally {
  Pop-Location
}

if ($status -ne 0 -and -not $Offline) {
  Write-Host ''
  Write-Host 'If this failed with "SEC_E_NO_CREDENTIALS" while updating the registry index,' -ForegroundColor Yellow
  Write-Host 'the sandbox is blocking schannel: rerun this script with the wider sandbox mode,' -ForegroundColor Yellow
  Write-Host 'or use -Offline once the crates are cached.' -ForegroundColor Yellow
}
exit $status

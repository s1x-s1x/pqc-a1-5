<#
.SYNOPSIS
  Fetch the Verifpal symbolic verifier into .tools\verifpal.

.DESCRIPTION
  Verifpal publishes a single static Windows binary, so there is nothing to build:
  the release zip is downloaded and unpacked. It is the tool behind
  verification\verifpal\README.md.

  Tamarin and ProVerif were considered first and rejected for this machine: Tamarin
  is Haskell and there is no GHC here, ProVerif ships no Windows binary, Docker's
  daemon is not running, and WSL is not accessible from this account. Verifpal is the
  one symbolic verifier that actually runs in this environment, which is worth more
  than a more expressive tool that does not.

.EXAMPLE
  powershell -File tools\install_verifpal.ps1
  powershell -File tools\install_verifpal.ps1 -Version 1.4.12 -Force
#>
[CmdletBinding()]
param(
  [string]$Version = '1.4.12',
  [switch]$Force
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$target = Join-Path $projectRoot '.tools\verifpal'
$binary = Join-Path $target 'verifpal.exe'
$pyfix = Join-Path $PSScriptRoot 'sandbox_pyfix'

if ((Test-Path -LiteralPath $binary) -and -not $Force) {
  Write-Host "already installed: $binary"
  & $binary about | Select-Object -First 2
  exit 0
}

$env:PYTHONPATH = $pyfix
New-Item -ItemType Directory -Force -Path $target | Out-Null

Write-Host "downloading Verifpal $Version"
& python -c @'
import io
import sys
import urllib.request
import zipfile
from pathlib import Path

version = sys.argv[1]
target = Path(sys.argv[2])
url = (
    "https://github.com/symbolicsoft/verifpal/releases/download/"
    f"v{version}/verifpal_{version}_windows_amd64.zip"
)
data = urllib.request.urlopen(url, timeout=180).read()
archive = zipfile.ZipFile(io.BytesIO(data))
archive.extractall(target)
print("downloaded", len(data), "bytes;", len(archive.namelist()), "members")
'@ $Version $target
if ($LASTEXITCODE -ne 0) { throw "download failed with exit code $LASTEXITCODE" }

if (-not (Test-Path -LiteralPath $binary)) { throw "verifpal.exe not found under $target" }

Write-Host 'verifying'
& $binary about | Select-Object -First 3

Write-Host ''
Write-Host 'now run:'
Write-Host '  python verification\verifpal\generate_models.py'
Write-Host '  .tools\verifpal\verifpal.exe verify verification\verifpal\hybrid_auth*.vp --sessions 1 --result-code'

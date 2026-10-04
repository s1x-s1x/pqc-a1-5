<#
.SYNOPSIS
  Install the project's Python dependencies into .deps inside the workspace.

.DESCRIPTION
  Dependencies are installed with `pip --target` rather than into site-packages,
  because the DSH file sandbox denies writes outside the workspace. The same
  sandbox makes tempfile.mkdtemp unusable (see tools\sandbox_pyfix), so PYTHONPATH
  points at the patch directory for the duration of the install.

  Run tools\install_falcon_provider.ps1 afterwards: Falcon is not part of the
  pqcrypto 1.0.0 distribution.

  Dependencies are installed from `requirements.lock.txt` with `--require-hashes`, so
  every package is pinned to an exact version and every file is checked against the
  SHA-256 PyPI publishes for it. An audit of this repository pointed out that the
  earlier form of this script (`cryptography>=42` plus `--upgrade`) could resolve to
  different versions on different days. Pass -Unpinned to do that deliberately, for
  example to try a newer cryptography.

.EXAMPLE
  powershell -File tools\bootstrap_env.ps1
  powershell -File tools\bootstrap_env.ps1 -Unpinned
  powershell -File tools\bootstrap_env.ps1 -Extra "matplotlib>=3.8"
#>
[CmdletBinding()]
param(
  # Extra requirement specifiers appended to the default set.
  [string[]]$Extra = @(),
  # Ignore the lock file and install with lower bounds, the pre-audit behaviour.
  [switch]$Unpinned
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$deps = Join-Path $projectRoot '.deps'
$pyfix = Join-Path $PSScriptRoot 'sandbox_pyfix'
$lock = Join-Path $projectRoot 'requirements.lock.txt'

$requirements = @('cryptography>=42', 'pqcrypto>=1.0.0', 'pytest>=8.0') + $Extra

Write-Host "project root : $projectRoot"
Write-Host "target       : $deps"

$env:PYTHONPATH = $pyfix
$env:PIP_DISABLE_PIP_VERSION_CHECK = '1'
$env:PIP_NO_INPUT = '1'

New-Item -ItemType Directory -Force -Path $deps | Out-Null

if ($Unpinned -or -not (Test-Path -LiteralPath $lock)) {
  if (-not (Test-Path -LiteralPath $lock)) {
    Write-Warning "no lock file at $lock; falling back to a lower-bound installation"
  }
  Write-Host '--- installing requirements (unpinned) ---'
  python -m pip install --no-input --disable-pip-version-check --upgrade --target $deps @requirements
} else {
  Write-Host "--- installing from requirements.lock.txt with hashes ---"
  python -m pip install --no-input --disable-pip-version-check --target $deps --require-hashes -r $lock @Extra
}
if ($LASTEXITCODE -ne 0) { throw "pip install failed with exit code $LASTEXITCODE" }

Write-Host '--- verifying ---'
& python -c @'
import sys
from pathlib import Path
sys.path.append(str(Path(r"__DEPS__")))
import cryptography, pqcrypto, pytest
from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_44
print("cryptography", cryptography.__version__)
print("pytest      ", pytest.__version__)
print("ml_kem_768  ", ml_kem_768.PUBLIC_KEY_SIZE, "byte public keys")
print("ml_dsa_44   ", ml_dsa_44.SIGNATURE_SIZE, "byte signatures")
'@.Replace('__DEPS__', $deps)
if ($LASTEXITCODE -ne 0) { throw "verification failed with exit code $LASTEXITCODE" }

Write-Host 'bootstrap complete; run tools\install_falcon_provider.ps1 for Falcon'

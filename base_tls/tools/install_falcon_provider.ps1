<#
.SYNOPSIS
  Install the Falcon provider: pqcrypto 0.4.0 (PQClean), renamed to pqcrypto_pqclean.

.DESCRIPTION
  pqcrypto 1.0.0 ships only standardized algorithms -- ML-KEM, ML-DSA, SLH-DSA --
  and has no Falcon. The earlier 0.4.0 release wraps PQClean and does include
  Falcon, and it publishes a cp313 win_amd64 wheel.

  Both releases install the same top-level package name `pqcrypto`, so importing
  `pqcrypto.sign.falcon_512` from 0.4.0 while 1.0.0 provides ML-KEM is impossible
  in one interpreter unless one of them is renamed. Renaming is safe here because
  every wrapper in 0.4.0 uses relative imports and every `__init__.py` is empty,
  so copying the tree to `pqcrypto_pqclean` yields a working, independent package.

  The copy is appended -- never prepended -- to sys.path by tls\pq\providers.py, so
  it cannot shadow the 1.0.0 modules the handshake depends on.

.EXAMPLE
  powershell -File tools\install_falcon_provider.ps1
  powershell -File tools\install_falcon_provider.ps1 -Force
#>
[CmdletBinding()]
param(
  [switch]$Force
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$providerDir = Join-Path $projectRoot '.deps-falcon'
$sourcePackage = Join-Path $providerDir 'pqcrypto'
$renamedPackage = Join-Path $providerDir 'pqcrypto_pqclean'
$pyfix = Join-Path $PSScriptRoot 'sandbox_pyfix'

Write-Host "provider dir : $providerDir"

$env:PYTHONPATH = $pyfix
$env:PIP_DISABLE_PIP_VERSION_CHECK = '1'
$env:PIP_NO_INPUT = '1'

if ($Force -and (Test-Path -LiteralPath $providerDir)) {
  Remove-Item -LiteralPath $providerDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $providerDir | Out-Null

Write-Host '--- installing pqcrypto 0.4.0 (hash-pinned when the lock is present) ---'
$falconLock = Join-Path $projectRoot 'requirements-falcon.lock.txt'
if (Test-Path -LiteralPath $falconLock) {
  python -m pip install --no-input --disable-pip-version-check --target $providerDir --require-hashes -r $falconLock
} else {
  Write-Warning "no lock file at $falconLock; falling back to an unpinned install"
  python -m pip install --no-input --disable-pip-version-check --upgrade --target $providerDir 'pqcrypto==0.4.0'
}
if ($LASTEXITCODE -ne 0) { throw "pip install failed with exit code $LASTEXITCODE" }

if (Test-Path -LiteralPath $renamedPackage) {
  Remove-Item -LiteralPath $renamedPackage -Recurse -Force
}
Write-Host '--- renaming the package so both releases can coexist ---'
Copy-Item -LiteralPath $sourcePackage -Destination $renamedPackage -Recurse

Write-Host '--- verifying Falcon and ML-KEM together ---'
& python -c @'
import sys
from pathlib import Path
project = Path(r"__PROJECT__")
sys.path.append(str(project / ".deps"))
sys.path.append(str(project / ".deps-falcon"))
from pqcrypto.kem import ml_kem_768
from pqcrypto_pqclean.sign import falcon_512, falcon_1024

public_key, secret_key = ml_kem_768.keygen()
ciphertext, secret = ml_kem_768.encaps(public_key)
assert ml_kem_768.decaps(secret_key, ciphertext) == secret
print("ml_kem_768   ok, public key", len(public_key), "bytes")

for name, module in (("falcon-512", falcon_512), ("falcon-1024", falcon_1024)):
    public, secret = module.generate_keypair()
    signature = module.sign(secret, b"hybrid CertificateVerify input")
    assert module.verify(public, b"hybrid CertificateVerify input", signature)
    assert not module.verify(public, b"tampered", signature)
    print(f"{name:<13}ok, public key {len(public)} bytes, signature {len(signature)} bytes")
'@.Replace('__PROJECT__', $projectRoot)
if ($LASTEXITCODE -ne 0) { throw "verification failed with exit code $LASTEXITCODE" }

Write-Host 'Falcon provider ready'

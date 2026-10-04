<#
.SYNOPSIS
  Run every acceptance check for the hybrid TLS 1.3 implementation and print a verdict.

.DESCRIPTION
  This is the objective's single success command. It sets up the environment the way
  the project expects (project-local dependencies plus the sandbox mkdir patch), then
  runs, in order:

    1. backend inventory            -- which KEMs and PQ signers actually import
    2. full handshake, three PQ backends (Falcon, ML-DSA, WOTS+/XMSS)
    3. the tamper matrix            -- four corruptions, each rejected at a named step
    4. the pytest suite
    5. both benchmarks, writing .bench-out/

  Every check prints PASS or FAIL and the script exits non-zero if any check fails,
  so it can gate a commit or a claim.

.EXAMPLE
  powershell -File tools\verify_all.ps1
  powershell -File tools\verify_all.ps1 -SkipBench -Repeats 3
#>
[CmdletBinding()]
param(
  # Skip the two benchmark runs (the slowest part on a cold interpreter).
  [switch]$SkipBench,
  # Handshakes per profile in the size/latency benchmark.
  [int]$Repeats = 10,
  # Tree height for the XMSS profile in the benchmark.
  [int]$XmssHeight = 10,
  # Timed repetitions per primitive in the primitive benchmark.
  [int]$Iterations = 30,
  # Loopback handshakes per profile in the TCP benchmark.
  [int]$TcpRepeats = 5,
  # Handshakes per variant in the shaped-latency benchmark.
  [int]$ShapedRepeats = 2
)

$ErrorActionPreference = 'Continue'
$projectRoot = Split-Path -Parent $PSScriptRoot
$venvPatch = Join-Path $PSScriptRoot 'sandbox_pyfix'

$env:PYTHONPATH = "$projectRoot\.deps;$venvPatch"
$env:PYTHONDONTWRITEBYTECODE = '1'

$script:results = @()

function Add-Result {
  param([string]$Check, [bool]$Passed, [string]$Detail)
  $script:results += [pscustomobject]@{ Check = $Check; Result = $(if ($Passed) { 'PASS' } else { 'FAIL' }); Detail = $Detail }
  $colour = if ($Passed) { 'Green' } else { 'Red' }
  Write-Host ("{0,-42}{1,-6}{2}" -f $Check, $(if ($Passed) { 'PASS' } else { 'FAIL' }), $Detail) -ForegroundColor $colour
}

function Invoke-Capture {
  param([string]$Exe, [string[]]$Arguments)
  $output = & $Exe @Arguments 2>&1 | Out-String
  return @{ ExitCode = $LASTEXITCODE; Output = $output }
}

Push-Location $projectRoot
try {
  Write-Host '=== 1. backend inventory ===' -ForegroundColor Cyan
  $inventory = Invoke-Capture 'python' @('demo\run_handshake.py', '--list-backends')
  $addResult = $inventory.Output
  foreach ($required in @('ml-kem-512', 'ml-kem-768', 'ml-kem-1024', 'hqc-128', 'falcon-512', 'falcon-1024', 'ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87', 'xmss')) {
    Add-Result "backend: $required" ($addResult -match "(?m)^\s+$([regex]::Escape($required))\s") ''
  }

  Write-Host "`n=== 2. full handshake per post-quantum backend ===" -ForegroundColor Cyan
  $profiles = @(
    @{ Name = 'ml-kem-768 + falcon-512'; Args = @() },
    @{ Name = 'ml-kem-768 + ml-dsa-44'; Args = @('--pq', 'ml-dsa-44') },
    @{ Name = 'ml-kem-768 + xmss(h=8)'; Args = @('--pq', 'xmss', '--xmss-height', '8') },
    @{ Name = 'ml-kem-1024 + falcon-1024'; Args = @('--kem', 'ml-kem-1024', '--pq', 'falcon-1024') },
    @{ Name = 'hqc-128 + falcon-512'; Args = @('--kem', 'hqc-128') }
  )
  foreach ($profile in $profiles) {
    $run = Invoke-Capture 'python' (@('demo\run_handshake.py') + $profile.Args)
    $ok = ($run.ExitCode -eq 0) -and ($run.Output -match 'application data round trip: ok') -and ($run.Output -match 'exporter secrets agree:\s+yes')
    $bytes = if ($run.Output -match 'handshake bytes \(with record protection\):\s+(\d+)') { $Matches[1] } else { '?' }
    Add-Result $profile.Name $ok "$bytes bytes, exit $($run.ExitCode)"
  }

  Write-Host "`n=== 3. tamper matrix ===" -ForegroundColor Cyan
  $tampers = @{
    'pq-signature'     = 'certificate_verify'
    'classic-signature' = 'certificate_verify'
    'certificate'      = 'certificate'
    'kem-ciphertext'   = 'record'
  }
  foreach ($tamper in $tampers.Keys) {
    $run = Invoke-Capture 'python' @('demo\run_handshake.py', '--tamper', $tamper)
    $ok = ($run.ExitCode -eq 0) -and ($run.Output -match [regex]::Escape($tampers[$tamper]))
    Add-Result "tamper: $tamper" $ok ($run.Output.Trim() -split "`n" | Select-Object -First 1)
  }

  Write-Host "`n=== 4. pytest suite ===" -ForegroundColor Cyan
  $pytest = Invoke-Capture 'python' @('-m', 'pytest', 'tests', '-q')
  $summary = ($pytest.Output -split "`n" | Where-Object { $_ -match 'passed|failed|error' } | Select-Object -Last 1)
  Add-Result 'pytest tests' ($pytest.ExitCode -eq 0) "$($summary -replace '\s+', ' ')"

  Write-Host "`n=== 4b. every security check is on the live path ===" -ForegroundColor Cyan
  # Three reviews each found the same defect shape: a check that exists, is correct, and is
  # not called by anything that runs. This turns that class into an assertion instead of
  # something a reader has to notice. See docs/AUDIT_SWEEPS.md.
  $liveChecks = Invoke-Capture 'python' @('tools\audit_live_checks.py')
  $liveSummary = ($liveChecks.Output -split "`n" | Where-Object { $_ -match 'referenced nowhere|referenced only from unreachable|PASS:|FAIL:' } | ForEach-Object { $_.Trim() }) -join ' / '
  Add-Result 'audit: no unreachable security check' ($liveChecks.ExitCode -eq 0) $liveSummary

  Write-Host "`n=== 4c. dependency locks: per-package pin and hash ===" -ForegroundColor Cyan
  # A hash count is not an association: every package must be pinned and carry its own hashes,
  # and a downloaded artefact must match one of them before it is used. See docs/AUDIT_V8_RESPONSE.md.
  $locks = Invoke-Capture 'python' @('tools\verify_dependency_lock.py')
  $lockSummary = ($locks.Output -split "`n" | Where-Object { $_ -match '^PASS:|^FAIL:' } | ForEach-Object { $_.Trim() }) -join ' / '
  Add-Result 'locks: version-hash association' ($locks.ExitCode -eq 0) $lockSummary

  Write-Host "`n=== 4d. environment manifest for an independent run ===" -ForegroundColor Cyan
  # The verifier records the environment rather than inheriting the author's: interpreter,
  # lock hashes, installed distributions, import paths, and the sandbox helper's hash and
  # whether it is on PYTHONPATH. See validation/README.md.
  $envRun = Invoke-Capture 'python' @('tools\report_environment.py', '--out', 'validation\environment.json')
  Add-Result 'environment: manifest written' ($envRun.ExitCode -eq 0) 'validation/environment.json'

  if (-not $SkipBench) {
    Write-Host "`n=== 5. benchmarks ===" -ForegroundColor Cyan
    $primitives = Invoke-Capture 'python' @('bench\measure_primitives.py', '--iterations', "$Iterations", '--keygen-iterations', '5', '--xmss-height', '8', '--xmss-keygen-iterations', '2')
    Add-Result 'bench: primitives' ($primitives.ExitCode -eq 0) 'wrote .bench-out/primitives.{json,md}'

    $handshake = Invoke-Capture 'python' @('bench\measure_handshake.py', '--repeats', "$Repeats", '--xmss-height', "$XmssHeight")
    $profilesRun = ([regex]::Matches($handshake.Output, 'ok=True')).Count
    $anyFailed = $handshake.Output -match 'ok=False'
    Add-Result 'bench: handshake size + latency' (($handshake.ExitCode -eq 0) -and (-not $anyFailed)) "$profilesRun profiles ok=True, exit $($handshake.ExitCode)"

    Write-Host "`n=== 5b. real X.509 chain: the comparable profile ===" -ForegroundColor Cyan
    $x509 = Invoke-Capture 'python' @('tools\check_x509.py')
    $baseline = if ($x509.Output -match 'BASELINE\s+(\d+)') { [int]$Matches[1] } else { 0 }
    $ratio = if ($x509.Output -match 'RATIO\s+([\d.]+)') { [double]$Matches[1] } else { 0 }
    # A real chain makes the baseline an order of magnitude larger than the modelled
    # certificate does; if it ever drops back, the comparison stopped being comparable.
    Add-Result 'x509: chain measured, ratio sane' (($x509.ExitCode -eq 0) -and ($baseline -gt 1200) -and ($ratio -gt 1.0) -and ($ratio -lt 20.0)) "baseline $baseline B, ratio ${ratio}x"

    Write-Host "`n=== 5c. XMSS lifecycle: keygen, cold and hot ===" -ForegroundColor Cyan
    # A red-team pass measured a per-connection stall and asked what it buys. This separates the
    # whole-tree key generation from the handshake, cold (credentials inside the timer) from hot
    # (credential reused, everything else per handshake). Small counts here; the full run is
    # `python bench\measure_xmss_lifecycle.py --heights 8 10 --cold 5 --hot 30`.
    $lifecycle = Invoke-Capture 'python' @('bench\measure_xmss_lifecycle.py', '--heights', '8', '--cold', '2', '--hot', '5', '--out', '.bench-lifecycle-quick')
    $hotLine = ($lifecycle.Output -split "`n" | Where-Object { $_ -match 'h=8' } | Select-Object -First 1)
    Add-Result 'xmss: cold vs hot separated' ($lifecycle.ExitCode -eq 0) ($hotLine -replace '\s+', ' ').Trim()

    Write-Host "`n=== 6. loopback TCP: the 1-RTT claim as an observation ===" -ForegroundColor Cyan
    $tcp = Invoke-Capture 'python' @('bench\measure_tcp.py', '--repeats', "$TcpRepeats", '--xmss-height', '8')
    $oneRtt = ([regex]::Matches($tcp.Output, '1-RTT: True')).Count
    $notOneRtt = ([regex]::Matches($tcp.Output, '1-RTT: False')).Count
    Add-Result 'tcp: one wait before authenticated' (($tcp.ExitCode -eq 0) -and ($oneRtt -ge 3) -and ($notOneRtt -eq 0)) "$oneRtt profiles 1-RTT, $notOneRtt not"

    Write-Host "`n=== 7. symbolic verification of the hybrid authentication (Verifpal) ===" -ForegroundColor Cyan
    $verifpal = Join-Path $projectRoot '.tools\verifpal\verifpal.exe'
    if (-not (Test-Path -LiteralPath $verifpal)) {
      Write-Host '  skipped: Verifpal is not installed (tools\install_verifpal.ps1)' -ForegroundColor Yellow
    }
    else {
      & python (Join-Path $projectRoot 'verification\verifpal\generate_models.py') | Out-Null
      # The expected codes are the result: the baseline and BOTH single-half
      # compromises must be verdict-identical, and the two controls must break.
      $expected = [ordered]@{
        'hybrid_auth'                  = 'c0a0a0f0a1'
        'hybrid_auth_classical_leaked' = 'c0a0a0f0a1'
        'hybrid_auth_pq_leaked'        = 'c0a0a0f0a1'
        'hybrid_auth_both_leaked'      = 'c1a1a1f0a1'
        'hybrid_auth_classical_only'   = 'c1a1f0a1'
        'kex_only_no_auth'             = 'c1f0'
      }
      foreach ($model in $expected.Keys) {
        $path = Join-Path $projectRoot "verification\verifpal\$model.vp"
        $code = (& $verifpal verify $path --sessions 1 --result-code --quiet 2>&1 | Out-String).Trim()
        Add-Result "verifpal: $model" ($code -eq $expected[$model]) "got $code, expected $($expected[$model])"
      }
    }

    Write-Host "`n=== 8. latency under an emulated link ===" -ForegroundColor Cyan
    $shaped = Invoke-Capture 'python' @('bench\measure_shaped.py', '--repeats', "$ShapedRepeats", '--links', 'wan-slow')
    $shapedOk = ([regex]::Matches($shaped.Output, 'ok=True')).Count
    $shapedBad = ([regex]::Matches($shaped.Output, 'ok=False')).Count
    # The link's own arithmetic has to land near the measurement, and the handshake has
    # to stay one round trip under shaping -- if either breaks, the latency numbers stop
    # meaning anything about a network.
    $overheads = [regex]::Matches($shaped.Output, 'overhead ([+-][\d.]+)') | ForEach-Object { [math]::Abs([double]$_.Groups[1].Value) }
    $worstOverhead = if ($overheads.Count) { ($overheads | Measure-Object -Maximum).Maximum } else { 9999 }
    Add-Result 'shaped: 195.6 ms RTT, 10 Mbps' (($shaped.ExitCode -eq 0) -and ($shapedOk -ge 2) -and ($shapedBad -eq 0) -and ($worstOverhead -lt 150)) "$shapedOk profiles ok, worst harness overhead $worstOverhead ms"
  }
  else {
    Write-Host "`n=== 5. benchmarks skipped (-SkipBench) ===" -ForegroundColor Yellow
  }
}
finally {
  Pop-Location
}

$failed = @($script:results | Where-Object Result -eq 'FAIL')
Write-Host ''
Write-Host ("=" * 72)
Write-Host ("{0} checks, {1} passed, {2} failed" -f $script:results.Count, ($script:results.Count - $failed.Count), $failed.Count) -ForegroundColor $(if ($failed.Count) { 'Red' } else { 'Green' })
if ($failed.Count) {
  Write-Host 'failed checks:' -ForegroundColor Red
  $failed | ForEach-Object { Write-Host "  - $($_.Check): $($_.Detail)" }
  exit 1
}
Write-Host 'all acceptance checks passed' -ForegroundColor Green
exit 0

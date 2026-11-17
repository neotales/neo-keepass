#Requires -Version 7.0
# Self-tests for windows-validate.ps1, windows-package.ps1 and
# windows-verify-artifact.ps1. Runs under pwsh on any host (the PE check
# reads bytes, so no Windows is needed).
#
# Invocation discipline: every script under test runs in an ISOLATED pwsh
# child process (-File), so its exit code is always fresh and defined —
# the parent never reads a stale or unset $LASTEXITCODE, and a script that
# throws (ErrorActionPreference Stop) surfaces as a nonzero exit whose
# stderr carries the diagnostic. Negative tests assert both the nonzero
# exit AND the diagnostic text.
#
# Usage: test-windows-package.ps1 [-WorkDir <dir>]
[CmdletBinding()]
param(
    [string] $WorkDir = ([IO.Path]::GetTempPath())
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scripts = $PSScriptRoot
$script:failures = 0

function Assert-True {
    param([bool] $Condition, [Parameter(Mandatory)][string] $Message)
    if ($Condition) {
        Write-Host "ok   $Message"
    } else {
        Write-Host "FAIL $Message"
        $script:failures += 1
    }
}

# Runs a script under test in an isolated pwsh child process. Returns
# exit code plus captured stdout/stderr for diagnostic assertions.
$selfPwsh = (Get-Process -Id $PID).Path
function Invoke-Isolated {
    param(
        [Parameter(Mandatory)][string] $ScriptPath,
        [string[]] $ArgumentList = @()
    )
    $tag = [guid]::NewGuid().ToString('N')
    $outFile = Join-Path $work "capture-$tag.out"
    $errFile = Join-Path $work "capture-$tag.err"
    & $selfPwsh -NoProfile -File $ScriptPath @ArgumentList >$outFile 2>$errFile
    $code = $LASTEXITCODE
    $out = [IO.File]::ReadAllText($outFile)
    $err = [IO.File]::ReadAllText($errFile)
    Remove-Item $outFile, $errFile -Force -ErrorAction SilentlyContinue
    return [pscustomobject]@{ ExitCode = $code; StdOut = $out; StdErr = $err }
}

# Writes a minimal fake PE: MZ signature, e_lfanew at 0x3C pointing at a
# PE\0\0 signature followed by the given COFF machine value.
function New-FakePE {
    param([Parameter(Mandatory)][ushort] $Machine, [Parameter(Mandatory)][string] $Path)
    $peOffset = [uint32]0x80
    $buf = [byte[]]::new(0x200)
    $buf[0] = 0x4D; $buf[1] = 0x5A                                 # 'M','Z'
    [BitConverter]::GetBytes($peOffset).CopyTo($buf, 0x3C)         # e_lfanew
    $buf[$peOffset] = 0x50; $buf[$peOffset + 1] = 0x45             # 'P','E'
    [BitConverter]::GetBytes($Machine).CopyTo($buf, $peOffset + 4) # machine
    [IO.File]::WriteAllBytes($Path, $buf)
}

$work = Join-Path $WorkDir ("nkeepass-pkgtest-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $validate = Join-Path $scripts 'windows-validate.ps1'
    $package = Join-Path $scripts 'windows-package.ps1'
    $verify = Join-Path $scripts 'windows-verify-artifact.ps1'
    $triple = 'x86_64-pc-windows-msvc'

    # ---- windows-validate.ps1 -------------------------------------------------
    $peX64 = Join-Path $work 'fake-x64.exe'
    New-FakePE -Machine 0x8664 -Path $peX64
    $r = Invoke-Isolated -ScriptPath $validate -ArgumentList @('-Binary', $peX64, '-Machine', 'x64')
    Assert-True ($r.ExitCode -eq 0) 'validate: fake x64 PE accepted'

    $peI386 = Join-Path $work 'fake-i386.exe'
    New-FakePE -Machine 0x014c -Path $peI386
    $r = Invoke-Isolated -ScriptPath $validate -ArgumentList @('-Binary', $peI386, '-Machine', 'x64')
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'PE machine 0x014C != expected 0x8664')) `
        'validate: i386 PE rejected with exact machine diagnostic'
    $r = Invoke-Isolated -ScriptPath $validate -ArgumentList @('-Binary', $peI386, '-Machine', 'i386')
    Assert-True ($r.ExitCode -eq 0) 'validate: i386 PE accepted when expecting i386'

    $notPe = Join-Path $work 'not-pe.bin'
    [IO.File]::WriteAllBytes($notPe, [byte[]]::new(0x100))
    $r = Invoke-Isolated -ScriptPath $validate -ArgumentList @('-Binary', $notPe, '-Machine', 'x64')
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'missing MZ signature')) `
        'validate: zero-filled file rejected with MZ diagnostic'

    $r = Invoke-Isolated -ScriptPath $validate -ArgumentList @('-Binary', (Join-Path $work 'missing.exe'), '-Machine', 'x64')
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'not a file')) `
        'validate: missing file rejected with diagnostic'

    # ---- windows-package.ps1 --------------------------------------------------
    $out = Join-Path $work 'dist'
    $name = "nkeepass-9.9.9-test-$triple"
    $r = Invoke-Isolated -ScriptPath $package -ArgumentList @(
        '-Binary', $peX64, '-Version', '9.9.9-test', '-Triple', $triple, '-OutputDir', $out)
    Assert-True ($r.ExitCode -eq 0) 'package: ran clean'

    $zip = Join-Path $out "$name.zip"
    Assert-True (Test-Path -LiteralPath $zip -PathType Leaf) "package: $name.zip exists"
    Assert-True (Test-Path -LiteralPath (Join-Path $out 'nkeepass.exe') -PathType Leaf) 'package: raw nkeepass.exe shipped'
    Assert-True (Test-Path -LiteralPath (Join-Path $out 'WINDOWS-LIMITATIONS.txt') -PathType Leaf) 'package: limitations readme shipped'
    $sumsPath = Join-Path $out 'SHA256SUMS'
    Assert-True (Test-Path -LiteralPath $sumsPath -PathType Leaf) 'package: SHA256SUMS shipped'

    # Zip entries: one named enclosing directory, exactly four regular
    # non-empty entries under it.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($zip)
    try {
        $entryNames = @($archive.Entries | ForEach-Object { $_.FullName -replace '\\', '/' }) | Sort-Object
        $expect = @(
            "$name/LICENSE.md",
            "$name/README.md",
            "$name/WINDOWS-LIMITATIONS.txt",
            "$name/nkeepass.exe"
        ) | Sort-Object
        Assert-True (@(Compare-Object $entryNames $expect).Count -eq 0) `
            "zip: entries are exactly the four payloads under $name/"
        $noEmpty = $true
        foreach ($e in $archive.Entries) {
            if ($e.FullName.EndsWith('/') -or $e.Length -le 0) { $noEmpty = $false }
        }
        Assert-True $noEmpty 'zip: every entry is a regular non-empty file'
        $limitEntry = $archive.Entries | Where-Object { $_.FullName -like '*WINDOWS-LIMITATIONS.txt' }
        $reader = New-Object IO.StreamReader($limitEntry.Open())
        $limitText = $reader.ReadToEnd()
        $reader.Close()
        Assert-True (($limitText -match 'SECURE OWNER-ONLY FILE WRITES ARE NOT SUPPORTED') -and
            ($limitText -match 'FAILS CLOSED')) 'zip: limitations readme carries the fail-closed warning'
    } finally {
        $archive.Dispose()
    }

    # SHA256SUMS: three entries, sha256sum-compatible, hashes correct.
    $sums = [IO.File]::ReadAllText($sumsPath)
    $lines = $sums -split "`n" | Where-Object { $_ -ne '' }
    Assert-True ($lines.Count -eq 3) 'SHA256SUMS: exactly three entries'
    $formatOk = $true
    foreach ($line in $lines) {
        if ($line -notmatch '^[0-9a-f]{64}  \S+$') { $formatOk = $false }
    }
    Assert-True $formatOk 'SHA256SUMS: every entry matches "<64 lowercase hex>  <name>"'
    $hashOk = $true
    foreach ($line in $lines) {
        $parts = $line -split '  ', 2
        $actual = (Get-FileHash -LiteralPath (Join-Path $out $parts[1]) -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($parts[0] -ne $actual) { $hashOk = $false }
    }
    Assert-True $hashOk 'SHA256SUMS: every hash matches Get-FileHash'
    Assert-True (($sums.EndsWith("`n")) -and -not ($sums.Contains("`r"))) 'SHA256SUMS: LF endings, trailing newline'

    # Idempotency: a second run overwrites cleanly instead of failing.
    $r = Invoke-Isolated -ScriptPath $package -ArgumentList @(
        '-Binary', $peX64, '-Version', '9.9.9-test', '-Triple', $triple, '-OutputDir', $out)
    Assert-True ($r.ExitCode -eq 0) 'package: second run is a clean overwrite'

    # Failure path, and no partial output: a failing package run into a
    # fresh output directory must leave NO files — no checksum over a
    # partial or mismatched set.
    $outFail = Join-Path $work 'dist-fail'
    New-Item -ItemType Directory -Path $outFail | Out-Null
    $r = Invoke-Isolated -ScriptPath $package -ArgumentList @(
        '-Binary', (Join-Path $work 'missing.exe'), '-Version', '9.9.9-test', '-Triple', $triple, '-OutputDir', $outFail)
    $leftovers = @(Get-ChildItem -LiteralPath $outFail -Force)
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'not a file') -and ($leftovers.Count -eq 0)) `
        'package: missing binary rejected, zero partial output'

    # ---- windows-verify-artifact.ps1 ------------------------------------------
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $zip, '-BuiltExe', $peX64, '-Version', '9.9.9-test', '-Triple', $triple)
    Assert-True ($r.ExitCode -eq 0) 'verify: structural checks pass on the packaged artifact'

    # Negative: tampered SHA256SUMS (hash no longer matches the file).
    $tampered = Join-Path $work 'dist-tampered'
    Copy-Item -Recurse -Force $out $tampered
    $sumsFile = Join-Path $tampered 'SHA256SUMS'
    $originalSums = [IO.File]::ReadAllText($sumsFile)
    [IO.File]::WriteAllText($sumsFile, $originalSums.Replace($originalSums.Substring(0, 64),
        ('0000000000000000000000000000000000000000000000000000000000000000')))
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', (Join-Path $tampered "$name.zip"), '-BuiltExe', $peX64,
        '-Version', '9.9.9-test', '-Triple', $triple)
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'SHA256SUMS')) `
        'verify: tampered SHA256SUMS rejected with diagnostic'
    Remove-Item -Recurse -Force $tampered

    # Negative: a flattened zip (no named enclosing directory) is rejected.
    # Built via the wildcard variant of Compress-Archive, which drops the
    # root directory from entry names.
    $staging = Join-Path $work 'flat-stage'
    New-Item -ItemType Directory -Path (Join-Path $staging $name) -Force | Out-Null
    Copy-Item -Recurse -Force (Join-Path $out "$name.zip") $staging
    Copy-Item -Force (Join-Path $out 'nkeepass.exe'), (Join-Path $out 'WINDOWS-LIMITATIONS.txt') `
        (Join-Path $staging $name)
    $flatZip = Join-Path $work "$name.flat.zip"
    Compress-Archive -Path (Join-Path (Join-Path $staging $name) '*') -DestinationPath $flatZip -Force
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $flatZip, '-BuiltExe', $peX64, '-Version', '9.9.9-test', '-Triple', $triple)
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'zip entries differ')) `
        'verify: flattened zip (missing enclosing directory) rejected'

    # Smoke harness, exercised through the test-only -SmokeExeOverride seam
    # (checks 1..6 still run against the real artifact; only the executed
    # program is substituted, so this works on hosts that cannot run a PE).
    $havePosixBinaries = (Test-Path '/bin/true') -and (Test-Path '/bin/sh')
    if ($havePosixBinaries) {
        $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
            '-Zip', $zip, '-BuiltExe', $peX64, '-Version', '9.9.9-test', '-Triple', $triple,
            '-Smoke', '-SmokeExeOverride', '/bin/true')
        Assert-True ($r.ExitCode -eq 0) 'verify: bounded smoke run passes on a well-behaved program'

        # /bin/sleep cannot hang here: `sleep --version` exits immediately.
        # The hang target must ignore its arguments entirely, so the test
        # generates one: a shell script that sleeps no matter how invoked.
        $hangExe = Join-Path $work 'hang-forever.sh'
        [IO.File]::WriteAllText($hangExe, "#!/bin/sh`nsleep 30`n")
        & /bin/chmod 755 $hangExe
        $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
            '-Zip', $zip, '-BuiltExe', $peX64, '-Version', '9.9.9-test', '-Triple', $triple,
            '-Smoke', '-SmokeExeOverride', $hangExe, '-SmokeTimeoutSeconds', '2')
        Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'exceeded 2s and was killed')) `
            'verify: hung smoke run is killed at the timeout with diagnostic'
    } else {
        Write-Host 'skip smoke harness tests: /bin/true and /bin/sh not present'
    }

    if ($script:failures -gt 0) {
        Write-Host "windows packaging tests failed: $script:failures problem(s)"
        exit 1
    }
    Write-Host 'windows packaging tests ok'
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

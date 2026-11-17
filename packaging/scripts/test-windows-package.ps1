#Requires -Version 7.0
# Self-tests for windows-validate.ps1, windows-package.ps1 and
# windows-verify-artifact.ps1. Runs under pwsh on any host (the PE check
# reads bytes, so no Windows is needed; smoke fixtures are pwsh-based, so
# the same tests run natively on Windows too).
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
# -CommandString runs an arbitrary command line instead of -File (needed
# when a script parameter must receive an array containing tokens like
# '-Command', which pwsh -File argument parsing would misbind).
$selfPwsh = (Get-Process -Id $PID).Path
function Invoke-Isolated {
    param(
        [string] $ScriptPath,
        [string[]] $ArgumentList = @(),
        [string] $CommandString
    )
    $tag = [guid]::NewGuid().ToString('N')
    $outFile = Join-Path $work "capture-$tag.out"
    $errFile = Join-Path $work "capture-$tag.err"
    if ($CommandString) {
        & $selfPwsh -NoProfile -Command $CommandString >$outFile 2>$errFile
    } else {
        # Flatten: nested arrays inside ArgumentList would be stringified
        # when splatted to a native command; emit them as separate elements.
        $flatArgs = @(foreach ($a in $ArgumentList) {
            if ($a -is [System.Array]) { foreach ($x in $a) { $x } } else { $a }
        })
        & $selfPwsh -NoProfile -File $ScriptPath @flatArgs >$outFile 2>$errFile
    }
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

# Overwrites the recorded CRC of the FIRST zip entry (local header and
# central directory, patched consistently) with a wrong value, simulating
# an archive corrupted in transit without corrupting the compressed bytes.
function Patch-FirstCrc {
    param([Parameter(Mandatory)][string] $ZipPath)
    $bytes = [IO.File]::ReadAllBytes($ZipPath)
    $eocd = -1
    for ($i = $bytes.Length - 4; $i -ge 0; $i--) {
        if ($bytes[$i] -eq 0x50 -and $bytes[$i + 1] -eq 0x4B -and $bytes[$i + 2] -eq 0x05 -and $bytes[$i + 3] -eq 0x06) {
            $eocd = $i; break
        }
    }
    if ($eocd -lt 0) { throw 'test bug: EOCD not found' }
    # EOCD: cd offset lives at +16 (sig 4, disk 2x2, entries 2x2, size 4).
    $cdOffset = [int][BitConverter]::ToUInt32($bytes, $eocd + 16)
    $localOffset = [int][BitConverter]::ToUInt32($bytes, $cdOffset + 42)
    $newCrc = [BitConverter]::GetBytes([uint32]3735928559) # 0xDEADBEEF
    [Array]::Copy($newCrc, 0, $bytes, $cdOffset + 16, 4)   # central entry CRC
    [Array]::Copy($newCrc, 0, $bytes, $localOffset + 14, 4) # local header CRC
    [IO.File]::WriteAllBytes($ZipPath, $bytes)
}

# Crafts a fresh zip with arbitrary entry names/attributes for the
# malicious-archive fixtures: -Entries maps full entry name to a spec
# hashtable (@{ Path = source file } or @{ Bytes = byte[] }, optional
# Attrs = external attributes).
function New-CraftedZip {
    param(
        [Parameter(Mandatory)][string] $TargetZip,
        [Parameter(Mandatory)][string] $ExeSource,
        [Parameter(Mandatory)][object[]] $Entries
    )
    $fs = [IO.File]::Open($TargetZip, [IO.FileMode]::Create)
    $za = New-Object IO.Compression.ZipArchive($fs, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($spec in $Entries) {
            $e = $za.CreateEntry($spec['Name'])
            $e.ExternalAttributes = [int]$spec['Attrs']
            $s = $e.Open()
            try {
                # Plain assignment in each branch: an if-expression would
                # collect the byte[] as Object[] and Stream.Write needs
                # the real type.
                if ($spec['Path']) {
                    $bytes = [IO.File]::ReadAllBytes($spec['Path'])
                } else {
                    $bytes = [byte[]]$spec['Bytes']
                }
                $s.Write($bytes, 0, $bytes.Length)
            } finally {
                $s.Dispose()
            }
        }
    } finally {
        $za.Dispose()
        $fs.Dispose()
    }
}

$work = Join-Path $WorkDir ("nkeepass-pkgtest-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $validate = Join-Path $scripts 'windows-validate.ps1'
    $package = Join-Path $scripts 'windows-package.ps1'
    $verify = Join-Path $scripts 'windows-verify-artifact.ps1'
    $triple = 'x86_64-pc-windows-msvc'
    $version = '9.9.9-test'
    $name = "nkeepass-$version-$triple"

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
    $r = Invoke-Isolated -ScriptPath $package -ArgumentList @(
        '-Binary', $peX64, '-Version', $version, '-Triple', $triple, '-OutputDir', $out)
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
        '-Binary', $peX64, '-Version', $version, '-Triple', $triple, '-OutputDir', $out)
    Assert-True ($r.ExitCode -eq 0) 'package: second run is a clean overwrite'

    # Failure path, and no manifest over a partial set: a failing package
    # run into a fresh output directory must leave NO files.
    $outFail = Join-Path $work 'dist-fail'
    New-Item -ItemType Directory -Path $outFail | Out-Null
    $r = Invoke-Isolated -ScriptPath $package -ArgumentList @(
        '-Binary', (Join-Path $work 'missing.exe'), '-Version', $version, '-Triple', $triple, '-OutputDir', $outFail)
    $leftovers = @(Get-ChildItem -LiteralPath $outFail -Force)
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'not a file') -and ($leftovers.Count -eq 0)) `
        'package: missing binary rejected, zero partial output'

    # Mid-publish failure injection: a failure between payload publishes
    # may leave a mixed set of old and new payload files, but must NEVER
    # leave a SHA256SUMS describing it.
    $env:NEOKEEPASS_PACKAGE_FAIL_AFTER = 'exe'
    try {
        $r = Invoke-Isolated -ScriptPath $package -ArgumentList @(
            '-Binary', $peX64, '-Version', $version, '-Triple', $triple, '-OutputDir', $out)
    } finally {
        Remove-Item Env:NEOKEEPASS_PACKAGE_FAIL_AFTER -ErrorAction SilentlyContinue
    }
    Assert-True ($r.ExitCode -ne 0) 'publish: injected mid-publish failure fails the run'
    Assert-True (-not (Test-Path -LiteralPath $sumsPath)) `
        'publish: manifest invalidated during publish — no SHA256SUMS after mid-publish failure'
    Assert-True (Test-Path -LiteralPath (Join-Path $out 'nkeepass.exe') -PathType Leaf) `
        'publish: partial payload set present after mid-publish failure (documented non-atomic state)'
    # Recovery: an uninterrupted rerun restores the full consistent set.
    $r = Invoke-Isolated -ScriptPath $package -ArgumentList @(
        '-Binary', $peX64, '-Version', $version, '-Triple', $triple, '-OutputDir', $out)
    Assert-True ($r.ExitCode -eq 0) 'publish: rerun after failure restores the consistent set'

    # ---- windows-verify-artifact.ps1: happy path --------------------------------
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $zip, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True ($r.ExitCode -eq 0) 'verify: structural checks pass on the packaged artifact'

    # Fresh dist copies for each negative, so tests stay independent.
    function New-DistCopy {
        param([string] $Suffix)
        $c = Join-Path $work "dist-$Suffix"
        Copy-Item -Recurse -Force $out $c
        return $c
    }

    # Negative: tampered SHA256SUMS (hash no longer matches the file).
    $c = New-DistCopy 'tampered-sums'
    $sumsFile = Join-Path $c 'SHA256SUMS'
    $originalSums = [IO.File]::ReadAllText($sumsFile)
    $tamperedSums = $originalSums -replace '^.{64}', ('0' * 64)
    [IO.File]::WriteAllText($sumsFile, $tamperedSums)
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', (Join-Path $c "$name.zip"), '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'SHA256SUMS')) `
        'verify: tampered SHA256SUMS rejected with diagnostic'

    # Negative: a flattened zip (no named enclosing directory) is rejected.
    # Built via the wildcard variant of Compress-Archive, which drops the
    # root directory from entry names.
    $staging = Join-Path $work 'flat-stage'
    New-Item -ItemType Directory -Path (Join-Path $staging $name) -Force | Out-Null
    Copy-Item -Force (Join-Path $out 'nkeepass.exe'), (Join-Path $out 'WINDOWS-LIMITATIONS.txt') (Join-Path $staging $name)
    $flatZip = Join-Path $work "$name.flat.zip"
    Compress-Archive -Path (Join-Path (Join-Path $staging $name) '*') -DestinationPath $flatZip -Force
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $flatZip, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'zip (has|entries)')) `
        'verify: flattened zip (missing enclosing directory) rejected'

    # Negative: zip path traversal — an out-of-root canary entry must be
    # rejected at the manifest stage and NEVER read or extracted.
    $pad = @{ Bytes = [Text.Encoding]::UTF8.GetBytes('x'); Attrs = 0 }
    $canaryZip = Join-Path $work 'canary.zip'
    New-CraftedZip -TargetZip $canaryZip -ExeSource $peX64 -Entries @(
        @{ Name = "$name/nkeepass.exe"; Path = $peX64; Attrs = 0 },
        @{ Name = "$name/LICENSE.md"; Path = $null; Attrs = 0; Bytes = [Text.Encoding]::UTF8.GetBytes('x') },
        @{ Name = "$name/README.md"; Path = $null; Attrs = 0; Bytes = [Text.Encoding]::UTF8.GetBytes('x') },
        @{ Name = '../canary.txt'; Path = $null; Attrs = 0; Bytes = [Text.Encoding]::UTF8.GetBytes('CANARY') })
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $canaryZip, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'outside the expected canonical set')) `
        'verify: ../ traversal entry rejected at manifest stage'
    $canaryZip2 = Join-Path $work 'canary2.zip'
    New-CraftedZip -TargetZip $canaryZip2 -ExeSource $peX64 -Entries @(
        @{ Name = "$name/nkeepass.exe"; Path = $peX64; Attrs = 0 },
        @{ Name = "$name/LICENSE.md"; Path = $null; Attrs = 0; Bytes = [Text.Encoding]::UTF8.GetBytes('x') },
        @{ Name = "$name/README.md"; Path = $null; Attrs = 0; Bytes = [Text.Encoding]::UTF8.GetBytes('x') },
        @{ Name = "$name/../../canary_deep.txt"; Path = $null; Attrs = 0; Bytes = [Text.Encoding]::UTF8.GetBytes('CANARY') })
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $canaryZip2, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True ($r.ExitCode -ne 0) 'verify: nested ../ traversal entry rejected'
    Start-Sleep -Milliseconds 200
    # Match the exact canary FILENAMES, not 'canary*' — the crafted zip
    # files themselves are named canary*.zip and live in the work dir.
    $canaryFound = @(Get-ChildItem -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq 'canary.txt' -or $_.Name -eq 'canary_deep.txt' })
    $tempRoot = [IO.Path]::GetTempPath()
    $canaryTemp = @(foreach ($cn in @('canary.txt', 'canary_deep.txt')) {
        if ((Test-Path -LiteralPath (Join-Path $tempRoot $cn)) -or (Test-Path -LiteralPath (Join-Path $work $cn))) { $cn }
    })
    Assert-True (($canaryFound.Count -eq 0) -and ($canaryTemp.Count -eq 0)) `
        'verify: out-of-root canary never extracted (checked work dir and temp root)'

    # Negative: duplicate entry rejected.
    $dupZip = Join-Path $work 'dup.zip'
    New-CraftedZip -TargetZip $dupZip -ExeSource $peX64 -Entries @(
        @{ Name = "$name/nkeepass.exe"; Path = $peX64; Attrs = 0 },
        @{ Name = "$name/LICENSE.md"; Path = $null; Attrs = 0; Bytes = [Text.Encoding]::UTF8.GetBytes('x') },
        @{ Name = "$name/README.md"; Path = $null; Attrs = 0; Bytes = [Text.Encoding]::UTF8.GetBytes('x') },
        @{ Name = "$name/README.md"; Path = $null; Attrs = 0; Bytes = [Text.Encoding]::UTF8.GetBytes('y') },
        @{ Name = "$name/WINDOWS-LIMITATIONS.txt"; Path = $null; Attrs = 0; Bytes = [Text.Encoding]::UTF8.GetBytes('x') })
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $dupZip, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True ($r.ExitCode -ne 0) 'verify: duplicate zip entry rejected'

    # Negative: symlink external attributes rejected (four canonical names,
    # one carrying S_IFLNK in the Unix mode bits).
    $linkZip = Join-Path $work 'symlink.zip'
    New-CraftedZip -TargetZip $linkZip -ExeSource $peX64 -Entries @(
        @{ Name = "$name/nkeepass.exe"; Path = $peX64; Attrs = 0 },
        @{ Name = "$name/LICENSE.md"; Path = $null; Attrs = 0; Bytes = [Text.Encoding]::UTF8.GetBytes('x') },
        @{ Name = "$name/README.md"; Path = $null; Attrs = ([int](0xA1FF -shl 16)); Bytes = [Text.Encoding]::UTF8.GetBytes('../../canary') },
        @{ Name = "$name/WINDOWS-LIMITATIONS.txt"; Path = $null; Attrs = 0; Bytes = [Text.Encoding]::UTF8.GetBytes('x') })
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $linkZip, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'symlink/reparse')) `
        'verify: symlink external attributes rejected'

    # Negative: corrupted CRC (recorded checksum no longer matches the
    # data) rejected before extraction.
    $crcZip = Join-Path $work 'crc.zip'
    Copy-Item -Force $zip $crcZip
    Patch-FirstCrc -ZipPath $crcZip
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $crcZip, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'CRC mismatch')) `
        'verify: corrupt archive CRC rejected before extraction'

    # Negative: mutated payload data with internally consistent CRC (the
    # zip API recomputes CRC on rewrite) — caught by hash parity.
    $mutZip = Join-Path $work 'mutated.zip'
    Copy-Item -Force $zip $mutZip
    $za = [IO.Compression.ZipFile]::Open($mutZip, 'Update')
    try {
        $e = $za.Entries | Where-Object { ($_.FullName -replace '\\', '/') -eq "$name/nkeepass.exe" }
        $data = New-Object byte[] ([int]$e.Length)
        $s = $e.Open()
        try { $null = $s.Read($data, 0, $data.Length) } finally { $s.Dispose() }
        $data[10] = $data[10] -bxor 0xFF
        $entryName = $e.FullName
        $e.Delete()
        $ne = $za.CreateEntry($entryName)
        $os = $ne.Open()
        try { $os.Write($data, 0, $data.Length) } finally { $os.Dispose() }
    } finally {
        $za.Dispose()
    }
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $mutZip, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'sha256')) `
        'verify: mutated payload (consistent CRC) rejected by hash parity'

    # Negative: raw top-level exe differs from the built binary.
    $c = New-DistCopy 'raw-exe'
    New-FakePE -Machine 0x014c -Path (Join-Path $c 'nkeepass.exe')
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', (Join-Path $c "$name.zip"), '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'raw top-level exe')) `
        'verify: raw top-level exe differing from built binary rejected'

    # Negative: raw top-level limitations text tampered.
    $c = New-DistCopy 'raw-lim'
    [IO.File]::WriteAllText((Join-Path $c 'WINDOWS-LIMITATIONS.txt'),
        [IO.File]::ReadAllText((Join-Path $c 'WINDOWS-LIMITATIONS.txt')) + 'TAMPERED')
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', (Join-Path $c "$name.zip"), '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'WINDOWS-LIMITATIONS')) `
        'verify: tampered top-level limitations readme rejected'

    # ---- smoke harness (pwsh fixtures; runs natively on Windows too) ------------
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $zip, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple,
        '-Smoke', '-SmokeExeOverride', $selfPwsh)
    Assert-True ($r.ExitCode -eq 0) 'verify: bounded smoke run passes on pwsh (--version/--help)'

    # Hang: child itself hangs; the deadline must expire, kill the whole
    # tree, and return — never wait indefinitely. Invoked via -CommandString
    # so the SmokeArguments array binds in-process (through pwsh -File the
    # '-Command' element would be misparsed as a script parameter).
    $cmd = "& '$verify' -Zip '$zip' -BuiltExe '$peX64' -Version '$version' -Triple '$triple' " +
        "-Smoke -SmokeExeOverride '$selfPwsh' " +
        "-SmokeArguments @('-NoProfile','-Command','Start-Sleep -Seconds 60') -SmokeTimeoutSeconds 3"
    $r = Invoke-Isolated -CommandString $cmd
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'exceeded 3s and was killed')) `
        'verify: hung smoke run killed at the deadline with diagnostic'

    # Orphan: the child exits immediately after spawning a descendant that
    # inherits the redirected pipes and outlives it. The harness must fail
    # BOUNDED (never hang on the drain), kill what it can reach, and — on
    # Windows — remove the escapee via the kill-on-close job.
    $orphanFixture = Join-Path $work 'orphan-child.ps1'
    [IO.File]::WriteAllText($orphanFixture, "param(`$Pwsh)`n" +
        "Start-Process -FilePath `$Pwsh -ArgumentList @('-NoProfile','-Command','Start-Sleep -Seconds 15')`n" +
        "exit 0`n")
    $cmd = "& '$verify' -Zip '$zip' -BuiltExe '$peX64' -Version '$version' -Triple '$triple' " +
        "-Smoke -SmokeExeOverride '$selfPwsh' " +
        "-SmokeArguments @('-NoProfile','-File','$orphanFixture','$selfPwsh') -SmokeTimeoutSeconds 8"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-Isolated -CommandString $cmd
    $sw.Stop()
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'did not drain')) `
        'verify: orphaned pipe-holding descendant detected and failed bounded'
    Assert-True ($sw.Elapsed.TotalSeconds -lt 30) 'verify: orphan case returned well within the deadline (no indefinite wait)'

    if ($script:failures -gt 0) {
        Write-Host "windows packaging tests failed: $script:failures problem(s)"
        exit 1
    }
    Write-Host 'windows packaging tests ok'
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

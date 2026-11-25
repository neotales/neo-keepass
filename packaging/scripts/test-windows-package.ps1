#Requires -Version 7.0
# Self-tests for windows-validate.ps1, windows-package.ps1 and
# windows-verify-artifact.ps1. Runs under pwsh on any host (the PE check
# reads bytes, so no Windows is needed; smoke fixtures are pwsh-based, so
# the same tests run natively on Windows too).
#
# The compiled C# helpers of windows-verify-artifact.ps1 (CRC32, the raw
# zip header parser and the Windows job-object runner) are added as ONE
# type definition on EVERY host with the exact source the Windows runner
# compiles — so a C# syntax error on the Windows-only class (the CS1529
# class of bug: a using clause after a type declaration, which only
# breaks when the sources are concatenated on Windows) fails on this
# Linux host too, in every verify invocation below.
#
# Invocation discipline: every script under test runs in an ISOLATED pwsh
# child process (-File), so its exit code is always fresh and defined —
# the parent never reads a stale or unset $LASTEXITCODE, and a script that
# throws (ErrorActionPreference Stop) surfaces as a nonzero exit whose
# stderr carries the diagnostic. Negative tests assert both the nonzero
# exit AND the diagnostic text.
#
# Windows-only assertions (the kill-on-close job removing a pipe-holding
# escapee) are guarded by $isWinHost and run natively on the windows-2025
# runner; on the Linux dev host they are skipped — the bounded-failure
# assertions still run everywhere.
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
    param(
        [bool] $Condition,
        [Parameter(Mandatory)][string] $Message,
        [string] $Diag
    )
    if ($Condition) {
        Write-Host "ok   $Message"
    } else {
        Write-Host "FAIL $Message"
        if ($Diag) {
            # The first native Windows run failed all three smoke tests and
            # its log carried ONLY the FAIL lines — the captured child
            # output was never printed. On failure, surface it: the next
            # native run must carry the actual diagnostic (Win32 error,
            # fixture error) in the log, not just the assertion name.
            Write-Host '----- captured output (first 30 lines) -----'
            $Diag -split "`r?`n" | Select-Object -First 30 | ForEach-Object { Write-Host $_ }
            Write-Host '----- end captured output -----'
        }
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

# Reads the zip's central directory from the raw bytes and returns one
# record per entry: CentralOffset, LocalOffset and Name. Test-side
# counterpart of the verifier's own raw parser, used to aim byte patches.
function Get-ZipLayout {
    param([Parameter(Mandatory)][string] $ZipPath)
    $bytes = [IO.File]::ReadAllBytes($ZipPath)
    $eocd = -1
    for ($i = $bytes.Length - 4; $i -ge 0; $i--) {
        if ($bytes[$i] -eq 0x50 -and $bytes[$i + 1] -eq 0x4B -and $bytes[$i + 2] -eq 0x05 -and $bytes[$i + 3] -eq 0x06) {
            $eocd = $i; break
        }
    }
    if ($eocd -lt 0) { throw 'test bug: EOCD not found' }
    $count = $bytes[$eocd + 10] -bor ($bytes[$eocd + 11] -shl 8)
    $p = [int][BitConverter]::ToUInt32($bytes, $eocd + 16)
    $records = @()
    for ($i = 0; $i -lt $count; $i++) {
        $nameLen = $bytes[$p + 28] -bor ($bytes[$p + 29] -shl 8)
        $extraLen = $bytes[$p + 30] -bor ($bytes[$p + 31] -shl 8)
        $commentLen = $bytes[$p + 32] -bor ($bytes[$p + 33] -shl 8)
        $records += [pscustomobject]@{
            CentralOffset = $p
            LocalOffset   = [int][BitConverter]::ToUInt32($bytes, $p + 42)
            Name          = [Text.Encoding]::UTF8.GetString($bytes, $p + 46, $nameLen)
        }
        $p += 46 + $nameLen + $extraLen + $commentLen
    }
    return $records
}

# Patches raw bytes at one absolute offset inside a zip file. The offsets
# come from Get-ZipLayout; the field offsets are the APPNOTE.TXT ones
# (local header: flags +6, CRC +14, compressed size +18, uncompressed
# size +22, name length +26, name +30).
function Patch-ZipBytes {
    param(
        [Parameter(Mandatory)][string] $ZipPath,
        [Parameter(Mandatory)][int] $Offset,
        [Parameter(Mandatory)][byte[]] $Value
    )
    $bytes = [IO.File]::ReadAllBytes($ZipPath)
    [Array]::Copy($Value, 0, $bytes, $Offset, $Value.Length)
    [IO.File]::WriteAllBytes($ZipPath, $bytes)
}

function Get-TestCrc32 {
    param([Parameter(Mandatory)][byte[]] $Data)
    # Decimal constants: PowerShell parses hex literals in the high half
    # of a 32-bit word (0xEDB88320, 0xFFFFFFFF) as NEGATIVE int32, which
    # cannot be cast to an unsigned type.
    $crc = [uint64]4294967295
    $poly = [uint64]3988292384   # 0xEDB88320
    foreach ($b in $Data) {
        $crc = $crc -bxor [uint64]$b
        for ($i = 0; $i -lt 8; $i++) {
            if (($crc -band 1) -ne 0) {
                $crc = (($crc -shr 1) -bxor $poly)
            } else {
                $crc = $crc -shr 1
            }
        }
    }
    # 32-bit complement via XOR (PowerShell's -bnot promotes past 32 bits).
    return [uint32]((4294967295 -bxor $crc) -band 4294967295)
}

# Crafts the canonical four-entry zip with general purpose bit 3 (data
# descriptor) set: the local headers record zero CRC/sizes and the real
# values live in trailing data descriptors (APPNOTE 4.3.9). A correct
# verifier must handle this layout, not reject it. The payload is the
# same as the packager's (real repo README/LICENSE/WINDOWS-LIMITATIONS),
# so the end-to-end verification — including the byte-compare of the
# limitations copies — can pass. -OmitDescriptorSig drops the optional
# 0x08074b50 descriptor signature (APPNOTE 4.3.9.2) — a correct verifier
# must locate and validate the descriptor without it.
function New-DescriptorZip {
    param(
        [Parameter(Mandatory)][string] $TargetZip,
        [Parameter(Mandatory)][string] $ExeSource,
        [Parameter(Mandatory)][string] $Root,
        [Parameter(Mandatory)][string] $RepoRoot,
        [switch] $OmitDescriptorSig,
        [byte[]] $ReadmeBytes
    )
    $specs = @(
        @{ Name = "$Root/nkp.exe"; Bytes = [IO.File]::ReadAllBytes($ExeSource) },
        @{ Name = "$Root/README.md"; Bytes = $(if ($ReadmeBytes) { $ReadmeBytes } else { [IO.File]::ReadAllBytes((Join-Path $RepoRoot 'README.md')) }) },
        @{ Name = "$Root/LICENSE.md"; Bytes = [IO.File]::ReadAllBytes((Join-Path $RepoRoot 'LICENSE.md')) },
        @{ Name = "$Root/WINDOWS-LIMITATIONS.txt"; Bytes = [IO.File]::ReadAllBytes((Join-Path $RepoRoot 'packaging/windows/WINDOWS-LIMITATIONS.txt')) }
    )
    $fs = [IO.File]::Create($TargetZip)
    $bw = New-Object IO.BinaryWriter($fs)
    $central = New-Object IO.MemoryStream
    $cw = New-Object IO.BinaryWriter($central)
    try {
        foreach ($spec in $specs) {
            $data = [byte[]]$spec['Bytes']
            $crc = Get-TestCrc32 $data
            $localOffset = $bw.BaseStream.Position
            $nameBytes = [Text.Encoding]::UTF8.GetBytes($spec['Name'])
            # local file header: sig, version, flags(bit3), method(stored),
            # time, date, crc=0, comp=0, uncomp=0 (real values in the
            # descriptor after the data), name len, extra len, name, data,
            # descriptor (sig, crc, comp, uncomp).
            $bw.Write([uint32]0x04034B50)
            $bw.Write([uint16]20)
            $bw.Write([uint16]0x0008)
            $bw.Write([uint16]0)
            $bw.Write([uint16]0)
            $bw.Write([uint16]0)
            $bw.Write([uint32]0)
            $bw.Write([uint32]0)
            $bw.Write([uint32]0)
            $bw.Write([uint16]$nameBytes.Length)
            $bw.Write([uint16]0)
            $bw.Write($nameBytes)
            $bw.Write($data)
            if (-not $OmitDescriptorSig) { $bw.Write([uint32]0x08074B50) }
            $bw.Write([uint32]$crc)
            $bw.Write([uint32]$data.Length)
            $bw.Write([uint32]$data.Length)
            # central directory record with the REAL crc/sizes and bit 3.
            $cw.Write([uint32]0x02014B50)
            $cw.Write([uint16]20)   # version made by
            $cw.Write([uint16]20)   # version needed
            $cw.Write([uint16]0x0008)
            $cw.Write([uint16]0)    # method: stored
            $cw.Write([uint16]0)    # time
            $cw.Write([uint16]0)    # date
            $cw.Write([uint32]$crc)
            $cw.Write([uint32]$data.Length)
            $cw.Write([uint32]$data.Length)
            $cw.Write([uint16]$nameBytes.Length)
            $cw.Write([uint16]0)    # extra
            $cw.Write([uint16]0)    # comment
            $cw.Write([uint16]0)    # disk start
            $cw.Write([uint16]0)    # internal attrs
            $cw.Write([uint32]0)    # external attrs
            $cw.Write([uint32]$localOffset)
            $cw.Write($nameBytes)
        }
        $cdOffset = $bw.BaseStream.Position
        $bw.Write($central.ToArray())
        $cdSize = $central.Length
        $bw.Write([uint32]0x06054B50)
        $bw.Write([uint16]0)
        $bw.Write([uint16]0)
        $bw.Write([uint16]$specs.Count)
        $bw.Write([uint16]$specs.Count)
        $bw.Write([uint32]$cdSize)
        $bw.Write([uint32]$cdOffset)
        $bw.Write([uint16]0)
        $bw.Flush()
    } finally {
        $bw.Dispose()
        $central.Dispose()
        $fs.Dispose()
    }
}

# Returns the offset of the first occurrence of a byte pattern, or -1.
function Find-Bytes {
    param(
        [Parameter(Mandatory)][byte[]] $Haystack,
        [Parameter(Mandatory)][byte[]] $Needle
    )
    for ($i = 0; $i -le $Haystack.Length - $Needle.Length; $i++) {
        $ok = $true
        for ($j = 0; $j -lt $Needle.Length; $j++) {
            if ($Haystack[$i + $j] -ne $Needle[$j]) { $ok = $false; break }
        }
        if ($ok) { return $i }
    }
    return -1
}

# Rewrites ONLY the "<hash>  <zipname>" line of a SHA256SUMS file (used
# when a test swaps in crafted zip bytes but needs the rest of the
# manifest to stay self-consistent).
function Update-SumsZipLine {
    param(
        [Parameter(Mandatory)][string] $SumsPath,
        [Parameter(Mandatory)][string] $ZipName,
        [Parameter(Mandatory)][string] $NewHash
    )
    $lines = [IO.File]::ReadAllText($SumsPath) -split "`n"
    $out = foreach ($l in $lines) {
        if ($l -match ('  ' + [regex]::Escape($ZipName) + '$')) { "$NewHash  $ZipName" } else { $l }
    }
    [IO.File]::WriteAllText($SumsPath, ($out -join "`n"))
}

function Update-SumsLine {
    param(
        [Parameter(Mandatory)][string] $SumsPath,
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)][string] $NewHash
    )
    $lines = [IO.File]::ReadAllText($SumsPath) -split "`n"
    $out = foreach ($line in $lines) {
        if ($line -match ('  ' + [regex]::Escape($Name) + '$')) { "$NewHash  $Name" } else { $line }
    }
    [IO.File]::WriteAllText($SumsPath, ($out -join "`n"))
}

$work = Join-Path $WorkDir ("nkeepass-pkgtest-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    # Fresh dist copies for each negative, so tests stay independent.
    function New-DistCopy {
        param([string] $Suffix)
        $c = Join-Path $work "dist-$Suffix"
        Copy-Item -Recurse -Force $out $c
        return $c
    }

    $validate = Join-Path $scripts 'windows-validate.ps1'
    $package = Join-Path $scripts 'windows-package.ps1'
    $verify = Join-Path $scripts 'windows-verify-artifact.ps1'
    $triple = 'x86_64-pc-windows-msvc'
    $version = '9.9.9-test'
    $name = "nkp-$version-$triple"

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
    Assert-True (Test-Path -LiteralPath (Join-Path $out 'nkp.exe') -PathType Leaf) 'package: raw nkp.exe shipped'
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
            "$name/nkp.exe"
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
        $normalizedLimitText = [regex]::Replace($limitText, '\s+', ' ').Trim()
        $requiredLimitations = @(
            'Private file writes are supported only when a protected current-user-only DACL is created and the resulting security descriptor verifies before writing.',
            'The volume must advertise persistent ACL enforcement.',
            'Unsupported or unqueryable volumes, and failed security verification, fail closed before file contents are written.',
            'The implementation uses path-based staging and assumes the containing directory is trusted and not controlled by an adversary.',
            'These guarantees are not established for every filesystem, elevated execution, or every Windows account/configuration.'
        )
        $limitationsComplete = $true
        foreach ($marker in $requiredLimitations) {
            if ($normalizedLimitText.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
                $limitationsComplete = $false
            }
        }
        Assert-True $limitationsComplete 'zip: limitations readme states exact protected-write, fail-closed, trusted-parent, and scope contract'
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
    Assert-True (Test-Path -LiteralPath (Join-Path $out 'nkp.exe') -PathType Leaf) `
        'publish: partial payload set present after mid-publish failure (documented non-atomic state)'
    # Recovery: an uninterrupted rerun restores the full consistent set.
    $r = Invoke-Isolated -ScriptPath $package -ArgumentList @(
        '-Binary', $peX64, '-Version', $version, '-Triple', $triple, '-OutputDir', $out)
    Assert-True ($r.ExitCode -eq 0) 'publish: rerun after failure restores the consistent set'

    # Fault injection: an existing manifest that CANNOT be invalidated
    # (locked by another handle on Windows; unwritable directory on Unix —
    # the real-world case is an antivirus or backup holding the file) must
    # fail the run BEFORE any payload file is updated, leaving the old,
    # still-consistent set byte-for-byte intact.
    $isWinHost = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [System.Runtime.InteropServices.OSPlatform]::Windows)
    $c = New-DistCopy 'invalidation-fail'
    $tracked = @("$name.zip", 'nkp.exe', 'WINDOWS-LIMITATIONS.txt', 'SHA256SUMS')
    $before = @{}
    foreach ($f in $tracked) {
        $before[$f] = (Get-FileHash -LiteralPath (Join-Path $c $f) -Algorithm SHA256).Hash
    }
    $heldHandle = $null
    if ($isWinHost) {
        # Open with FileShare.None: no other handle may open the file, so
        # the delete must fail with a sharing violation.
        $heldHandle = [IO.File]::Open((Join-Path $c 'SHA256SUMS'),
            [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    } else {
        # Without write permission on the directory, unlinking the manifest
        # fails with EACCES.
        [IO.File]::SetUnixFileMode($c,
            [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserExecute)
    }
    try {
        try {
            $r = Invoke-Isolated -ScriptPath $package -ArgumentList @(
                '-Binary', $peI386, '-Version', $version, '-Triple', $triple, '-OutputDir', $c)
            Assert-True ($r.ExitCode -ne 0) 'publish: failed manifest invalidation fails the run'
            Assert-True ($r.StdErr -match 'invalidate') 'publish: invalidation failure carries a diagnostic'
        } finally {
            # Release the lock BEFORE reading the files for the unchanged
            # comparison: Get-FileHash on the FileShare.None-locked manifest
            # would die with a sharing violation of its own, and the test
            # process must never be the reason its own assertions cannot
            # run. The lock only needs to be held while the child runs.
            if ($heldHandle) { $heldHandle.Dispose() }
        }
        $unchanged = $true
        foreach ($f in $tracked) {
            $h = (Get-FileHash -LiteralPath (Join-Path $c $f) -Algorithm SHA256).Hash
            if ($h -ne $before[$f]) { $unchanged = $false }
        }
        Assert-True $unchanged 'publish: invalidation failure aborts before ANY file update'
    } finally {
        if ($heldHandle) { $heldHandle.Dispose() }
        if (-not $isWinHost) {
            [IO.File]::SetUnixFileMode($c,
                [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::UserExecute)
        }
    }

    # ---- windows-verify-artifact.ps1: job-object interop layout -------------
    # Native run 44206164232 failed at SetInformationJobObject with Win32
    # error 87: LimitFlags carried 0x200 (JOB_OBJECT_LIMIT_JOB_MEMORY)
    # under the name KILL_ON_JOB_CLOSE (0x2000) — a wrong VALUE, not a
    # wrong layout. These assertions run on any 64-bit host (the interop
    # layout is explicit, not observed) so the sizes, the field offsets
    # and every constant are pinned to the documented winnt.h x64 layout.
    $verifyRaw = Get-Content -LiteralPath $verify -Raw
    # Single-quoted so $helperSource is a regex literal, not interpolation
    # (PowerShell does not backslash-escape $ inside double quotes).
    $helperMatch = [regex]::Match($verifyRaw, '(?s)\$helperSource = @''\r?\n(.*?)\r?\n''@')
    if (-not $helperMatch.Success) { throw 'test bug: helper C# source not found in verify script' }
    Add-Type -TypeDefinition $helperMatch.Groups[1].Value
    $basicType = [JobOps+JOBOBJECT_BASIC_LIMIT_INFORMATION]
    $extType = [JobOps+JOBOBJECT_EXTENDED_LIMIT_INFORMATION]
    Assert-True (([System.Runtime.InteropServices.Marshal]::SizeOf([type]$basicType) -eq 64) -and
        ([System.Runtime.InteropServices.Marshal]::SizeOf([type][JobOps+IO_COUNTERS]) -eq 48) -and
        ([System.Runtime.InteropServices.Marshal]::SizeOf([type]$extType) -eq 144)) `
        'verify: job struct sizes match the documented x64 layout (64/48/144)'
    Assert-True (([int][System.Runtime.InteropServices.Marshal]::OffsetOf([type]$basicType, 'LimitFlags') -eq 16) -and
        ([int][System.Runtime.InteropServices.Marshal]::OffsetOf([type]$basicType, 'ActiveProcessLimit') -eq 40) -and
        ([int][System.Runtime.InteropServices.Marshal]::OffsetOf([type]$basicType, 'Affinity') -eq 48) -and
        ([int][System.Runtime.InteropServices.Marshal]::OffsetOf([type]$basicType, 'PriorityClass') -eq 56) -and
        ([int][System.Runtime.InteropServices.Marshal]::OffsetOf([type]$basicType, 'SchedulingClass') -eq 60)) `
        'verify: JOBOBJECT_BASIC_LIMIT_INFORMATION field offsets match winnt.h x64'
    Assert-True (([int][System.Runtime.InteropServices.Marshal]::OffsetOf([type]$extType, 'IoInfo') -eq 64) -and
        ([int][System.Runtime.InteropServices.Marshal]::OffsetOf([type]$extType, 'ProcessMemoryLimit') -eq 112) -and
        ([int][System.Runtime.InteropServices.Marshal]::OffsetOf([type]$extType, 'PeakJobMemoryUsed') -eq 136)) `
        'verify: JOBOBJECT_EXTENDED_LIMIT_INFORMATION field offsets match winnt.h x64'
    Assert-True ([JobOps]::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE -eq 0x2000) `
        'verify: KILL_ON_JOB_CLOSE flag is 0x2000 per winnt.h (0x200 is JOB_MEMORY — the run 44206164232 root cause)'
    Assert-True ([JobOps]::PROC_THREAD_ATTRIBUTE_JOB_LIST -eq 131085) `
        'verify: PROC_THREAD_ATTRIBUTE_JOB_LIST is 131085 = 0x0002000D (decimal attribute number 13)'

    # ---- windows-verify-artifact.ps1: happy path --------------------------------
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $zip, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True ($r.ExitCode -eq 0) 'verify: structural checks pass on the packaged artifact'

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
    Copy-Item -Force (Join-Path $out 'nkp.exe'), (Join-Path $out 'WINDOWS-LIMITATIONS.txt') (Join-Path $staging $name)
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
        @{ Name = "$name/nkp.exe"; Path = $peX64; Attrs = 0 },
        @{ Name = "$name/LICENSE.md"; Path = $null; Attrs = 0; Bytes = [Text.Encoding]::UTF8.GetBytes('x') },
        @{ Name = "$name/README.md"; Path = $null; Attrs = 0; Bytes = [Text.Encoding]::UTF8.GetBytes('x') },
        @{ Name = '../canary.txt'; Path = $null; Attrs = 0; Bytes = [Text.Encoding]::UTF8.GetBytes('CANARY') })
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $canaryZip, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'outside the expected canonical set')) `
        'verify: ../ traversal entry rejected at manifest stage'
    $canaryZip2 = Join-Path $work 'canary2.zip'
    New-CraftedZip -TargetZip $canaryZip2 -ExeSource $peX64 -Entries @(
        @{ Name = "$name/nkp.exe"; Path = $peX64; Attrs = 0 },
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
        @{ Name = "$name/nkp.exe"; Path = $peX64; Attrs = 0 },
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
        @{ Name = "$name/nkp.exe"; Path = $peX64; Attrs = 0 },
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

    # ---- central-directory/local-header agreement (raw byte patching) ----

    # Negative: the LOCAL header carries a different name than the central
    # directory (an extraction-confusion classic).
    $c = New-DistCopy 'local-name'
    $lz = Join-Path $c "$name.zip"
    $rec = Get-ZipLayout -ZipPath $lz | Where-Object { $_.Name -eq "$name/nkp.exe" }
    $locBytes = [IO.File]::ReadAllBytes($lz)
    $locNameLen = $locBytes[$rec.LocalOffset + 26] -bor ($locBytes[$rec.LocalOffset + 27] -shl 8)
    $locBytes[$rec.LocalOffset + 30 + $locNameLen - 1] = $locBytes[$rec.LocalOffset + 30 + $locNameLen - 1] -bxor 0x01
    [IO.File]::WriteAllBytes($lz, $locBytes)
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $lz, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'local header name disagrees')) `
        'verify: local header name disagreeing with central directory rejected'

    # Negative: local CRC differs from the central directory while no data
    # descriptor flag is set (general purpose bit 3 clear).
    # NB: 0xDEADBEEF as a PowerShell hex literal is a NEGATIVE int32, so
    # the decimal form is used for the [uint32] conversion.
    $c = New-DistCopy 'local-crc'
    $lz = Join-Path $c "$name.zip"
    $rec = Get-ZipLayout -ZipPath $lz | Where-Object { $_.Name -eq "$name/nkp.exe" }
    Patch-ZipBytes -ZipPath $lz -Offset ($rec.LocalOffset + 14) -Value ([BitConverter]::GetBytes([uint32]3735928559))
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $lz, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'local header CRC disagrees')) `
        'verify: local header CRC disagreeing with central directory rejected'

    # Negative: local compressed size differs from the central directory,
    # descriptor flag clear.
    $c = New-DistCopy 'local-size'
    $lz = Join-Path $c "$name.zip"
    $rec = Get-ZipLayout -ZipPath $lz | Where-Object { $_.Name -eq "$name/nkp.exe" }
    Patch-ZipBytes -ZipPath $lz -Offset ($rec.LocalOffset + 18) -Value ([BitConverter]::GetBytes([uint32]0x7FFFFFFF))
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $lz, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'local header sizes disagree')) `
        'verify: local header sizes disagreeing with central directory rejected'

    # Positive: data descriptors are HANDLED, not rejected — a zip whose
    # local headers record zero CRC/sizes (general purpose bit 3 set) and
    # carry the real values in trailing descriptors verifies end-to-end
    # against a regenerated manifest line.
    $c = New-DistCopy 'descriptor'
    $dz = Join-Path $c "$name.zip"
    New-DescriptorZip -TargetZip $dz -ExeSource $peX64 -Root $name -RepoRoot (Resolve-Path (Join-Path $scripts '..' '..')).Path
    Update-SumsZipLine -SumsPath (Join-Path $c 'SHA256SUMS') -ZipName "$name.zip" `
        -NewHash ((Get-FileHash -LiteralPath $dz -Algorithm SHA256).Hash.ToLowerInvariant())
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $dz, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True ($r.ExitCode -eq 0) 'verify: zip using data descriptors verifies end-to-end'

    # Negative: the LOCAL header claims a data descriptor (general purpose
    # bit 3 set) while the central directory does not — flipping the flag
    # in one header alone would otherwise turn the local-vs-central
    # CRC/size comparison off.
    $c = New-DistCopy 'local-flag'
    $lz = Join-Path $c "$name.zip"
    $rec = Get-ZipLayout -ZipPath $lz | Where-Object { $_.Name -eq "$name/nkp.exe" }
    $locBytes = [IO.File]::ReadAllBytes($lz)
    $locFlags = $locBytes[$rec.LocalOffset + 6] -bor ($locBytes[$rec.LocalOffset + 7] -shl 8)
    Patch-ZipBytes -ZipPath $lz -Offset ($rec.LocalOffset + 6) -Value ([BitConverter]::GetBytes([uint16]($locFlags -bor 8)))
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $lz, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    # (?s): pwsh renders the child's error wrapped across lines, and the
    # entry name in the middle of the message can push the wrap point
    # between the two words the assertion matches.
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match '(?s)descriptor flag.*disagrees')) `
        'verify: local descriptor flag set where central is clear rejected'

    # Negative: the reverse disagreement — starting from the ORDINARY
    # archive (both flags clear), set ONLY the CENTRAL directory's bit 3,
    # leaving the local header clear.
    $c = New-DistCopy 'central-flag'
    $lz = Join-Path $c "$name.zip"
    $rec = Get-ZipLayout -ZipPath $lz | Where-Object { $_.Name -eq "$name/nkp.exe" }
    $cenBytes = [IO.File]::ReadAllBytes($lz)
    $cenFlags = $cenBytes[$rec.CentralOffset + 8] -bor ($cenBytes[$rec.CentralOffset + 9] -shl 8)
    Patch-ZipBytes -ZipPath $lz -Offset ($rec.CentralOffset + 8) -Value ([BitConverter]::GetBytes([uint16]($cenFlags -bor 8)))
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $lz, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match '(?s)descriptor flag.*disagrees')) `
        'verify: central descriptor flag set where local is clear rejected'

    # Negative: a MALFORMED data descriptor — the descriptor's own CRC does
    # not match the central directory it claims to describe.
    $c = New-DistCopy 'desc-crc'
    $lz = Join-Path $c "$name.zip"
    New-DescriptorZip -TargetZip $lz -ExeSource $peX64 -Root $name `
        -RepoRoot (Resolve-Path (Join-Path $scripts '..' '..')).Path
    $descBytes = [IO.File]::ReadAllBytes($lz)
    # The 0x08074b50 signature occurs only in data descriptors.
    $descOff = Find-Bytes -Haystack $descBytes -Needle ([byte[]]@(0x50, 0x4B, 0x07, 0x08))
    if ($descOff -lt 0) { throw 'test bug: descriptor signature not found' }
    Patch-ZipBytes -ZipPath $lz -Offset ($descOff + 4) -Value ([BitConverter]::GetBytes([uint32]3735928559))
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $lz, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'data descriptor CRC/sizes disagree')) `
        'verify: malformed data descriptor (CRC disagrees with central) rejected'

    # Positive: signature-less descriptors are handled — the signature is
    # optional, so a zip whose descriptors carry only CRC/sizes must
    # verify end-to-end.
    $c = New-DistCopy 'descriptor-nosig'
    $dz2 = Join-Path $c "$name.zip"
    New-DescriptorZip -TargetZip $dz2 -ExeSource $peX64 -Root $name `
        -RepoRoot (Resolve-Path (Join-Path $scripts '..' '..')).Path -OmitDescriptorSig
    Update-SumsZipLine -SumsPath (Join-Path $c 'SHA256SUMS') -ZipName "$name.zip" `
        -NewHash ((Get-FileHash -LiteralPath $dz2 -Algorithm SHA256).Hash.ToLowerInvariant())
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $dz2, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True ($r.ExitCode -eq 0) 'verify: zip using signature-less data descriptors verifies end-to-end'

    # Positive, real collision: a signature-less descriptor whose CRC
    # GENUINELY equals the descriptor-signature value (0x08074b50). The
    # four bytes at the data end are then ambiguous — signature or CRC —
    # and only consistency with the central directory may decide. The
    # README payload's CRC32 is exactly 0x08074b50: "readme-collision:"
    # plus bytes 4,5,145,238, solved offline by brute force (the bytes are
    # hard-coded, the assertion proves the fixture).
    $readmePrefix = [Text.Encoding]::UTF8.GetBytes('readme-collision:')
    $collisionReadme = [byte[]]::new($readmePrefix.Length + 4)
    [Array]::Copy($readmePrefix, $collisionReadme, $readmePrefix.Length)
    $collisionReadme[$readmePrefix.Length + 0] = 4
    $collisionReadme[$readmePrefix.Length + 1] = 5
    $collisionReadme[$readmePrefix.Length + 2] = 145
    $collisionReadme[$readmePrefix.Length + 3] = 238
    Assert-True ((Get-TestCrc32 $collisionReadme) -eq 0x08074B50) `
        'test: collision fixture README really has CRC32 0x08074b50'
    $c = New-DistCopy 'descriptor-collision'
    $dz3 = Join-Path $c "$name.zip"
    New-DescriptorZip -TargetZip $dz3 -ExeSource $peX64 -Root $name `
        -RepoRoot (Resolve-Path (Join-Path $scripts '..' '..')).Path `
        -OmitDescriptorSig -ReadmeBytes $collisionReadme
    Update-SumsZipLine -SumsPath (Join-Path $c 'SHA256SUMS') -ZipName "$name.zip" `
        -NewHash ((Get-FileHash -LiteralPath $dz3 -Algorithm SHA256).Hash.ToLowerInvariant())
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $dz3, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True ($r.ExitCode -eq 0) `
        'verify: signature-less descriptor whose CRC equals the signature value still verifies'

    # Negative: the same ambiguous prefix, but the descriptor's sizes do
    # NOT match the central directory under either layout — the collision
    # must not blind the check into accepting a lying descriptor.
    $c = New-DistCopy 'descriptor-collision-bad'
    $dz4 = Join-Path $c "$name.zip"
    New-DescriptorZip -TargetZip $dz4 -ExeSource $peX64 -Root $name `
        -RepoRoot (Resolve-Path (Join-Path $scripts '..' '..')).Path `
        -OmitDescriptorSig -ReadmeBytes $collisionReadme
    $badBytes = [IO.File]::ReadAllBytes($dz4)
    $pattern = [Text.Encoding]::UTF8.GetBytes('readme-collision:') + $collisionReadme[$readmePrefix.Length..($readmePrefix.Length + 3)]
    $dataEnd = (Find-Bytes -Haystack $badBytes -Needle ([byte[]]$pattern)) + $pattern.Length
    if ($dataEnd -le $pattern.Length) { throw 'test bug: collision payload not found in crafted zip' }
    Patch-ZipBytes -ZipPath $dz4 -Offset ($dataEnd + 4) -Value ([BitConverter]::GetBytes([uint32]0x7FFFFFFF))
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $dz4, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'data descriptor CRC/sizes disagree')) `
        'verify: ambiguous prefix with lying descriptor sizes rejected'

    # Negative: DOS directory attribute bit on one entry.
    $dosDirZip = Join-Path $work 'dos-dir.zip'
    New-CraftedZip -TargetZip $dosDirZip -ExeSource $peX64 -Entries @(
        @{ Name = "$name/nkp.exe"; Path = $peX64; Attrs = 0 },
        @{ Name = "$name/LICENSE.md"; Path = $null; Attrs = 0; Bytes = [Text.Encoding]::UTF8.GetBytes('x') },
        @{ Name = "$name/README.md"; Path = $null; Attrs = 0; Bytes = [Text.Encoding]::UTF8.GetBytes('x') },
        @{ Name = "$name/WINDOWS-LIMITATIONS.txt"; Path = $null; Attrs = 0x10; Bytes = [Text.Encoding]::UTF8.GetBytes('x') })
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $dosDirZip, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'DOS directory attribute')) `
        'verify: DOS directory attribute rejected'

    # Negative: DOS reparse-point attribute bit on one entry.
    $dosReparseZip = Join-Path $work 'dos-reparse.zip'
    New-CraftedZip -TargetZip $dosReparseZip -ExeSource $peX64 -Entries @(
        @{ Name = "$name/nkp.exe"; Path = $peX64; Attrs = 0 },
        @{ Name = "$name/LICENSE.md"; Path = $null; Attrs = 0; Bytes = [Text.Encoding]::UTF8.GetBytes('x') },
        @{ Name = "$name/README.md"; Path = $null; Attrs = 0; Bytes = [Text.Encoding]::UTF8.GetBytes('x') },
        @{ Name = "$name/WINDOWS-LIMITATIONS.txt"; Path = $null; Attrs = 0x400; Bytes = [Text.Encoding]::UTF8.GetBytes('x') })
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $dosReparseZip, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'reparse-point attribute')) `
        'verify: DOS reparse-point attribute rejected'

    # Negative: Unix fifo type in the mode bits (S_IFIFO) — anything that
    # is not S_IFREG is rejected.
    $fifoZip = Join-Path $work 'fifo.zip'
    New-CraftedZip -TargetZip $fifoZip -ExeSource $peX64 -Entries @(
        @{ Name = "$name/nkp.exe"; Path = $peX64; Attrs = 0 },
        @{ Name = "$name/LICENSE.md"; Path = $null; Attrs = 0; Bytes = [Text.Encoding]::UTF8.GetBytes('x') },
        @{ Name = "$name/README.md"; Path = $null; Attrs = ([int](0x11ED -shl 16)); Bytes = [Text.Encoding]::UTF8.GetBytes('x') },
        @{ Name = "$name/WINDOWS-LIMITATIONS.txt"; Path = $null; Attrs = 0; Bytes = [Text.Encoding]::UTF8.GetBytes('x') })
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $fifoZip, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'not a regular file')) `
        'verify: Unix non-regular type (fifo) rejected'

    # Negative: an empty mandatory payload (zero-length exe entry) is
    # rejected.
    $emptyZip = Join-Path $work 'empty-payload.zip'
    New-CraftedZip -TargetZip $emptyZip -ExeSource $peX64 -Entries @(
        @{ Name = "$name/nkp.exe"; Path = $null; Attrs = 0; Bytes = @() },
        @{ Name = "$name/LICENSE.md"; Path = $null; Attrs = 0; Bytes = [Text.Encoding]::UTF8.GetBytes('x') },
        @{ Name = "$name/README.md"; Path = $null; Attrs = 0; Bytes = [Text.Encoding]::UTF8.GetBytes('x') },
        @{ Name = "$name/WINDOWS-LIMITATIONS.txt"; Path = $null; Attrs = 0; Bytes = [Text.Encoding]::UTF8.GetBytes('x') })
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $emptyZip, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'mandatory payload entry is empty')) `
        'verify: empty mandatory payload rejected'

    # Negative: mutated payload data with internally consistent CRC (the
    # zip API recomputes CRC on rewrite) — caught by hash parity.
    $mutZip = Join-Path $work 'mutated.zip'
    Copy-Item -Force $zip $mutZip
    $za = [IO.Compression.ZipFile]::Open($mutZip, 'Update')
    try {
        $e = $za.Entries | Where-Object { ($_.FullName -replace '\\', '/') -eq "$name/nkp.exe" }
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
    New-FakePE -Machine 0x014c -Path (Join-Path $c 'nkp.exe')
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

    # Contract-negative tests: remove each critical full statement from BOTH
    # published copies, keep them byte-identical, and refresh both manifest
    # hashes. The verifier must reject for that specific missing statement,
    # not because of parity or stale checksums.
    $contractStatements = @(
        'Private file writes are supported only when a protected current-user-only DACL is created and the resulting security descriptor verifies before writing.',
        'The volume must advertise persistent ACL enforcement.',
        'Unsupported or unqueryable volumes, and failed security verification, fail closed before file contents are written.',
        'The implementation uses path-based staging and assumes the containing directory is trusted and not controlled by an adversary.',
        'These guarantees are not established for every filesystem, elevated execution, or every Windows account/configuration.'
    )
    $contractNames = @(
        'protected current-user-only DACL and verified descriptor',
        'persistent ACL enforcement',
        'fail-closed unsupported-volume and verification conditions',
        'trusted containing-directory assumption',
        'unverified filesystem, elevation, and account boundaries'
    )
    for ($contractIndex = 0; $contractIndex -lt $contractStatements.Count; $contractIndex++) {
        $statement = $contractStatements[$contractIndex]
        $c = New-DistCopy "contract-$contractIndex"
        $rawLimPath = Join-Path $c 'WINDOWS-LIMITATIONS.txt'
        $normalizedNotice = [regex]::Replace([IO.File]::ReadAllText($rawLimPath), '\s+', ' ').Trim()
        $editedText = $normalizedNotice.Replace($statement, '[required statement removed]')
        [IO.File]::WriteAllText($rawLimPath, $editedText)

        $contractArchive = [IO.Compression.ZipFile]::Open(
            (Join-Path $c "$name.zip"), [IO.Compression.ZipArchiveMode]::Update)
        try {
            $entryName = "$name/WINDOWS-LIMITATIONS.txt"
            $entry = $contractArchive.GetEntry($entryName)
            $entry.Delete()
            $replacement = $contractArchive.CreateEntry($entryName)
            $stream = $replacement.Open()
            try {
                $bytes = [Text.Encoding]::UTF8.GetBytes($editedText)
                $stream.Write($bytes, 0, $bytes.Length)
            } finally {
                $stream.Dispose()
            }
        } finally {
            $contractArchive.Dispose()
        }

        $sumsFile = Join-Path $c 'SHA256SUMS'
        $limHash = (Get-FileHash -LiteralPath $rawLimPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $zipHash = (Get-FileHash -LiteralPath (Join-Path $c "$name.zip") -Algorithm SHA256).Hash.ToLowerInvariant()
        Update-SumsLine -SumsPath $sumsFile -Name 'WINDOWS-LIMITATIONS.txt' -NewHash $limHash
        Update-SumsLine -SumsPath $sumsFile -Name "$name.zip" -NewHash $zipHash

        $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
            '-Zip', (Join-Path $c "$name.zip"), '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
        $diagnostic = [regex]::Replace(($r.StdErr + ' ' + $r.StdOut), '[|\s]+', ' ').Trim()
        $reasonPresent = ($diagnostic.IndexOf('missing the required statement', [StringComparison]::OrdinalIgnoreCase) -ge 0) -and
            ($diagnostic.IndexOf($contractNames[$contractIndex], [StringComparison]::OrdinalIgnoreCase) -ge 0)
        Assert-True (($r.ExitCode -ne 0) -and
            $reasonPresent) `
            "verify: missing Windows contract statement $contractIndex rejected for the exact omission" `
            -Diag $diagnostic
    }

    # ---- SHA256SUMS validation: whitelist before read, reparse, zip identity ----

    # Negative: a traversal name in SHA256SUMS must be rejected by the
    # whitelist BEFORE the named file is opened for hashing — the escaped
    # file never exists here, so an implementation that reached the
    # filesystem would fail differently. The other two lines are exactly
    # the published names with their real hashes, so the whitelist check
    # (not the entry-count check) is what must fire.
    $c = New-DistCopy 'sums-traversal'
    $exeHash = (Get-FileHash -LiteralPath (Join-Path $c 'nkp.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    $limHash = (Get-FileHash -LiteralPath (Join-Path $c 'WINDOWS-LIMITATIONS.txt') -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText((Join-Path $c 'SHA256SUMS'), (@(
        "$exeHash  ../outside.txt",
        "$exeHash  nkp.exe",
        "$limHash  WINDOWS-LIMITATIONS.txt") -join "`n") + "`n")
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', (Join-Path $c "$name.zip"), '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'wrong file set')) `
        'verify: SHA256SUMS traversal name rejected by whitelist before any read'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $work 'outside.txt'))) `
        'verify: traversal name never resolved outside the dist dir'

    # Negative: a SHA256SUMS name that resolves to a reparse point (here a
    # symlink whose hash is recorded CORRECTLY, so a naive reader would
    # pass everything) must be rejected before hashing.
    $c = New-DistCopy 'sums-symlink'
    $reparseTarget = Join-Path $work 'reparse-target.txt'
    Copy-Item -Force (Join-Path $c 'WINDOWS-LIMITATIONS.txt') $reparseTarget
    Remove-Item -Force (Join-Path $c 'WINDOWS-LIMITATIONS.txt')
    $made = $false
    try {
        $null = New-Item -ItemType SymbolicLink -Path (Join-Path $c 'WINDOWS-LIMITATIONS.txt') -Target $reparseTarget
        $made = $true
    } catch {
        Write-Host 'skip (symlink creation unavailable on this host)'
    }
    if ($made) {
        # Record the symlink target's real hash everywhere: every naive
        # hash check now passes, only the reparse check can reject.
        Update-SumsZipLine -SumsPath (Join-Path $c 'SHA256SUMS') -ZipName 'WINDOWS-LIMITATIONS.txt' `
            -NewHash ((Get-FileHash -LiteralPath $reparseTarget -Algorithm SHA256).Hash.ToLowerInvariant())
        $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
            '-Zip', (Join-Path $c "$name.zip"), '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple)
        Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'reparse point')) `
            'verify: SHA256SUMS name resolving to a reparse point rejected'
    }

    # Negative: the dist dir's canonical zip must BE the zip that was
    # checked. Here every published hash matches (the sums line was
    # regenerated over a swapped zip), the checked zip passes all checks —
    # and an implementation that never ties the two together would let a
    # stale or substituted zip ship under a valid manifest.
    $c = New-DistCopy 'zip-identity'
    $swapped = Join-Path $c "$name.zip"
    [IO.File]::WriteAllBytes($swapped, [byte[]]@(
        0x50, 0x4B, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    Update-SumsZipLine -SumsPath (Join-Path $c 'SHA256SUMS') -ZipName "$name.zip" `
        -NewHash ((Get-FileHash -LiteralPath $swapped -Algorithm SHA256).Hash.ToLowerInvariant())
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $zip, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple, '-DistDir', $c)
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'canonical dist zip')) `
        'verify: checked zip not identical to the canonical dist zip rejected'

    # ---- smoke harness (pwsh fixtures; runs natively on Windows too) ------------
    $r = Invoke-Isolated -ScriptPath $verify -ArgumentList @(
        '-Zip', $zip, '-BuiltExe', $peX64, '-Version', $version, '-Triple', $triple,
        '-Smoke', '-SmokeExeOverride', $selfPwsh)
    $smokeDiag = "stdout:`n$($r.StdOut)`nstderr:`n$($r.StdErr)"
    Assert-True ($r.ExitCode -eq 0) 'verify: bounded smoke run passes on pwsh (--version/--help)' $smokeDiag
    if ($isWinHost) {
        # NATIVE assertion: containment is required on Windows — a passing
        # smoke run must report the kill-on-close job it actually got, not
        # a best-effort claim (a containment failure throws before this
        # line is ever printed).
        Assert-True ($r.StdOut -match 'containment: job') `
            'verify: Windows smoke run reports kill-on-close job containment' $smokeDiag
    }

    # Hang: child itself hangs; the deadline must expire, kill the whole
    # tree, and return — never wait indefinitely. Invoked via -CommandString
    # so the SmokeArguments array binds in-process (through pwsh -File the
    # '-Command' element would be misparsed as a script parameter).
    $cmd = "& '$verify' -Zip '$zip' -BuiltExe '$peX64' -Version '$version' -Triple '$triple' " +
        "-Smoke -SmokeExeOverride '$selfPwsh' " +
        "-SmokeArguments @('-NoProfile','-Command','Start-Sleep -Seconds 60') -SmokeTimeoutSeconds 3"
    $r = Invoke-Isolated -CommandString $cmd
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'exceeded 3s and was killed')) `
        'verify: hung smoke run killed at the deadline with diagnostic' `
        "stdout:`n$($r.StdOut)`nstderr:`n$($r.StdErr)"

    # Orphan: the child exits immediately after spawning a descendant that
    # inherits the redirected pipes and outlives it. The harness must fail
    # BOUNDED (never hang on the drain), kill what it can reach, and — on
    # Windows — remove the escapee via the kill-on-close job. The fixture
    # ALWAYS writes the pid file (the failure reason when it could not
    # spawn) so a Windows-native failure diagnoses itself instead of
    # crashing the suite on a missing file. -NoNewWindow makes the
    # descendant ATTACH to the fixture's console instead of creating a new
    # one, so on Windows it inherits the redirected std handles (the pipe
    # write ends) rather than getting fresh console handles — without it
    # the drain completes instantly and the orphan case never happens;
    # -ErrorAction Stop makes the spawn failure catchable so it reaches
    # the pid file instead of dying mid-assignment.
    $orphanFixture = Join-Path $work 'orphan-child.ps1'
    $orphanPidFile = Join-Path $work 'orphan-grandchild.pid'
    [IO.File]::WriteAllText($orphanFixture, "param(`$Pwsh, `$PidFile)`n" +
        "try {`n" +
        "  `$g = Start-Process -FilePath `$Pwsh -ArgumentList @('-NoProfile','-Command','Start-Sleep -Seconds 15') -NoNewWindow -PassThru -ErrorAction Stop`n" +
        "  [IO.File]::WriteAllText(`$PidFile, `$g.Id)`n" +
        "} catch {`n" +
        "  [IO.File]::WriteAllText(`$PidFile, 'ERROR: ' + `$_.Exception.Message)`n" +
        "  exit 0`n" +
        "}`n" +
        "exit 0`n")
    $cmd = "& '$verify' -Zip '$zip' -BuiltExe '$peX64' -Version '$version' -Triple '$triple' " +
        "-Smoke -SmokeExeOverride '$selfPwsh' " +
        "-SmokeArguments @('-NoProfile','-File','$orphanFixture','$selfPwsh','$orphanPidFile') -SmokeTimeoutSeconds 8"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-Isolated -CommandString $cmd
    $sw.Stop()
    $orphanDiag = "orphan pid file: $(if (Test-Path -LiteralPath $orphanPidFile) { [IO.File]::ReadAllText($orphanPidFile).Trim() } else { '<absent>' })`nstdout:`n$($r.StdOut)`nstderr:`n$($r.StdErr)"
    Assert-True (($r.ExitCode -ne 0) -and ($r.StdErr -match 'did not drain')) `
        'verify: orphaned pipe-holding descendant detected and failed bounded' $orphanDiag
    Assert-True ($sw.Elapsed.TotalSeconds -lt 30) 'verify: orphan case returned well within the deadline (no indefinite wait)'
    if ($isWinHost) {
        $pidFileText = if (Test-Path -LiteralPath $orphanPidFile -PathType Leaf) {
            [IO.File]::ReadAllText($orphanPidFile).Trim()
        } else {
            '<missing - fixture child never ran to the write>'
        }
        if ($pidFileText -match '^ERROR') {
            Assert-True $false "verify: orphan fixture could not spawn the escapee on Windows: $pidFileText" $orphanDiag
        } elseif ($pidFileText -match '<missing') {
            Assert-True $false "verify: orphan fixture never wrote the escapee PID (smoke child did not run)" $orphanDiag
        } else {
            Start-Sleep -Milliseconds 500
            $survivor = Get-Process -Id $pidFileText -ErrorAction SilentlyContinue
            if ($null -ne $survivor) {
                Assert-True $false 'verify: pipe-holding escapee SURVIVED the harness on Windows (kill-on-close job did not remove it)' $orphanDiag
            } else {
                Write-Host 'ok   verify: Windows kill-on-close job removed the pipe-holding escapee (no survivor)'
            }
        }
    }

    if ($script:failures -gt 0) {
        Write-Host "windows packaging tests failed: $script:failures problem(s)"
        exit 1
    }
    Write-Host 'windows packaging tests ok'
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

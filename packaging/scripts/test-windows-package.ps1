#Requires -Version 7.0
# Self-tests for windows-validate.ps1 and windows-package.ps1. Runs under
# pwsh on any host (the PE check reads bytes, so no Windows is needed).
# Crafts fake PE binaries, asserts the pass and failure paths, runs the
# packager end-to-end, and verifies the produced zip, SHA256SUMS format,
# hashes, and shipped limitations readme.
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

# Writes a minimal fake PE: MZ signature, e_lfanew at 0x3C pointing at a
# PE\0\0 signature followed by the given COFF machine value.
function New-FakePE {
    param([Parameter(Mandatory)][ushort] $Machine, [Parameter(Mandatory)][string] $Path)
    $peOffset = [uint32]0x80
    $buf = [byte[]]::new(0x200)
    $buf[0] = 0x4D; $buf[1] = 0x5A                                # 'M','Z'
    [BitConverter]::GetBytes($peOffset).CopyTo($buf, 0x3C)        # e_lfanew
    $buf[$peOffset] = 0x50; $buf[$peOffset + 1] = 0x45            # 'P','E'
    [BitConverter]::GetBytes($Machine).CopyTo($buf, $peOffset + 4) # machine
    [IO.File]::WriteAllBytes($Path, $buf)
}

# Runs a script and reports whether it threw.
function Test-Throws {
    param([Parameter(Mandatory)][scriptblock] $Block, [Parameter(Mandatory)][string] $Message)
    $threw = $false
    try { & $Block } catch { $threw = $true }
    Assert-True $threw $Message
}

$work = Join-Path $WorkDir ("nkeepass-pkgtest-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    # ---- windows-validate.ps1 -------------------------------------------------
    $peX64 = Join-Path $work 'fake-x64.exe'
    New-FakePE -Machine 0x8664 -Path $peX64
    & (Join-Path $scripts 'windows-validate.ps1') -Binary $peX64 -Machine x64
    Assert-True ($LASTEXITCODE -eq 0) 'validate: fake x64 PE accepted'

    $peI386 = Join-Path $work 'fake-i386.exe'
    New-FakePE -Machine 0x014c -Path $peI386
    Test-Throws { & (Join-Path $scripts 'windows-validate.ps1') -Binary $peI386 -Machine x64 } `
        'validate: i386 PE rejected when expecting x64'
    & (Join-Path $scripts 'windows-validate.ps1') -Binary $peI386 -Machine i386
    Assert-True ($LASTEXITCODE -eq 0) 'validate: i386 PE accepted when expecting i386'

    $notPe = Join-Path $work 'not-pe.bin'
    [IO.File]::WriteAllBytes($notPe, [byte[]]::new(0x100))
    Test-Throws { & (Join-Path $scripts 'windows-validate.ps1') -Binary $notPe -Machine x64 } `
        'validate: zero-filled file rejected'
    Test-Throws { & (Join-Path $scripts 'windows-validate.ps1') -Binary (Join-Path $work 'missing.exe') -Machine x64 } `
        'validate: missing file rejected'

    # ---- windows-package.ps1 --------------------------------------------------
    $out = Join-Path $work 'dist'
    & (Join-Path $scripts 'windows-package.ps1') -Binary $peX64 -Version '9.9.9-test' `
        -Triple x86_64-pc-windows-msvc -OutputDir $out
    Assert-True ($LASTEXITCODE -eq 0) 'package: ran clean'

    $name = 'nkeepass-9.9.9-test-x86_64-pc-windows-msvc'
    $zip = Join-Path $out "$name.zip"
    Assert-True (Test-Path -LiteralPath $zip -PathType Leaf) "package: $name.zip exists"
    Assert-True (Test-Path -LiteralPath (Join-Path $out 'nkeepass.exe') -PathType Leaf) 'package: raw nkeepass.exe shipped'
    Assert-True (Test-Path -LiteralPath (Join-Path $out 'WINDOWS-LIMITATIONS.txt') -PathType Leaf) 'package: limitations readme shipped'
    $sumsPath = Join-Path $out 'SHA256SUMS'
    Assert-True (Test-Path -LiteralPath $sumsPath -PathType Leaf) 'package: SHA256SUMS shipped'

    # SHA256SUMS: three entries, sha256sum-compatible, hashes correct.
    $sums = [IO.File]::ReadAllText($sumsPath)
    $lines = $sums -split "`n" | Where-Object { $_ -ne '' }
    Assert-True ($lines.Count -eq 3) 'SHA256SUMS: exactly three entries'
    foreach ($line in $lines) {
        Assert-True ($line -match '^[0-9a-f]{64}  \S+$') "SHA256SUMS: entry format: $line"
    }
    $hashOk = $true
    foreach ($line in $lines) {
        $parts = $line -split '  ', 2
        $actual = (Get-FileHash -LiteralPath (Join-Path $out $parts[1]) -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($parts[0] -ne $actual) { $hashOk = $false }
    }
    Assert-True $hashOk 'SHA256SUMS: every hash matches Get-FileHash'
    Assert-True ($sums.EndsWith("`n") -and -not $sums.Contains("`r")) 'SHA256SUMS: LF endings, trailing newline'

    # Zip contents and the limitations text inside it.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($zip)
    try {
        $entryNames = $archive.Entries.FullName | Sort-Object
        $expect = @("$name/LICENSE.md", "$name/README.md", "$name/WINDOWS-LIMITATIONS.txt", "$name/nkeepass.exe") | Sort-Object
        Assert-True (@(Compare-Object $entryNames $expect).Count -eq 0) "zip: entries are exactly the expected four"
        $limitEntry = $archive.Entries | Where-Object { $_.FullName -like '*WINDOWS-LIMITATIONS.txt' }
        $reader = New-Object IO.StreamReader($limitEntry.Open())
        $limitText = $reader.ReadToEnd()
        $reader.Close()
        Assert-True ($limitText -match 'SECURE OWNER-ONLY FILE WRITES ARE NOT SUPPORTED') `
            'zip: limitations readme carries the secure-writes warning'
    } finally {
        $archive.Dispose()
    }

    # Idempotency: a second run overwrites cleanly instead of failing.
    & (Join-Path $scripts 'windows-package.ps1') -Binary $peX64 -Version '9.9.9-test' `
        -Triple x86_64-pc-windows-msvc -OutputDir $out
    Assert-True ($LASTEXITCODE -eq 0) 'package: second run is a clean overwrite'

    # Failure path: missing binary input.
    Test-Throws { & (Join-Path $scripts 'windows-package.ps1') -Binary (Join-Path $work 'missing.exe') `
            -Version '9.9.9-test' -Triple x86_64-pc-windows-msvc -OutputDir $out } `
        'package: missing binary rejected'

    if ($script:failures -gt 0) {
        Write-Host "windows packaging tests failed: $script:failures problem(s)"
        exit 1
    }
    Write-Host 'windows packaging tests ok'
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

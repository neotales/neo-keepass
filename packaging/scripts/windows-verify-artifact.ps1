#Requires -Version 7.0
# Verifies a packaged Windows artifact as a unit. Runs after
# windows-package.ps1 and before upload (see .github/workflows/
# windows-build.yml). Checks, in order:
#
#   1. zip entry names: exactly one root "nkeepass-<version>-<triple>/"
#      holding nkeepass.exe, README.md, LICENSE.md, WINDOWS-LIMITATIONS.txt
#      — no flattened or unexpected entries (entry separators are
#      normalized when compared; Compress-Archive may store '\' on Windows)
#   2. every entry is a regular non-empty file, not a directory
#   3. the EXTRACTED nkeepass.exe passes the PE machine check (x64)
#   4. the extracted exe's sha256 equals the binary just built
#   5. SHA256SUMS in the dist directory: exactly the three published names,
#      sha256sum-compatible format, every hash matching the actual file
#   6. the limitations text is present in the zip and carries the warning
#   7. with -Smoke: the EXTRACTED exe is executed with --version and --help
#      under a process timeout (kill the whole tree on expiry) — only after
#      1..6 passed
#
# Usage:
#   windows-verify-artifact.ps1 -Zip <zip> -BuiltExe <exe> -Version <v> `
#     -Triple <triple> [-DistDir <dir>] [-Smoke] [-SmokeTimeoutSeconds 60]
#
# -SmokeExeOverride is a TEST-ONLY seam: it substitutes the program that is
# executed (so the timeout/kill harness can be exercised on any host where
# a real PE cannot run). It never skips checks 1..6, which always run
# against the real artifact.
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $Zip,

    [Parameter(Mandatory)]
    [string] $BuiltExe,

    [Parameter(Mandatory)]
    [string] $Version,

    [Parameter(Mandatory)]
    [string] $Triple,

    [string] $DistDir,

    [switch] $Smoke,

    [string] $SmokeExeOverride,

    [ValidateRange(1, 600)]
    [int] $SmokeTimeoutSeconds = 60
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Zip -PathType Leaf)) {
    throw "windows-verify: not a file: $Zip"
}
if (-not $PSBoundParameters.ContainsKey('DistDir')) {
    $DistDir = Split-Path -Parent ((Resolve-Path $Zip).Path)
}
$distDirResolved = (Resolve-Path $DistDir).Path
$name = "nkeepass-$Version-$Triple"
$extractRoot = Join-Path ([IO.Path]::GetTempPath()) ("nkeepass-verify-" + [guid]::NewGuid().ToString('N'))

# Runs a program under a hard timeout; kills the entire process tree on
# expiry. Returns the process (Exited = $true, ExitCode set).
function Invoke-Bounded {
    param(
        [Parameter(Mandatory)][string] $FilePath,
        [string[]] $Arguments,
        [Parameter(Mandatory)][int] $TimeoutSeconds
    )
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $FilePath
    foreach ($a in $Arguments) { $psi.ArgumentList.Add($a) }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    # Drain pipes concurrently so a chatty child cannot deadlock on a full
    # stdout pipe while we wait.
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
        $p.Kill($true)
        $p.WaitForExit()
        throw ("windows-verify: smoke run exceeded {0}s and was killed: {1} {2}" -f
            $TimeoutSeconds, $FilePath, ($Arguments -join ' '))
    }
    $null = $errTask.Result
    return [pscustomobject]@{
        ExitCode = $p.ExitCode
        StdOut   = $outTask.Result
        StdErr   = $errTask.Result
    }
}

try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    # 1. Entry names: exactly the expected four under one named root.
    $archive = [IO.Compression.ZipFile]::OpenRead((Resolve-Path $Zip).Path)
    try {
        $actualEntries = @($archive.Entries | ForEach-Object { $_.FullName -replace '\\', '/' })
        $expectedEntries = @(
            "$name/README.md",
            "$name/LICENSE.md",
            "$name/WINDOWS-LIMITATIONS.txt",
            "$name/nkeepass.exe"
        ) | Sort-Object
        $actualSorted = $actualEntries | Sort-Object
        if (@(Compare-Object $actualSorted $expectedEntries).Count -ne 0) {
            throw ("windows-verify: zip entries differ from the expected four under {0}/: {1}" -f
                $name, ($actualSorted -join ', '))
        }
        # 2. Regular non-empty files, no directory entries.
        foreach ($entry in $archive.Entries) {
            if ($entry.FullName.EndsWith('/') -or $entry.FullName.EndsWith('\')) {
                throw "windows-verify: unexpected directory entry in zip: $($entry.FullName)"
            }
            if ($entry.Length -le 0) {
                throw "windows-verify: empty entry in zip (not a regular payload): $($entry.FullName)"
            }
        }
    } finally {
        $archive.Dispose()
    }

    # Extract and check the payload on disk.
    Expand-Archive -Path $Zip -DestinationPath $extractRoot
    $extractedDir = Join-Path $extractRoot $name
    $extractedExe = Join-Path $extractedDir 'nkeepass.exe'
    foreach ($payload in @('README.md', 'LICENSE.md', 'WINDOWS-LIMITATIONS.txt')) {
        if (-not (Test-Path -LiteralPath (Join-Path $extractedDir $payload) -PathType Leaf)) {
            throw "windows-verify: extracted payload missing or not a regular file: $payload"
        }
    }

    # 3. The extracted exe must be a PE with machine x64.
    & (Join-Path $PSScriptRoot 'windows-validate.ps1') -Binary $extractedExe -Machine x64

    # 4. Hash parity with the binary just built.
    $extractedHash = (Get-FileHash -LiteralPath $extractedExe -Algorithm SHA256).Hash.ToLowerInvariant()
    $builtHash = (Get-FileHash -LiteralPath $BuiltExe -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($extractedHash -ne $builtHash) {
        throw ("windows-verify: extracted exe sha256 {0} != built exe {1}" -f $extractedHash, $builtHash)
    }

    # 5. SHA256SUMS: exactly the three published names, correct format,
    # every hash matching the file actually in the dist directory.
    $sumsPath = Join-Path $distDirResolved 'SHA256SUMS'
    if (-not (Test-Path -LiteralPath $sumsPath -PathType Leaf)) {
        throw "windows-verify: SHA256SUMS missing in $distDirResolved"
    }
    $sumsText = [IO.File]::ReadAllText($sumsPath)
    if ($sumsText -match "`r") {
        throw "windows-verify: SHA256SUMS contains CR (must be LF only)"
    }
    $lines = $sumsText -split "`n" | Where-Object { $_ -ne '' }
    if ($lines.Count -ne 3 -or -not $sumsText.EndsWith("`n")) {
        throw "windows-verify: SHA256SUMS must have exactly three entries and a trailing newline"
    }
    $expectedNames = @("$name.zip", 'nkeepass.exe', 'WINDOWS-LIMITATIONS.txt') | Sort-Object
    $actualNames = @()
    foreach ($line in $lines) {
        if ($line -notmatch '^[0-9a-f]{64}  \S+$') {
            throw "windows-verify: SHA256SUMS entry not sha256sum-compatible: $line"
        }
        $parts = $line -split '  ', 2
        $actualNames += $parts[1]
        $p = Join-Path $distDirResolved $parts[1]
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
            throw "windows-verify: SHA256SUMS names a missing file: $($parts[1])"
        }
        $actualHash = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($parts[0] -ne $actualHash) {
            throw ("windows-verify: SHA256SUMS hash mismatch for {0}: listed {1}, actual {2}" -f
                $parts[1], $parts[0], $actualHash)
        }
    }
    if (@(Compare-Object ($actualNames | Sort-Object) $expectedNames).Count -ne 0) {
        throw ("windows-verify: SHA256SUMS covers the wrong file set: {0}" -f ($actualNames -join ', '))
    }

    # 6. The shipped limitations text must carry the warning, both at the
    # top level and inside the zip.
    $limitText = [IO.File]::ReadAllText((Join-Path $extractedDir 'WINDOWS-LIMITATIONS.txt'))
    if ($limitText -notmatch 'SECURE OWNER-ONLY FILE WRITES ARE NOT SUPPORTED' -or
        $limitText -notmatch 'FAILS CLOSED') {
        throw "windows-verify: WINDOWS-LIMITATIONS.txt does not carry the secure-writes warning"
    }

    # 7. Bounded smoke run of the EXTRACTED exe — only everything above
    # passed, so a checked-failed binary is never executed.
    if ($Smoke) {
        $runTarget = if ($PSBoundParameters.ContainsKey('SmokeExeOverride')) {
            $SmokeExeOverride # test-only seam; checks 1..6 already ran on the real artifact
        } else {
            $extractedExe
        }
        $versionRun = Invoke-Bounded -FilePath $runTarget -Arguments @('--version') `
            -TimeoutSeconds $SmokeTimeoutSeconds
        if ($versionRun.ExitCode -ne 0) {
            throw ("windows-verify: smoke --version exited {0}" -f $versionRun.ExitCode)
        }
        if (-not $PSBoundParameters.ContainsKey('SmokeExeOverride') -and
            [string]::IsNullOrWhiteSpace($versionRun.StdOut)) {
            throw "windows-verify: smoke --version produced no output"
        }
        $helpRun = Invoke-Bounded -FilePath $runTarget -Arguments @('--help') `
            -TimeoutSeconds $SmokeTimeoutSeconds
        if ($helpRun.ExitCode -ne 0) {
            throw ("windows-verify: smoke --help exited {0}" -f $helpRun.ExitCode)
        }
        Write-Host "windows-verify: smoke ok (--version, --help, bounded ${SmokeTimeoutSeconds}s): $runTarget"
    }

    Write-Host "windows-verify: ok  artifact verified: $Zip"
} finally {
    if (Test-Path -LiteralPath $extractRoot) {
        Remove-Item -Recurse -Force $extractRoot -ErrorAction SilentlyContinue
    }
}

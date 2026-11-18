#Requires -Version 7.0
# Packages an already-built Windows release binary for distribution:
#
#   <OutputDir>/nkeepass-<version>-<triple>.zip
#       one entry root "nkeepass-<version>-<triple>/" containing
#       nkp.exe (the product's executable name), README.md, LICENSE.md,
#       WINDOWS-LIMITATIONS.txt
#   <OutputDir>/nkp.exe                    (raw, for direct download)
#   <OutputDir>/WINDOWS-LIMITATIONS.txt    (readable without unzipping)
#   <OutputDir>/SHA256SUMS                 (covers all three, sha256sum -c
#                                           compatible: "<hex>  <name>",
#                                           LF line endings, forward-slash
#                                           names relative to <OutputDir>)
#
# Output discipline: publication is NOT atomic, and this script does not
# claim a transaction. The SHA256SUMS manifest is invalidated (removed)
# FIRST — and if the existing manifest cannot be removed the run FAILS
# BEFORE touching any payload file — then the payload files are copied,
# and the manifest is written LAST of all. Therefore an interrupted or
# failed run can leave a mixed set of old and new payload files with NO
# manifest, or the untouched old set with the untouched old manifest, but
# never a manifest describing a set it does not match — a consumer that
# treats a missing or failing `sha256sum -c` as fatal cannot be fooled by
# a partial publish. The test-only NEOKEEPASS_PACKAGE_FAIL_AFTER env var
# (values: zip | exe | limitations) injects a failure after that file is
# published to exercise the mid-publish state; the manifest-invalidation
# failure path is exercised by locking the manifest (Windows) or making
# the output directory read-only (Unix) in test-windows-package.ps1.
#
# Re-running overwrites the outputs; it is safe to re-run. Usage:
#
#   windows-package.ps1 -Binary <nkp.exe> -Version <ver> `
#     -Triple x86_64-pc-windows-msvc -OutputDir <dir>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $Binary,

    [Parameter(Mandatory)]
    [string] $Version,

    [Parameter(Mandatory)]
    [string] $Triple,

    [Parameter(Mandatory)]
    [string] $OutputDir
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    throw "windows-package: not a file: $Binary"
}
$limitations = Join-Path $repoRoot 'packaging/windows/WINDOWS-LIMITATIONS.txt'
foreach ($required in @((Join-Path $repoRoot 'README.md'), (Join-Path $repoRoot 'LICENSE.md'), $limitations)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "windows-package: required file missing: $required"
    }
}

$name = "nkeepass-$Version-$Triple"
if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}
$outDir = (Resolve-Path $OutputDir).Path
$stage = Join-Path ([IO.Path]::GetTempPath()) ("nkeepass-package-" + [guid]::NewGuid().ToString('N'))

try {
    # Stage the archive payload in a fresh private temp directory. The
    # directory itself is passed to Compress-Archive — NOT "$pkgDir\*",
    # which would flatten the payload and drop the enclosing
    # nkeepass-<version>-<triple>/ root from the entry names.
    $pkgDir = Join-Path $stage $name
    New-Item -ItemType Directory -Path $pkgDir -Force | Out-Null
    Copy-Item -LiteralPath $Binary -Destination (Join-Path $pkgDir 'nkp.exe')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'README.md') $pkgDir
    Copy-Item -LiteralPath (Join-Path $repoRoot 'LICENSE.md') $pkgDir
    Copy-Item -LiteralPath $limitations $pkgDir

    $zip = Join-Path $stage "$name.zip"
    Compress-Archive -Path $pkgDir -DestinationPath $zip -CompressionLevel Optimal

    # Top-level copies, hashed from the staging tree (identical bytes to
    # what gets published below).
    $rawExe = Join-Path $stage 'nkp.exe'
    $rawLimitations = Join-Path $stage 'WINDOWS-LIMITATIONS.txt'
    Copy-Item -LiteralPath $Binary -Destination $rawExe
    Copy-Item -LiteralPath $limitations -Destination $rawLimitations

    # sha256sum-compatible checksums: lowercase hex, two spaces, forward-slash
    # name, LF endings and a trailing newline, so `sha256sum -c SHA256SUMS`
    # works unchanged on Linux and macOS.
    $files = @("$name.zip", 'nkp.exe', 'WINDOWS-LIMITATIONS.txt')
    $sources = @($zip, $rawExe, $rawLimitations)
    $lines = for ($i = 0; $i -lt $files.Count; $i++) {
        $hash = (Get-FileHash -LiteralPath $sources[$i] -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $($files[$i])"
    }
    $sums = Join-Path $stage 'SHA256SUMS'
    [IO.File]::WriteAllText($sums, ($lines -join "`n") + "`n", [Text.UTF8Encoding]::new($false))

    # Commit to <OutputDir>. Invalidate the manifest first, publish the
    # payload files, write the manifest last — see the header note: this
    # is not atomic, but a manifest is never left describing a set it
    # does not match.
    #
    # Invalidation is a HARD step: if the existing manifest cannot be
    # removed (locked by a scanner or backup, ACL-denied, a directory),
    # the run fails BEFORE any payload file is updated — continuing would
    # replace files underneath a manifest that still stands, publishing a
    # stale manifest over a mixed set. Only a genuinely absent manifest
    # (nothing to invalidate) is tolerated.
    $existingSums = Join-Path $outDir 'SHA256SUMS'
    try {
        Remove-Item -LiteralPath $existingSums -Force -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
        # Nothing to invalidate.
    } catch {
        throw ("windows-package: could not invalidate the existing SHA256SUMS, refusing to update any payload file under a manifest that cannot be removed: {0}" -f
            $_.Exception.Message)
    }
    Copy-Item -LiteralPath $zip -Destination (Join-Path $outDir "$name.zip") -Force
    if ($env:NEOKEEPASS_PACKAGE_FAIL_AFTER -eq 'zip') { throw 'windows-package: injected test failure after zip publish' }
    Copy-Item -LiteralPath $rawExe -Destination (Join-Path $outDir 'nkp.exe') -Force
    if ($env:NEOKEEPASS_PACKAGE_FAIL_AFTER -eq 'exe') { throw 'windows-package: injected test failure after exe publish' }
    Copy-Item -LiteralPath $rawLimitations -Destination (Join-Path $outDir 'WINDOWS-LIMITATIONS.txt') -Force
    if ($env:NEOKEEPASS_PACKAGE_FAIL_AFTER -eq 'limitations') { throw 'windows-package: injected test failure after limitations publish' }
    Copy-Item -LiteralPath $sums -Destination (Join-Path $outDir 'SHA256SUMS') -Force
}
finally {
    if (Test-Path -LiteralPath $stage) {
        Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
    }
}
Write-Host "windows-package: wrote $name.zip, nkp.exe, WINDOWS-LIMITATIONS.txt, SHA256SUMS to $OutputDir"

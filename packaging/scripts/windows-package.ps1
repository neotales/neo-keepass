#Requires -Version 7.0
# Packages an already-built Windows release binary for distribution:
#
#   <OutputDir>/nkeepass-<version>-<triple>.zip
#       one entry root "nkeepass-<version>-<triple>/" containing
#       nkeepass.exe, README.md, LICENSE.md, WINDOWS-LIMITATIONS.txt
#   <OutputDir>/nkeepass.exe               (raw, for direct download)
#   <OutputDir>/WINDOWS-LIMITATIONS.txt    (readable without unzipping)
#   <OutputDir>/SHA256SUMS                 (covers all three, sha256sum -c
#                                           compatible: "<hex>  <name>",
#                                           LF line endings, forward-slash
#                                           names relative to <OutputDir>)
#
# Output discipline: everything is built and hashed in a private temp
# staging tree first; the four files are copied into <OutputDir> only at
# the end, in that order, SHA256SUMS last. A failed run therefore never
# leaves a checksum file describing files that are missing or different —
# either the full consistent set is present or the output is untouched.
#
# Re-running overwrites the outputs; it is safe to re-run. Usage:
#
#   windows-package.ps1 -Binary <nkeepass.exe> -Version <ver> `
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
    Copy-Item -LiteralPath $Binary -Destination (Join-Path $pkgDir 'nkeepass.exe')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'README.md') $pkgDir
    Copy-Item -LiteralPath (Join-Path $repoRoot 'LICENSE.md') $pkgDir
    Copy-Item -LiteralPath $limitations $pkgDir

    $zip = Join-Path $stage "$name.zip"
    Compress-Archive -Path $pkgDir -DestinationPath $zip -CompressionLevel Optimal

    # Top-level copies, hashed from the staging tree (identical bytes to
    # what gets published below).
    $rawExe = Join-Path $stage 'nkeepass.exe'
    $rawLimitations = Join-Path $stage 'WINDOWS-LIMITATIONS.txt'
    Copy-Item -LiteralPath $Binary -Destination $rawExe
    Copy-Item -LiteralPath $limitations -Destination $rawLimitations

    # sha256sum-compatible checksums: lowercase hex, two spaces, forward-slash
    # name, LF endings and a trailing newline, so `sha256sum -c SHA256SUMS`
    # works unchanged on Linux and macOS.
    $files = @("$name.zip", 'nkeepass.exe', 'WINDOWS-LIMITATIONS.txt')
    $sources = @($zip, $rawExe, $rawLimitations)
    $lines = for ($i = 0; $i -lt $files.Count; $i++) {
        $hash = (Get-FileHash -LiteralPath $sources[$i] -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $($files[$i])"
    }
    $sums = Join-Path $stage 'SHA256SUMS'
    [IO.File]::WriteAllText($sums, ($lines -join "`n") + "`n", [Text.UTF8Encoding]::new($false))

    # Commit to <OutputDir> last, in this order: payload files first,
    # SHA256SUMS last — a checksum file never precedes the files it
    # describes, so an interrupted run cannot leave a "valid-looking" SUMS
    # over a partial set.
    Copy-Item -LiteralPath $zip -Destination (Join-Path $outDir "$name.zip") -Force
    Copy-Item -LiteralPath $rawExe -Destination (Join-Path $outDir 'nkeepass.exe') -Force
    Copy-Item -LiteralPath $rawLimitations -Destination (Join-Path $outDir 'WINDOWS-LIMITATIONS.txt') -Force
    Copy-Item -LiteralPath $sums -Destination (Join-Path $outDir 'SHA256SUMS') -Force
}
finally {
    if (Test-Path -LiteralPath $stage) {
        Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
    }
}
Write-Host "windows-package: wrote $name.zip, nkeepass.exe, WINDOWS-LIMITATIONS.txt, SHA256SUMS to $OutputDir"

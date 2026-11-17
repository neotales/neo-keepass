#Requires -Version 7.0
# Packages an already-built Windows release binary for distribution:
#
#   <OutputDir>/nkeepass-<version>-<triple>.zip
#       contains nkeepass.exe, README.md, LICENSE.md,
#       WINDOWS-LIMITATIONS.txt
#   <OutputDir>/nkeepass.exe               (raw, for direct download)
#   <OutputDir>/WINDOWS-LIMITATIONS.txt    (readable without unzipping)
#   <OutputDir>/SHA256SUMS                 (covers all three, sha256sum -c
#                                           compatible: "<hex>  <name>",
#                                           LF line endings, forward-slash
#                                           names relative to <OutputDir>)
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
    # Stage the archive payload in a fresh private temp directory.
    $pkgDir = Join-Path $stage $name
    New-Item -ItemType Directory -Path $pkgDir -Force | Out-Null
    Copy-Item -LiteralPath $Binary -Destination (Join-Path $pkgDir 'nkeepass.exe')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'README.md') $pkgDir
    Copy-Item -LiteralPath (Join-Path $repoRoot 'LICENSE.md') $pkgDir
    Copy-Item -LiteralPath $limitations $pkgDir

    $zip = Join-Path $outDir "$name.zip"
    if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
    # Compress-Archive note: on Windows, .NET writes zip entry names with the
    # platform separator. Mainstream extractors (Explorer, 7-Zip, Info-ZIP
    # unzip) normalize them to directory separators. If POSIX-exact entry
    # names ever matter, switch to tar.exe -a -cf (bsdtar writes '/').
    Compress-Archive -Path (Join-Path $pkgDir '*') -DestinationPath $zip -CompressionLevel Optimal

    # Also ship the raw binary and the limitations readme at the top level so
    # the artifact is inspectable without unzipping.
    Copy-Item -LiteralPath $Binary -Destination (Join-Path $outDir 'nkeepass.exe') -Force
    Copy-Item -LiteralPath $limitations -Destination (Join-Path $outDir 'WINDOWS-LIMITATIONS.txt') -Force

    # sha256sum-compatible checksums: lowercase hex, two spaces, forward-slash
    # name, LF endings and a trailing newline, so `sha256sum -c SHA256SUMS`
    # works unchanged on Linux and macOS.
    $files = @("$name.zip", 'nkeepass.exe', 'WINDOWS-LIMITATIONS.txt')
    $lines = foreach ($f in $files) {
        $p = Join-Path $outDir $f
        $hash = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $f"
    }
    [IO.File]::WriteAllText(
        (Join-Path $outDir 'SHA256SUMS'),
        ($lines -join "`n") + "`n",
        [Text.UTF8Encoding]::new($false))
}
finally {
    if (Test-Path -LiteralPath $stage) {
        Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
    }
}
Write-Host "windows-package: wrote $name.zip, nkeepass.exe, WINDOWS-LIMITATIONS.txt, SHA256SUMS to $OutputDir"

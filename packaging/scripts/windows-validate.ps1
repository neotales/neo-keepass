#Requires -Version 7.0
# Validates that a Windows binary is a PE executable whose COFF machine
# field matches the expected architecture. Reads bytes only — no Windows
# required, so it runs under pwsh on any host. Exits nonzero with a
# diagnostic on any mismatch: missing file, missing MZ signature, missing
# PE signature, or wrong machine.
#
# Usage:
#   windows-validate.ps1 -Binary <path-to-.exe> [-Machine x64|i386|arm64]
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $Binary,

    [ValidateSet('x64', 'i386', 'arm64')]
    [string] $Machine = 'x64'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# COFF machine constants from the PE/COFF specification.
$expected = switch ($Machine) {
    'x64'   { 0x8664 } # IMAGE_FILE_MACHINE_AMD64
    'i386'  { 0x014c } # IMAGE_FILE_MACHINE_I386
    'arm64' { 0xaa64 } # IMAGE_FILE_MACHINE_ARM64
}

if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    throw "windows-validate: not a file: $Binary"
}

$bytes = [IO.File]::ReadAllBytes($Binary)
if ($bytes.Length -lt 0x40) {
    throw "windows-validate: too small to hold a DOS header ($($bytes.Length) bytes): $Binary"
}
if ($bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
    throw "windows-validate: missing MZ signature: $Binary"
}

# e_lfanew at offset 0x3C points at the PE signature.
$peOffset = [BitConverter]::ToUInt32($bytes, 0x3C)
if ($peOffset -lt 0x40 -or ($peOffset + 6) -gt $bytes.Length) {
    throw "windows-validate: e_lfanew (0x$($peOffset.ToString('X'))) out of range: $Binary"
}
if ($bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45 -or
    $bytes[$peOffset + 2] -ne 0 -or $bytes[$peOffset + 3] -ne 0) {
    throw "windows-validate: missing PE signature: $Binary"
}

# Named $actualMachine, NOT $machine: PowerShell variables are
# case-insensitive, so $machine would collide with the $Machine parameter
# and overwrite it — corrupting both the diagnostic and, in any future
# reordering, the check itself.
$actualMachine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
if ($actualMachine -ne $expected) {
    throw ("windows-validate: PE machine 0x{0:X4} != expected 0x{1:X4} ({2}): {3}" -f
        $actualMachine, $expected, $Machine, $Binary)
}
Write-Host ("windows-validate: ok  PE machine 0x{0:X4} ({1}): {2}" -f $actualMachine, $Machine, $Binary)

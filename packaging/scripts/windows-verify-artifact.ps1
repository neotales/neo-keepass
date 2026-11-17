#Requires -Version 7.0
# Verifies a packaged Windows artifact as a unit. Runs after
# windows-package.ps1 and before upload (see .github/workflows/
# windows-build.yml). Checks, in order:
#
#   1. zip manifest is parsed and WHITELISTED BEFORE anything is opened for
#      extraction: exactly four entries, each named "<root>/<file>" with a
#      strict filename charset (no path separators beyond the single root,
#      no ".." segments, no absolute paths), no duplicates, no directory
#      entries, and no symlink/reparse external attributes. An entry that
#      is not exactly the expected canonical set fails the verification
#      before any byte is read from it — an out-of-root canary entry is
#      never read, let alone extracted.
#   2. every whitelisted entry's CRC32 is computed explicitly (compiled
#      helper) and compared to the recorded value — corrupt archives are
#      rejected before extraction.
#   3. extraction is manual, from the validated set, into a fresh private
#      temp dir (paths are built from the constant canonical names, never
#      from entry strings).
#   4. the EXTRACTED nkeepass.exe passes the PE machine check (x64).
#   5. the extracted exe's sha256 equals the binary just built.
#   6. the RAW top-level dist files are checked too: nkeepass.exe must
#      equal the built binary's hash and pass the PE check;
#      WINDOWS-LIMITATIONS.txt must be byte-identical to the zip copy and
#      carry the mandated warning text.
#   7. SHA256SUMS in the dist directory: exactly the three published
#      names, sha256sum-compatible format, every hash matching the actual
#      file.
#   8. with -Smoke: the EXTRACTED exe is executed with --version and
#      --help under ONE deadline that encompasses execution, stream
#      completion and cleanup. Nothing waits indefinitely: process wait,
#      stdout/stderr drains and cleanup are all bounded by the deadline;
#      on expiry the whole process tree is killed. On Windows the child is
#      assigned to a kill-on-close job object, so descendants that outlive
#      the parent (holding redirected pipes) are still terminated when the
#      job handle is closed — no orphan can hold the harness hostage. On
#      non-Windows hosts tree kill is best-effort but every wait stays
#      bounded, so the harness itself can never hang.
#
# Usage:
#   windows-verify-artifact.ps1 -Zip <zip> -BuiltExe <exe> -Version <v> `
#     -Triple <triple> [-DistDir <dir>] [-Smoke] [-SmokeTimeoutSeconds 60]
#
# -SmokeExeOverride and -SmokeArguments are TEST-ONLY seams: they
# substitute the program and arguments executed in step 8 (so the
# timeout/kill/orphan harness can be exercised on any host where a real
# PE cannot run). They never skip steps 1..7, which always run against
# the real artifact.
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

    [string[]] $SmokeArguments,

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
$isWindowsHost = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
    [System.Runtime.InteropServices.OSPlatform]::Windows)

# Compiled helpers: CRC32 (explicit archive integrity) and, on Windows
# only, a kill-on-close job object (orphan containment).
if (-not ('Crc32' -as [type])) {
    $jobCode = ''
    if ($isWindowsHost) {
        $jobCode = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class JobOps {
    [StructLayout(LayoutKind.Sequential)]
    struct IO_COUNTERS { public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount; }
    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string lpName);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetInformationJobObject(IntPtr hJob, int JobObjectInfoClass, IntPtr lpJobObjectInfo, int cbJobObjectInfoLength);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);
    public static IntPtr CreateKillOnCloseJob() {
        IntPtr job = CreateJobObjectW(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw new Win32Exception();
        var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        info.BasicLimitInformation.LimitFlags = 0x200; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        int len = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
        IntPtr ptr = Marshal.AllocHGlobal(len);
        try {
            Marshal.StructureToPtr(info, ptr, false);
            if (!SetInformationJobObject(job, 9, ptr, len)) throw new Win32Exception();
        } finally { Marshal.FreeHGlobal(ptr); }
        return job;
    }
    public static void Assign(IntPtr hJob, IntPtr hProcess) {
        if (!AssignProcessToJobObject(hJob, hProcess)) throw new Win32Exception();
    }
    public static bool Close(IntPtr hJob) { return CloseHandle(hJob); }
}
'@
    }
    $crcSource = @"
using System.IO;
public static class Crc32 {
    static readonly uint[] Table = new uint[256];
    static Crc32() {
        for (uint i = 0; i < 256; i++) {
            uint c = i;
            for (int j = 0; j < 8; j++) c = ((c & 1) != 0) ? (c >> 1) ^ 0xEDB88320u : c >> 1;
            Table[i] = c;
        }
    }
    public static uint Compute(Stream stream) {
        uint crc = 0xFFFFFFFFu;
        var buf = new byte[8192];
        int n;
        while ((n = stream.Read(buf, 0, buf.Length)) > 0)
            for (int k = 0; k < n; k++) crc = (crc >> 8) ^ Table[(crc ^ buf[k]) & 0xFF];
        return crc ^ 0xFFFFFFFFu;
    }
}
"@
    Add-Type -TypeDefinition ($crcSource + $jobCode)
    }

    # Kills the process and its whole tree, then waits (bounded) for exit.
    function Stop-Tree {
        param([Parameter(Mandatory)] $Process)
        if ($Process.HasExited) { return }
        try {
            $Process.Kill($true)
        } catch {
            if ($isWindowsHost) {
                Start-Process -FilePath 'taskkill.exe' -ArgumentList @('/T', '/F', '/PID', "$($Process.Id)") -WindowStyle Hidden | Out-Null
            } else {
                $Process.Kill()
            }
        }
        $null = $Process.WaitForExit(5000)
    }

    # Runs a program under ONE deadline that covers execution, stream
    # completion and cleanup. No wait in this function is unbounded: a
    # hung child, or a descendant orphan holding the redirected pipes,
    # surfaces as a throw (plus whole-tree kill), never a deadlock.
    function Invoke-Bounded {
        param(
            [Parameter(Mandatory)][string] $FilePath,
            [string[]] $Arguments,
            [Parameter(Mandatory)][int] $TimeoutSeconds
        )
        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        $p = $null
        $jobHandle = [IntPtr]::Zero
        try {
            $psi = [System.Diagnostics.ProcessStartInfo]::new()
            $psi.FileName = $FilePath
            foreach ($a in $Arguments) { $psi.ArgumentList.Add($a) }
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $p = [System.Diagnostics.Process]::Start($psi)
            if ($isWindowsHost) {
                # Kill-on-close job: even a descendant that outlives the
                # parent and escapes tree-kill dies when the job handle is
                # closed in the finally block.
                $jobHandle = [JobOps]::CreateKillOnCloseJob()
                [JobOps]::Assign($jobHandle, $p.Handle)
            }
            # Drain pipes concurrently so a chatty child cannot deadlock on
            # a full pipe while we wait; the WAITS below are bounded.
            $outTask = $p.StandardOutput.ReadToEndAsync()
            $errTask = $p.StandardError.ReadToEndAsync()

            $remainingMs = [Math]::Max(1, [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds)
            if (-not $p.WaitForExit($remainingMs)) {
                Stop-Tree $p
                throw ("windows-verify: smoke run exceeded {0}s and was killed (whole tree): {1} {2}" -f
                    $TimeoutSeconds, $FilePath, ($Arguments -join ' '))
            }
            $remainingMs = [Math]::Max(1, [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds)
            if (-not $outTask.Wait($remainingMs) -or -not $errTask.Wait([Math]::Max(1, [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds))) {
                # A descendant is holding the redirected pipes after the
                # parent exited. Bounded: kill what is reachable and fail —
                # on Windows the job handle close below removes escapees.
                Stop-Tree $p
                throw ("windows-verify: redirected output did not drain within the deadline after exit (orphaned descendant holding pipes) — tree killed: {0} {1}" -f
                    $FilePath, ($Arguments -join ' '))
            }
            return [pscustomobject]@{
                ExitCode = $p.ExitCode
                StdOut   = $outTask.Result
                StdErr   = $errTask.Result
            }
        } finally {
            if ($p -and -not $p.HasExited) { Stop-Tree $p }
            if ($p) { $p.Dispose() }
            if ($jobHandle -ne [IntPtr]::Zero) { $null = [JobOps]::Close($jobHandle) }
        }
    }

try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $expectedSet = @(
        "$name/README.md",
        "$name/LICENSE.md",
        "$name/WINDOWS-LIMITATIONS.txt",
        "$name/nkeepass.exe"
    ) | Sort-Object

    # ---- 1. Parse and whitelist the manifest BEFORE opening any entry ----
    $archive = [IO.Compression.ZipFile]::OpenRead((Resolve-Path $Zip).Path)
    try {
        $entries = @($archive.Entries)
        if ($entries.Count -ne $expectedSet.Count) {
            throw ("windows-verify: zip has {0} entries, expected exactly {1} under {2}/" -f
                $entries.Count, $expectedSet.Count, $name)
        }
        $seen = @{}
        foreach ($e in $entries) {
            $n = $e.FullName -replace '\\', '/'
            if ($n -notmatch ('^' + [regex]::Escape($name) + '/[A-Za-z0-9._-]+$')) {
                throw ("windows-verify: zip entry name outside the expected canonical set (traversal, absolute path, or unsafe character): {0}" -f $n)
            }
            if ($expectedSet -notcontains $n) {
                throw ("windows-verify: zip entry not in the expected canonical set: {0}" -f $n)
            }
            if ($seen.ContainsKey($n)) {
                throw ("windows-verify: duplicate zip entry: {0}" -f $n)
            }
            if ($e.FullName.EndsWith('/') -or $e.FullName.EndsWith('\')) {
                throw ("windows-verify: unexpected directory entry in zip: {0}" -f $e.FullName)
            }
            # Symlink/reparse: Unix mode lives in the high 16 bits of the
            # external attributes; S_IFMT 0xF000 == S_IFLNK 0xA000 is a
            # symlink. Windows-created zips carry zero here.
            if (((($e.ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000)) {
                throw ("windows-verify: zip entry has symlink/reparse external attributes: {0}" -f $n)
            }
            $seen[$n] = $e
        }

        # ---- 2. Explicit CRC verification of every whitelisted entry ----
        foreach ($n in $expectedSet) {
            $e = $seen[$n]
            $stream = $e.Open()
            try {
                $actualCrc = [Crc32]::Compute($stream)
            } finally {
                $stream.Dispose()
            }
            if ($actualCrc -ne $e.Crc32) {
                throw ("windows-verify: CRC mismatch for {0}: recorded 0x{1:X8}, actual 0x{2:X8}" -f
                    $n, $e.Crc32, $actualCrc)
            }
        }
    } finally {
        $archive.Dispose()
    }

    # ---- 3. Manual extraction from the validated set (paths built from
    # the constant canonical names, never from entry strings) ----
    New-Item -ItemType Directory -Path $extractRoot | Out-Null
    $extractedDir = Join-Path $extractRoot $name
    New-Item -ItemType Directory -Path $extractedDir | Out-Null
    $archive = [IO.Compression.ZipFile]::OpenRead((Resolve-Path $Zip).Path)
    try {
        foreach ($n in $expectedSet) {
            $e = $archive.Entries | Where-Object { ($_.FullName -replace '\\', '/') -eq $n }
            $target = Join-Path $extractedDir ($n.Substring($name.Length + 1))
            $in = $e.Open()
            try {
                $out = [IO.File]::Create($target)
                try { $in.CopyTo($out) } finally { $out.Dispose() }
            } finally {
                $in.Dispose()
            }
        }
    } finally {
        $archive.Dispose()
    }

    $extractedExe = Join-Path $extractedDir 'nkeepass.exe'
    foreach ($payload in @('README.md', 'LICENSE.md', 'WINDOWS-LIMITATIONS.txt')) {
        if (-not (Test-Path -LiteralPath (Join-Path $extractedDir $payload) -PathType Leaf)) {
            throw "windows-verify: extracted payload missing or not a regular file: $payload"
        }
    }

    # ---- 4. The extracted exe must be a PE with machine x64. ----
    & (Join-Path $PSScriptRoot 'windows-validate.ps1') -Binary $extractedExe -Machine x64

    # ---- 5. Hash parity of the extracted exe with the built binary. ----
    $builtHash = (Get-FileHash -LiteralPath $BuiltExe -Algorithm SHA256).Hash.ToLowerInvariant()
    $extractedHash = (Get-FileHash -LiteralPath $extractedExe -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($extractedHash -ne $builtHash) {
        throw ("windows-verify: extracted exe sha256 {0} != built exe {1}" -f $extractedHash, $builtHash)
    }

    # ---- 6. Raw top-level dist files: same binary, same warning text. ----
    $rawExe = Join-Path $distDirResolved 'nkeepass.exe'
    if (-not (Test-Path -LiteralPath $rawExe -PathType Leaf)) {
        throw "windows-verify: raw top-level nkeepass.exe missing in $distDirResolved"
    }
    $rawHash = (Get-FileHash -LiteralPath $rawExe -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($rawHash -ne $builtHash) {
        throw ("windows-verify: raw top-level exe sha256 {0} != built exe {1}" -f $rawHash, $builtHash)
    }
    & (Join-Path $PSScriptRoot 'windows-validate.ps1') -Binary $rawExe -Machine x64

    $rawLimitations = Join-Path $distDirResolved 'WINDOWS-LIMITATIONS.txt'
    if (-not (Test-Path -LiteralPath $rawLimitations -PathType Leaf)) {
        throw "windows-verify: raw top-level WINDOWS-LIMITATIONS.txt missing in $distDirResolved"
    }
    $rawLimBytes = [IO.File]::ReadAllBytes($rawLimitations)
    $zipLimBytes = [IO.File]::ReadAllBytes((Join-Path $extractedDir 'WINDOWS-LIMITATIONS.txt'))
    if ([Convert]::ToBase64String($rawLimBytes) -ne [Convert]::ToBase64String($zipLimBytes)) {
        throw "windows-verify: raw top-level WINDOWS-LIMITATIONS.txt differs from the copy inside the zip"
    }

    # ---- 7. SHA256SUMS: exactly the three published names, correct
    # format, every hash matching the file actually in the dist dir. ----
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

    # Mandated warning content — checked on the raw copy (and the zip copy
    # is byte-identical to it).
    foreach ($marker in @('SECURE OWNER-ONLY FILE WRITES ARE NOT SUPPORTED', 'FAILS CLOSED')) {
        if (([IO.File]::ReadAllText($rawLimitations)) -notmatch $marker) {
            throw "windows-verify: WINDOWS-LIMITATIONS.txt is missing the mandated text: $marker"
        }
    }

    # ---- 8. Bounded smoke run of the EXTRACTED exe — only everything
    # above passed, so a checked-failed binary is never executed. ----
    if ($Smoke) {
        $runTarget = if ($PSBoundParameters.ContainsKey('SmokeExeOverride')) {
            $SmokeExeOverride # test-only seam; checks 1..7 already ran on the real artifact
        } else {
            $extractedExe
        }
        if ($PSBoundParameters.ContainsKey('SmokeArguments')) {
            # Test-only: a single invocation with explicit arguments.
            $r = Invoke-Bounded -FilePath $runTarget -Arguments $SmokeArguments `
                -TimeoutSeconds $SmokeTimeoutSeconds
            if ($r.ExitCode -ne 0) {
                throw ("windows-verify: smoke run exited {0}" -f $r.ExitCode)
            }
        } else {
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
        }
        Write-Host "windows-verify: smoke ok (bounded ${SmokeTimeoutSeconds}s, tree-kill + job close): $runTarget"
    }

    Write-Host "windows-verify: ok  artifact verified: $Zip"
} finally {
    if (Test-Path -LiteralPath $extractRoot) {
        Remove-Item -Recurse -Force $extractRoot -ErrorAction SilentlyContinue
    }
}

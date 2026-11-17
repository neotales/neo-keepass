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
#   2. central-directory vs local-header agreement and entry types, read
#      from the RAW zip bytes (fields the ZipArchive API does not expose):
#      the local header must carry the same name as the central directory;
#      its CRC and sizes must agree with the central directory unless
#      general purpose bit 3 (data descriptor) marks them as trailing —
#      descriptors are handled, not rejected; DOS directory and
#      reparse-point attribute bits and any non-regular Unix file type
#      (symlink, directory, fifo, device, socket) are rejected; an empty
#      mandatory payload is rejected.
#   3. every whitelisted entry's CRC32 is computed explicitly (compiled
#      helper) and compared to the recorded value — corrupt archives are
#      rejected before extraction.
#   4. extraction is manual, from the validated set, into a fresh private
#      temp dir (paths are built from the constant canonical names, never
#      from entry strings).
#   5. the EXTRACTED nkeepass.exe passes the PE machine check (x64), and
#      the extracted exe's sha256 equals the binary just built.
#   6. the RAW top-level dist files are checked too: nkeepass.exe must
#      equal the built binary's hash AND the archived (extracted) exe's
#      hash and pass the PE check; WINDOWS-LIMITATIONS.txt must be
#      byte-identical to the zip copy and both copies must carry the
#      mandated warning text.
#   7. SHA256SUMS in the dist directory: every NAME is whitelisted against
#      the exact three published names BEFORE any file it names is read
#      (traversal, absolute paths and any other name are rejected before
#      they can be opened); a name that resolves to a reparse point
#      (symlink/junction) instead of a regular file is rejected; every
#      hash must match the actual file; and the canonical
#      nkeepass-<version>-<triple>.zip in the dist dir must BE the file
#      that was checked (same resolved path, not just the same name), so
#      the verified artifact is the one whose hash was published.
#   8. with -Smoke: the EXTRACTED exe is executed with --version and
#      --help under ONE deadline that encompasses execution, stream
#      completion and cleanup. Nothing waits indefinitely: process wait,
#      stdout/stderr drains and cleanup are all bounded by the deadline;
#      on expiry the whole process tree is killed. On Windows the child
#      is created SUSPENDED, assigned to a kill-on-close job object
#      BEFORE its first instruction runs, and only then resumed — there
#      is no window in which the child or any descendant can be outside
#      the job, so a descendant that outlives the parent while holding
#      the redirected pipes is terminated when the job handle closes.
#      Every native handle is closed on every error path. On non-Windows
#      hosts tree kill is best-effort but every wait stays bounded, so
#      the harness itself can never hang.
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

# Compiled helpers: CRC32 (explicit archive integrity), the raw zip
# header parser (central/local agreement), and the Windows job-object
# runner (orphan containment). ONE Add-Type on EVERY host, with the
# usings of all classes merged at the top of the source: the exact bytes
# the Windows runner compiles must also compile on the Linux dev host,
# where the suite runs — a C# syntax error on the Windows-only class
# (e.g. CS1529: a using clause after a type declaration, which only
# breaks when the job-object source is actually concatenated) must fail
# here too, not only on the runner. JobOps is compiled everywhere but
# only ever INVOKED on a Windows host.
if (-not ('Crc32' -as [type])) {
    $helperSource = @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

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

// Parses the zip central directory and each entry's local header straight
// from the raw bytes — the fields the ZipArchive API does not expose — so
// central/local disagreement and entry-type checks do not have to trust
// either API view alone. Canonical payload names are ASCII, so UTF-8
// decoding is exact for them.
public static class ZipRaw {
    public struct Entry {
        public string Name;
        public ushort GpFlags;
        public uint Crc, CompSize, UncompSize;
        public uint ExternalAttrs;
        public string LocalName;
        public ushort LocalGpFlags;
        public uint LocalCrc, LocalCompSize, LocalUncompSize;
    }

    static uint U32(byte[] b, long p) {
        return (uint)(b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24));
    }
    static ushort U16(byte[] b, long p) {
        return (ushort)(b[p] | (b[p + 1] << 8));
    }

    public static Entry[] ReadCentralDirectory(string zipPath) {
        byte[] b = File.ReadAllBytes(zipPath);
        long eocd = -1;
        long floor = b.Length - 22 - 65535; if (floor < 0) floor = 0;
        for (long i = b.Length - 4; i >= floor; i--) {
            if (b[i] == 0x50 && b[i + 1] == 0x4B && b[i + 2] == 0x05 && b[i + 3] == 0x06) { eocd = i; break; }
        }
        if (eocd < 0) throw new InvalidOperationException("zip: end of central directory not found");
        int count = U16(b, eocd + 10);
        long cdOffset = U32(b, eocd + 16);
        long cdSize = U32(b, eocd + 12);
        if (cdOffset < 0 || cdOffset + cdSize > b.Length)
            throw new InvalidOperationException("zip: central directory out of range");
        var list = new System.Collections.Generic.List<Entry>(count);
        long p = cdOffset;
        for (int i = 0; i < count; i++) {
            if (p + 46 > b.Length || U32(b, p) != 0x02014B50u)
                throw new InvalidOperationException("zip: bad central directory entry " + i);
            var e = new Entry();
            e.GpFlags = U16(b, p + 8);
            e.Crc = U32(b, p + 16);
            e.CompSize = U32(b, p + 20);
            e.UncompSize = U32(b, p + 24);
            int nameLen = U16(b, p + 28);
            int extraLen = U16(b, p + 30);
            int commentLen = U16(b, p + 32);
            e.ExternalAttrs = U32(b, p + 38);
            long localOffset = U32(b, p + 42);
            if (nameLen < 0 || p + 46 + nameLen > b.Length)
                throw new InvalidOperationException("zip: bad central name length for entry " + i);
            e.Name = Encoding.UTF8.GetString(b, (int)(p + 46), nameLen);
            if (localOffset < 0 || localOffset + 30 > b.Length || U32(b, localOffset) != 0x04034B50u)
                throw new InvalidOperationException("zip: bad local header for entry " + e.Name);
            e.LocalGpFlags = U16(b, localOffset + 6);
            e.LocalCrc = U32(b, localOffset + 14);
            e.LocalCompSize = U32(b, localOffset + 18);
            e.LocalUncompSize = U32(b, localOffset + 22);
            int locNameLen = U16(b, localOffset + 26);
            int locExtraLen = U16(b, localOffset + 28);
            if (locNameLen < 0 || localOffset + 30 + locNameLen + locExtraLen > b.Length)
                throw new InvalidOperationException("zip: bad local name length for entry " + e.Name);
            e.LocalName = Encoding.UTF8.GetString(b, (int)(localOffset + 30), locNameLen);
            list.Add(e);
            p += 46 + nameLen + extraLen + commentLen;
        }
        return list.ToArray();
    }
}

// Windows-only RUNTIME (never invoked off Windows, but compiled
// everywhere): kill-on-close job object plus a bounded, race-free
// process runner. The child is created SUSPENDED, assigned to the job
// BEFORE its first instruction runs, then resumed — a suspended process
// cannot create descendants, so there is no window in which anything can
// be outside the job; descendants inherit the membership. Every native
// handle is closed on every path.
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
        public UIntPtr ActiveProcessLimit;
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
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFOW {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public ushort wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION {
        public IntPtr hProcess, hThread;
        public uint dwProcessId, dwThreadId;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_ATTRIBUTES {
        public uint nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string lpName);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetInformationJobObject(IntPtr hJob, int JobObjectInfoClass, IntPtr lpJobObjectInfo, int cbJobObjectInfoLength);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessW(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFOW lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr hThread);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    const uint CREATE_SUSPENDED = 0x00000004;
    const uint CREATE_NO_WINDOW = 0x08000000;
    const uint STARTF_USESTDHANDLES = 0x00000100;
    const uint HANDLE_FLAG_INHERIT = 0x00000001;
    const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00000200;
    const uint WAIT_OBJECT_0 = 0x00000000;
    const uint WAIT_TIMEOUT = 0x00000102;

    public struct RunResult {
        public int ExitCode;
        public string StdOut;
        public string StdErr;
        public string ErrorKind;
        public string ErrorDetail;
    }

    static Exception Win32Error(string what) {
        return new InvalidOperationException(what + " failed (Win32 error " + Marshal.GetLastWin32Error() + ")");
    }

    public static IntPtr CreateKillOnCloseJob() {
        IntPtr job = CreateJobObjectW(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw Win32Error("CreateJobObjectW");
        var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        int len = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
        IntPtr ptr = Marshal.AllocHGlobal(len);
        try {
            Marshal.StructureToPtr(info, ptr, false);
            if (!SetInformationJobObject(job, 9, ptr, len)) throw Win32Error("SetInformationJobObject");
        } finally { Marshal.FreeHGlobal(ptr); }
        return job;
    }

    // Quotes one argument for a Windows command line: backslashes before
    // an embedded quote (and before a trailing quote) are doubled, the
    // quote is escaped.
    static string Quote(string a) {
        if (a.Length == 0) return "\"\"";
        bool needsQuotes = false;
        for (int i = 0; i < a.Length; i++) {
            char c = a[i];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '"') { needsQuotes = true; break; }
        }
        if (!needsQuotes) return a;
        var sb = new StringBuilder();
        sb.Append('"');
        int backslashes = 0;
        for (int i = 0; i < a.Length; i++) {
            char c = a[i];
            if (c == '\\') { backslashes++; continue; }
            if (c == '"') {
                sb.Append('\\', backslashes * 2 + 1);
                backslashes = 0;
            } else {
                if (backslashes > 0) { sb.Append('\\', backslashes); backslashes = 0; }
            }
            sb.Append(c);
        }
        sb.Append('\\', backslashes * 2);
        sb.Append('"');
        return sb.ToString();
    }

    // Drains one pipe read handle to the end. Blocks until every write
    // end is closed — including those held by descendants — which is
    // bounded overall because the job handle close below breaks the
    // pipes of any surviving member.
    static string Drain(IntPtr readHandle) {
        var ms = new MemoryStream();
        var buf = new byte[4096];
        uint got;
        while (ReadFile(readHandle, buf, (uint)buf.Length, out got, IntPtr.Zero) && got > 0)
            ms.Write(buf, 0, (int)got);
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    static int RemainingMs(DateTime deadline) {
        double ms = (deadline - DateTime.UtcNow).TotalMilliseconds;
        if (ms < 1) ms = 1;
        return (int)Math.Min(ms, int.MaxValue);
    }

    public static RunResult RunBounded(string filePath, string[] arguments, int timeoutMs) {
        var r = new RunResult();
        r.ErrorKind = "";
        DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        IntPtr job = IntPtr.Zero, outR = IntPtr.Zero, outW = IntPtr.Zero, errR = IntPtr.Zero, errW = IntPtr.Zero;
        IntPtr thread = IntPtr.Zero, process = IntPtr.Zero;
        Task<string> outTask = null, errTask = null;
        bool started = false;
        try {
            // The job exists BEFORE the process: with CREATE_SUSPENDED the
            // child cannot run — so cannot spawn descendants — until it is
            // assigned to the job and resumed.
            job = CreateKillOnCloseJob();

            var sa = new SECURITY_ATTRIBUTES();
            sa.nLength = (uint)Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            sa.lpSecurityDescriptor = IntPtr.Zero;
            sa.bInheritHandle = true;
            if (!CreatePipe(out outR, out outW, ref sa, 0)) throw Win32Error("CreatePipe");
            if (!CreatePipe(out errR, out errW, ref sa, 0)) throw Win32Error("CreatePipe");
            // The write ends cross to the child; the read ends must not.
            if (!SetHandleInformation(outR, HANDLE_FLAG_INHERIT, 0)) throw Win32Error("SetHandleInformation");
            if (!SetHandleInformation(errR, HANDLE_FLAG_INHERIT, 0)) throw Win32Error("SetHandleInformation");

            var si = new STARTUPINFOW();
            si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFOW));
            si.lpReserved = null; si.lpDesktop = null; si.lpTitle = null; si.lpReserved2 = IntPtr.Zero;
            si.hStdInput = IntPtr.Zero;
            si.hStdOutput = outW;
            si.hStdError = errW;
            si.dwFlags = STARTF_USESTDHANDLES;

            var cmd = new StringBuilder(Quote(filePath));
            for (int i = 0; i < arguments.Length; i++) { cmd.Append(' '); cmd.Append(Quote(arguments[i])); }

            PROCESS_INFORMATION pi;
            if (!CreateProcessW(filePath, cmd.ToString(), IntPtr.Zero, IntPtr.Zero, true,
                    CREATE_SUSPENDED | CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out pi))
                throw Win32Error("CreateProcessW");
            process = pi.hProcess;
            thread = pi.hThread;

            if (!AssignProcessToJobObject(job, process)) throw Win32Error("AssignProcessToJobObject");
            if (ResumeThread(thread) == 0xFFFFFFFFu) throw Win32Error("ResumeThread");
            started = true;
            if (!CloseHandle(thread)) throw Win32Error("CloseHandle");
            thread = IntPtr.Zero;

            // The parent must drop its own copies of the write ends, or
            // the drains below never complete even after the whole tree
            // exits.
            if (!CloseHandle(outW)) throw Win32Error("CloseHandle"); outW = IntPtr.Zero;
            if (!CloseHandle(errW)) throw Win32Error("CloseHandle"); errW = IntPtr.Zero;

            outTask = Task.Run(() => Drain(outR));
            errTask = Task.Run(() => Drain(errR));

            uint w = WaitForSingleObject(process, (uint)RemainingMs(deadline));
            if (w == WAIT_TIMEOUT) {
                r.ErrorKind = "timeout";
                r.ErrorDetail = string.Format("exceeded {0}ms", timeoutMs);
                return r; // finally kills the tree and closes the job
            }
            if (w != WAIT_OBJECT_0) throw Win32Error("WaitForSingleObject");

            if (!outTask.Wait(RemainingMs(deadline)) || !errTask.Wait(RemainingMs(deadline))) {
                r.ErrorKind = "drain";
                r.ErrorDetail = "redirected output did not drain within the deadline after exit (orphaned descendant holding pipes)";
                return r; // finally closes the job, which removes the escapee
            }

            if (!GetExitCodeProcess(process, out uint code)) throw Win32Error("GetExitCodeProcess");
            r.ExitCode = unchecked((int)code);
            r.StdOut = outTask.Result;
            r.StdErr = errTask.Result;
            return r;
        } catch (Exception e) {
            r.ErrorKind = started ? "internal" : "spawn";
            r.ErrorDetail = e.Message;
            return r;
        } finally {
            // 1. The direct child: terminate if still running, wait bounded.
            if (process != IntPtr.Zero) {
                uint w = WaitForSingleObject(process, 0);
                if (w != WAIT_OBJECT_0) {
                    TerminateProcess(process, 0xFFFFFFFFu);
                    uint waited = 0;
                    do {
                        w = WaitForSingleObject(process, 250);
                        waited += 250;
                    } while (w != WAIT_OBJECT_0 && waited < 5000);
                }
            }
            // 2. The job: closing the kill-on-close handle terminates every
            // remaining member, including a descendant that outlived the
            // child while holding the redirected pipes.
            if (job != IntPtr.Zero) CloseHandle(job);
            // 3. The drains unblocked by (2); join briefly, never hang.
            if (outTask != null) outTask.Wait(2000);
            if (errTask != null) errTask.Wait(2000);
            // 4. Every remaining native handle, on every path.
            if (thread != IntPtr.Zero) CloseHandle(thread);
            if (outW != IntPtr.Zero) CloseHandle(outW);
            if (errW != IntPtr.Zero) CloseHandle(errW);
            if (outR != IntPtr.Zero) CloseHandle(outR);
            if (errR != IntPtr.Zero) CloseHandle(errR);
            if (process != IntPtr.Zero) CloseHandle(process);
        }
    }
}
'@
    Add-Type -TypeDefinition $helperSource
    }

    # Kills the process and its whole tree, then waits (bounded) for exit.
    # Only used on non-Windows hosts: on Windows the compiled runner owns
    # the whole lifecycle (terminate + kill-on-close job).
    function Stop-Tree {
        param([Parameter(Mandatory)] $Process)
        if ($Process.HasExited) { return }
        try {
            $Process.Kill($true)
        } catch {
            $Process.Kill()
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
        if ($isWindowsHost) {
            $r = [JobOps]::RunBounded($FilePath, $Arguments, $TimeoutSeconds * 1000)
            if ($r.ErrorKind -eq 'timeout') {
                throw ("windows-verify: smoke run exceeded {0}s and was killed (whole tree): {1} {2}" -f
                    $TimeoutSeconds, $FilePath, ($Arguments -join ' '))
            }
            if ($r.ErrorKind -eq 'drain') {
                throw ("windows-verify: redirected output did not drain within the deadline after exit (orphaned descendant holding pipes) — tree killed: {0} {1}" -f
                    $FilePath, ($Arguments -join ' '))
            }
            if ($r.ErrorKind -eq 'spawn') {
                throw ("windows-verify: smoke run failed to start: {0}: {1} {2}" -f
                    $r.ErrorDetail, $FilePath, ($Arguments -join ' '))
            }
            if ($r.ErrorKind -ne '') {
                throw ("windows-verify: smoke run internal failure ({0}): {1}: {2} {3}" -f
                    $r.ErrorKind, $r.ErrorDetail, $FilePath, ($Arguments -join ' '))
            }
            return [pscustomobject]@{
                ExitCode = $r.ExitCode
                StdOut   = $r.StdOut
                StdErr   = $r.StdErr
            }
        }
        # Non-Windows: test seam only (a real PE cannot run here). Bounded
        # waits, best-effort tree kill — the harness still cannot hang.
        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        $p = $null
        try {
            $psi = [System.Diagnostics.ProcessStartInfo]::new()
            $psi.FileName = $FilePath
            foreach ($a in $Arguments) { $psi.ArgumentList.Add($a) }
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $p = [System.Diagnostics.Process]::Start($psi)
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
                # parent exited. Bounded: kill what is reachable and fail.
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
    # One archive stays open across steps 1-3: the entry objects held in
    # $seen belong to it and must outlive both the whitelist and the CRC
    # pass.
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
            # symlink. Windows-created zips carry zero here. (Full type
            # validation follows in step 2 from the raw bytes.)
            if (((($e.ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000)) {
                throw ("windows-verify: zip entry has symlink/reparse external attributes: {0}" -f $n)
            }
            $seen[$n] = $e
        }

        # ---- 2. Central/local header agreement and entry types, from the RAW
        # zip bytes, BEFORE any entry stream is opened. The ZipArchive API does
        # not expose local headers, so they are parsed directly: names must
        # agree exactly; CRC and sizes must agree with the central directory
        # unless general purpose bit 3 (data descriptor) marks them as
        # trailing; DOS directory/reparse attribute bits and non-regular Unix
        # file types are rejected; and none of the mandatory payloads is
        # empty.
        $rawEntries = [ZipRaw]::ReadCentralDirectory((Resolve-Path $Zip).Path)
        if ($rawEntries.Length -ne $entries.Count) {
            throw ("windows-verify: raw central directory has {0} records but the archive API reported {1}" -f
                $rawEntries.Length, $entries.Count)
        }
        $rawByName = @{}
        foreach ($re in $rawEntries) { $rawByName[($re.Name -replace '\\', '/')] = $re }
        foreach ($n in $expectedSet) {
            $re = $rawByName[$n]
            if ($null -eq $re) {
                throw ("windows-verify: whitelisted entry missing from the raw central directory: {0}" -f $n)
            }
            if ($re.LocalName -ne $n) {
                throw ("windows-verify: local header name disagrees with central directory for {0}: local header says '{1}'" -f
                    $n, $re.LocalName)
            }
            if ((($re.LocalGpFlags -band 8) -eq 0)) {
                # No data descriptor: the local header must carry the real
                # values and they must agree with the central directory.
                if ($re.LocalCrc -ne $re.Crc) {
                    throw ("windows-verify: local header CRC disagrees with central directory for {0}: local 0x{1:X8}, central 0x{2:X8}" -f
                        $n, $re.LocalCrc, $re.Crc)
                }
                if ($re.LocalCompSize -ne $re.CompSize -or $re.LocalUncompSize -ne $re.UncompSize) {
                    throw ("windows-verify: local header sizes disagree with central directory for {0}" -f $n)
                }
            }
            $dos = $re.ExternalAttrs -band 0xFFFF
            $unix = ($re.ExternalAttrs -shr 16) -band 0xFFFF
            if (($dos -band 0x10) -ne 0) {
                throw ("windows-verify: zip entry carries the DOS directory attribute: {0}" -f $n)
            }
            if (($dos -band 0x400) -ne 0) {
                throw ("windows-verify: zip entry carries a reparse-point attribute: {0}" -f $n)
            }
            if ($unix -ne 0 -and (($unix -band 0xF000) -ne 0x8000)) {
                throw ("windows-verify: zip entry is not a regular file (symlink/reparse/directory/fifo/device/socket Unix mode 0x{0:X4}): {1}" -f
                    $unix, $n)
            }
            if ($re.UncompSize -eq 0) {
                throw ("windows-verify: mandatory payload entry is empty: {0}" -f $n)
            }
        }

        # ---- 3. Explicit CRC verification of every whitelisted entry ----
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

    # ---- 4. Manual extraction from the validated set (paths built from
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

    # ---- 5. The extracted exe must be a PE with machine x64, and must
    # hash-equal the binary just built. ----
    & (Join-Path $PSScriptRoot 'windows-validate.ps1') -Binary $extractedExe -Machine x64

    $builtHash = (Get-FileHash -LiteralPath $BuiltExe -Algorithm SHA256).Hash.ToLowerInvariant()
    $extractedHash = (Get-FileHash -LiteralPath $extractedExe -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($extractedHash -ne $builtHash) {
        throw ("windows-verify: extracted exe sha256 {0} != built exe {1}" -f $extractedHash, $builtHash)
    }

    # ---- 6. Raw top-level dist files: same binary as built AND as
    # archived, same warning text as the zip copy. ----
    $rawExe = Join-Path $distDirResolved 'nkeepass.exe'
    if (-not (Test-Path -LiteralPath $rawExe -PathType Leaf)) {
        throw "windows-verify: raw top-level nkeepass.exe missing in $distDirResolved"
    }
    $rawHash = (Get-FileHash -LiteralPath $rawExe -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($rawHash -ne $builtHash) {
        throw ("windows-verify: raw top-level exe sha256 {0} != built exe {1}" -f $rawHash, $builtHash)
    }
    if ($rawHash -ne $extractedHash) {
        throw ("windows-verify: raw top-level exe sha256 {0} != archived exe {1}" -f $rawHash, $extractedHash)
    }
    & (Join-Path $PSScriptRoot 'windows-validate.ps1') -Binary $rawExe -Machine x64

    $rawLimitations = Join-Path $distDirResolved 'WINDOWS-LIMITATIONS.txt'
    if (-not (Test-Path -LiteralPath $rawLimitations -PathType Leaf)) {
        throw "windows-verify: raw top-level WINDOWS-LIMITATIONS.txt missing in $distDirResolved"
    }
    $rawLimBytes = [IO.File]::ReadAllBytes($rawLimitations)
    $zipLimPath = Join-Path $extractedDir 'WINDOWS-LIMITATIONS.txt'
    $zipLimBytes = [IO.File]::ReadAllBytes($zipLimPath)
    if ([Convert]::ToBase64String($rawLimBytes) -ne [Convert]::ToBase64String($zipLimBytes)) {
        throw "windows-verify: raw top-level WINDOWS-LIMITATIONS.txt differs from the copy inside the zip"
    }

    # ---- 7. SHA256SUMS: the NAMES are whitelisted against the exact three
    # published names BEFORE any file they name is opened (traversal and
    # absolute paths never reach the filesystem); a name resolving to a
    # reparse point is rejected; every hash must match; and the canonical
    # dist zip must BE the zip that was checked, so the published hash
    # describes the artifact that passed steps 1..6. ----
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
    }
    # Whitelist every name BEFORE reading any of the named files.
    if (@(Compare-Object ($actualNames | Sort-Object) $expectedNames).Count -ne 0) {
        throw ("windows-verify: SHA256SUMS covers the wrong file set (only the three exact published names are accepted, no traversal or absolute paths): {0}" -f
            ($actualNames -join ', '))
    }
    foreach ($line in $lines) {
        $parts = $line -split '  ', 2
        $p = Join-Path $distDirResolved $parts[1]
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
            throw "windows-verify: SHA256SUMS names a missing file: $($parts[1])"
        }
        $item = Get-Item -LiteralPath $p -Force
        if ($item.PSIsContainer) {
            throw ("windows-verify: SHA256SUMS names a directory, not a regular file: {0}" -f $parts[1])
        }
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw ("windows-verify: SHA256SUMS names a reparse point (symlink/junction), not a regular file: {0}" -f $parts[1])
        }
        $actualHash = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($parts[0] -ne $actualHash) {
            throw ("windows-verify: SHA256SUMS hash mismatch for {0}: listed {1}, actual {2}" -f
                $parts[1], $parts[0], $actualHash)
        }
    }
    # The zip that was checked must be the canonical zip in the dist dir —
    # the same FILE, not a same-named copy: the hash validated above is the
    # hash of the artifact that passed steps 1..6, so the published sums
    # must describe exactly that artifact.
    $canonicalZip = Join-Path $distDirResolved "$name.zip"
    if (-not (Test-Path -LiteralPath $canonicalZip -PathType Leaf)) {
        throw "windows-verify: canonical dist zip missing in $distDirResolved"
    }
    $checkedZip = (Resolve-Path $Zip).Path
    $distZip = (Resolve-Path $canonicalZip).Path
    if ($checkedZip -ne $distZip) {
        throw ("windows-verify: checked zip {0} is not the canonical dist zip {1} that SHA256SUMS describes" -f
            $checkedZip, $distZip)
    }

    # Mandated warning content — checked on BOTH copies (the byte-compare
    # above already implies it; assert it directly on each).
    foreach ($limPath in @($rawLimitations, $zipLimPath)) {
        $limText = [IO.File]::ReadAllText($limPath)
        foreach ($marker in @('SECURE OWNER-ONLY FILE WRITES ARE NOT SUPPORTED', 'FAILS CLOSED')) {
            if ($limText -notmatch $marker) {
                throw "windows-verify: WINDOWS-LIMITATIONS.txt is missing the mandated text: $marker ($limPath)"
            }
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

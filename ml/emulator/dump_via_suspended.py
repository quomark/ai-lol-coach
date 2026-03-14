"""
Dump unpacked League binary via CREATE_SUSPENDED.

Strategy:
  1. CreateProcess with CREATE_SUSPENDED → Windows loads the EXE + stub.dll
  2. stub.dll's DllMain runs during loading (unpacks code, resolves imports)
  3. Process is suspended BEFORE entry point executes
  4. We dump the fully unpacked binary from memory
  5. Kill the process (never actually runs the game)

No Vanguard issue because:
  - Vanguard is stopped (we stop it first)
  - The process is our child process
  - DllMain already ran (imports resolved, code unpacked)
  - We never let the game actually execute

Requirements: Run as Administrator, stop Vanguard first
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import struct
import time
import subprocess
import sys
from pathlib import Path

if sys.platform != "win32":
    raise RuntimeError("Windows only")

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

# ── Constants ──
CREATE_SUSPENDED    = 0x00000004
PROCESS_ALL_ACCESS  = 0x001F0FFF
MEM_COMMIT          = 0x1000
PAGE_SIZE           = 0x1000


# ── Structures ──
class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_uint32),
        ("lpReserved", ctypes.c_wchar_p),
        ("lpDesktop", ctypes.c_wchar_p),
        ("lpTitle", ctypes.c_wchar_p),
        ("dwX", ctypes.c_uint32),
        ("dwY", ctypes.c_uint32),
        ("dwXSize", ctypes.c_uint32),
        ("dwYSize", ctypes.c_uint32),
        ("dwXCountChars", ctypes.c_uint32),
        ("dwYCountChars", ctypes.c_uint32),
        ("dwFillAttribute", ctypes.c_uint32),
        ("dwFlags", ctypes.c_uint32),
        ("wShowWindow", ctypes.c_uint16),
        ("cbReserved2", ctypes.c_uint16),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", ctypes.c_void_p),
        ("hStdOutput", ctypes.c_void_p),
        ("hStdError", ctypes.c_void_p),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", ctypes.c_void_p),
        ("hThread", ctypes.c_void_p),
        ("dwProcessId", ctypes.c_uint32),
        ("dwThreadId", ctypes.c_uint32),
    ]


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved1", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.c_void_p),
        ("Reserved2", ctypes.c_void_p * 2),
        ("UniqueProcessId", ctypes.POINTER(ctypes.c_ulong)),
        ("Reserved3", ctypes.c_void_p),
    ]


def enable_debug_privilege():
    """Enable SeDebugPrivilege."""
    advapi32 = ctypes.windll.advapi32
    kernel32.GetCurrentProcess.restype = ctypes.wintypes.HANDLE
    advapi32.OpenProcessToken.argtypes = [
        ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.OpenProcessToken.restype = ctypes.wintypes.BOOL

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", ctypes.c_uint32), ("HighPart", ctypes.c_int32)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", ctypes.c_uint32)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [
            ("PrivilegeCount", ctypes.c_uint32),
            ("Privileges", LUID_AND_ATTRIBUTES * 1),
        ]

    hToken = ctypes.c_void_p()
    advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), 0x0020 | 0x0008,
        ctypes.byref(hToken),
    )

    luid = LUID()
    advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid))

    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = 0x00000002

    advapi32.AdjustTokenPrivileges(
        hToken, False, ctypes.byref(tp), ctypes.sizeof(tp), None, None
    )
    kernel32.CloseHandle(hToken)
    print("  SeDebugPrivilege enabled")


def stop_vanguard():
    """Stop Vanguard services."""
    print("[1] Stopping Vanguard...")
    subprocess.run(["taskkill", "/IM", "vgtray.exe", "/F"],
                   capture_output=True)
    subprocess.run(["sc", "stop", "vgc"], capture_output=True)
    subprocess.run(["sc", "stop", "vgk"], capture_output=True)
    time.sleep(2)
    print("  Done")


def start_vanguard():
    """Restart Vanguard."""
    print("[6] Restarting Vanguard...")
    subprocess.run(["sc", "start", "vgc"], capture_output=True)
    vgtray = Path(r"C:\Program Files\Riot Vanguard\vgtray.exe")
    if vgtray.exists():
        subprocess.Popen([str(vgtray)], creationflags=0x00000008)


def create_suspended_process(exe_path: str, args: str = "") -> PROCESS_INFORMATION:
    """Create a suspended process."""
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()

    cmd_line = f'"{exe_path}" {args}'.strip()

    kernel32.CreateProcessW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_bool, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_wchar_p,
        ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION),
    ]
    kernel32.CreateProcessW.restype = ctypes.c_bool

    cwd = str(Path(exe_path).parent)

    success = kernel32.CreateProcessW(
        None,           # lpApplicationName
        cmd_line,       # lpCommandLine
        None, None,     # security attributes
        False,          # inherit handles
        CREATE_SUSPENDED,  # creation flags
        None,           # environment
        cwd,            # working directory
        ctypes.byref(si),
        ctypes.byref(pi),
    )

    if not success:
        err = kernel32.GetLastError()
        raise OSError(f"CreateProcess failed (error={err})")

    return pi


def get_image_base_from_peb(hProcess: int) -> int:
    """Read the image base from the process's PEB."""
    # NtQueryInformationProcess to get PEB address
    pbi = PROCESS_BASIC_INFORMATION()
    status = ntdll.NtQueryInformationProcess(
        ctypes.c_void_p(hProcess),
        0,  # ProcessBasicInformation
        ctypes.byref(pbi),
        ctypes.sizeof(pbi),
        None,
    )

    if status != 0:
        print(f"  NtQueryInformationProcess status: 0x{status:X}")
        return 0

    peb_addr = pbi.PebBaseAddress
    print(f"  PEB at: 0x{peb_addr:X}")

    # Read ImageBaseAddress from PEB (offset 0x10 on x64)
    image_base = ctypes.c_uint64()
    bytes_read = ctypes.c_size_t()
    kernel32.ReadProcessMemory(
        ctypes.c_void_p(hProcess),
        ctypes.c_void_p(peb_addr + 0x10),
        ctypes.byref(image_base),
        8,
        ctypes.byref(bytes_read),
    )

    return image_base.value


def dump_process(hProcess: int, base: int, size: int, output: Path) -> bool:
    """Dump process memory to file."""
    print(f"  Dumping 0x{base:X} - 0x{base+size:X} ({size // 1024 // 1024} MB)")

    data = bytearray()
    read_buf = ctypes.create_string_buffer(PAGE_SIZE)
    bytes_read = ctypes.c_size_t()
    errors = 0

    for offset in range(0, size, PAGE_SIZE):
        addr = base + offset
        success = kernel32.ReadProcessMemory(
            ctypes.c_void_p(hProcess),
            ctypes.c_void_p(addr),
            read_buf,
            PAGE_SIZE,
            ctypes.byref(bytes_read),
        )
        if success and bytes_read.value > 0:
            data.extend(read_buf.raw[:bytes_read.value])
        else:
            data.extend(b"\x00" * PAGE_SIZE)
            errors += 1

        if offset % (1024 * 1024) == 0 and offset > 0:
            print(f"    {offset // 1024 // 1024} MB / {size // 1024 // 1024} MB "
                  f"({errors} unreadable pages)")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(bytes(data))
    print(f"  Saved {len(data):,} bytes to {output}")
    print(f"  ({errors} unreadable pages)")
    return errors < size // PAGE_SIZE  # success if most pages readable


def verify_unpacked(data: bytes, expected_rva: int = 0x0066E5F0) -> bool:
    """Check if the dispatcher prologue is present (= successfully unpacked)."""
    expected = bytes.fromhex("48 89 5c 24 08 55 56 57 41 54 41 55 41 56 41 57".replace(" ", ""))
    offset = expected_rva
    if offset + len(expected) <= len(data):
        actual = data[offset:offset + len(expected)]
        if actual == expected:
            print(f"  Dispatcher at RVA 0x{expected_rva:X}: MATCH (unpacked!)")
            return True
        else:
            print(f"  Dispatcher at RVA 0x{expected_rva:X}: {actual.hex(' ')}")
            print(f"  Expected: {expected.hex(' ')}")

    # Also check if .text has real code (not all zeros)
    text_offset = 0x4000  # .text starts at RVA 0x1000, code at +0x3000
    sample = data[text_offset:text_offset + 16]
    has_code = any(b != 0 for b in sample)
    print(f"  .text code present: {has_code}")
    return False


def main():
    import argparse

    p = argparse.ArgumentParser(
        description="Dump unpacked League binary via suspended process"
    )
    p.add_argument("--exe", default=r"C:\Riot Games\League of Legends\Game\League of Legends.exe")
    p.add_argument("-o", "--output", default=None)
    p.add_argument("--run-time", type=float, default=0,
                   help="Seconds to let process run before dumping (for init)")
    p.add_argument("--rofl", default=None,
                   help="Path to .rofl file (passed as arg to game exe)")
    args = p.parse_args()

    exe_path = args.exe
    if not Path(exe_path).exists():
        print(f"Not found: {exe_path}")
        sys.exit(1)

    output = Path(args.output) if args.output else Path("ml/data/league_unpacked.bin")

    print("=" * 60)
    print("  League Binary Dumper (Suspended Process Method)")
    print("=" * 60)

    # Get expected size from PE headers
    import pefile
    pe = pefile.PE(exe_path, fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
    pe.close()
    print(f"\n  Expected base: 0x{image_base:X}, size: 0x{size_of_image:X}")

    enable_debug_privilege()
    stop_vanguard()

    print(f"\n[2] Creating suspended process...")
    # Pass rofl arg so the game thinks it's loading a replay
    game_args = f'"{args.rofl}"' if args.rofl else ""
    try:
        pi = create_suspended_process(exe_path, game_args)
    except OSError as e:
        print(f"  FAILED: {e}")
        start_vanguard()
        sys.exit(1)

    print(f"  PID: {pi.dwProcessId}")
    print(f"  Thread ID: {pi.dwThreadId}")

    try:
        # If --run-time specified, resume process to let initialization run
        if args.run_time > 0:
            print(f"\n[2b] Resuming process for {args.run_time}s (initialization)...")
            kernel32.ResumeThread(ctypes.c_void_p(pi.hThread))
            time.sleep(args.run_time)

            # Suspend again
            print(f"  Suspending...")
            kernel32.SuspendThread(ctypes.c_void_p(pi.hThread))
            time.sleep(0.5)
            print(f"  Process suspended after {args.run_time}s of execution")

        print(f"\n[3] Reading process memory...")

        # Get actual image base from PEB
        actual_base = get_image_base_from_peb(pi.hProcess)
        if actual_base:
            print(f"  Image base from PEB: 0x{actual_base:X}")
        else:
            actual_base = image_base
            print(f"  Using expected base: 0x{actual_base:X}")

        # Try reading the MZ header to verify access
        mz_buf = ctypes.create_string_buffer(2)
        bytes_read = ctypes.c_size_t()
        success = kernel32.ReadProcessMemory(
            ctypes.c_void_p(pi.hProcess),
            ctypes.c_void_p(actual_base),
            mz_buf, 2,
            ctypes.byref(bytes_read),
        )
        print(f"  Read MZ header: {'OK' if success and mz_buf.raw[:2] == b'MZ' else 'FAILED'}")

        if not success:
            print("  Cannot read process memory!")
            print("  This might mean Vanguard kernel driver is still loaded.")
            print("  Try rebooting and running before opening League Client.")
            raise RuntimeError("Memory read failed")

        # Read SizeOfImage from PE header in memory (might differ if unpacked)
        pe_buf = ctypes.create_string_buffer(4096)
        kernel32.ReadProcessMemory(
            ctypes.c_void_p(pi.hProcess),
            ctypes.c_void_p(actual_base),
            pe_buf, 4096,
            ctypes.byref(bytes_read),
        )
        e_lfanew = struct.unpack_from("<I", pe_buf.raw, 0x3C)[0]
        mem_size_of_image = struct.unpack_from("<I", pe_buf.raw, e_lfanew + 24 + 56)[0]
        print(f"  SizeOfImage (in memory): 0x{mem_size_of_image:X}")

        dump_size = max(size_of_image, mem_size_of_image)

        print(f"\n[4] Dumping {dump_size // 1024 // 1024} MB...")
        success = dump_process(pi.hProcess, actual_base, dump_size, output)

        if success:
            print(f"\n[5] Verifying dump...")
            dump_data = output.read_bytes()
            unpacked = verify_unpacked(dump_data)

            if unpacked:
                # Save metadata for the decoder
                import json as _json
                meta_path = output.parent / "league_dump_meta.json"
                meta_path.write_text(_json.dumps({
                    "base": actual_base,
                    "size": dump_size,
                    "exe": str(exe_path),
                    "time": time.time(),
                }))
                print(f"  Metadata saved to {meta_path}")

                print(f"\n{'=' * 60}")
                print(f"  SUCCESS! Unpacked binary saved to: {output}")
                print(f"  Load address: 0x{actual_base:X}")
                print(f"  Next: convert a replay:")
                print(f"    .venv\\Scripts\\python.exe -m ml.emulator.rofl_to_json \\")
                print(f'      "path/to/replay.rofl" -o output.json')
                print(f"{'=' * 60}")
            else:
                print(f"\n  Binary may not be fully unpacked.")
                print(f"  DllMain might not have run yet with CREATE_SUSPENDED.")
                print(f"  Try: let the process run briefly, then dump.")

    finally:
        # Kill the suspended process
        print(f"\n  Terminating suspended process (PID {pi.dwProcessId})...")
        kernel32.TerminateProcess(ctypes.c_void_p(pi.hProcess), 0)
        kernel32.CloseHandle(ctypes.c_void_p(pi.hProcess))
        kernel32.CloseHandle(ctypes.c_void_p(pi.hThread))

        start_vanguard()


if __name__ == "__main__":
    main()

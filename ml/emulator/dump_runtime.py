"""
Dump League binary at RUNTIME (after initialization).

Unlike dump_via_suspended.py (CREATE_SUSPENDED, pre-init), this script:
  1. Stops Vanguard services
  2. Launches the replay viewer (League of Legends.exe + .rofl path)
  3. Waits for initialization (cipher tables, LUTs populated)
  4. Suspends all threads and dumps the fully initialized binary
  5. Kills the process and restarts Vanguard

This gets us a binary where LUT tables at RVA 0x19B60F0 etc. are
properly initialized, fixing the coordinate decoding issue.

Requirements:
  - Run as Administrator
  - pip install pefile psutil
  - .rofl file from a recent game (same patch as installed client)

Usage:
  python -m ml.emulator.dump_runtime --rofl "path/to/replay.rofl"
  python -m ml.emulator.dump_runtime --rofl "path/to/replay.rofl" --wait 15
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import struct
import subprocess
import sys
import time
from pathlib import Path

if sys.platform != "win32":
    raise RuntimeError("Windows only")

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll
psapi = ctypes.windll.psapi


# ── ctypes setup ──

class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", ctypes.c_uint32),
        ("EntryPoint", ctypes.c_void_p),
    ]


PROCESS_ALL_ACCESS = 0x001F0FFF
THREAD_SUSPEND_RESUME = 0x0002
PAGE_SIZE = 0x1000
TH32CS_SNAPTHREAD = 0x00000004

class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_uint32),
        ("cntUsage", ctypes.c_uint32),
        ("th32ThreadID", ctypes.c_uint32),
        ("th32OwnerProcessID", ctypes.c_uint32),
        ("tpBasePri", ctypes.c_long),
        ("tpDeltaPri", ctypes.c_long),
        ("dwFlags", ctypes.c_uint32),
    ]


def enable_debug_privilege():
    """Enable SeDebugPrivilege for this process."""
    advapi32 = ctypes.windll.advapi32
    kernel32.GetCurrentProcess.restype = ctypes.wintypes.HANDLE

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
    """Stop Vanguard services and tray."""
    print("[*] Stopping Vanguard...")
    subprocess.run(["taskkill", "/IM", "vgtray.exe", "/F"],
                   capture_output=True)
    subprocess.run(["sc", "stop", "vgc"], capture_output=True)
    subprocess.run(["sc", "stop", "vgk"], capture_output=True)
    time.sleep(2)
    print("  Done")


def start_vanguard():
    """Restart Vanguard services."""
    print("[*] Restarting Vanguard...")
    subprocess.run(["sc", "start", "vgc"], capture_output=True)
    vgtray = Path(r"C:\Program Files\Riot Vanguard\vgtray.exe")
    if vgtray.exists():
        subprocess.Popen([str(vgtray)], creationflags=0x00000008)


def find_league_exe():
    """Find League of Legends.exe."""
    candidates = [
        Path(r"C:\Riot Games\League of Legends\Game\League of Legends.exe"),
        Path(r"D:\Riot Games\League of Legends\Game\League of Legends.exe"),
    ]
    for p in candidates:
        if p.exists():
            return str(p)
    return None


def wait_for_process(name: str, timeout: float = 30) -> int | None:
    """Wait for a process by name. Returns PID."""
    import psutil
    deadline = time.time() + timeout
    while time.time() < deadline:
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if proc.info["name"] and name.lower() in proc.info["name"].lower():
                    return proc.info["pid"]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        time.sleep(0.5)
    return None


def suspend_all_threads(pid: int) -> list[int]:
    """Suspend all threads of a process. Returns thread IDs."""
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snapshot == -1:
        raise OSError("CreateToolhelp32Snapshot failed")

    te = THREADENTRY32()
    te.dwSize = ctypes.sizeof(te)
    thread_ids = []

    if kernel32.Thread32First(snapshot, ctypes.byref(te)):
        while True:
            if te.th32OwnerProcessID == pid:
                hThread = kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, te.th32ThreadID)
                if hThread:
                    kernel32.SuspendThread(hThread)
                    kernel32.CloseHandle(hThread)
                    thread_ids.append(te.th32ThreadID)
            if not kernel32.Thread32Next(snapshot, ctypes.byref(te)):
                break

    kernel32.CloseHandle(snapshot)
    return thread_ids


def dump_module(hProcess, base: int, size: int, output: Path) -> int:
    """Dump process memory region to file. Returns count of unreadable pages."""
    print(f"  Dumping 0x{base:X}, size=0x{size:X} ({size // 1024 // 1024} MB)")

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

        if offset > 0 and offset % (4 * 1024 * 1024) == 0:
            print(f"    {offset // 1024 // 1024} MB / {size // 1024 // 1024} MB")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(bytes(data))
    print(f"  Saved {len(data):,} bytes to {output}")
    print(f"  ({errors} unreadable pages out of {size // PAGE_SIZE})")
    return errors


def verify_dump(data: bytes) -> dict:
    """Verify the dump has key structures initialized."""
    results = {}

    # Check dispatcher function prologue at known RVA
    dispatcher_rva = 0x0066E5F0
    expected = bytes.fromhex("4889 5c24 0855 5657 4154 4155 4156 4157".replace(" ", ""))
    if dispatcher_rva + len(expected) <= len(data):
        actual = data[dispatcher_rva:dispatcher_rva + len(expected)]
        results["dispatcher"] = actual == expected
        if not results["dispatcher"]:
            print(f"  Dispatcher at 0x{dispatcher_rva:X}: {actual.hex(' ')}")
    else:
        results["dispatcher"] = False

    # Check LUT at 0x19B60F0 (used by 0x0228 cipher)
    lut_rva = 0x19B60F0
    if lut_rva + 256 <= len(data):
        lut = data[lut_rva:lut_rva + 256]
        unique_vals = len(set(lut))
        all_zero = all(b == 0 for b in lut)
        results["lut_0228"] = not all_zero
        results["lut_0228_unique"] = unique_vals
        if all_zero:
            print(f"  WARNING: LUT at 0x{lut_rva:X} is ALL ZEROS (not initialized!)")
        else:
            print(f"  LUT at 0x{lut_rva:X}: {unique_vals} unique values (initialized)")

    # Check function pointer table at 0x019B6200
    fptable_rva = 0x019B6200
    if fptable_rva + 48 * 10 <= len(data):
        nonzero_entries = 0
        for i in range(10):
            entry_offset = fptable_rva + i * 48
            qwords = struct.unpack_from("<6Q", data, entry_offset)
            if any(q != 0 for q in qwords):
                nonzero_entries += 1
        results["fptable_populated"] = nonzero_entries > 0
        print(f"  Function pointer table at 0x{fptable_rva:X}: "
              f"{nonzero_entries}/10 first entries non-zero")
    else:
        results["fptable_populated"] = False

    # Check known 0x0228 deserializer code at 0x00E748B0
    deser_rva = 0x00E748B0
    if deser_rva + 16 <= len(data):
        code = data[deser_rva:deser_rva + 16]
        has_code = any(b != 0 for b in code)
        results["deserializer_0228"] = has_code
        if not has_code:
            print(f"  WARNING: 0x0228 deserializer at 0x{deser_rva:X} is empty!")
    else:
        results["deserializer_0228"] = False

    return results


def main():
    import argparse

    p = argparse.ArgumentParser(
        description="Dump League binary at runtime (after initialization)"
    )
    p.add_argument("--exe", default=None,
                   help="Path to League of Legends.exe (auto-detected if not set)")
    p.add_argument("--rofl", required=True,
                   help="Path to .rofl replay file")
    p.add_argument("-o", "--output", default="ml/data/league_runtime_dump.bin",
                   help="Output path for dump")
    p.add_argument("--wait", type=float, default=10,
                   help="Seconds to wait for game initialization (default: 10)")
    p.add_argument("--no-vanguard-stop", action="store_true",
                   help="Skip stopping Vanguard (if already stopped)")
    p.add_argument("--no-vanguard-restart", action="store_true",
                   help="Skip restarting Vanguard after dump")
    args = p.parse_args()

    exe_path = args.exe or find_league_exe()
    if not exe_path or not Path(exe_path).exists():
        print(f"League of Legends.exe not found. Use --exe to specify path.")
        sys.exit(1)

    rofl_path = Path(args.rofl).resolve()
    if not rofl_path.exists():
        print(f"ROFL file not found: {rofl_path}")
        sys.exit(1)

    output = Path(args.output)

    print("=" * 60)
    print("  League Runtime Binary Dumper")
    print("  (Vanguard stopped → launch replay → wait → dump)")
    print("=" * 60)
    print(f"  EXE:  {exe_path}")
    print(f"  ROFL: {rofl_path}")
    print(f"  Wait: {args.wait}s")
    print(f"  Out:  {output}")

    # Get expected image size
    try:
        import pefile
        pe = pefile.PE(exe_path, fast_load=True)
        expected_size = pe.OPTIONAL_HEADER.SizeOfImage
        expected_base = pe.OPTIONAL_HEADER.ImageBase
        pe.close()
        print(f"  PE image: base=0x{expected_base:X}, size=0x{expected_size:X}")
    except ImportError:
        print("  WARNING: pefile not installed, using default size")
        expected_size = 0x2200000  # ~34MB fallback
        expected_base = 0x7FF76C300000

    # Step 1: Enable debug privilege
    enable_debug_privilege()

    # Step 2: Stop Vanguard
    if not args.no_vanguard_stop:
        stop_vanguard()
    else:
        print("[*] Skipping Vanguard stop (--no-vanguard-stop)")

    # Step 3: Kill any existing League processes
    print("[*] Killing existing League processes...")
    subprocess.run(["taskkill", "/IM", "League of Legends.exe", "/F"],
                   capture_output=True)
    time.sleep(1)

    # Step 4: Launch replay viewer
    print(f"[*] Launching replay viewer...")
    game_dir = str(Path(exe_path).parent)
    cmd = [
        exe_path,
        str(rofl_path),
        "-GameBaseDir=..",
        "-SkipBuild",
        "-EnableCrashpad=true",
        "-EnableLNP",
        "-UseDX11=1:1",
        "-UseMetal=0:1",
        "-UseNewX3D",
        "-UseNewX3DFramebuffers",
    ]
    print(f"  CMD: {' '.join(cmd[:3])} ...")

    try:
        proc = subprocess.Popen(cmd, cwd=game_dir)
    except OSError as e:
        print(f"  Failed to launch: {e}")
        if not args.no_vanguard_restart:
            start_vanguard()
        sys.exit(1)

    pid = proc.pid
    print(f"  PID: {pid}")

    try:
        # Step 5: Wait for initialization
        print(f"[*] Waiting {args.wait}s for game initialization...")
        print(f"    (Game window should appear. This is normal.)")

        for i in range(int(args.wait)):
            # Check if process is still alive
            ret = proc.poll()
            if ret is not None:
                print(f"\n  ERROR: Game exited early with code {ret}")
                print(f"  The game may require Vanguard to run.")
                print(f"  Check logs in: {game_dir}\\Logs\\")
                if not args.no_vanguard_restart:
                    start_vanguard()
                sys.exit(1)
            time.sleep(1)
            sys.stdout.write(f"\r    {i+1}/{int(args.wait)}s")
            sys.stdout.flush()
        print()

        # Check process is still alive
        if proc.poll() is not None:
            print(f"  ERROR: Game exited during wait period")
            if not args.no_vanguard_restart:
                start_vanguard()
            sys.exit(1)

        # Step 6: Suspend all threads
        print(f"[*] Suspending all threads...")
        threads = suspend_all_threads(pid)
        print(f"  Suspended {len(threads)} threads")
        time.sleep(0.5)

        # Step 7: Open process and find main module
        print(f"[*] Opening process for memory read...")
        hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not hProcess:
            err = kernel32.GetLastError()
            print(f"  ERROR: OpenProcess failed (error={err})")
            print(f"  Vanguard kernel driver may still be active.")
            print(f"  Try rebooting, then run this BEFORE opening League Client.")
            proc.kill()
            if not args.no_vanguard_restart:
                start_vanguard()
            sys.exit(1)

        # Get module info
        mi = MODULEINFO()
        hMod = ctypes.c_void_p()
        cbNeeded = ctypes.c_uint32()

        psapi.EnumProcessModules(
            hProcess,
            ctypes.byref(hMod),
            ctypes.sizeof(hMod),
            ctypes.byref(cbNeeded),
        )

        psapi.GetModuleInformation(
            hProcess, hMod, ctypes.byref(mi), ctypes.sizeof(mi)
        )

        base = mi.lpBaseOfDll or 0
        size = mi.SizeOfImage or expected_size

        print(f"  Module base: 0x{base:X}")
        print(f"  Module size: 0x{size:X} ({size // 1024 // 1024} MB)")

        # Quick sanity check: read MZ header
        mz_buf = ctypes.create_string_buffer(2)
        bytes_read = ctypes.c_size_t()
        ok = kernel32.ReadProcessMemory(
            ctypes.c_void_p(hProcess),
            ctypes.c_void_p(base),
            mz_buf, 2, ctypes.byref(bytes_read),
        )
        if ok and mz_buf.raw[:2] == b"MZ":
            print(f"  MZ header: OK")
        else:
            print(f"  ERROR: Cannot read MZ header! Memory access blocked.")
            kernel32.CloseHandle(hProcess)
            proc.kill()
            if not args.no_vanguard_restart:
                start_vanguard()
            sys.exit(1)

        # Step 8: Dump
        print(f"\n[*] Dumping runtime memory...")
        errors = dump_module(hProcess, base, size, output)

        kernel32.CloseHandle(hProcess)

        # Step 9: Verify
        print(f"\n[*] Verifying dump...")
        dump_data = output.read_bytes()
        results = verify_dump(dump_data)

        all_ok = all(results.values())
        if all_ok:
            print(f"\n{'=' * 60}")
            print(f"  SUCCESS! Runtime dump saved to: {output}")
            print(f"  All key structures verified.")
            print(f"")
            print(f"  To use with movement decoder:")
            print(f"    # Update binary_path in your scripts:")
            print(f"    binary_path = \"{output}\"")
            print(f"{'=' * 60}")
        else:
            print(f"\n  Dump saved but some structures may not be initialized.")
            print(f"  Results: {results}")
            print(f"  Try increasing --wait (current: {args.wait}s)")

        # Save metadata
        import json as _json
        meta = {
            "base": base,
            "size": size,
            "exe": str(exe_path),
            "rofl": str(rofl_path),
            "wait_seconds": args.wait,
            "timestamp": time.time(),
            "unreadable_pages": errors,
            "verification": {k: v for k, v in results.items()
                            if not isinstance(v, bool) or v},
            "type": "runtime_dump",
        }
        meta_path = output.with_suffix(".json")
        meta_path.write_text(_json.dumps(meta, indent=2))
        print(f"  Metadata: {meta_path}")

    finally:
        # Kill the game process
        print(f"\n[*] Terminating game process...")
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)

        if not args.no_vanguard_restart:
            start_vanguard()

    print("\nDone.")


if __name__ == "__main__":
    main()

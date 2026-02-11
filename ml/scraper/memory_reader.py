"""
Windows-only memory reader for League of Legends game state.

Reads champion positions, health, and other data directly from the
game process memory while a replay is playing.

This is the "secret sauce" from the TLoL approach — the LoL client
decodes the replay for us, and we just read the decoded game state
from memory.

NOTE: Memory offsets change each patch. The offsets here are
placeholders that need to be updated. Community resources:
  - https://github.com/LeagueSandbox
  - Various scripting communities maintain offset databases

Usage:
    reader = LoLMemoryReader()
    reader.attach()
    positions = reader.get_champion_positions()
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import struct
import sys
import time
from dataclasses import dataclass
from typing import Any

if sys.platform != "win32":
    raise ImportError("memory_reader.py is Windows-only (requires ReadProcessMemory)")

import psutil

# ── Windows API constants ────────────────────────────────────────────

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [
    ctypes.wintypes.HANDLE,  # hProcess
    ctypes.wintypes.LPCVOID,  # lpBaseAddress
    ctypes.wintypes.LPVOID,  # lpBuffer
    ctypes.c_size_t,  # nSize
    ctypes.POINTER(ctypes.c_size_t),  # lpNumberOfBytesRead
]
ReadProcessMemory.restype = ctypes.wintypes.BOOL

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
OpenProcess.restype = ctypes.wintypes.HANDLE

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
CloseHandle.restype = ctypes.wintypes.BOOL


# ── Memory offset definitions ────────────────────────────────────────
#
# IMPORTANT: These offsets are PLACEHOLDERS. They change every patch.
# You need to update them using a tool like Cheat Engine or by
# checking community-maintained offset databases.
#
# The structure is: base_address + offset chain to reach each field.
#
# Common approach:
#   1. Find the "GameClient" or "NetClient" base pointer
#   2. Follow pointer chains to the ObjectManager
#   3. ObjectManager has a list of all game objects (champions, minions, etc.)
#   4. Each object has fields at known offsets (position, health, etc.)

@dataclass
class MemoryOffsets:
    """
    Patch-specific memory offsets.

    UPDATE THESE EACH PATCH. See README_SETUP.md for resources.
    """
    # Base module: "League of Legends.exe"
    # These are offsets from the module base address

    # Object Manager — contains list of all game objects
    obj_manager: int = 0x0  # PLACEHOLDER — find via signature scan

    # Game time (float, seconds)
    game_time: int = 0x0  # PLACEHOLDER

    # Object list
    obj_list_start: int = 0x0  # PLACEHOLDER
    obj_list_end: int = 0x0  # PLACEHOLDER

    # Per-object offsets (from object base)
    obj_team: int = 0x4C
    obj_position: int = 0x220  # Vec3 (x, y, z) as 3x f32
    obj_health: int = 0xF8C
    obj_max_health: int = 0xFA0
    obj_mana: int = 0x340
    obj_max_mana: int = 0x368
    obj_armor: int = 0x16A4
    obj_magic_resist: int = 0x16AC
    obj_attack_damage: int = 0x1694
    obj_ability_power: int = 0x0  # PLACEHOLDER
    obj_move_speed: int = 0x16C4
    obj_attack_speed: int = 0x16DC
    obj_level: int = 0x47A0
    obj_is_dead: int = 0x328
    obj_gold: int = 0x1C98
    obj_name: int = 0x38  # char* to champion name string
    obj_network_id: int = 0xCC

    # Champion-specific
    obj_spell_book: int = 0x2D50  # Spell slots
    obj_buff_manager: int = 0x2600

    # Patch info
    patch: str = "UNKNOWN"


# Default offsets — MUST be updated per patch
CURRENT_OFFSETS = MemoryOffsets(patch="PLACEHOLDER_UPDATE_ME")


# ── Memory Reader ────────────────────────────────────────────────────

class LoLMemoryReader:
    """Read League of Legends process memory on Windows."""

    def __init__(self, offsets: MemoryOffsets | None = None):
        self.offsets = offsets or CURRENT_OFFSETS
        self.process_handle = None
        self.pid = None
        self.base_address = None
        self._attached = False

    def attach(self) -> bool:
        """Find and attach to the League of Legends game process."""
        # Find the game process (not the client — the actual game)
        target_name = "League of Legends.exe"
        for proc in psutil.process_iter(["name", "pid"]):
            if proc.info["name"] == target_name:
                self.pid = proc.info["pid"]
                break

        if self.pid is None:
            print(f"[MemReader] {target_name} not found. Is a replay running?")
            return False

        # Open process for reading
        self.process_handle = OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            False,
            self.pid,
        )

        if not self.process_handle:
            print(f"[MemReader] Failed to open process {self.pid}")
            return False

        # Get base address of the main module
        self.base_address = self._get_module_base(target_name)
        if self.base_address is None:
            print(f"[MemReader] Failed to get base address")
            return False

        self._attached = True
        print(f"[MemReader] Attached to PID {self.pid}, base=0x{self.base_address:X}")
        return True

    def detach(self):
        """Close the process handle."""
        if self.process_handle:
            CloseHandle(self.process_handle)
            self.process_handle = None
            self._attached = False

    def _get_module_base(self, module_name: str) -> int | None:
        """Get the base address of a module in the target process."""
        try:
            proc = psutil.Process(self.pid)
            # On Windows, we can enumerate modules
            import ctypes
            from ctypes import wintypes

            hModuleSnap = ctypes.windll.kernel32.CreateToolhelp32Snapshot(0x00000008, self.pid)
            if hModuleSnap == -1:
                return None

            class MODULEENTRY32(ctypes.Structure):
                _fields_ = [
                    ("dwSize", wintypes.DWORD),
                    ("th32ModuleID", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("GlblcntUsage", wintypes.DWORD),
                    ("ProccntUsage", wintypes.DWORD),
                    ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
                    ("modBaseSize", wintypes.DWORD),
                    ("hModule", wintypes.HMODULE),
                    ("szModule", ctypes.c_char * 256),
                    ("szExePath", ctypes.c_char * 260),
                ]

            me32 = MODULEENTRY32()
            me32.dwSize = ctypes.sizeof(MODULEENTRY32)

            if ctypes.windll.kernel32.Module32First(hModuleSnap, ctypes.byref(me32)):
                while True:
                    if me32.szModule.decode("utf-8", errors="ignore").lower() == module_name.lower():
                        base = ctypes.cast(me32.modBaseAddr, ctypes.c_void_p).value
                        ctypes.windll.kernel32.CloseHandle(hModuleSnap)
                        return base
                    if not ctypes.windll.kernel32.Module32Next(hModuleSnap, ctypes.byref(me32)):
                        break

            ctypes.windll.kernel32.CloseHandle(hModuleSnap)
        except Exception as e:
            print(f"[MemReader] Module enumeration error: {e}")

        return None

    # ── Raw memory reads ──────────────────────────────────────────────

    def read_bytes(self, address: int, size: int) -> bytes | None:
        """Read raw bytes from process memory."""
        if not self._attached:
            return None
        buf = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        ok = ReadProcessMemory(
            self.process_handle,
            ctypes.c_void_p(address),
            buf,
            size,
            ctypes.byref(bytes_read),
        )
        if ok and bytes_read.value == size:
            return buf.raw
        return None

    def read_int(self, address: int) -> int | None:
        data = self.read_bytes(address, 4)
        return struct.unpack("<i", data)[0] if data else None

    def read_uint(self, address: int) -> int | None:
        data = self.read_bytes(address, 4)
        return struct.unpack("<I", data)[0] if data else None

    def read_float(self, address: int) -> float | None:
        data = self.read_bytes(address, 4)
        return struct.unpack("<f", data)[0] if data else None

    def read_vec3(self, address: int) -> tuple[float, float, float] | None:
        data = self.read_bytes(address, 12)
        if data:
            return struct.unpack("<fff", data)
        return None

    def read_pointer(self, address: int) -> int | None:
        """Read a pointer (4 bytes on 32-bit, 8 on 64-bit)."""
        # LoL game is 64-bit now
        data = self.read_bytes(address, 8)
        return struct.unpack("<Q", data)[0] if data else None

    def read_string(self, address: int, max_len: int = 64) -> str | None:
        data = self.read_bytes(address, max_len)
        if data:
            null_idx = data.find(b"\x00")
            if null_idx >= 0:
                data = data[:null_idx]
            return data.decode("utf-8", errors="replace")
        return None

    # ── High-level reads ──────────────────────────────────────────────

    def get_game_time(self) -> float | None:
        """Read current game time from memory."""
        if self.offsets.game_time == 0:
            return None
        addr = self.base_address + self.offsets.game_time
        return self.read_float(addr)

    def get_champion_positions(self) -> list[dict]:
        """
        Read all champion positions from the object manager.

        Returns list of {name, team, x, y, z, health, max_health, ...}
        """
        if self.offsets.obj_manager == 0:
            print("[MemReader] WARNING: obj_manager offset is 0 (placeholder). "
                  "Update CURRENT_OFFSETS for your patch!")
            return []

        results = []
        # Read object manager pointer
        obj_mgr_ptr = self.read_pointer(self.base_address + self.offsets.obj_manager)
        if not obj_mgr_ptr:
            return []

        # Read object list bounds
        list_start = self.read_pointer(obj_mgr_ptr + self.offsets.obj_list_start)
        list_end = self.read_pointer(obj_mgr_ptr + self.offsets.obj_list_end)
        if not list_start or not list_end:
            return []

        # Each entry is a pointer (8 bytes)
        count = (list_end - list_start) // 8
        if count <= 0 or count > 500:  # sanity check
            return []

        for i in range(count):
            obj_ptr = self.read_pointer(list_start + i * 8)
            if not obj_ptr or obj_ptr < 0x10000:
                continue

            # Read team
            team = self.read_int(obj_ptr + self.offsets.obj_team)
            if team not in (100, 200):  # Not a champion/unit
                continue

            # Read position
            pos = self.read_vec3(obj_ptr + self.offsets.obj_position)
            if not pos:
                continue

            # Read health
            hp = self.read_float(obj_ptr + self.offsets.obj_health)
            max_hp = self.read_float(obj_ptr + self.offsets.obj_max_health)

            # Read name pointer and string
            name_ptr = self.read_pointer(obj_ptr + self.offsets.obj_name)
            name = self.read_string(name_ptr) if name_ptr else "?"

            results.append({
                "name": name,
                "team": "blue" if team == 100 else "red",
                "x": pos[0],
                "y": pos[1],
                "z": pos[2],
                "health": hp or 0,
                "max_health": max_hp or 0,
            })

        return results


# ── Quick test ────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== LoL Memory Reader Test ===")
    print("NOTE: Memory offsets are PLACEHOLDERS. Update CURRENT_OFFSETS first!")
    print()

    reader = LoLMemoryReader()
    if reader.attach():
        gt = reader.get_game_time()
        print(f"Game time: {gt}")

        champs = reader.get_champion_positions()
        print(f"Champions found: {len(champs)}")
        for c in champs:
            print(f"  {c['name']} ({c['team']}): ({c['x']:.0f}, {c['y']:.0f}) "
                  f"HP: {c['health']:.0f}/{c['max_health']:.0f}")

        reader.detach()
    else:
        print("Failed to attach. Is a replay running?")

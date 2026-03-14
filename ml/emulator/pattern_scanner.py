"""
Pattern Scanner — Find game functions by byte patterns.

Instead of manually reversing each patch in Ghidra, this scans the
loaded game binary for known byte patterns that identify key functions.

The patterns are stable across patches because:
  - Function prologues don't change much
  - The packet handler's switch statement structure is consistent
  - String references to packet names remain in the binary

Usage:
    scanner = PatternScanner(base_address, image_size)
    results = scanner.scan_all()
    # results = {"packet_handler": 0x1234, "movement": 0x5678, ...}

When patterns break (after a major patch), update PATTERNS below
by finding the new patterns in Ghidra once — then all future patches
with the same structure will work automatically.
"""

from __future__ import annotations

import ctypes
import struct
import re
from dataclasses import dataclass
from typing import Any


@dataclass
class Pattern:
    """A byte pattern to search for in the binary."""
    name: str
    # Pattern format: "48 89 5C 24 ?? 48 89 74 24 ?? 57"
    # ?? = wildcard byte (matches anything)
    pattern: str
    # Offset from match start to the actual function entry
    offset: int = 0
    # Description for debugging
    description: str = ""


# ═══════════════════════════════════════════════════════════════════════
# Known Patterns
# ═══════════════════════════════════════════════════════════════════════
#
# These are byte patterns found in League of Legends.exe that identify
# specific functions. They use x86-64 instruction sequences that tend
# to stay stable across patches.
#
# Format: hex bytes separated by spaces, ?? for wildcard
#
# To find new patterns:
#   1. Open the target function in Ghidra
#   2. Copy the first ~20 bytes of the function
#   3. Replace any bytes that look patch-specific with ??
#   4. Test against multiple patch versions
#
# ═══════════════════════════════════════════════════════════════════════

PATTERNS: list[Pattern] = [
    # ── Packet Handler ────────────────────────────────────────────
    # The main packet processing function typically has a prologue that
    # saves several registers and sets up a large stack frame for the
    # switch/case on packet type IDs.
    #
    # Look for a function that:
    #   - Takes 4 args: this, channel, data*, length
    #   - Has a switch on data[0] (packet type byte)
    #   - References many handler sub-functions
    Pattern(
        name="packet_handler",
        # Common x64 function prologue: push rbx; sub rsp, ??; mov [rsp+??], ...
        # followed by accessing the packet type byte
        pattern="48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 8B ?? 0F B6",
        description="Main packet processing function (switch on packet type)",
    ),

    # Alternative pattern for packet handler — some versions use different prologues
    Pattern(
        name="packet_handler_alt",
        # push rbp; mov rbp, rsp; push r15; push r14; ... sub rsp, large_value
        pattern="55 48 8B EC 41 57 41 56 41 55 41 54 53 48 81 EC",
        description="Alt packet handler prologue (large stack frame)",
    ),

    # ── ENet Receive ──────────────────────────────────────────────
    # The function that receives ENet packets and dispatches them.
    # Usually references the string "ENet" nearby.
    Pattern(
        name="enet_receive",
        pattern="48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 48 89 7C 24 ?? 41 56 48 83 EC ?? 48 8B",
        description="ENet packet receive function",
    ),

    # ── Packet Decryption ─────────────────────────────────────────
    # The decryption function uses lookup tables (255 bytes) and
    # bitwise operations. Look for:
    #   - ROL/ROR instructions
    #   - NOT instructions
    #   - Multiple table lookups (movzx + array access)
    Pattern(
        name="packet_decrypt",
        # movzx + lea (table access) + rol/not sequence
        pattern="0F B6 ?? 48 8D ?? ?? ?? ?? ?? 0F B6 ?? ?? C0",
        description="Packet decryption function (lookup table + bitwise ops)",
    ),

    # ── Movement Data Handler ─────────────────────────────────────
    Pattern(
        name="movement",
        # Typically reads position floats: movss xmm?, [reg+offset]
        pattern="F3 0F 10 ?? ?? ?? ?? ?? F3 0F 10 ?? ?? ?? ?? ?? F3 0F 11",
        description="Movement data parser (reads x,y position floats)",
    ),

    # ── Spell Cast Handler ────────────────────────────────────────
    Pattern(
        name="spell_cast",
        # Often references spell slot (0-3 for Q/W/E/R) and cooldown
        pattern="48 89 5C 24 ?? 48 89 74 24 ?? 48 89 7C 24 ?? 41 56 48 83 EC ?? 44 0F B6",
        description="Spell cast packet handler",
    ),

    # ── Death Handler ─────────────────────────────────────────────
    Pattern(
        name="death",
        # Die_S2C typically accesses killer/victim net IDs
        pattern="48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 54 41 55",
        description="Death event handler",
    ),

    # ── Stats Update Handler ──────────────────────────────────────
    Pattern(
        name="stats_update",
        # UpdateStats reads many float values (HP, mana, AD, etc.)
        pattern="48 89 5C 24 ?? 48 89 74 24 ?? 48 89 7C 24 ?? 55 41 54 41 55 41 56 41 57 48 8D",
        description="Stats update handler (HP, mana, etc.)",
    ),
]

# ── String-based patterns ─────────────────────────────────────────
# These find functions by looking for references to known strings
# in the binary's .rdata section.

STRING_MARKERS: dict[str, list[str]] = {
    "packet_handler": [
        "HandlePacket",
        "ProcessPacket",
        "OnPacket",
        "PacketHandler",
    ],
    "enet_receive": [
        "ENetPacket",
        "ENet::Receive",
        "enet_peer",
    ],
    "movement": [
        "MovementData",
        "waypoint",
        "Waypoint",
    ],
    "spell_cast": [
        "SpellCast",
        "CastSpell",
        "S2C_SpellCast",
    ],
    "death": [
        "Die_S2C",
        "OnDeath",
        "DeathEvent",
    ],
}


class PatternScanner:
    """
    Scan loaded PE memory for known function patterns.

    Works on the natively-loaded game binary (after NativePELoader.load()).
    """

    def __init__(self, base_address: int, image_size: int):
        self.base = base_address
        self.size = image_size

        # Read the entire image into a Python bytes object for fast scanning
        self._data = (ctypes.c_uint8 * image_size).from_address(base_address)

    def scan_pattern(self, pattern: Pattern) -> int | None:
        """
        Scan for a byte pattern in the loaded image.
        Returns the RVA (relative to image base) or None.
        """
        regex = self._pattern_to_regex(pattern.pattern)
        data_bytes = bytes(self._data)

        match = regex.search(data_bytes)
        if match:
            rva = match.start() + pattern.offset
            print(f"  [SCAN] Found {pattern.name} at RVA 0x{rva:X} "
                  f"({pattern.description})")
            return rva

        return None

    def scan_string(self, target: str) -> list[int]:
        """
        Find all occurrences of a string in the image.
        Returns list of RVAs where the string was found.
        """
        data_bytes = bytes(self._data)
        encoded = target.encode("ascii")
        results = []

        start = 0
        while True:
            idx = data_bytes.find(encoded, start)
            if idx == -1:
                break
            results.append(idx)
            start = idx + 1

        return results

    def find_xrefs_to(self, rva: int) -> list[int]:
        """
        Find cross-references to a given RVA.

        Searches for LEA/MOV instructions that reference the target address.
        This is how we find functions that use specific strings.

        Returns list of RVAs where references were found.
        """
        data_bytes = bytes(self._data)
        target_abs = self.base + rva
        xrefs = []

        # Search for RIP-relative LEA instructions: 48 8D ?? XX XX XX XX
        # The displacement is relative to the NEXT instruction (RIP + 7)
        for i in range(len(data_bytes) - 7):
            # LEA r64, [rip+disp32]
            if data_bytes[i] == 0x48 and data_bytes[i+1] == 0x8D:
                modrm = data_bytes[i+2]
                # Check for RIP-relative addressing (mod=00, r/m=101)
                if (modrm & 0xC7) == 0x05:
                    disp = struct.unpack_from("<i", data_bytes, i + 3)[0]
                    target = i + 7 + disp  # RIP + 7 + displacement
                    if target == rva:
                        xrefs.append(i)

        return xrefs

    def scan_for_function_by_string(self, func_name: str,
                                     strings: list[str]) -> int | None:
        """
        Find a function by looking for string references.

        1. Find the string in .rdata
        2. Find code that references that string (LEA instruction)
        3. Walk backwards to find the function prologue
        """
        data_bytes = bytes(self._data)

        for s in strings:
            string_rvas = self.scan_string(s)
            for string_rva in string_rvas:
                # Find code references to this string
                xrefs = self.find_xrefs_to(string_rva)
                for xref_rva in xrefs:
                    # Walk backwards to find function start
                    func_start = self._find_function_start(xref_rva)
                    if func_start is not None:
                        print(f"  [SCAN] Found {func_name} via string "
                              f"\"{s}\" at RVA 0x{func_start:X}")
                        return func_start

        return None

    def _find_function_start(self, code_rva: int) -> int | None:
        """
        Walk backwards from a code reference to find the function prologue.

        Common x64 prologues:
          - push rbp (55)
          - push rbx (53)
          - sub rsp, XX (48 83 EC XX or 48 81 EC XX XX XX XX)
          - mov [rsp+XX], rbx (48 89 5C 24 XX)
        """
        data_bytes = bytes(self._data)

        # Search backwards up to 4KB
        for offset in range(0, min(4096, code_rva)):
            addr = code_rva - offset

            # Check for common prologues
            if addr >= 0:
                b = data_bytes[addr]

                # push rbp
                if b == 0x55:
                    # Verify next bytes look like a prologue
                    if addr + 1 < len(data_bytes):
                        next_b = data_bytes[addr + 1]
                        if next_b in (0x48, 0x41, 0x53, 0x56, 0x57):
                            return addr

                # push rbx
                if b == 0x53:
                    return addr

                # mov [rsp+XX], ... (save register to stack)
                if (b == 0x48 and addr + 4 < len(data_bytes) and
                        data_bytes[addr + 1] == 0x89 and
                        data_bytes[addr + 2] == 0x5C and
                        data_bytes[addr + 3] == 0x24):
                    return addr

                # sub rsp, XX
                if (b == 0x48 and addr + 3 < len(data_bytes) and
                        data_bytes[addr + 1] == 0x83 and
                        data_bytes[addr + 2] == 0xEC):
                    return addr

                # Check for CC CC padding (INT3 padding between functions)
                # If we hit padding, the function starts right after
                if b == 0xCC and addr + 1 < len(data_bytes):
                    next_b = data_bytes[addr + 1]
                    if next_b != 0xCC:
                        return addr + 1

        return None

    def scan_all(self) -> dict[str, int]:
        """
        Scan for all known patterns and return found RVAs.

        Returns: {name: rva} for each function found.
        """
        print("[SCAN] Scanning for known function patterns...")
        results: dict[str, int] = {}

        # 1. Try byte patterns first (fastest)
        for pattern in PATTERNS:
            if pattern.name in results:
                continue  # Already found via another pattern
            rva = self.scan_pattern(pattern)
            if rva is not None:
                # Strip _alt suffix for alternative patterns
                name = pattern.name.replace("_alt", "")
                if name not in results:
                    results[name] = rva

        # 2. For any not found, try string-based search
        for func_name, strings in STRING_MARKERS.items():
            if func_name in results:
                continue
            rva = self.scan_for_function_by_string(func_name, strings)
            if rva is not None:
                results[func_name] = rva

        # Summary
        print(f"\n[SCAN] Results: {len(results)} functions found")
        for name, rva in sorted(results.items()):
            print(f"  {name:<20s} RVA 0x{rva:08X}")

        not_found = (
            {"packet_handler", "movement", "spell_cast", "death"}
            - set(results.keys())
        )
        if not_found:
            print(f"\n[SCAN] NOT FOUND: {', '.join(sorted(not_found))}")
            print("  These may need manual Ghidra analysis or updated patterns.")
            print("  Run ghidra_find_handlers.py for guidance.")

        return results

    @staticmethod
    def _pattern_to_regex(pattern: str) -> re.Pattern:
        """
        Convert a hex pattern string to a regex.
        "48 89 5C ?? 08" → b"\\x48\\x89\\x5C.\\x08"
        """
        parts = []
        for byte_str in pattern.strip().split():
            if byte_str == "??":
                parts.append(b".")
            else:
                parts.append(re.escape(bytes([int(byte_str, 16)])))
        return re.compile(b"".join(parts), re.DOTALL)


# ═══════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m ml.emulator.pattern_scanner <League_of_Legends.exe>")
        print()
        print("Loads the binary and scans for known function patterns.")
        print("Output can be fed to native_emulator.py")
        sys.exit(1)

    from ml.emulator.native_emulator import NativePELoader

    exe_path = sys.argv[1]
    print(f"Loading {exe_path}...")

    loader = NativePELoader(exe_path)
    base = loader.load()

    scanner = PatternScanner(base, loader.size_of_image)
    results = scanner.scan_all()

    if results:
        print("\n\nTo use these results with the emulator:")
        print("  python -m ml.emulator.native_emulator \\")
        print(f"    {exe_path} \\")
        if "packet_handler" in results:
            print(f"    --handler-rva 0x{results['packet_handler']:X} \\")
        print("    replay.rofl")

    loader.unload()

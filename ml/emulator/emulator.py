"""
Replay Emulator — Feed .rofl packets into League's own decoding functions.

Architecture (Sabrina-style):
  1. Load League of Legends.exe into Unicorn CPU emulator
  2. Set up stack, heap, TLS (thread-local storage)
  3. Hook imported functions (malloc, memcpy, etc.) with stubs
  4. Hook invalid memory accesses (map pages on demand)
  5. Find the packet processing function (via Ghidra reversing)
  6. Feed each packet from our ROFL parser into that function
  7. Hook output locations to capture decoded game state

Phase 1 (this file): Scaffold + on-demand memory mapping.
  You will need to fill in PACKET_HANDLER_RVA after reversing with Ghidra.

Requires: pip install unicorn pefile
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

try:
    from unicorn import (
        Uc, UC_ARCH_X86, UC_MODE_64,
        UC_PROT_ALL,
        UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
        UC_HOOK_MEM_FETCH_UNMAPPED,
        UC_HOOK_CODE,
        UcError,
    )
    from unicorn.x86_const import (
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RSP, UC_X86_REG_RBP,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
        UC_X86_REG_RIP,
    )
    HAS_UNICORN = True
except ImportError:
    HAS_UNICORN = False

from ml.emulator.pe_loader import PELoader


# ── Memory layout ────────────────────────────────────────────────────

STACK_BASE   = 0x0000_0070_0000_0000
STACK_SIZE   = 2 * 1024 * 1024       # 2 MB

HEAP_BASE    = 0x0000_0080_0000_0000
HEAP_SIZE    = 64 * 1024 * 1024       # 64 MB

# Scratch buffer for passing packet data to emulated functions
PACKET_BUF   = 0x0000_0060_0000_0000
PACKET_BUF_SZ = 1 * 1024 * 1024      # 1 MB

# "Return" address — when the emulated function hits this, we stop
STOP_ADDR    = 0x0000_00FF_0000_0000

# TLS (Thread Local Storage) — some game functions read from gs:[0x58] etc.
TLS_BASE     = 0x0000_0050_0000_0000
TLS_SIZE     = 0x1000

PAGE_SIZE    = 0x1000


# ── Decoded output ───────────────────────────────────────────────────

@dataclass
class DecodedPacket:
    """Output from running a packet through the game's decoder."""
    channel: int
    packet_type: int  # first 1-2 bytes of packet data
    game_time: float
    raw_data: bytes
    decoded: dict[str, Any] = field(default_factory=dict)


@dataclass
class DecodedReplay:
    """Full decoded replay — all packets across all frames."""
    game_version: str
    game_id: str
    packets: list[DecodedPacket] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    decode_time_s: float = 0.0


# ── Emulator ─────────────────────────────────────────────────────────

class ReplayEmulator:
    """
    CPU emulator that loads League of Legends.exe and runs its
    packet decoding functions on replay data.
    """

    def __init__(self, game_exe: str | Path):
        if not HAS_UNICORN:
            raise ImportError("pip install unicorn")

        self.loader = PELoader(game_exe)
        self.emu: Uc | None = None
        self.heap_ptr = HEAP_BASE  # bump allocator
        self._page_faults = 0
        self._hooks: dict[int, Callable] = {}  # addr -> hook function

        # ═══════════════════════════════════════════════════════════════
        # !! FILL THESE IN after reversing with Ghidra !!
        # These are RVAs (relative to image base) of key functions.
        # ═══════════════════════════════════════════════════════════════
        self.PACKET_HANDLER_RVA: int = 0  # void ProcessPacket(ctx, channel, data, len)
        self.MOVEMENT_HANDLER_RVA: int = 0  # MovementDataNormal handler
        self.SPELL_HANDLER_RVA: int = 0  # SpellCastS2C handler
        # Add more as you find them in Ghidra

    def setup(self):
        """Initialize emulator, load PE, set up memory regions."""
        print("[EMU] Initializing x86-64 emulator...")
        self.emu = Uc(UC_ARCH_X86, UC_MODE_64)
        mu = self.emu

        # 1. Load the game binary
        self.loader.load_into(mu)

        # 2. Stack
        mu.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
        mu.reg_write(UC_X86_REG_RSP, STACK_BASE + STACK_SIZE - 0x1000)
        mu.reg_write(UC_X86_REG_RBP, STACK_BASE + STACK_SIZE - 0x1000)

        # 3. Heap (for malloc stubs)
        mu.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_ALL)

        # 4. Packet input buffer
        mu.mem_map(PACKET_BUF, PACKET_BUF_SZ, UC_PROT_ALL)

        # 5. Stop address (return trampoline)
        mu.mem_map(STOP_ADDR, PAGE_SIZE, UC_PROT_ALL)
        # Write INT3 (0xCC) at stop address — will cause exception
        mu.mem_write(STOP_ADDR, b"\xcc")

        # 6. TLS
        mu.mem_map(TLS_BASE, TLS_SIZE, UC_PROT_ALL)

        # 7. Hook: on-demand page mapping for uninitialized game state
        mu.hook_add(
            UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
            UC_HOOK_MEM_FETCH_UNMAPPED,
            self._hook_mem_invalid,
        )

        # 8. Hook imported functions with stubs
        self._hook_imports()

        print(f"[EMU] Ready. Image base=0x{self.loader.image_base:X}")

    def _hook_mem_invalid(self, emu, access, address, size, value, user_data):
        """
        On-demand memory mapping — the Sabrina trick.

        When the game code accesses uninitialized memory (game state structs
        that don't exist because we're not running the full game), we just
        map a zero page and continue. The function returns harmless zero
        values instead of crashing.
        """
        aligned = address & ~(PAGE_SIZE - 1)
        try:
            emu.mem_map(aligned, PAGE_SIZE, UC_PROT_ALL)
            emu.mem_write(aligned, b"\x00" * PAGE_SIZE)
            self._page_faults += 1
            return True  # continue execution
        except Exception:
            return False  # give up

    def _hook_imports(self):
        """
        Replace imported function calls with stubs.

        When the game's packet decoder calls malloc(), memcpy(), etc.,
        we intercept and handle them ourselves since we don't have the
        full Windows runtime loaded.
        """
        if not self.emu:
            return

        info = self.loader.info
        base = self.loader.image_base

        # For each imported function, write a stub at its IAT entry
        # that jumps to STOP_ADDR (where we intercept)
        stub_funcs = {
            "malloc": self._stub_malloc,
            "free": self._stub_noop,
            "calloc": self._stub_calloc,
            "realloc": self._stub_realloc,
            "memcpy": self._stub_memcpy,
            "memset": self._stub_memset,
            "memmove": self._stub_memcpy,  # close enough
            "strlen": self._stub_strlen,
            # Add more as needed — Ghidra will show which imports matter
        }

        # We'll use code hooks at the IAT stub addresses
        # For now, just log what imports exist
        for dll, funcs in info.imports.items():
            for name, rva in funcs.items():
                if name.lower() in {k.lower() for k in stub_funcs}:
                    # The IAT entry at base+rva contains the address
                    # to the actual function. We overwrite it with our stub.
                    # For now, just track it.
                    pass

        print(f"[EMU] Import stubs registered (placeholder — fill after Ghidra)")

    # ── Stubs for C runtime functions ────────────────────────────────

    def _stub_malloc(self, size: int) -> int:
        """Bump allocator."""
        ptr = self.heap_ptr
        self.heap_ptr += (size + 0xF) & ~0xF  # 16-byte aligned
        return ptr

    def _stub_calloc(self, count: int, size: int) -> int:
        return self._stub_malloc(count * size)

    def _stub_realloc(self, ptr: int, size: int) -> int:
        # Simplified — just allocate new, don't free old
        return self._stub_malloc(size)

    def _stub_memcpy(self, dst: int, src: int, size: int) -> int:
        if self.emu and size > 0:
            data = self.emu.mem_read(src, size)
            self.emu.mem_write(dst, bytes(data))
        return dst

    def _stub_memset(self, dst: int, val: int, size: int) -> int:
        if self.emu and size > 0:
            self.emu.mem_write(dst, bytes([val & 0xFF]) * size)
        return dst

    def _stub_strlen(self, ptr: int) -> int:
        if not self.emu:
            return 0
        length = 0
        while True:
            b = self.emu.mem_read(ptr + length, 1)
            if b[0] == 0:
                break
            length += 1
            if length > 0x10000:  # safety limit
                break
        return length

    def _stub_noop(self, *args) -> int:
        return 0

    # ── Core: decode a single packet ────────────────────────────────

    def decode_packet(self, channel: int, data: bytes,
                      game_time: float = 0.0) -> DecodedPacket:
        """
        Feed a single packet into the game's packet handler.

        This is the heart of the emulator: we set up the function arguments
        (Windows x64 calling convention: rcx, rdx, r8, r9) and run until
        the function returns.

        !! Requires PACKET_HANDLER_RVA to be set from Ghidra !!
        """
        if not self.emu:
            raise RuntimeError("Call setup() first")
        if self.PACKET_HANDLER_RVA == 0:
            raise RuntimeError(
                "PACKET_HANDLER_RVA not set. "
                "Open League of Legends.exe in Ghidra, find the packet "
                "processing function, and set its RVA."
            )

        mu = self.emu
        base = self.loader.image_base
        handler_addr = base + self.PACKET_HANDLER_RVA

        # Write packet data to input buffer
        mu.mem_write(PACKET_BUF, data)

        # Push return address (STOP_ADDR) onto stack
        rsp = mu.reg_read(UC_X86_REG_RSP)
        rsp -= 8
        mu.mem_write(rsp, struct.pack("<Q", STOP_ADDR))
        mu.reg_write(UC_X86_REG_RSP, rsp)

        # Windows x64 calling convention:
        #   rcx = 1st arg (context/this pointer — may need game state struct)
        #   rdx = 2nd arg (channel)
        #   r8  = 3rd arg (data pointer)
        #   r9  = 4th arg (data length)
        mu.reg_write(UC_X86_REG_RCX, 0)  # context — may need to set up
        mu.reg_write(UC_X86_REG_RDX, channel)
        mu.reg_write(UC_X86_REG_R8, PACKET_BUF)
        mu.reg_write(UC_X86_REG_R9, len(data))

        # Run
        try:
            mu.emu_start(handler_addr, STOP_ADDR, timeout=5_000_000)  # 5s timeout
        except UcError as e:
            return DecodedPacket(
                channel=channel,
                packet_type=data[0] if data else -1,
                game_time=game_time,
                raw_data=data,
                decoded={"error": str(e)},
            )

        # Restore stack
        mu.reg_write(UC_X86_REG_RSP, rsp + 8)

        # Read output — this is where you hook specific handlers
        # to capture the decoded result. For now, return raw.
        pkt_type = data[0] if data else -1
        return DecodedPacket(
            channel=channel,
            packet_type=pkt_type,
            game_time=game_time,
            raw_data=data,
            decoded={},  # fill after hooking specific packet handlers
        )

    # ── High-level: decode a full replay ────────────────────────────

    def decode_replay(self, rofl_path: str | Path) -> DecodedReplay:
        """
        Decode an entire .rofl file.

        Uses our existing ROFLParser to extract packets, then feeds
        each one through the emulator.
        """
        from ml.parsers.rofl_parser import ROFLParser
        from ml.parsers.chunk_parser import parse_payload_frames

        parser = ROFLParser(rofl_path)
        match_info = parser.get_match_info()

        result = DecodedReplay(
            game_version=match_info.get("game_version", ""),
            game_id=Path(rofl_path).stem,
        )

        t0 = time.time()

        # Decompress all frames
        print(f"[EMU] Decompressing {rofl_path}...")
        frames = parser.decompress_payload_frames()
        print(f"[EMU] {len(frames)} frames decompressed")

        # Parse frames into packets
        payload = parse_payload_frames(frames, parse_packets=True)
        total_pkts = payload.total_packets
        print(f"[EMU] {total_pkts:,} packets to decode")

        # Feed each packet through the emulator
        decoded = 0
        for frame in payload.frames:
            game_time = frame.header.timestamp
            for pkt in frame.packets:
                try:
                    dpkt = self.decode_packet(
                        channel=pkt.channel,
                        data=pkt.data,
                        game_time=game_time,
                    )
                    result.packets.append(dpkt)
                    decoded += 1
                except Exception as e:
                    result.errors.append(f"frame={frame.index} pkt_offset={pkt.offset}: {e}")

                if decoded % 1000 == 0 and decoded > 0:
                    print(f"  [{decoded:,}/{total_pkts:,}] "
                          f"time={game_time:.0f}s page_faults={self._page_faults}")

        result.decode_time_s = time.time() - t0
        print(f"[EMU] Done: {decoded:,} packets in {result.decode_time_s:.1f}s, "
              f"{self._page_faults} page faults")

        return result


# ── CLI ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m ml.emulator.emulator <game_exe> [rofl_file]")
        print()
        print("Step 1: Inspect the PE")
        print("  python -m ml.emulator.pe_loader League_of_Legends.exe")
        print()
        print("Step 2: After setting PACKET_HANDLER_RVA from Ghidra:")
        print("  python -m ml.emulator.emulator League_of_Legends.exe replay.rofl")
        sys.exit(1)

    game_exe = sys.argv[1]

    if len(sys.argv) == 2:
        # Just inspect
        loader = PELoader(game_exe)
        loader.print_info()
    else:
        # Decode a replay
        rofl_file = sys.argv[2]
        emu = ReplayEmulator(game_exe)
        emu.setup()
        result = emu.decode_replay(rofl_file)
        print(f"\nResult: {len(result.packets)} decoded, {len(result.errors)} errors")

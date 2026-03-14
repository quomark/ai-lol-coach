"""
Unicorn-based emulator for decoding League of Legends movement packets.

Follows the Mowokuma/ROFL architecture:
  1. Map binary dump into Unicorn at original base address with RWX
  2. Set up stack, heap, and bump allocator
  3. Hook TLS/global accesses and external calls
  4. Feed raw packet bytes through the deserialize function
  5. Read decoded fields from the packet struct

Movement packet structure (from reverse engineering):
  The top-level deserialize function (RVA 0xF60EF0) is a CACHING WRAPPER:
    - Reads an entity ID varint -> writes to this+0x0C
    - Reads 1 flag bit: 1=return cached data, 0=delegate to child deserializer
    - The child is embedded at this+0x10 (another object with its own vtable)
    - The child chain goes several levels deep, each reading one field

  Object layout (each level):
    +0x00: vtable pointer  (8 bytes)
    +0x08: field data      (4 bytes)
    +0x0C: varint result   (4 bytes, written by varint decoder)
    +0x10: child object    (starts here, another vtable+data+child)

  Vtable layout:
    [0] = destructor
    [1] = deserialize (the function we call)
    [2] = other method
    ...

Usage:
    python -m ml.emulator.unicorn_emulator
"""

from __future__ import annotations

import json
import struct
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from unicorn import (
    Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL,
    UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_HOOK_MEM_FETCH_UNMAPPED,
    UC_HOOK_CODE, UC_HOOK_MEM_WRITE,
    UcError,
)
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RSP, UC_X86_REG_RBP,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
    UC_X86_REG_RIP, UC_X86_REG_RFLAGS, UC_X86_REG_AL,
    UC_X86_REG_GS_BASE,
)

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


# =====================================================================
# Memory layout
# =====================================================================

STACK_BASE      = 0x0000_7FFF_FFFF_0000
STACK_SIZE      = 0x4000                   # 16KB stack
HEAP_BASE       = 0x0000_7FFF_FFFF_8000
HEAP_SIZE       = 0x8000                   # 32KB heap
PACKET_BUF      = 0x0000_0060_0000_0000    # Raw packet data area
PACKET_BUF_SZ   = 0x10000
PKT_STRUCT_BASE = 0x0000_0061_0000_0000    # Packet struct (this ptr)
PKT_STRUCT_SZ   = 0x10000
TLS_BASE        = 0x0000_0062_0000_0000    # Fake TLS area
TLS_SIZE        = 0x10000
GS_BASE         = 0x0000_0063_0000_0000    # Fake GS segment base
GS_SIZE         = 0x10000
STOP_ADDR       = 0x0000_00FF_0000_0000    # Return trampoline
STUB_BASE       = 0x0000_00FE_0000_0000    # Import stubs
STUB_SIZE       = 0x10000

PAGE_SIZE = 0x1000


def _align(v: int, a: int) -> int:
    return (v + a - 1) & ~(a - 1)


# =====================================================================
# Known vtable RVAs for movement deserializer chain
# These are the vtables found in the binary's .rdata section.
# Each vtable[1] is the deserialize function for that level.
# =====================================================================

# Level order in the caching wrapper chain (discovered from binary analysis)
# Each level: vtable_rva -> deserialize_rva
DESERIALIZER_VTABLES = {
    # vtable_rva: deserialize_func_rva
    0x19B9BC0: 0xF60EF0,   # L1: top-level movement
    0x19B9BF0: 0xF61020,   # L2: second field
    0x19B9A48: 0xF61150,   # L3: complex (2-bit flag, multiple paths)
    0x19B9A78: 0xF617A0,   # L4
    0x19B9C50: 0xF619F0,   # leaf1: simple inline varint (no sub_01150B40)
    0x19B9C78: 0xF61AE0,   # L5
    0x19B9CA8: 0xF61BF0,   # L6
    0x19B9AD8: 0xF61D00,   # L7
}


# =====================================================================
# Emulator
# =====================================================================

class MovementDecoder:
    """Unicorn-based movement packet decoder."""

    DESERIALIZE_RVA     = 0x00F60EF0   # Top-level movement deserialize
    VARINT_DECODER_RVA  = 0x01150B40   # Encrypted LEB128 varint decoder
    BITFIELD_READER_RVA = 0x00E7F010   # Bitfield reader
    TLS_INIT_GUARD_RVA  = 0x0182C714   # TLS initialization guard

    MAX_INSN = 2_000_000  # Safety limit per packet

    def __init__(self, dump_path: str | Path = "ml/data/league_unpacked_patched.bin",
                 meta_path: str | Path = "ml/data/league_dump_meta.json"):
        self.dump_path = Path(dump_path)
        self.meta_path = Path(meta_path)
        self.emu: Uc | None = None
        self.disasm: Cs | None = None

        self._image_base: int = 0
        self._image_size: int = 0

        # Debug tracking
        self._insn_count: int = 0
        self._page_faults: int = 0
        self._total_page_faults: int = 0
        self._mapped_pages: set[int] = set()
        self._call_log: list[str] = []
        self._mem_write_log: list[tuple[int, int, int]] = []
        self._call_targets: Counter = Counter()
        self._hooked_returns: Counter = Counter()

        # Verbose tracing control
        self.trace_calls = True
        self.trace_mem = False
        self.trace_insn = False
        self.trace_limit = 200

        # Hook control: force non-cached path
        self.force_delegate = False   # If True, bitfield reader returns 0

    def setup(self):
        """Initialize Unicorn emulator and load binary dump."""
        if not self.dump_path.exists():
            raise FileNotFoundError(f"Dump not found: {self.dump_path}")

        # Load metadata
        if self.meta_path.exists():
            meta = json.loads(self.meta_path.read_text())
            self._image_base = meta.get("base", 0x7FF76C300000)
        else:
            self._image_base = 0x7FF76C300000

        dump_data = self.dump_path.read_bytes()
        self._image_size = len(dump_data)

        print(f"[EMU] Loading binary dump: {self.dump_path}")
        print(f"      Base: 0x{self._image_base:016X}")
        print(f"      Size: {self._image_size:,} bytes ({self._image_size / 1024 / 1024:.1f} MB)")

        if HAS_CAPSTONE:
            self.disasm = Cs(CS_ARCH_X86, CS_MODE_64)
            print(f"      Capstone: available")

        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        self.emu = mu

        # 1. Map and load game binary
        aligned_size = _align(self._image_size, PAGE_SIZE)
        mu.mem_map(self._image_base, aligned_size, UC_PROT_ALL)
        mu.mem_write(self._image_base, dump_data)
        del dump_data
        print(f"      Binary: 0x{self._image_base:X} - 0x{self._image_base + aligned_size:X}")

        # Verify deserialize function
        d_addr = self._image_base + self.DESERIALIZE_RVA
        d_bytes = bytes(mu.mem_read(d_addr, 4))
        assert d_bytes == b"\x48\x89\x5c\x24", f"Bad prologue: {d_bytes.hex()}"
        print(f"      Deserialize verified at RVA 0x{self.DESERIALIZE_RVA:X}")

        # 2. Map support regions
        for name, addr, size in [
            ("Stack",      STACK_BASE,      STACK_SIZE),
            ("Heap",       HEAP_BASE,       HEAP_SIZE),
            ("PacketBuf",  PACKET_BUF,      PACKET_BUF_SZ),
            ("PktStruct",  PKT_STRUCT_BASE, PKT_STRUCT_SZ),
            ("TLS",        TLS_BASE,        TLS_SIZE),
            ("GS",         GS_BASE,         GS_SIZE),
            ("Stop",       STOP_ADDR,       PAGE_SIZE),
            ("Stubs",      STUB_BASE,       STUB_SIZE),
        ]:
            mu.mem_map(addr, size, UC_PROT_ALL)
            print(f"      {name:12s}: 0x{addr:X} ({size:#x})")

        # Stop address = INT3
        mu.mem_write(STOP_ADDR, b"\xCC")

        # 3. Set up GS segment for TLS access
        # gs:[0x58] -> TLS slot array -> slot entries -> TLS data block
        mu.reg_write(UC_X86_REG_GS_BASE, GS_BASE)
        tls_slot_array = TLS_BASE
        mu.mem_write(GS_BASE + 0x58, struct.pack("<Q", tls_slot_array))
        tls_data = TLS_BASE + 0x1000
        for i in range(256):
            mu.mem_write(tls_slot_array + i * 8, struct.pack("<Q", tls_data))
        print(f"      GS segment configured")

        # 4. Write stubs
        self._write_stubs()

        # 5. Install hooks
        mu.hook_add(
            UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
            UC_HOOK_MEM_FETCH_UNMAPPED,
            self._hook_mem_unmapped,
        )
        mu.hook_add(UC_HOOK_CODE, self._hook_code)
        mu.hook_add(UC_HOOK_MEM_WRITE, self._hook_mem_write)

        self._mapped_pages = set()
        print(f"[EMU] Setup complete\n")

    def _write_stubs(self):
        """Write stub functions for import replacement."""
        mu = self.emu
        off = 0
        # ret0: xor eax,eax; ret
        self._stub_ret0 = STUB_BASE + off
        mu.mem_write(STUB_BASE + off, b"\x31\xC0\xC3")
        off += 0x10
        # ret1: mov eax,1; ret
        self._stub_ret1 = STUB_BASE + off
        mu.mem_write(STUB_BASE + off, b"\xB8\x01\x00\x00\x00\xC3")
        off += 0x10

    def _hook_mem_unmapped(self, uc, access, address, size, value, user_data):
        """Auto-map zero pages for unmapped memory (Sabrina trick)."""
        aligned = address & ~(PAGE_SIZE - 1)
        if aligned in self._mapped_pages:
            return False
        try:
            uc.mem_map(aligned, PAGE_SIZE, UC_PROT_ALL)
            uc.mem_write(aligned, b"\x00" * PAGE_SIZE)
            self._mapped_pages.add(aligned)
            self._page_faults += 1
            self._total_page_faults += 1
            if self.trace_mem and len(self._call_log) < self.trace_limit:
                self._call_log.append(f"  [FAULT] 0x{address:X} -> mapped 0x{aligned:X}")
            return True
        except Exception:
            return False

    def _hook_mem_write(self, uc, access, address, size, value, user_data):
        """Track writes outside stack/image."""
        if STACK_BASE <= address < STACK_BASE + STACK_SIZE:
            return
        if self._image_base <= address < self._image_base + self._image_size:
            return
        self._mem_write_log.append((address, size, value))

    def _rva(self, addr: int) -> int:
        return addr - self._image_base

    def _disasm_at(self, addr: int) -> str:
        if not self.disasm or not self.emu:
            return ""
        try:
            code = bytes(self.emu.mem_read(addr, 15))
            for insn in self.disasm.disasm(code, addr):
                return f"{insn.mnemonic} {insn.op_str}"
        except Exception:
            pass
        return "???"

    def _hook_code(self, uc, address, size, user_data):
        """Instruction hook: intercept specific functions and external calls."""
        self._insn_count += 1

        if self._insn_count >= self.MAX_INSN:
            if len(self._call_log) < self.trace_limit:
                self._call_log.append(f"  [LIMIT] Hit {self.MAX_INSN} instruction limit")
            uc.emu_stop()
            return

        # Inside game image
        if self._image_base <= address < self._image_base + self._image_size:
            rva = address - self._image_base

            if self.trace_insn and len(self._call_log) < self.trace_limit:
                self._call_log.append(
                    f"  [INSN] RVA 0x{rva:X}: {self._disasm_at(address)}"
                )

            # Hook: TLS init guard -> return 1
            if rva == self.TLS_INIT_GUARD_RVA:
                self._hooked_returns["tls_init_guard"] += 1
                rsp = uc.reg_read(UC_X86_REG_RSP)
                ret_addr = struct.unpack("<Q", bytes(uc.mem_read(rsp, 8)))[0]
                uc.reg_write(UC_X86_REG_RAX, 1)
                uc.reg_write(UC_X86_REG_RSP, rsp + 8)
                uc.reg_write(UC_X86_REG_RIP, ret_addr)
                if self.trace_calls and len(self._call_log) < self.trace_limit:
                    self._call_log.append(f"  [HOOK] TLS init guard -> ret 1")
                return

            # Hook: bitfield reader -> force return 0 ONLY for 1-bit reads
            # The bitfield reader is called with R8B = num_bits
            # For the cached flag: R8B=1 -> we force 0 (delegate path)
            # For the 2-bit encoding flag (L3): R8B=2 -> let it execute naturally
            if self.force_delegate and rva == self.BITFIELD_READER_RVA:
                num_bits = uc.reg_read(UC_X86_REG_R8) & 0xFF
                if num_bits == 1:
                    self._hooked_returns["bitfield_forced_0 (1bit)"] += 1
                    rsp = uc.reg_read(UC_X86_REG_RSP)
                    ret_addr = struct.unpack("<Q", bytes(uc.mem_read(rsp, 8)))[0]
                    uc.reg_write(UC_X86_REG_RAX, 0)
                    uc.reg_write(UC_X86_REG_RSP, rsp + 8)
                    uc.reg_write(UC_X86_REG_RIP, ret_addr)
                    if self.trace_calls and len(self._call_log) < self.trace_limit:
                        self._call_log.append(f"  [HOOK] Bitfield 1-bit -> forced 0 (delegate)")
                    return
                else:
                    if self.trace_calls and len(self._call_log) < self.trace_limit:
                        self._call_log.append(f"  [PASS] Bitfield {num_bits}-bit -> execute naturally")
                    # Let it execute naturally
                    pass

            # Track CALL destinations
            if size == 5:
                try:
                    insn_bytes = bytes(uc.mem_read(address, 5))
                    if insn_bytes[0] == 0xE8:
                        rel = struct.unpack_from("<i", insn_bytes, 1)[0]
                        target_rva = rva + 5 + rel
                        self._call_targets[target_rva] += 1
                        if self.trace_calls and len(self._call_log) < self.trace_limit:
                            self._call_log.append(
                                f"  [CALL] RVA 0x{rva:X} -> 0x{target_rva:X}"
                            )
                except Exception:
                    pass
            return

        # Stop address
        if address == STOP_ADDR:
            uc.emu_stop()
            return

        # Our stubs
        if STUB_BASE <= address < STUB_BASE + STUB_SIZE:
            return

        # External call -> return 0
        self._call_targets[address] += 1
        if self.trace_calls and len(self._call_log) < self.trace_limit:
            self._call_log.append(f"  [EXT] 0x{address:X} -> ret 0")

        rsp = uc.reg_read(UC_X86_REG_RSP)
        try:
            ret_addr = struct.unpack("<Q", bytes(uc.mem_read(rsp, 8)))[0]
            uc.reg_write(UC_X86_REG_RAX, 0)
            uc.reg_write(UC_X86_REG_RSP, rsp + 8)
            uc.reg_write(UC_X86_REG_RIP, ret_addr)
        except Exception:
            uc.emu_stop()

    def _build_deserializer_chain(self, struct_base: int):
        """
        Build a nested chain of deserializer objects in memory.

        The movement packet uses a chain of caching wrappers. Each object:
          +0x00: vtable pointer (points to vtable in binary)
          +0x08: some field (4 bytes)
          +0x0C: varint result (4 bytes, written by decoder)
          +0x10: child object (next level, same layout)

        We build the chain using the known vtable RVAs.
        The vtable pointers reference actual vtables in the binary dump,
        which contain pointers to the correct deserialize functions.
        """
        mu = self.emu
        base = self._image_base

        # Clear the struct area
        mu.mem_write(struct_base, b"\x00" * 0x1000)

        # Chain order: L1 -> L2 -> L3 -> L4 -> leaf1 -> L5 -> L6 -> L7
        # This is a guess based on the function addresses being sequential.
        # We may need to adjust this order.
        chain_vtables = [
            0x19B9BC0,  # L1: 0xF60EF0
            0x19B9BF0,  # L2: 0xF61020
            0x19B9A48,  # L3: 0xF61150
            0x19B9A78,  # L4: 0xF617A0
            0x19B9C50,  # leaf1: 0xF619F0
            0x19B9C78,  # L5: 0xF61AE0
            0x19B9CA8,  # L6: 0xF61BF0
            0x19B9AD8,  # L7: 0xF61D00
        ]

        # Each object is 0x30 bytes (conservative estimate)
        OBJ_SIZE = 0x30
        offset = 0

        for i, vt_rva in enumerate(chain_vtables):
            obj_addr = struct_base + offset
            # Write vtable pointer (absolute VA)
            vt_va = base + vt_rva
            mu.mem_write(obj_addr, struct.pack("<Q", vt_va))
            # Zero out the rest of the object
            # +0x08 and +0x0C will be written by the varint decoder
            # +0x10 is where the child starts (next iteration)

            if i < len(chain_vtables) - 1:
                # The child starts at +0x10 relative to this object
                # But the delegate code does: lea rcx, [rbx+0x10]
                # So the child IS at this+0x10
                # We need to set [this+0x10] = vtable of next level
                # Wait, re-read the code:
                #   mov rax, [rbx+0x10]   ; load value at this+0x10
                #   lea rcx, [rbx+0x10]   ; rcx = address of this+0x10
                #   call [rax+8]          ; call vtable[1]
                # So [this+0x10] must be a vtable pointer (the child's vtable)
                # And rcx = &this[0x10] = address of the child object
                # Meaning the child object STARTS at this+0x10
                # And [this+0x10] = child.vtable = next vtable pointer
                pass  # The next iteration will write the vtable at the correct offset

            offset += 0x10  # Each level occupies 0x10 bytes (vtable + varint + padding)
            # Actually each level takes more space. Let me reconsider.

        # Actually the struct layout is:
        # Level 1 (struct_base + 0x00):
        #   +0x00: vtable ptr (L1)
        #   +0x08: 4 bytes data
        #   +0x0C: 4 bytes varint result
        #   +0x10: [Level 2 starts here]
        #     +0x10: vtable ptr (L2)  <- this is [this+0x10] which delegate reads
        #     +0x18: data
        #     +0x1C: varint
        #     +0x20: [Level 3 starts here]
        #       ...
        # Each level takes exactly 0x10 bytes (vtable:8 + data:4 + varint:4)

        # Re-do: write vtable pointers at proper offsets
        mu.mem_write(struct_base, b"\x00" * 0x1000)

        for i, vt_rva in enumerate(chain_vtables):
            obj_offset = i * 0x10
            obj_addr = struct_base + obj_offset
            vt_va = base + vt_rva
            mu.mem_write(obj_addr, struct.pack("<Q", vt_va))

        return struct_base, len(chain_vtables)

    def decode_movement_packet(self, raw_payload: bytes,
                               packet_id: int = 0,
                               param: int = 0,
                               game_time: float = 0.0,
                               verbose: bool = True) -> dict | None:
        """
        Decode a single movement packet.

        The approach:
        1. Set up nested deserializer struct with correct vtable chain
        2. Place raw payload in memory, create cursor pointer
        3. Emulate the top-level deserialize function
        4. Read decoded values from the struct
        """
        mu = self.emu
        if not mu:
            return None

        # Reset per-packet state
        self._insn_count = 0
        self._call_log = []
        self._mem_write_log = []
        self._page_faults = 0

        if verbose:
            print(f"\n{'='*70}")
            print(f"  Decoding movement packet:")
            print(f"    packet_id=0x{packet_id:04X}, param=0x{param:08X}")
            print(f"    game_time={game_time:.2f}s, payload={len(raw_payload)} bytes")
            print(f"    hex: {raw_payload[:64].hex()}")
            print(f"{'='*70}")

        # Build the nested deserializer struct
        pkt_struct, chain_len = self._build_deserializer_chain(PKT_STRUCT_BASE)

        if verbose:
            print(f"  Built deserializer chain: {chain_len} levels")
            # Verify the chain
            for i in range(chain_len):
                obj_addr = pkt_struct + i * 0x10
                vt_ptr = struct.unpack("<Q", bytes(mu.mem_read(obj_addr, 8)))[0]
                if vt_ptr:
                    vt_rva = vt_ptr - self._image_base
                    # Read vtable[1] = deserialize func
                    func_ptr = struct.unpack("<Q", bytes(mu.mem_read(vt_ptr + 8, 8)))[0]
                    func_rva = func_ptr - self._image_base
                    print(f"    Level {i}: obj@0x{obj_addr:X} vtable@RVA 0x{vt_rva:X} "
                          f"deser@RVA 0x{func_rva:X}")

        # Place raw payload in packet buffer
        payload_start = PACKET_BUF + 0x100
        mu.mem_write(payload_start, raw_payload)
        payload_end = payload_start + len(raw_payload)

        # Cursor variable
        cursor_var = PACKET_BUF
        mu.mem_write(cursor_var, struct.pack("<Q", payload_start))

        # Stack setup
        rsp = STACK_BASE + STACK_SIZE - 0x100
        mu.mem_write(rsp, struct.pack("<Q", STOP_ADDR))
        mu.mem_write(rsp + 8, b"\x00" * 32)  # shadow space

        # Registers (Windows x64 ABI)
        mu.reg_write(UC_X86_REG_RCX, pkt_struct)     # this
        mu.reg_write(UC_X86_REG_RDX, cursor_var)      # &cursor
        mu.reg_write(UC_X86_REG_R8, payload_end)       # end
        mu.reg_write(UC_X86_REG_RSP, rsp)
        mu.reg_write(UC_X86_REG_RBP, rsp + 0x80)

        for reg in [UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RSI,
                    UC_X86_REG_RDI, UC_X86_REG_R9, UC_X86_REG_R10,
                    UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13,
                    UC_X86_REG_R14, UC_X86_REG_R15]:
            mu.reg_write(reg, 0)
        mu.reg_write(UC_X86_REG_RFLAGS, 0x202)

        # Emulate
        start_addr = self._image_base + self.DESERIALIZE_RVA
        t0 = time.time()
        error_msg = None

        try:
            mu.emu_start(start_addr, STOP_ADDR,
                         timeout=30_000_000, count=self.MAX_INSN)
        except UcError as e:
            error_msg = str(e)

        elapsed = time.time() - t0
        rax = mu.reg_read(UC_X86_REG_RAX)
        rip = mu.reg_read(UC_X86_REG_RIP)
        al_result = rax & 0xFF

        # Read the full struct to see what was written
        struct_data = bytes(mu.mem_read(pkt_struct, 0x100))

        # Read cursor to see how many bytes were consumed
        cursor_now = struct.unpack("<Q", bytes(mu.mem_read(cursor_var, 8)))[0]
        bytes_consumed = cursor_now - payload_start

        if verbose:
            print(f"\n  === Result ===")
            print(f"  AL (success): {al_result}")
            print(f"  Instructions: {self._insn_count:,}")
            print(f"  Time: {elapsed:.3f}s")
            print(f"  Page faults: {self._page_faults}")
            print(f"  Bytes consumed: {bytes_consumed}/{len(raw_payload)}")
            print(f"  Final RIP: 0x{rip:X} (RVA 0x{self._rva(rip):X})")
            if error_msg:
                print(f"  ERROR: {error_msg}")

            # Call trace
            if self._call_log:
                print(f"\n  === Trace ({len(self._call_log)} entries) ===")
                for entry in self._call_log[:150]:
                    print(entry)
                if len(self._call_log) > 150:
                    print(f"  ... ({len(self._call_log) - 150} more)")

            # Call targets
            if self._call_targets:
                print(f"\n  === Call Targets ===")
                for target, count in self._call_targets.most_common(20):
                    if 0 <= target < self._image_size:
                        print(f"    RVA 0x{target:X}: {count}x")
                    else:
                        print(f"    ext 0x{target:X}: {count}x")

            # Hooked functions
            if self._hooked_returns:
                print(f"\n  === Hooked ===")
                for name, count in self._hooked_returns.items():
                    print(f"    {name}: {count}x")

            # Memory writes
            if self._mem_write_log:
                print(f"\n  === Memory Writes ({len(self._mem_write_log)}) ===")
                regions: dict[str, list] = defaultdict(list)
                for addr, sz, val in self._mem_write_log:
                    if PKT_STRUCT_BASE <= addr < PKT_STRUCT_BASE + PKT_STRUCT_SZ:
                        off = addr - PKT_STRUCT_BASE
                        regions["STRUCT"].append((off, sz, val))
                    elif PACKET_BUF <= addr < PACKET_BUF + PACKET_BUF_SZ:
                        off = addr - PACKET_BUF
                        regions["PKTBUF"].append((off, sz, val))
                    elif TLS_BASE <= addr < TLS_BASE + TLS_SIZE:
                        off = addr - TLS_BASE
                        regions["TLS"].append((off, sz, val))
                    elif GS_BASE <= addr < GS_BASE + GS_SIZE:
                        off = addr - GS_BASE
                        regions["GS"].append((off, sz, val))
                    else:
                        regions["OTHER"].append((addr, sz, val))

                for region, writes in sorted(regions.items()):
                    print(f"\n    [{region}] ({len(writes)} writes):")
                    for off, sz, val in writes[:40]:
                        if region == "STRUCT":
                            # Show which level this belongs to
                            level = off // 0x10
                            field_off = off % 0x10
                            label = f"L{level}+0x{field_off:02X}"
                        else:
                            label = f"+0x{off:04X}"
                        print(f"      {label} ({sz}B) = 0x{val:X} ({val})")
                    if len(writes) > 40:
                        print(f"      ... ({len(writes) - 40} more)")

            # Struct hex dump
            print(f"\n  === Struct Dump (0x100 bytes) ===")
            for i in range(0, 0x100, 16):
                chunk = struct_data[i:i+16]
                if any(b != 0 for b in chunk):
                    hex_str = " ".join(f"{b:02x}" for b in chunk)
                    ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                    level = i // 0x10
                    print(f"    +0x{i:03X} (L{level}): {hex_str}  {ascii_str}")

        # Build result
        result = {
            "success": al_result == 1,
            "instructions": self._insn_count,
            "page_faults": self._page_faults,
            "bytes_consumed": bytes_consumed,
            "error": error_msg,
            "time_s": round(elapsed, 4),
        }

        # Extract decoded fields from each level
        fields = {}
        for i in range(8):
            off = i * 0x10
            varint_val = struct.unpack_from("<I", struct_data, off + 0x0C)[0]
            if varint_val != 0:
                fields[f"level{i}_varint_0x0C"] = varint_val
            # Also check +0x18, +0x1C, +0x20, +0x24 (cached value locations)
            # These are at absolute offsets in the struct
        result["fields"] = fields

        # Check specific offsets for movement data
        # The top-level writes to this+0x18, +0x1c, +0x20, +0x24
        for off in [0x18, 0x1C, 0x20, 0x24]:
            val = struct.unpack_from("<I", struct_data, off)[0]
            if val != 0:
                result[f"struct_0x{off:02X}"] = val

        result["struct_hex"] = struct_data[:0x100].hex()

        return result


def find_movement_packets(rofl_path: str | Path) -> list[dict]:
    """Parse ROFL and find movement packets (ID 0x0425)."""
    from ml.parsers.rofl_parser import ROFLParser
    from ml.parsers.chunk_parser import parse_payload_frames

    rofl_path = Path(rofl_path)
    print(f"\n[ROFL] Parsing: {rofl_path.name}")

    parser = ROFLParser(rofl_path)
    info = parser.get_match_info()
    print(f"  Version: {info.get('game_version', '?')}")
    print(f"  Length: {info.get('game_length_ms', 0) / 60000:.1f} min")

    print(f"  Decompressing...")
    frames = parser.decompress_payload_frames()
    payload = parse_payload_frames(frames, parse_packets=True)
    print(f"  {len(payload.frames)} frames, {payload.total_packets:,} total packets")

    pkt_id_counts = Counter()
    movement_packets = []

    for frame in payload.frames:
        for pkt in frame.packets:
            if not pkt.data or pkt.size == 0:
                continue
            pkt_id_counts[pkt.packet_id] += 1
            if pkt.packet_id == 0x0425:
                movement_packets.append({
                    "timestamp": pkt.timestamp,
                    "packet_id": pkt.packet_id,
                    "param": pkt.param,
                    "size": pkt.size,
                    "data": pkt.data,
                })

    print(f"\n  Top packet IDs:")
    for pid, count in pkt_id_counts.most_common(10):
        marker = " <-- MOVEMENT" if pid == 0x0425 else ""
        print(f"    0x{pid:04X}: {count:>7,}{marker}")

    print(f"\n  Movement packets (0x0425): {len(movement_packets)}")

    # Show size distribution of movement packets
    if movement_packets:
        sizes = Counter(p["size"] for p in movement_packets)
        print(f"  Size distribution:")
        for sz, cnt in sizes.most_common(10):
            print(f"    {sz} bytes: {cnt:,}")

    return movement_packets


def decode_varint_field(raw_val: int) -> int:
    """
    Decode a varint value from the emulator.

    The varint decoder does: btc ecx, 0x1e (toggle bit 30)
    then: if lower 24 bits are zero, keep original; else use toggled value.
    """
    toggled = raw_val ^ (1 << 30)
    if (raw_val & 0xFFFFFF) == 0:
        return raw_val
    return toggled


def main():
    """Main: test emulator with movement packets from ROFL replay."""
    print("=" * 70)
    print("  League of Legends Movement Packet Decoder")
    print("  Unicorn Emulator v2 - Test Run")
    print("=" * 70)

    project_root = Path(__file__).resolve().parent.parent.parent
    dump_path = project_root / "ml" / "data" / "league_unpacked_patched.bin"
    meta_path = project_root / "ml" / "data" / "league_dump_meta.json"

    # Find ROFL
    rofl_path = None
    for p in [
        project_root / "ml" / "data" / "TW2-396324158.rofl",
        Path(r"C:\Users\ngan9\OneDrive\Documents\League of Legends\Replays\TW2-396324158.rofl"),
    ]:
        if p.exists():
            rofl_path = p
            break
    if not rofl_path:
        replay_dir = Path(r"C:\Users\ngan9\OneDrive\Documents\League of Legends\Replays")
        if replay_dir.exists():
            rofls = sorted(replay_dir.glob("*.rofl"))
            if rofls:
                rofl_path = rofls[-1]
    if not rofl_path:
        print("[ERROR] No .rofl file found!")
        sys.exit(1)

    print(f"\nROFL: {rofl_path}")
    print(f"Dump: {dump_path}")

    # Step 1: Find movement packets
    packets = find_movement_packets(rofl_path)
    if not packets:
        print("[ERROR] No movement packets found!")
        sys.exit(1)

    # Step 2: Set up emulator
    print(f"\n{'='*70}")
    print(f"  Setting up emulator...")
    print(f"{'='*70}")

    decoder = MovementDecoder(dump_path, meta_path)
    decoder.trace_calls = True
    decoder.trace_mem = True
    decoder.force_delegate = False
    decoder.setup()

    # Step 3: Single verbose test
    pkt = packets[0]
    print(f"\n{'='*70}")
    print(f"  TEST: Detailed single-packet decode (natural path)")
    print(f"{'='*70}")

    result = decoder.decode_movement_packet(
        raw_payload=pkt["data"],
        packet_id=pkt["packet_id"],
        param=pkt["param"],
        game_time=pkt["timestamp"],
        verbose=True,
    )

    # Step 4: Forced delegate test (for analysis)
    print(f"\n{'='*70}")
    print(f"  TEST: Forced delegate path (deeper decode)")
    print(f"{'='*70}")

    decoder.force_delegate = True
    decoder.trace_calls = True
    decoder.trace_mem = True

    result2 = decoder.decode_movement_packet(
        raw_payload=pkt["data"],
        packet_id=pkt["packet_id"],
        param=pkt["param"],
        game_time=pkt["timestamp"],
        verbose=True,
    )

    # Step 5: Batch decode - natural path
    print(f"\n{'='*70}")
    print(f"  BATCH: Decoding {min(50, len(packets))} movement packets")
    print(f"{'='*70}")

    decoder.force_delegate = False
    decoder.trace_calls = False
    decoder.trace_insn = False
    decoder.trace_mem = False

    ok_count = 0
    fail_count = 0
    decoded_results = []

    t0 = time.time()
    for i, pkt in enumerate(packets[:50]):
        r = decoder.decode_movement_packet(
            raw_payload=pkt["data"],
            packet_id=pkt["packet_id"],
            param=pkt["param"],
            game_time=pkt["timestamp"],
            verbose=False,
        )
        if r and r.get("success"):
            ok_count += 1
            # Decode the varint fields
            decoded = {
                "pkt_idx": i,
                "time": pkt["timestamp"],
                "param": pkt["param"],
                "size": pkt["size"],
                "consumed": r.get("bytes_consumed", 0),
                "insn": r.get("instructions", 0),
            }
            raw_fields = r.get("fields", {})
            for k, v in raw_fields.items():
                decoded[f"{k}_raw"] = f"0x{v:08X}"
                decoded[f"{k}_decoded"] = decode_varint_field(v)
            decoded_results.append(decoded)
        else:
            fail_count += 1

    elapsed = time.time() - t0

    print(f"\n  Results: {ok_count} OK, {fail_count} FAIL ({elapsed:.2f}s)")
    print(f"  Rate: {(ok_count + fail_count) / elapsed:.0f} packets/sec")

    # Print decoded results table
    print(f"\n  === Decoded Movement Data (first 30) ===")
    print(f"  {'#':>3s} {'Time':>7s} {'Param':>12s} {'Sz':>3s} "
          f"{'Entity(L0)':>12s} {'Field2(L1)':>12s} {'Consumed':>8s}")
    print(f"  {'─'*65}")

    for d in decoded_results[:30]:
        entity = d.get("level0_varint_0x0C_decoded", "")
        field2 = d.get("level1_varint_0x0C_decoded", "")
        entity_str = f"0x{entity:X}" if isinstance(entity, int) else str(entity)
        field2_str = f"0x{field2:X}" if isinstance(field2, int) else str(field2)
        print(f"  {d['pkt_idx']:3d} {d['time']:7.2f} 0x{d['param']:08X} "
              f"{d['size']:3d} {entity_str:>12s} {field2_str:>12s} "
              f"{d['consumed']:>3d}/{d['size']}")

    # Entity ID distribution
    entity_ids = Counter()
    for d in decoded_results:
        v = d.get("level0_varint_0x0C_decoded", 0)
        if isinstance(v, int):
            entity_ids[v] += 1

    print(f"\n  === Entity ID Distribution ===")
    for eid, count in entity_ids.most_common(20):
        print(f"    0x{eid:08X} ({eid:>10d}): {count:>4d} packets")

    # Unique params
    params = Counter(d["param"] for d in decoded_results)
    print(f"\n  === Param (NetID) Distribution ===")
    for p, count in params.most_common(20):
        print(f"    0x{p:08X}: {count:>4d} packets")

    print(f"\n{'='*70}")
    print(f"  Summary:")
    print(f"    Movement packets found: {len(packets):,}")
    print(f"    Successfully decoded: {ok_count} / {min(50, len(packets))}")
    print(f"    Varint fields extracted per packet: L0 entity ID + optional L1 field")
    print(f"    Cached path returns zeros for position data (globals uninitialized)")
    print(f"    Delegate path decodes deeper but needs full child chain setup")
    print(f"    Total page faults: {decoder._total_page_faults}")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()

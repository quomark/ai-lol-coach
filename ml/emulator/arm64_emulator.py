"""
ARM64 Unicorn emulator for the macOS League of Legends binary.

Maps the 161MB runtime dump at its original base address and provides
helpers to call arbitrary functions with ARM64 calling convention.

Usage:
    from ml.emulator.arm64_emulator import ARM64Emulator

    emu = ARM64Emulator("ml/data/league_macos_dump.bin")
    emu.setup()
    result = emu.call_function(0x10659D218, [arg0, arg1, ...])
"""

from __future__ import annotations

import struct
import time
from pathlib import Path
from typing import Optional

from unicorn import (
    Uc,
    UC_ARCH_ARM64,
    UC_MODE_ARM,
    UC_PROT_ALL,
    UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_HOOK_MEM_FETCH_UNMAPPED,
    UC_HOOK_CODE,
    UC_HOOK_MEM_WRITE,
    UcError,
)
from unicorn.arm64_const import (
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
    UC_ARM64_REG_X8, UC_ARM64_REG_X9, UC_ARM64_REG_X10, UC_ARM64_REG_X11,
    UC_ARM64_REG_X12, UC_ARM64_REG_X13, UC_ARM64_REG_X14, UC_ARM64_REG_X15,
    UC_ARM64_REG_X16, UC_ARM64_REG_X17, UC_ARM64_REG_X18, UC_ARM64_REG_X19,
    UC_ARM64_REG_X20, UC_ARM64_REG_X21, UC_ARM64_REG_X22, UC_ARM64_REG_X23,
    UC_ARM64_REG_X24, UC_ARM64_REG_X25, UC_ARM64_REG_X26, UC_ARM64_REG_X27,
    UC_ARM64_REG_X28, UC_ARM64_REG_X29, UC_ARM64_REG_X30,
    UC_ARM64_REG_SP, UC_ARM64_REG_PC, UC_ARM64_REG_NZCV,
)

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


# ── Memory layout ────────────────────────────────────────────────────

BINARY_BASE     = 0x104944000      # macOS ASLR base from runtime dump
STACK_BASE      = 0x200000000      # 64KB stack
STACK_SIZE      = 0x10000
HEAP_BASE       = 0x300000000      # 64KB heap
HEAP_SIZE       = 0x10000
SCRATCH_BASE    = 0x400000000      # scratch/packet buffers
SCRATCH_SIZE    = 0x10000
STRUCT_BASE     = 0x500000000      # for packet structs
STRUCT_SIZE     = 0x10000
STOP_ADDR       = 0x600000000      # return trampoline (BRK)

PAGE_SIZE = 0x4000  # ARM64 macOS uses 16KB pages

# ARM64 argument registers (x0-x7)
_ARG_REGS = [
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
]

# All general-purpose registers for reset
_GP_REGS = [getattr(__import__('unicorn.arm64_const', fromlist=[f'UC_ARM64_REG_X{i}']),
             f'UC_ARM64_REG_X{i}') for i in range(29)]


def _align(v: int, a: int) -> int:
    return (v + a - 1) & ~(a - 1)


class ARM64Emulator:
    """ARM64 Unicorn emulator for the macOS League binary."""

    MAX_INSN = 5_000_000  # safety limit per call

    def __init__(self, dump_path: str | Path = "ml/data/league_macos_dump.bin",
                 base_addr: int = BINARY_BASE):
        self.dump_path = Path(dump_path)
        self.base_addr = base_addr
        self.emu: Optional[Uc] = None
        self.disasm: Optional[Cs] = None

        self._image_size: int = 0
        self._mapped_pages: set[int] = set()
        self._heap_ptr: int = HEAP_BASE

        # Per-call tracking
        self._insn_count: int = 0
        self._page_faults: int = 0
        self._call_log: list[str] = []
        self._mem_writes: list[tuple[int, int, int]] = []

        # Tracing control
        self.trace_calls = False
        self.trace_insn = False
        self.trace_mem = False
        self.trace_limit = 300

    def setup(self):
        """Initialize Unicorn, load binary dump, set up stack/heap."""
        if not self.dump_path.exists():
            raise FileNotFoundError(f"Binary dump not found: {self.dump_path}")

        dump_data = self.dump_path.read_bytes()
        self._image_size = len(dump_data)

        print(f"[ARM64] Loading: {self.dump_path}")
        print(f"  Base: 0x{self.base_addr:X}")
        print(f"  Size: {self._image_size:,} bytes ({self._image_size / 1024 / 1024:.1f} MB)")

        if HAS_CAPSTONE:
            self.disasm = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.emu = mu

        # Map and load binary
        aligned_size = _align(self._image_size, PAGE_SIZE)
        mu.mem_map(self.base_addr, aligned_size, UC_PROT_ALL)
        mu.mem_write(self.base_addr, dump_data)
        del dump_data
        print(f"  Binary mapped: 0x{self.base_addr:X} - 0x{self.base_addr + aligned_size:X}")

        # Map support regions
        for name, addr, size in [
            ("Stack",   STACK_BASE,   STACK_SIZE),
            ("Heap",    HEAP_BASE,    HEAP_SIZE),
            ("Scratch", SCRATCH_BASE, SCRATCH_SIZE),
            ("Struct",  STRUCT_BASE,  STRUCT_SIZE),
            ("Stop",    STOP_ADDR,    PAGE_SIZE),
        ]:
            mu.mem_map(addr, size, UC_PROT_ALL)
            print(f"  {name:8s}: 0x{addr:X} ({size:#x})")

        # Write BRK #0 at stop address (0xD4200000)
        mu.mem_write(STOP_ADDR, struct.pack("<I", 0xD4200000))

        # Install hooks
        mu.hook_add(
            UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
            UC_HOOK_MEM_FETCH_UNMAPPED,
            self._hook_unmapped,
        )
        mu.hook_add(UC_HOOK_CODE, self._hook_code)

        self._mapped_pages = set()
        print(f"[ARM64] Setup complete\n")

    # ── Memory helpers ────────────────────────────────────────────────

    def write_u64(self, addr: int, val: int):
        self.emu.mem_write(addr, struct.pack("<Q", val))

    def write_u32(self, addr: int, val: int):
        self.emu.mem_write(addr, struct.pack("<I", val))

    def write_bytes(self, addr: int, data: bytes):
        self.emu.mem_write(addr, data)

    def read_u64(self, addr: int) -> int:
        return struct.unpack("<Q", bytes(self.emu.mem_read(addr, 8)))[0]

    def read_u32(self, addr: int) -> int:
        return struct.unpack("<I", bytes(self.emu.mem_read(addr, 4)))[0]

    def read_bytes(self, addr: int, size: int) -> bytes:
        return bytes(self.emu.mem_read(addr, size))

    def heap_alloc(self, size: int) -> int:
        """Bump-allocate from the heap region."""
        addr = self._heap_ptr
        self._heap_ptr = _align(self._heap_ptr + size, 16)
        if self._heap_ptr >= HEAP_BASE + HEAP_SIZE:
            raise MemoryError("Emulator heap exhausted")
        return addr

    def disasm_at(self, addr: int, count: int = 10) -> list[str]:
        """Disassemble instructions at an address."""
        if not self.disasm:
            return []
        try:
            code = self.read_bytes(addr, count * 4)
            lines = []
            for insn in self.disasm.disasm(code, addr):
                lines.append(f"0x{insn.address:X}: {insn.mnemonic} {insn.op_str}")
                if len(lines) >= count:
                    break
            return lines
        except Exception:
            return []

    # ── Function calling ──────────────────────────────────────────────

    def call_function(self, address: int, args: list[int] = None,
                      verbose: bool = True, max_insn: int = None) -> dict:
        """
        Call a function at `address` with ARM64 calling convention.

        Args in x0-x7, return address in x30 -> STOP_ADDR.
        Returns dict with x0 result, instruction count, etc.
        """
        mu = self.emu
        if not mu:
            raise RuntimeError("Emulator not set up — call setup() first")

        args = args or []
        if max_insn is None:
            max_insn = self.MAX_INSN

        # Reset per-call state
        self._insn_count = 0
        self._page_faults = 0
        self._call_log = []
        self._mem_writes = []

        # Set up stack
        sp = STACK_BASE + STACK_SIZE - 0x100  # leave room at top
        mu.reg_write(UC_ARM64_REG_SP, sp)
        mu.reg_write(UC_ARM64_REG_X29, sp)  # frame pointer

        # Set LR to stop address
        mu.reg_write(UC_ARM64_REG_X30, STOP_ADDR)

        # Clear all GP regs
        for i in range(29):
            mu.reg_write(_ARG_REGS[0] + i if i < 8 else UC_ARM64_REG_X8 + (i - 8), 0)
        # Actually just zero them all
        for reg in _GP_REGS:
            mu.reg_write(reg, 0)

        # Set arguments
        for i, val in enumerate(args[:8]):
            mu.reg_write(_ARG_REGS[i], val)

        # Clear NZCV flags
        mu.reg_write(UC_ARM64_REG_NZCV, 0)

        if verbose:
            print(f"[CALL] 0x{address:X} args=[{', '.join(f'0x{a:X}' for a in args)}]")

        t0 = time.time()
        error_msg = None

        try:
            mu.emu_start(address, STOP_ADDR, timeout=30_000_000, count=max_insn)
        except UcError as e:
            error_msg = str(e)

        elapsed = time.time() - t0
        x0 = mu.reg_read(UC_ARM64_REG_X0)
        pc = mu.reg_read(UC_ARM64_REG_PC)

        result = {
            "x0": x0,
            "pc": pc,
            "instructions": self._insn_count,
            "page_faults": self._page_faults,
            "time_s": round(elapsed, 4),
            "error": error_msg,
            "stopped_at_trampoline": pc == STOP_ADDR,
        }

        if verbose:
            status = "OK" if pc == STOP_ADDR else f"STOPPED at 0x{pc:X}"
            print(f"  -> x0=0x{x0:X} ({x0}) | {self._insn_count:,} insn | "
                  f"{self._page_faults} faults | {elapsed:.3f}s | {status}")
            if error_msg:
                print(f"  ERROR: {error_msg}")
            if self._call_log:
                for entry in self._call_log[:50]:
                    print(f"  {entry}")
                if len(self._call_log) > 50:
                    print(f"  ... ({len(self._call_log) - 50} more)")

        return result

    def call_cipher(self, func_addr: int, input_byte: int) -> int:
        """Call a cipher function with a single byte input. Returns output byte."""
        result = self.call_function(func_addr, [input_byte], verbose=False, max_insn=5000)
        if not result['stopped_at_trampoline']:
            raise RuntimeError(
                f"Cipher at 0x{func_addr:X} didn't return cleanly "
                f"(stopped at 0x{result['pc']:X}, error={result.get('error')})"
            )
        return result['x0'] & 0xFF

    def build_cipher_table(self, func_addr: int) -> list[int] | None:
        """Build a 256-byte substitution table by calling a cipher function 256 times.
        Returns the table if bijective, None otherwise."""
        table = []
        for i in range(256):
            try:
                val = self.call_cipher(func_addr, i)
                table.append(val)
            except RuntimeError:
                return None
        if len(set(table)) != 256:
            return None
        return table

    def read_reg(self, reg_name: str) -> int:
        """Read a register by name (e.g. 'x0', 'x1', 'sp')."""
        name = reg_name.lower()
        if name == "sp":
            return self.emu.reg_read(UC_ARM64_REG_SP)
        if name == "pc":
            return self.emu.reg_read(UC_ARM64_REG_PC)
        if name == "lr" or name == "x30":
            return self.emu.reg_read(UC_ARM64_REG_X30)
        if name.startswith("x"):
            num = int(name[1:])
            if 0 <= num <= 28:
                return self.emu.reg_read(_GP_REGS[num])
        raise ValueError(f"Unknown register: {reg_name}")

    # ── Hooks ─────────────────────────────────────────────────────────

    def _hook_unmapped(self, uc, access, address, size, value, user_data):
        """Auto-map zero pages for unmapped memory accesses."""
        aligned = address & ~(PAGE_SIZE - 1)
        if aligned in self._mapped_pages:
            return False
        try:
            uc.mem_map(aligned, PAGE_SIZE, UC_PROT_ALL)
            uc.mem_write(aligned, b"\x00" * PAGE_SIZE)
            self._mapped_pages.add(aligned)
            self._page_faults += 1
            if self.trace_mem and len(self._call_log) < self.trace_limit:
                self._call_log.append(f"[FAULT] 0x{address:X} -> mapped 0x{aligned:X}")
            return True
        except Exception:
            return False

    def _hook_code(self, uc, address, size, user_data):
        """Instruction hook for tracing and safety limit."""
        self._insn_count += 1

        if self._insn_count >= self.MAX_INSN:
            if len(self._call_log) < self.trace_limit:
                self._call_log.append(f"[LIMIT] Hit {self.MAX_INSN:,} instruction limit")
            uc.emu_stop()
            return

        # Stop trampoline
        if address == STOP_ADDR:
            uc.emu_stop()
            return

        in_binary = self.base_addr <= address < self.base_addr + self._image_size

        if in_binary and self.trace_insn and len(self._call_log) < self.trace_limit:
            rva = address - self.base_addr
            disasm_str = ""
            if self.disasm:
                try:
                    code = bytes(uc.mem_read(address, 4))
                    for insn in self.disasm.disasm(code, address):
                        disasm_str = f"{insn.mnemonic} {insn.op_str}"
                        break
                except Exception:
                    pass
            self._call_log.append(f"[INSN] 0x{address:X} (RVA 0x{rva:X}): {disasm_str}")

        # Track BL (branch-and-link) calls
        if in_binary and self.trace_calls and size == 4:
            try:
                insn_bytes = struct.unpack("<I", bytes(uc.mem_read(address, 4)))[0]
                # BL instruction: opcode bits [31:26] = 100101
                if (insn_bytes >> 26) == 0b100101:
                    # imm26 is sign-extended and shifted left by 2
                    imm26 = insn_bytes & 0x3FFFFFF
                    if imm26 & (1 << 25):
                        imm26 |= ~0x3FFFFFF  # sign extend
                    target = address + (imm26 << 2)
                    target &= 0xFFFFFFFFFFFFFFFF
                    if len(self._call_log) < self.trace_limit:
                        self._call_log.append(f"[BL] 0x{address:X} -> 0x{target:X}")
            except Exception:
                pass

        # If executing outside binary and not at stop addr, it's an external call
        if not in_binary and address != STOP_ADDR:
            if len(self._call_log) < self.trace_limit:
                self._call_log.append(f"[EXT] 0x{address:X} -> forcing ret 0")
            # Simulate return: x0=0, pc=LR
            lr = uc.reg_read(UC_ARM64_REG_X30)
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)


# ── Test: Call the 0x0425 handler ────────────────────────────────────

def test_0425_handler():
    """Test: call the 0x0425 handler with a crafted packet struct."""
    emu = ARM64Emulator()
    emu.setup()
    emu.trace_calls = True

    # The 0x0425 handler expects:
    #   x0 = pointer to packet struct where [x0+0] = packet_id, [x0+0x28] = data ptr
    #   x1 = pointer to output (where result is stored)
    #
    # Handler code:
    #   ldr w8, [x0]          ; w8 = packet_id
    #   cmp w8, #0x425
    #   b.ne fail
    #   ldr x8, [x0, #0x28]   ; x8 = data pointer
    #   ldrsw x9, [x8]        ; x9 = sign-extended int32 at data[0]
    #   str x9, [x1]          ; store to output
    #   ldr x0, [x8, #8]      ; x0 = data[8] (return value)
    #   ret

    pkt_struct = SCRATCH_BASE
    data_area = SCRATCH_BASE + 0x100
    output = SCRATCH_BASE + 0x200

    # Write packet ID
    emu.write_u32(pkt_struct, 0x0425)

    # Write data pointer at +0x28
    emu.write_u64(pkt_struct + 0x28, data_area)

    # Write test data: int32 = 42 at data[0], and 8 bytes at data[8]
    emu.write_u32(data_area, 42)
    emu.write_u64(data_area + 8, 0xDEADBEEFCAFE)

    # Clear output
    emu.write_u64(output, 0)

    result = emu.call_function(0x10659D218, [pkt_struct, output])

    # Read output
    out_val = emu.read_u64(output)
    ret_val = result["x0"]

    print(f"\n=== 0x0425 Handler Test ===")
    print(f"  Output (int32 from data):  {out_val} (expected 42)")
    print(f"  Return (x0, data[8]):      0x{ret_val:X} (expected 0xDEADBEEFCAFE)")
    print(f"  Stopped at trampoline:     {result['stopped_at_trampoline']}")

    assert out_val == 42, f"Output mismatch: {out_val} != 42"
    assert ret_val == 0xDEADBEEFCAFE, f"Return mismatch: 0x{ret_val:X}"
    print("  PASS!")

    return emu


def test_dispatch_function(emu: ARM64Emulator):
    """Test the dispatch function with type_code=7 (0x0425 path)."""
    print(f"\n=== Dispatch Function Test (type=7, 0x0425 path) ===")
    emu.trace_calls = True

    # The dispatch at 0x1065B7FEC:
    #   x0 = context object
    #   w1 (w23) = type_code (7 for 0x0425)
    #   w2 (w21) = data_size
    #   x3 (x20) = output pointer
    #
    # For type 7:
    #   1. pre-process #1: x19 = [x0+0x28]  (from original x0=ctx_obj)
    #   2. pre-process #2: x0 = [x0+0x10]   (from original x0=ctx_obj, via x22)
    #   3. calls handler(x0, &stack_buf) where x0 = [ctx_obj+0x10]

    ctx_obj = STRUCT_BASE
    pkt_struct = STRUCT_BASE + 0x100  # what [ctx_obj+0x10] points to
    data_area = SCRATCH_BASE + 0x300
    output = SCRATCH_BASE + 0x400

    # Clear areas
    emu.write_bytes(STRUCT_BASE, b"\x00" * 0x400)
    emu.write_bytes(SCRATCH_BASE + 0x300, b"\x00" * 0x200)

    # ctx_obj+0x10 -> pkt_struct (used by pre-process #2 for handler arg)
    emu.write_u64(ctx_obj + 0x10, pkt_struct)
    # ctx_obj+0x28 -> some valid pointer (used by pre-process #1, result saved to x19)
    emu.write_u64(ctx_obj + 0x28, SCRATCH_BASE + 0x500)

    # pkt_struct = handler's x0:
    #   [+0x00] = packet_id = 0x0425
    #   [+0x28] = data ptr
    emu.write_u32(pkt_struct, 0x0425)
    emu.write_u64(pkt_struct + 0x28, data_area)

    # data: int32=99 at [0], 8 bytes at [8]
    emu.write_u32(data_area, 99)
    emu.write_u64(data_area + 8, 0x1234567890ABCDEF)

    # Clear output
    emu.write_u64(output, 0)

    result = emu.call_function(
        0x1065B7FEC,
        [ctx_obj, 7, 0x20, output],
    )

    print(f"  x0 (return):    {result['x0']}")
    print(f"  Trampoline:     {result['stopped_at_trampoline']}")

    # After handler, dispatch checks [sp+8] (stack_buf) == 0x20 to proceed
    # The handler stores the data ptr return into [x1] = &stack_buf
    out_val = emu.read_u64(output)
    print(f"  Output buffer:  0x{out_val:X}")


def main():
    """Run emulator tests."""
    print("=" * 60)
    print("  ARM64 Unicorn Emulator - League of Legends macOS Binary")
    print("=" * 60)

    emu = test_0425_handler()
    test_dispatch_function(emu)

    print("\nDone.")


if __name__ == "__main__":
    main()

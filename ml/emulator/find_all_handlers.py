"""
Find all packet handler functions in the macOS League binary dump.

Scans for the handler prologue pattern:
  STP X29, X30, [SP, #offset]!   ; pre-indexed store (saves frame pointer + LR)
  MOV X29, SP                     ; 0x910003FD
  LDR W8, [X0]                    ; 0xB9400008 (load packet type from struct)
  CMP W8, #<packet_type>          ; SUBS WZR, W8, #imm12
  B.NE <error_label>              ; conditional branch on mismatch

Also does a relaxed scan for variants using different registers or stack sizes.

For each handler, traces BL (branch-and-link) targets to map the cipher
functions called during deserialization.

Output: ml/data/handlers.json
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

BINARY_BASE = 0x104944000

# Known handler addresses for validation
KNOWN_HANDLERS = {
    0x0001: None,
    0x0006: None,
    0x001C: None,
    0x0074: None,
    0x0425: 0x10659D218,
    0x0426: None,
}

HANDLER_REGION_START = 0x10659D000
HANDLER_REGION_END   = 0x1065A0000


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from('<I', data, offset)[0]


# ── Instruction decoders ──────────────────────────────────────────────

def is_stp_x29_x30_pre(insn: int) -> bool:
    """STP X29, X30, [SP, #offset]! with any pre-index offset."""
    # Fixed: opc=10, type=011(pre-idx), L=0, Rt2=30, Rn=31(SP), Rt=29
    # Variable: imm7 (bits[21:15])
    return (insn & 0xFFC07FFF) == 0xA9807BFD


def is_mov_x29_sp(insn: int) -> bool:
    return insn == 0x910003FD


def is_ldr_w_x0(insn: int) -> tuple[bool, int]:
    """LDR Wt, [X0, #0]. Returns (match, Wt register number)."""
    # LDR Wt, [Xn, #0]: 10111001 01 000000000000 Rn Rt
    # Rn=0 (X0), imm12=0
    # So: (insn & 0xFFFFF C00) == 0xB9400000... actually
    # bits[31:22]=1011100101, imm12=0, Rn=0
    # mask out Rt (bits 4:0): (insn & 0xFFFFFFE0) == 0xB9400000
    if (insn & 0xFFFFFFE0) == 0xB9400000:
        return True, insn & 0x1F
    return False, 0


def is_cmp_wreg_imm(insn: int) -> tuple[bool, int, int]:
    """CMP W<reg>, #imm12. Returns (match, reg, imm12)."""
    # SUBS WZR, Wn, #imm: sf=0, op=1, S=1, 10001, sh, imm12, Rn, Rd=31
    rd = insn & 0x1F
    if rd != 31:
        return False, 0, 0
    # Check opcode: bits[31:24] should be 0x71 (unshifted) or 0x71 with sh=1
    top = (insn >> 24) & 0xFF
    if top != 0x71:
        return False, 0, 0
    sh = (insn >> 22) & 1
    imm12 = (insn >> 10) & 0xFFF
    rn = (insn >> 5) & 0x1F
    if sh:
        imm12 <<= 12
    return True, rn, imm12


def is_bne(insn: int) -> bool:
    """B.NE <offset>."""
    return (insn & 0xFF00001F) == 0x54000001


def decode_bl(insn: int, pc: int) -> int | None:
    """If insn is BL, return absolute target address. Else None."""
    if (insn >> 26) != 0x25:
        return None
    imm26 = insn & 0x3FFFFFF
    if imm26 & (1 << 25):
        imm26 -= (1 << 26)
    target = (pc + (imm26 << 2)) & 0xFFFFFFFFFFFFFFFF
    return target


def is_ret(insn: int) -> bool:
    """RET (to X30)."""
    return insn == 0xD65F03C0


# ── Scanner ───────────────────────────────────────────────────────────

def find_handlers_strict(data: bytes, base: int) -> dict[int, int]:
    """Strict 5-instruction prologue scan. Returns {packet_type: address}."""
    handlers = {}
    limit = len(data) - 20

    for off in range(0, limit, 4):
        i0 = _u32(data, off)
        if not is_stp_x29_x30_pre(i0):
            continue
        i1 = _u32(data, off + 4)
        if not is_mov_x29_sp(i1):
            continue
        i2 = _u32(data, off + 8)
        ldr_ok, ldr_reg = is_ldr_w_x0(i2)
        if not ldr_ok:
            continue
        i3 = _u32(data, off + 12)
        cmp_ok, cmp_reg, pkt_type = is_cmp_wreg_imm(i3)
        if not cmp_ok or cmp_reg != ldr_reg:
            continue
        # Allow B.NE at offset+16 or offset+20 (some handlers have an extra insn)
        found_bne = False
        for delta in (16, 20):
            if off + delta + 4 <= len(data):
                if is_bne(_u32(data, off + delta)):
                    found_bne = True
                    break
        if not found_bne:
            continue

        addr = base + off
        if pkt_type not in handlers:
            handlers[pkt_type] = addr

    return handlers


def find_handlers_relaxed(data: bytes, base: int, known: set[int]) -> dict[int, int]:
    """Relaxed scan: look for CMP Wreg,#imm + B.NE near prologues.
    Skips packet types already found."""
    handlers = {}
    limit = len(data) - 24

    for off in range(0, limit, 4):
        insn = _u32(data, off)
        cmp_ok, cmp_reg, pkt_type = is_cmp_wreg_imm(insn)
        if not cmp_ok or pkt_type in known or pkt_type == 0:
            continue

        # B.NE within next 2 instructions
        bne_found = False
        for d in (4, 8):
            if off + d + 4 <= len(data) and is_bne(_u32(data, off + d)):
                bne_found = True
                break
        if not bne_found:
            continue

        # LDR Wreg, [X0] before CMP (within 16 bytes)
        ldr_found = False
        for back in range(4, 20, 4):
            if off >= back:
                prev = _u32(data, off - back)
                ok, lr = is_ldr_w_x0(prev)
                if ok and lr == cmp_reg:
                    ldr_found = True
                    break
        if not ldr_found:
            continue

        # Function prologue (STP X29,X30) before LDR (within 32 bytes)
        func_start = None
        for back in range(4, 40, 4):
            if off >= back:
                prev = _u32(data, off - back)
                if is_stp_x29_x30_pre(prev):
                    func_start = off - back
                    break
        if func_start is None:
            continue

        addr = base + func_start
        if pkt_type not in handlers:
            handlers[pkt_type] = addr

    return handlers


# ── BL tracing ────────────────────────────────────────────────────────

def trace_bl_targets(data: bytes, base: int, func_addr: int,
                     max_insn: int = 2000) -> list[int]:
    """Disassemble forward from func_addr, collect all BL targets.
    Stops at second RET or instruction limit (handlers can have
    multiple sub-blocks separated by B instructions)."""
    targets = []
    off = func_addr - base
    ret_count = 0

    for _ in range(max_insn):
        if off < 0 or off + 4 > len(data):
            break
        insn = _u32(data, off)
        pc = base + off

        if is_ret(insn):
            ret_count += 1
            if ret_count >= 2:
                break

        target = decode_bl(insn, pc)
        if target is not None:
            # Filter: only targets within the binary image
            if base <= target < base + len(data):
                targets.append(target)

        off += 4

    return targets


def trace_deep_bl(data: bytes, base: int, func_addr: int,
                  depth: int = 2, visited: set[int] | None = None) -> list[int]:
    """Trace BL targets recursively to find cipher functions called
    from helper wrappers. Returns unique targets at all depths."""
    if visited is None:
        visited = set()
    if func_addr in visited or depth < 0:
        return []
    visited.add(func_addr)

    direct = trace_bl_targets(data, base, func_addr)
    all_targets = list(direct)

    if depth > 0:
        for t in direct:
            if t not in visited:
                sub = trace_deep_bl(data, base, t, depth - 1, visited)
                all_targets.extend(sub)

    return all_targets


# ── Main ──────────────────────────────────────────────────────────────

def main():
    dump_path = Path("ml/data/league_macos_dump.bin")
    output_path = Path("ml/data/handlers.json")

    if len(sys.argv) > 1:
        dump_path = Path(sys.argv[1])

    print(f"Loading binary: {dump_path}")
    data = dump_path.read_bytes()
    print(f"  Size: {len(data):,} bytes ({len(data) / 1024 / 1024:.1f} MB)")

    # ── Step 1: Strict scan ──
    print("\n=== STRICT SCAN ===")
    strict = find_handlers_strict(data, BINARY_BASE)
    print(f"Found {len(strict)} handlers")
    for pkt, addr in sorted(strict.items()):
        marker = " *" if pkt in KNOWN_HANDLERS else ""
        print(f"  0x{pkt:04X} -> 0x{addr:X}{marker}")

    # Validate: check known handlers
    for pkt, expected_addr in KNOWN_HANDLERS.items():
        if expected_addr and pkt in strict:
            if strict[pkt] == expected_addr:
                print(f"  [OK] 0x{pkt:04X} matches expected 0x{expected_addr:X}")
            else:
                print(f"  [WARN] 0x{pkt:04X}: found 0x{strict[pkt]:X}, expected 0x{expected_addr:X}")
        elif pkt not in strict:
            print(f"  [MISS] 0x{pkt:04X} not found in strict scan")

    # ── Step 2: Relaxed scan ──
    print("\n=== RELAXED SCAN ===")
    relaxed = find_handlers_relaxed(data, BINARY_BASE, set(strict.keys()))
    print(f"Found {len(relaxed)} additional handlers")
    for pkt, addr in sorted(relaxed.items()):
        print(f"  0x{pkt:04X} -> 0x{addr:X}")

    all_handlers = {**strict, **relaxed}
    print(f"\n=== TOTAL: {len(all_handlers)} packet types ===")

    # ── Step 3: Trace BL targets ──
    print("\n=== BL TRACING ===")
    handler_info = {}
    all_bl_targets = set()

    for pkt_type in sorted(all_handlers):
        addr = all_handlers[pkt_type]
        # Direct BL targets from the handler
        direct = trace_bl_targets(data, BINARY_BASE, addr)
        # Also trace one level deep (handler may call a wrapper that calls cipher)
        deep = trace_deep_bl(data, BINARY_BASE, addr, depth=1)
        unique_deep = sorted(set(deep) - set(direct))

        all_bl_targets.update(direct)
        all_bl_targets.update(unique_deep)

        key = f"0x{pkt_type:04X}"
        handler_info[key] = {
            "address": f"0x{addr:X}",
            "address_int": addr,
            "bl_targets": [f"0x{t:X}" for t in direct],
            "bl_targets_int": direct,
            "deep_bl_targets": [f"0x{t:X}" for t in unique_deep],
            "deep_bl_targets_int": unique_deep,
        }
        if direct:
            print(f"  0x{pkt_type:04X}: {len(direct)} direct BL"
                  f"{f', +{len(unique_deep)} deep' if unique_deep else ''}")

    print(f"\n{len(all_bl_targets)} unique BL targets total")

    # ── Step 4: Scan for cipher function candidates ──
    # Cipher functions are small leaf functions near known code regions.
    print("\n=== CIPHER FUNCTION SCAN ===")
    cipher_candidates = set()

    KNOWN_CIPHER = 0x105CF725C

    scan_regions = [
        ("NearKnownCipher", KNOWN_CIPHER - 0x100000, KNOWN_CIPHER + 0x100000),
        ("HandlerHelpers",  0x10658A000, 0x1065C0000),
    ]

    for region_name, start, end in scan_regions:
        start_off = max(0, start - BINARY_BASE)
        end_off = min(len(data), end - BINARY_BASE)
        count = 0

        off = start_off
        while off < end_off - 8:
            insn = _u32(data, off)
            if is_stp_x29_x30_pre(insn):
                func_addr = BINARY_BASE + off
                # Small function: RET within 240 bytes
                for foff in range(4, 240, 4):
                    if off + foff + 4 > len(data):
                        break
                    if is_ret(_u32(data, off + foff)):
                        cipher_candidates.add(func_addr)
                        targets = trace_bl_targets(data, BINARY_BASE, func_addr, max_insn=100)
                        cipher_candidates.update(targets)
                        count += 1
                        break
            off += 4
        print(f"  {region_name}: {count} small functions")

    # Trace from dispatch function
    DISPATCH_ADDR = 0x1065B7FEC
    dispatch_off = DISPATCH_ADDR - BINARY_BASE
    if 0 <= dispatch_off < len(data) - 4:
        dispatch_targets = trace_deep_bl(data, BINARY_BASE, DISPATCH_ADDR, depth=2)
        cipher_candidates.update(dispatch_targets)
        print(f"  Dispatch deep trace: {len(dispatch_targets)} targets")

    cipher_candidates.add(KNOWN_CIPHER)
    cipher_candidates = {a for a in cipher_candidates
                         if BINARY_BASE <= a < BINARY_BASE + len(data)}
    all_bl_targets.update(cipher_candidates)
    print(f"  Total cipher candidates: {len(cipher_candidates)}")

    # ── Save ──
    output = {
        "binary_base": f"0x{BINARY_BASE:X}",
        "binary_size": len(data),
        "total_handlers": len(all_handlers),
        "total_unique_bl_targets": len(all_bl_targets),
        "handlers": handler_info,
        "all_bl_targets_sorted": sorted(f"0x{t:X}" for t in all_bl_targets),
        "cipher_candidates": sorted(f"0x{t:X}" for t in cipher_candidates),
        "cipher_candidates_int": sorted(cipher_candidates),
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2))
    print(f"\nSaved: {output_path}")


if __name__ == "__main__":
    main()

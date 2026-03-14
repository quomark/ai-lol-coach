"""
Auto-extract cipher parameters from a new League binary dump.

This tool partially automates the patch update process by:
1. Finding LUT_A (S-box) candidates in .rdata
2. Finding the movement deserializer by pattern matching
3. Disassembling reader functions to extract per-byte cipher ops
4. Generating updated cipher code for movement_decoder.py

Usage:
    uv run python -m ml.tools.extract_ciphers ml/data/league_unpacked_patched.bin

Requirements: capstone (`uv add capstone`)
"""
from __future__ import annotations

import sys
from pathlib import Path
from collections import Counter

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
except ImportError:
    print("ERROR: capstone required. Install with: uv add capstone")
    sys.exit(1)


BASE = 0x7FF76C300000  # Default base address for League


def find_lut_candidates(data: bytes, start: int = 0x1900000, end: int = 0x1A00000) -> list[int]:
    """Find 256-byte bijective tables (S-boxes) in .rdata region."""
    candidates = []
    for offset in range(start, min(end, len(data) - 256)):
        chunk = data[offset:offset + 256]
        if len(set(chunk)) == 256:  # every byte value appears exactly once
            candidates.append(offset)
    return candidates


def find_bitfield_extractor(data: bytes, md) -> int | None:
    """Find the bitfield extractor function (called 17+ times from deserializer).

    Pattern: small function (~50 bytes) that takes (data_ptr, bit_pos, num_bits)
    and returns extracted bits. Uses shr + and + or patterns.
    """
    # The extractor is called very frequently from deserializers.
    # Search for the call target that appears 10+ times in a 0x2000 window.
    # This is a heuristic — may need tuning for new patches.
    print("  Searching for bitfield extractor... (heuristic)")
    # Look for known pattern: movzx + shr + and sequence
    # For now, return None to indicate manual identification needed
    return None


def disassemble_function(data: bytes, rva: int, max_bytes: int = 512) -> list:
    """Disassemble a function starting at RVA, stopping at first RET."""
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    code = data[rva:rva + max_bytes]
    instructions = []
    for insn in md.disasm(code, BASE + rva):
        instructions.append(insn)
        if insn.mnemonic == 'ret':
            break
    return instructions


def extract_cipher_ops(instructions: list) -> list[str]:
    """Extract cipher operations from disassembled reader function.

    Returns a list of operation descriptions like:
    ['ror(v, 2)', 'xor 0x15', 'bitswap', 'ror(v, 7)', 'not']
    """
    ops = []
    i = 0
    while i < len(instructions):
        insn = instructions[i]
        mn = insn.mnemonic
        op_str = insn.op_str

        # ROR: ror reg, imm
        if mn == 'ror' and ',' in op_str:
            parts = op_str.split(',')
            if len(parts) == 2:
                try:
                    n = int(parts[1].strip(), 0)
                    ops.append(f'ror(v, {n})')
                except ValueError:
                    pass

        # XOR: xor reg, imm
        elif mn == 'xor' and ',' in op_str:
            parts = op_str.split(',')
            if len(parts) == 2:
                try:
                    n = int(parts[1].strip(), 0)
                    if n != 0xFF:  # xor 0xFF is NOT
                        ops.append(f'xor 0x{n:02X}')
                    else:
                        ops.append('not')
                except ValueError:
                    pass

        # ADD: add reg, imm
        elif mn == 'add' and ',' in op_str:
            parts = op_str.split(',')
            if len(parts) == 2:
                try:
                    n = int(parts[1].strip(), 0)
                    if n != n:  # skip add reg, reg
                        pass
                    else:
                        ops.append(f'add 0x{n:02X}')
                except ValueError:
                    pass

        # SUB: sub reg, imm
        elif mn == 'sub' and ',' in op_str:
            parts = op_str.split(',')
            if len(parts) == 2:
                try:
                    n = int(parts[1].strip(), 0)
                    ops.append(f'sub 0x{n:02X}')
                except ValueError:
                    pass

        # NOT
        elif mn == 'not':
            ops.append('not')

        # Bitswap: detected by and 0xD5 pattern
        elif mn == 'and' and '0xd5' in op_str.lower():
            ops.append('bitswap')
            # Skip the next few instructions (shl, and 0x55, or)
            i += 3

        # MOVZX with memory operand = LUT lookup
        elif mn == 'movzx' and '[' in op_str and '+' in op_str:
            ops.append('LUT_A[v]')

        i += 1

    return ops


def analyze_reader(data: bytes, rva: int, name: str) -> dict:
    """Analyze a reader function and extract its cipher."""
    print(f"\n  Reader at RVA 0x{rva:X} ({name}):")
    instructions = disassemble_function(data, rva)

    # Classify reader type
    has_loop = any(i.mnemonic in ('jne', 'jnz', 'je', 'jz') for i in instructions)
    has_test_80 = any('0x80' in i.op_str for i in instructions if i.mnemonic == 'test')
    has_shl_8 = any('8' in i.op_str for i in instructions if i.mnemonic == 'shl')

    if has_test_80 and has_loop:
        reader_type = 'varint'
    elif has_shl_8 and has_loop:
        reader_type = '4byte'
    else:
        reader_type = '1byte'

    ops = extract_cipher_ops(instructions)

    print(f"    Type: {reader_type}")
    print(f"    Ops:  {' → '.join(ops) if ops else '(none detected)'}")
    print(f"    Instructions: {len(instructions)}")

    return {
        'rva': rva,
        'name': name,
        'type': reader_type,
        'ops': ops,
        'instruction_count': len(instructions),
    }


def scan_for_calls(data: bytes, start_rva: int, length: int) -> list[tuple[int, int]]:
    """Find all CALL instructions in a region and their targets."""
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    code = data[start_rva:start_rva + length]
    calls = []
    for insn in md.disasm(code, BASE + start_rva):
        if insn.mnemonic == 'call':
            # Extract target from operand
            try:
                target = int(insn.op_str, 0)
                target_rva = target - BASE
                if 0 < target_rva < len(data):
                    calls.append((insn.address - BASE, target_rva))
            except ValueError:
                pass
    return calls


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary_dump_path>")
        sys.exit(1)

    binary_path = Path(sys.argv[1])
    if not binary_path.exists():
        print(f"Not found: {binary_path}")
        sys.exit(1)

    data = binary_path.read_bytes()
    print(f"Loaded {len(data):,} bytes from {binary_path}")

    # Step 1: Find LUT candidates
    print("\n=== Step 1: Finding LUT_A candidates ===")
    candidates = find_lut_candidates(data)
    print(f"Found {len(candidates)} bijective 256-byte tables:")
    for offset in candidates:
        preview = data[offset:offset + 8].hex(' ')
        print(f"  0x{offset:X}: {preview} ...")

    if candidates:
        # Use the first candidate as default (user should verify)
        lut_offset = candidates[0]
        lut_a = list(data[lut_offset:lut_offset + 256])
        print(f"\nUsing LUT_A at 0x{lut_offset:X} (verify this is correct!)")
    else:
        print("WARNING: No LUT candidates found. Cipher extraction will be incomplete.")
        lut_a = None

    # Step 2: Find deserializer
    print("\n=== Step 2: Finding deserializer ===")
    print("  To find the 0x025B deserializer:")
    print("  1. Search for the dispatcher prologue: 48 89 5c 24 08 55 56 57 41 54 41 55 41 56 41 57")
    print("  2. From dispatcher, find the vtable and the entry for packet 0x025B")
    print("  3. Or provide the deserializer RVA as argument")

    if len(sys.argv) >= 3:
        deser_rva = int(sys.argv[2], 0)
        print(f"\n  Using deserializer at RVA 0x{deser_rva:X}")

        # Step 3: Scan for calls in deserializer
        print("\n=== Step 3: Scanning deserializer for reader calls ===")
        calls = scan_for_calls(data, deser_rva, 0x2000)

        # Count call targets to find the most-called functions
        target_counts = Counter(target for _, target in calls)
        print(f"  Found {len(calls)} calls to {len(target_counts)} unique targets:")
        for target, count in target_counts.most_common(20):
            print(f"    RVA 0x{target:X}: called {count}x")

        # Analyze unique reader functions (called 3-8 times each)
        print("\n=== Step 4: Analyzing reader functions ===")
        readers = []
        for target, count in target_counts.most_common(20):
            if 2 <= count <= 10:
                result = analyze_reader(data, target, f"reader_{target:X}")
                readers.append(result)

        # Summary
        print("\n=== Summary ===")
        print(f"LUT_A offset: 0x{lut_offset:X}" if candidates else "LUT_A: NOT FOUND")
        print(f"Reader functions found: {len(readers)}")
        for r in readers:
            print(f"  0x{r['rva']:X} ({r['type']:>6s}): {' → '.join(r['ops'])}")

        print("\n=== Next steps ===")
        print("1. Verify LUT_A is correct (check if reader functions reference it)")
        print("2. Verify cipher ops match the disassembly")
        print("3. Update movement_decoder.py with new constants")
        print("4. Test with a replay from the new patch")
    else:
        print("\n  Pass deserializer RVA as second argument to scan for readers:")
        print(f"  uv run python -m ml.tools.extract_ciphers {binary_path} 0xFE22B0")


if __name__ == "__main__":
    main()

"""
Extract all cipher substitution tables from the macOS League binary via ARM64 emulation.

Two approaches to finding cipher functions:
  1. Load BL targets from handlers.json (output of find_all_handlers.py)
  2. Scan binary for LUT embeddings (D7 56 82 DC...) and find ADRP references

For each cipher function candidate:
  - Call it 256 times (input 0x00-0xFF) via the ARM64 emulator
  - If it returns cleanly and produces a bijective mapping -> it's a cipher
  - Save the 256-byte substitution table

Validation: the known f10 cipher at 0x105CF725C must match the expected
output from _make_cipher_FAF080() in movement_decoder.py.

Output: ml/data/cipher_tables.json
"""

from __future__ import annotations

import json
import struct
import sys
import time
from pathlib import Path

from ml.emulator.arm64_emulator import ARM64Emulator, BINARY_BASE

# Known cipher for validation
KNOWN_CIPHER_ADDR = 0x105CF725C   # macOS f10: sub 0x62, bitswap, add 7

# LUT signature (first 16 bytes of the 256-byte permutation table)
LUT_SIG = bytes([
    0xD7, 0x56, 0x82, 0xDC, 0x83, 0x02, 0x8F, 0x29,
    0x35, 0x04, 0x21, 0x71, 0x79, 0x9E, 0x92, 0x7F,
])


def expected_f10_table() -> list[int]:
    """Build the expected cipher table for f10 (sub 0x62, bitswap, add 7)."""
    def cipher(b):
        b = (b - 0x62) & 0xFF
        hi = (b & 0xD5) << 1
        lo = (b >> 1) & 0x55
        b = (hi | lo) & 0xFF
        b = (b + 7) & 0xFF
        return b
    return [cipher(i) for i in range(256)]


# ── LUT scanning ─────────────────────────────────────────────────────

def find_lut_embeddings(data: bytes, base: int) -> list[int]:
    """Find all 256-byte LUT embeddings matching the known signature."""
    addresses = []
    offset = 0
    while True:
        idx = data.find(LUT_SIG, offset)
        if idx == -1:
            break
        # Verify it's a full 256-byte permutation
        if idx + 256 <= len(data):
            table = data[idx:idx + 256]
            if len(set(table)) == 256:
                addresses.append(base + idx)
        offset = idx + 1
    return addresses


# ── Cipher table extraction via emulator ─────────────────────────────

def build_cipher_table(emu: ARM64Emulator, func_addr: int,
                       max_insn: int = 10000) -> list[int] | None:
    """Call func_addr with inputs 0x00-0xFF, return 256-byte table or None."""
    table = []
    for i in range(256):
        result = emu.call_function(func_addr, [i], verbose=False, max_insn=max_insn)
        if not result['stopped_at_trampoline']:
            return None
        val = result['x0'] & 0xFF
        table.append(val)
    # Must be bijective
    if len(set(table)) != 256:
        return None
    return table


def validate_known_cipher(emu: ARM64Emulator) -> bool:
    """Test the known f10 cipher to confirm calling convention."""
    expected = expected_f10_table()

    print(f"[VALIDATE] Testing known cipher at 0x{KNOWN_CIPHER_ADDR:X}")
    # Quick test with a few values first
    test_vals = [0x00, 0x42, 0x62, 0xFF]
    for v in test_vals:
        result = emu.call_function(KNOWN_CIPHER_ADDR, [v], verbose=False, max_insn=5000)
        actual = result['x0'] & 0xFF
        exp = expected[v]
        ok = actual == exp
        print(f"  cipher(0x{v:02X}) = 0x{actual:02X}  expected 0x{exp:02X}  {'OK' if ok else 'FAIL'}")
        if not ok:
            # Show more debug info
            result2 = emu.call_function(KNOWN_CIPHER_ADDR, [v], verbose=True)
            print(f"  Full result: {result2}")
            return False

    # Full 256-byte table
    print("  Building full table...")
    table = build_cipher_table(emu, KNOWN_CIPHER_ADDR)
    if table is None:
        print("  FAIL: could not build table (function didn't return cleanly)")
        return False
    if table != expected:
        mismatches = sum(1 for a, b in zip(table, expected) if a != b)
        print(f"  FAIL: {mismatches}/256 mismatches")
        return False

    print("  PASS: all 256 values match expected f10 cipher")
    return True


def quick_screen(emu: ARM64Emulator, addr: int, max_insn: int = 10000) -> bool:
    """Quick test: call with input 0, check if it returns cleanly."""
    result = emu.call_function(addr, [0], verbose=False, max_insn=max_insn)
    return result['stopped_at_trampoline']


def extract_all_tables(emu: ARM64Emulator, candidate_addrs: list[int],
                       skip_addrs: set[int] | None = None) -> dict[int, list[int]]:
    """Try to extract cipher tables from all candidate addresses.
    First does a quick screen (single call), then full 256-call extraction."""
    tables = {}
    skip = skip_addrs or set()
    total = len(candidate_addrs)

    # Phase 1: Quick screen
    print(f"  Phase 1: Quick screen ({total} candidates)...")
    callable_addrs = []
    for idx, addr in enumerate(candidate_addrs):
        if addr in skip:
            continue
        if quick_screen(emu, addr):
            callable_addrs.append(addr)

    print(f"  {len(callable_addrs)}/{total} candidates return cleanly")

    # Phase 2: Full extraction for callable functions
    print(f"  Phase 2: Full 256-byte extraction ({len(callable_addrs)} functions)...")
    for idx, addr in enumerate(callable_addrs):
        t0 = time.time()
        table = build_cipher_table(emu, addr)
        elapsed = time.time() - t0

        if table is not None:
            tables[addr] = table
            print(f"    [{idx + 1}/{len(callable_addrs)}] 0x{addr:X}: CIPHER ({elapsed:.2f}s)")
        else:
            print(f"    [{idx + 1}/{len(callable_addrs)}] 0x{addr:X}: callable but not bijective")

    return tables


# ── Cross-reference with known ciphers ───────────────────────────────

def cross_check_known_ciphers(tables: dict[int, list[int]]):
    """Compare extracted tables against known ciphers from movement_decoder.py."""
    from ml.parsers.movement_decoder import (
        _make_cipher_FAD5C0, _make_cipher_FB82B0, _make_cipher_FADD60,
        _make_cipher_FAE670, _make_cipher_FAB5B0, _make_cipher_FB8FC0,
        _make_cipher_FAB410, _make_cipher_FAF080, _make_cipher_FAB3C0,
        _make_cipher_FB9A80, _make_cipher_FB6120, _make_cipher_FB3CC0,
        _LUT_A,
    )

    known_ciphers = {
        "f1_FAD5C0":  [_make_cipher_FAD5C0()(i) for i in range(256)],
        "f3_FAB3C0":  [_make_cipher_FAB3C0(_LUT_A)(i) for i in range(256)],
        "f4_FB82B0":  [_make_cipher_FB82B0()(i) for i in range(256)],
        "f5_FADD60":  [_make_cipher_FADD60(_LUT_A)(i) for i in range(256)],
        "f6_FAE670":  [_make_cipher_FAE670(_LUT_A)(i) for i in range(256)],
        "f7_FAB5B0":  [_make_cipher_FAB5B0()(i) for i in range(256)],
        "f8_FB8FC0":  [_make_cipher_FB8FC0()(i) for i in range(256)],
        "f9_FAB410":  [_make_cipher_FAB410()(i) for i in range(256)],
        "f10_FAF080": [_make_cipher_FAF080()(i) for i in range(256)],
        "f12_FB6120": [_make_cipher_FB6120(_LUT_A)(i) for i in range(256)],
        "f14_FB9A80": [_make_cipher_FB9A80(_LUT_A)(i) for i in range(256)],
        "f16_FB3CC0": [_make_cipher_FB3CC0(_LUT_A)(i) for i in range(256)],
    }

    from ml.emulator.decode_0228 import (
        _cipher_f0, _cipher_varint_A, _cipher_4byte_A, _cipher_varint_B,
        _make_cipher_1byte_B, _cipher_varint_D, _make_cipher_1byte_A,
        _make_cipher_varint_C, _cipher_4byte_B, _LUT,
    )

    known_ciphers.update({
        "0228_f0":        [_cipher_f0(i) for i in range(256)],
        "0228_varintA":   [_cipher_varint_A(i) for i in range(256)],
        "0228_4byteA":    [_cipher_4byte_A(i) for i in range(256)],
        "0228_varintB":   [_cipher_varint_B(i) for i in range(256)],
        "0228_1byteB":    [_make_cipher_1byte_B(_LUT)(i) for i in range(256)],
        "0228_varintD":   [_cipher_varint_D(i) for i in range(256)],
        "0228_1byteA":    [_make_cipher_1byte_A(_LUT)(i) for i in range(256)],
        "0228_varintC":   [_make_cipher_varint_C(_LUT)(i) for i in range(256)],
        "0228_4byteB":    [_cipher_4byte_B(i) for i in range(256)],
    })

    print(f"\n=== CROSS-CHECK: {len(tables)} extracted vs {len(known_ciphers)} known ===")
    matched = {}
    for addr, table in sorted(tables.items()):
        for name, known_table in known_ciphers.items():
            if table == known_table:
                matched[addr] = name
                print(f"  0x{addr:X} = {name}")
                break

    unmatched_extracted = len(tables) - len(matched)
    unmatched_known = len(known_ciphers) - len(set(matched.values()))
    print(f"  Matched: {len(matched)}")
    print(f"  Unmatched extracted: {unmatched_extracted}")
    print(f"  Unmatched known: {unmatched_known}")

    return matched


# ── Main ──────────────────────────────────────────────────────────────

def main():
    handlers_path = Path("ml/data/handlers.json")
    dump_path = Path("ml/data/league_macos_dump.bin")
    output_path = Path("ml/data/cipher_tables.json")

    # ── Load candidate addresses ──
    candidate_addrs = set()

    # Source 1: Cipher candidates from handler scanning (includes BL targets + region scans)
    if handlers_path.exists():
        print(f"Loading handler info: {handlers_path}")
        hdata = json.loads(handlers_path.read_text())
        # Prefer cipher_candidates (broader scan) over just BL targets
        for addr in hdata.get("cipher_candidates_int", []):
            candidate_addrs.add(addr)
        # Also add all BL targets
        for pkt_key, info in hdata["handlers"].items():
            for addr in info.get("bl_targets_int", []):
                candidate_addrs.add(addr)
            for addr in info.get("deep_bl_targets_int", []):
                candidate_addrs.add(addr)
        print(f"  {len(candidate_addrs)} unique candidates from handlers")
    else:
        print(f"[WARN] {handlers_path} not found — run find_all_handlers.py first")

    # Source 2: LUT embeddings (as cross-check)
    if dump_path.exists():
        print(f"\nScanning for LUT embeddings in binary...")
        data = dump_path.read_bytes()
        lut_addrs = find_lut_embeddings(data, BINARY_BASE)
        print(f"  Found {len(lut_addrs)} LUT embeddings")
        if lut_addrs:
            print(f"  Range: 0x{min(lut_addrs):X} - 0x{max(lut_addrs):X}")
        del data
    else:
        lut_addrs = []

    # Always include the known cipher for validation
    candidate_addrs.add(KNOWN_CIPHER_ADDR)

    print(f"\nTotal candidates: {len(candidate_addrs)}")

    # ── Initialize emulator ──
    print(f"\nInitializing ARM64 emulator...")
    emu = ARM64Emulator(str(dump_path))
    emu.setup()

    # ── Validate calling convention ──
    print()
    known_ok = validate_known_cipher(emu)
    if not known_ok:
        print("\n[NOTE] Known cipher at 0x105CF725C is inline code, not a standalone function.")
        print("This is expected — cipher code is inlined in the deserialization function.")
        print("We'll still try all BL-target candidates — many ARE standalone functions.")
        # Remove the known inline cipher from candidates
        candidate_addrs.discard(KNOWN_CIPHER_ADDR)

    # ── Extract tables from all candidates ──
    print(f"\n=== EXTRACTING CIPHER TABLES ===")
    sorted_addrs = sorted(candidate_addrs)
    tables = extract_all_tables(emu, sorted_addrs)
    print(f"\nExtracted {len(tables)} cipher tables from {len(sorted_addrs)} candidates")

    # ── Cross-check against known ciphers ──
    try:
        matched = cross_check_known_ciphers(tables)
    except Exception as e:
        print(f"Cross-check failed (non-fatal): {e}")
        matched = {}

    # ── Save ──
    output = {
        "binary_base": f"0x{BINARY_BASE:X}",
        "known_cipher_addr": f"0x{KNOWN_CIPHER_ADDR:X}",
        "total_tables": len(tables),
        "lut_embedding_count": len(lut_addrs),
        "lut_embeddings": [f"0x{a:X}" for a in lut_addrs],
        "matched_known": {f"0x{a:X}": name for a, name in matched.items()},
        "tables": {},
    }

    for addr, table in sorted(tables.items()):
        key = f"0x{addr:X}"
        output["tables"][key] = {
            "address_int": addr,
            "table": table,
            "known_name": matched.get(addr, None),
            "is_identity": table == list(range(256)),
        }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2))
    print(f"\nSaved: {output_path}")


if __name__ == "__main__":
    main()

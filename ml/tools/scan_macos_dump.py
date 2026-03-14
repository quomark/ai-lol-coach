"""
Scan a macOS League binary dump to find LUT tables and cipher constants.

The macOS binary has the same cipher values as Windows (same protocol),
but at different offsets. This script finds them by pattern matching.

Usage:
    python ml/tools/scan_macos_dump.py path/to/league_macos_dump.bin
    python ml/tools/scan_macos_dump.py path/to/league_macos_dump.bin --validate replay.rofl
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path


def find_permutation_tables(data: bytes, min_unique: int = 240) -> list[tuple[int, int]]:
    """Find 256-byte regions that look like permutation tables (LUTs).

    A proper LUT has each byte value appearing exactly once (or close to it).
    Returns list of (offset, unique_count).
    """
    results = []
    # Slide a 256-byte window
    for i in range(0, len(data) - 256, 4):  # align to 4 bytes for speed
        window = data[i:i + 256]
        unique = len(set(window))
        if unique >= min_unique:
            # Check it's a real permutation (each value 0-255 appears once)
            counts = [0] * 256
            for b in window:
                counts[b] += 1
            max_count = max(counts)
            if max_count <= 2:  # allow minor imperfections
                results.append((i, unique))
    return results


def find_windows_lut_match(data: bytes, windows_lut: bytes) -> list[int]:
    """Find exact matches of the known Windows LUT in macOS binary."""
    matches = []
    for i in range(len(data) - 256):
        if data[i:i + 256] == windows_lut:
            matches.append(i)
    return matches


def find_cipher_constants(data: bytes) -> dict[str, list[int]]:
    """Search for known cipher constant sequences.

    These byte sequences appear in the cipher functions and should be
    identical across platforms.
    """
    patterns = {
        # f0 cipher: add 0x4F, xor 0x6C — look for 0x4F and 0x6C near each other
        "f0_add_xor": (b"\x4F", b"\x6C"),
        # f10 cipher (positions): sub 0x62, bitswap, add 7
        "f10_sub_62": b"\x62",
        # varint_A: xor 0x89, add 0x66
        "varint_A_xor89": b"\x89",
    }

    results = {}
    for name, pattern in patterns.items():
        if isinstance(pattern, tuple):
            # Find locations where both values appear within 20 bytes
            p1, p2 = pattern
            locs = []
            for i in range(len(data) - 20):
                if data[i:i + 1] == p1:
                    for j in range(i + 1, min(i + 20, len(data))):
                        if data[j:j + 1] == p2:
                            locs.append(i)
                            break
            results[name] = locs[:10]  # first 10
        else:
            locs = []
            pos = 0
            while True:
                pos = data.find(pattern, pos)
                if pos == -1:
                    break
                locs.append(pos)
                pos += 1
                if len(locs) > 1000:
                    break
            results[name] = locs[:10]

    return results


def extract_lut_at(data: bytes, offset: int) -> bytes:
    """Extract 256 bytes at offset."""
    return data[offset:offset + 256]


def compare_luts(lut1: bytes, lut2: bytes) -> dict:
    """Compare two LUT tables."""
    if len(lut1) != 256 or len(lut2) != 256:
        return {"error": "Invalid LUT size"}

    matching = sum(1 for a, b in zip(lut1, lut2) if a == b)
    return {
        "matching_bytes": matching,
        "match_pct": matching / 256 * 100,
        "is_identical": lut1 == lut2,
    }


def main():
    import argparse

    p = argparse.ArgumentParser(description="Scan macOS League dump for LUT/cipher tables")
    p.add_argument("dump", help="Path to macOS binary dump")
    p.add_argument("--windows-dump", default="ml/data/league_unpacked_patched.bin",
                   help="Path to Windows binary dump for comparison")
    p.add_argument("--validate", default=None,
                   help="Path to .rofl file to validate decoded positions")
    p.add_argument("--lut-offset", type=lambda x: int(x, 0), default=None,
                   help="If you already know the LUT offset, extract directly")
    args = p.parse_args()

    dump_path = Path(args.dump)
    if not dump_path.exists():
        print(f"Dump file not found: {dump_path}")
        sys.exit(1)

    print(f"Loading macOS dump: {dump_path} ({dump_path.stat().st_size / 1024 / 1024:.1f} MB)")
    mac_data = dump_path.read_bytes()

    # Load Windows dump for comparison
    win_lut = None
    win_path = Path(args.windows_dump)
    if win_path.exists():
        print(f"Loading Windows dump: {win_path}")
        win_data = win_path.read_bytes()
        win_lut_offset = 0x19B60F0
        if win_lut_offset + 256 <= len(win_data):
            win_lut = win_data[win_lut_offset:win_lut_offset + 256]
            unique = len(set(win_lut))
            all_zero = all(b == 0 for b in win_lut)
            print(f"  Windows LUT at 0x{win_lut_offset:X}: {unique} unique values, "
                  f"{'ALL ZEROS' if all_zero else 'has data'}")

    # If specific offset given, extract directly
    if args.lut_offset is not None:
        print(f"\n=== Extracting LUT at offset 0x{args.lut_offset:X} ===")
        lut = extract_lut_at(mac_data, args.lut_offset)
        print(f"  First 32 bytes: {lut[:32].hex(' ')}")
        print(f"  Unique values: {len(set(lut))}")
        if win_lut:
            cmp = compare_luts(lut, win_lut)
            print(f"  vs Windows LUT: {cmp}")

        # Save extracted LUT
        out_path = dump_path.parent / "macos_lut.bin"
        out_path.write_bytes(lut)
        print(f"  Saved to: {out_path}")
        return

    # Step 1: Try exact match of Windows LUT
    if win_lut and not all(b == 0 for b in win_lut):
        print(f"\n=== Searching for exact Windows LUT match ===")
        matches = find_windows_lut_match(mac_data, win_lut)
        if matches:
            print(f"  Found {len(matches)} exact matches:")
            for m in matches:
                print(f"    offset 0x{m:X}")
        else:
            print(f"  No exact match (expected — macOS may have different base values)")

    # Step 2: Find all permutation tables
    print(f"\n=== Scanning for 256-byte permutation tables ===")
    print(f"  (This may take a minute for large dumps...)")
    perm_tables = find_permutation_tables(mac_data, min_unique=250)
    print(f"  Found {len(perm_tables)} candidate permutation tables")

    if perm_tables:
        print(f"\n  {'Offset':<14} {'Unique':<8} {'First 16 bytes'}")
        print(f"  {'-'*14} {'-'*8} {'-'*48}")
        for offset, unique in perm_tables[:30]:
            first16 = mac_data[offset:offset + 16].hex(' ')
            marker = ""
            if win_lut:
                cmp = compare_luts(mac_data[offset:offset + 256], win_lut)
                if cmp.get("is_identical"):
                    marker = " *** EXACT MATCH ***"
                elif cmp.get("match_pct", 0) > 50:
                    marker = f" ({cmp['match_pct']:.0f}% match)"
            print(f"  0x{offset:08X}  {unique:<8} {first16}{marker}")

        if len(perm_tables) > 30:
            print(f"  ... and {len(perm_tables) - 30} more")

        # Auto-select best candidate
        if win_lut:
            best = max(perm_tables,
                       key=lambda t: compare_luts(mac_data[t[0]:t[0]+256], win_lut).get("matching_bytes", 0))
            best_cmp = compare_luts(mac_data[best[0]:best[0]+256], win_lut)
            print(f"\n  Best match to Windows LUT: offset 0x{best[0]:X} "
                  f"({best_cmp['matching_bytes']}/256 bytes match)")

    # Step 3: Look for cipher constant patterns
    print(f"\n=== Searching for cipher constant patterns ===")
    constants = find_cipher_constants(mac_data)
    for name, locs in constants.items():
        print(f"  {name}: {len(locs)} occurrences" +
              (f" (first: 0x{locs[0]:X})" if locs else ""))

    # Summary
    print(f"\n{'='*60}")
    print(f"NEXT STEPS:")
    print(f"  1. Pick the most likely LUT offset from the permutation tables above")
    print(f"  2. Run: python {sys.argv[0]} {args.dump} --lut-offset 0x<OFFSET>")
    print(f"  3. If the LUT looks good, copy it to ml/data/macos_lut.bin")
    print(f"  4. Update movement_decoder.py to use the macOS LUT values")
    if args.validate:
        print(f"  5. Validate with: python -m ml.parsers.game_state {args.validate}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()

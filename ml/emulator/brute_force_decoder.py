"""
Brute-force decoder for unknown League packet types.

Uses the 21 known cipher substitution tables from 0x025B/0x0228
and tries all combinations of (schema_size, field_reader, cipher_table)
to find configurations that produce zero leftover bytes.

Strategy:
  1. For each unknown packet type, try schema sizes 1/2/4/6
  2. For each schema size, greedily discover fields one at a time:
     - Try all 21 ciphers × 4 reader types for the next field
     - Pick the combination that maximises zero-leftover across a sample
  3. Handle optional fields by correlating schema bits with field presence
"""

from __future__ import annotations

import json
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from itertools import product
from pathlib import Path
from typing import Optional


# ── Stream readers (same as universal_decoder.py) ─────────────────────

def read_varint(data: bytes, pos: int, table: list[int]) -> tuple[int, int]:
    result = 0
    shift = 0
    while pos < len(data):
        decoded = table[data[pos]]
        pos += 1
        result |= (decoded & 0x7F) << shift
        shift += 7
        if not (decoded & 0x80):
            break
    if result & (1 << 30):
        result = -(result ^ (1 << 30))
    return result, pos


def read_4byte_be(data: bytes, pos: int, table: list[int]) -> tuple[int | None, int]:
    if pos + 4 > len(data):
        return None, pos
    result = 0
    for _ in range(4):
        decoded = table[data[pos]]
        pos += 1
        result = ((result << 8) | decoded) & 0xFFFFFFFF
    return result, pos


def read_4byte_bswap(data: bytes, pos: int, table: list[int]) -> tuple[int | None, int]:
    val, pos = read_4byte_be(data, pos, table)
    if val is not None:
        val = struct.unpack("<I", struct.pack(">I", val))[0]
    return val, pos


def read_1byte(data: bytes, pos: int, table: list[int]) -> tuple[int | None, int]:
    if pos >= len(data):
        return None, pos
    return table[data[pos]], pos + 1


READERS = {
    "varint": read_varint,
    "1byte": read_1byte,
    "4byte_be": read_4byte_be,
    "4byte_bswap": read_4byte_bswap,
}


# ── Load known cipher tables ─────────────────────────────────────────

def load_known_ciphers(path: str = "ml/data/cipher_tables.json") -> dict[str, list[int]]:
    data = json.loads(Path(path).read_text())
    ciphers = {}
    for name, info in data["tables"].items():
        if not info.get("is_identity", False):
            ciphers[name] = info["table"]
    # Also add identity cipher for fields with no encryption
    ciphers["identity"] = list(range(256))
    return ciphers


# ── Brute-force field discovery ───────────────────────────────────────

@dataclass
class FieldGuess:
    cipher_name: str
    reader_type: str
    zero_leftover_pct: float
    avg_leftover: float


@dataclass
class LayoutGuess:
    schema_size: int
    fields: list[tuple[str, str]]  # (cipher_name, reader_type) per field
    zero_leftover_pct: float
    sample_size: int


def try_read_field(data: bytes, pos: int, cipher: list[int],
                   reader_type: str) -> tuple[int | None, int]:
    """Try reading one field from data at pos. Returns (value, new_pos)."""
    reader = READERS[reader_type]
    try:
        val, new_pos = reader(data, pos, cipher)
        if new_pos > len(data):
            return None, pos
        return val, new_pos
    except Exception:
        return None, pos


def score_field_guess(packets_data: list[bytes], start_pos: int,
                      cipher: list[int], reader_type: str,
                      target_leftovers: list[int] | None = None) -> tuple[float, float, list[int]]:
    """Score a (cipher, reader) guess for one field position.

    Returns (zero_leftover_pct, avg_leftover, new_positions).
    If target_leftovers is given, score how many packets reach exactly that leftover.
    """
    new_positions = []
    zero = 0
    total_leftover = 0
    valid = 0

    for pkt_data in packets_data:
        if start_pos >= len(pkt_data):
            new_positions.append(start_pos)
            continue
        val, new_pos = try_read_field(pkt_data, start_pos, cipher, reader_type)
        if val is None:
            new_positions.append(start_pos)
            continue
        leftover = len(pkt_data) - new_pos
        new_positions.append(new_pos)
        valid += 1
        total_leftover += leftover
        if leftover == 0:
            zero += 1

    zero_pct = zero / valid * 100 if valid else 0
    avg_left = total_leftover / valid if valid else 999
    return zero_pct, avg_left, new_positions


def greedy_field_discovery(packets_data: list[bytes], schema_size: int,
                           ciphers: dict[str, list[int]],
                           max_fields: int = 15,
                           min_improvement: float = 1.0) -> LayoutGuess:
    """Greedily discover fields one at a time.

    For each field position, try all (cipher, reader) combos and pick the
    one that maximizes zero-leftover packets.
    """
    # Current read position for each packet
    positions = [schema_size] * len(packets_data)
    found_fields = []
    best_zero_pct = 0

    # Check initial state: how many packets already have zero leftover?
    initial_zero = sum(1 for i, d in enumerate(packets_data)
                       if positions[i] >= len(d)) / len(packets_data) * 100

    for field_idx in range(max_fields):
        best_guess = None
        best_score = (-1, 999)  # (zero_pct, -avg_leftover)

        for cipher_name, cipher_table in ciphers.items():
            for reader_type in ["varint", "1byte", "4byte_bswap", "4byte_be"]:
                # Score this combo across all packets at current positions
                zero_pct, avg_left, new_pos = score_field_guess(
                    packets_data, -1, cipher_table, reader_type  # placeholder
                )

                # Actually need per-packet positions
                zero = 0
                total_left = 0
                valid = 0
                candidate_pos = []

                for i, pkt_data in enumerate(packets_data):
                    pos = positions[i]
                    if pos >= len(pkt_data):
                        candidate_pos.append(pos)
                        continue
                    val, new_p = try_read_field(pkt_data, pos, cipher_table, reader_type)
                    if val is None or new_p > len(pkt_data):
                        candidate_pos.append(pos)
                        continue
                    candidate_pos.append(new_p)
                    leftover = len(pkt_data) - new_p
                    valid += 1
                    total_left += leftover
                    if leftover == 0:
                        zero += 1

                if valid == 0:
                    continue
                zero_pct = zero / valid * 100
                avg_left = total_left / valid
                score = (zero_pct, -avg_left)

                if score > best_score:
                    best_score = score
                    best_guess = (cipher_name, reader_type, candidate_pos, zero_pct)

        if best_guess is None:
            break

        cipher_name, reader_type, new_positions, zero_pct = best_guess

        # Check if this field actually improved things
        if zero_pct <= best_zero_pct + min_improvement and field_idx > 0:
            # No improvement, try if we should stop
            if zero_pct <= best_zero_pct:
                break

        found_fields.append((cipher_name, reader_type))
        positions = new_positions
        best_zero_pct = zero_pct

        # If we hit 95%+ zero leftover, we're done
        if zero_pct >= 95:
            break

    return LayoutGuess(
        schema_size=schema_size,
        fields=found_fields,
        zero_leftover_pct=best_zero_pct,
        sample_size=len(packets_data),
    )


# ── Schema bit analysis ──────────────────────────────────────────────

def analyze_schema_bits(packets_data: list[bytes], schema_size: int) -> dict:
    """Analyze which schema bits correlate with packet size changes."""
    schemas = []
    sizes = []
    for d in packets_data:
        if len(d) < schema_size:
            continue
        if schema_size == 1:
            schemas.append(d[0])
        elif schema_size == 2:
            schemas.append(struct.unpack_from('<H', d, 0)[0])
        elif schema_size == 4:
            schemas.append(struct.unpack_from('<I', d, 0)[0])
        elif schema_size == 6:
            schemas.append(int.from_bytes(d[:6], 'little'))
        sizes.append(len(d))

    if not schemas:
        return {}

    total_bits = schema_size * 8
    bit_size_corr = {}

    for bit in range(total_bits):
        # Partition packets by whether this bit is set
        sizes_0 = [s for sch, s in zip(schemas, sizes) if not (sch & (1 << bit))]
        sizes_1 = [s for sch, s in zip(schemas, sizes) if (sch & (1 << bit))]

        if not sizes_0 or not sizes_1:
            continue

        avg_0 = sum(sizes_0) / len(sizes_0)
        avg_1 = sum(sizes_1) / len(sizes_1)
        diff = avg_1 - avg_0

        if abs(diff) > 0.3:  # meaningful size difference
            bit_size_corr[bit] = round(diff, 2)

    return bit_size_corr


# ── Brute-force with schema-aware field skipping ─────────────────────

def brute_force_with_schema(packets_data: list[bytes], schema_size: int,
                            ciphers: dict[str, list[int]],
                            max_fields: int = 12) -> LayoutGuess:
    """More sophisticated brute-force that considers schema bits.

    Analyzes which schema bits control packet size (field presence),
    then only reads fields when the appropriate schema bits indicate presence.
    """
    # First, try greedy without schema awareness
    result = greedy_field_discovery(packets_data, schema_size, ciphers, max_fields)

    if result.zero_leftover_pct >= 90:
        return result

    # If greedy didn't work well, try with 3-bit type code grouping
    # (like 0x0228: each field has a 3-bit type code, some values = read, others = skip)
    # This is too complex for full brute force, so try some known patterns

    # Pattern: try the 0x0228 schema structure (4-byte schema, fields at known bit positions)
    if schema_size == 4:
        from ml.emulator.decode_0228 import _SCHEMA_FIELDS, _FIELD_READ_TYPES
        # Try the same bit positions but with different ciphers
        best = result
        for cipher_name, cipher_table in ciphers.items():
            for reader_type in ["varint", "1byte", "4byte_bswap"]:
                zero = 0
                valid = 0
                for pkt_data in packets_data:
                    if len(pkt_data) < 4:
                        continue
                    schema = struct.unpack_from('<I', pkt_data, 0)[0]
                    pos = 4
                    ok = True
                    for fnum in range(10):
                        if fnum == 2:  # 1-bit
                            continue
                        dl, nbits = _SCHEMA_FIELDS.get(fnum, (0, 3))
                        tc = (schema >> dl) & ((1 << nbits) - 1)
                        read_types = _FIELD_READ_TYPES.get(fnum, set())
                        if tc not in read_types:
                            continue
                        val, new_pos = try_read_field(pkt_data, pos, cipher_table, reader_type)
                        if val is None or new_pos > len(pkt_data):
                            ok = False
                            break
                        pos = new_pos
                    if ok:
                        valid += 1
                        if pos == len(pkt_data):
                            zero += 1
                if valid > 0:
                    pct = zero / valid * 100
                    if pct > best.zero_leftover_pct:
                        best = LayoutGuess(
                            schema_size=4,
                            fields=[(cipher_name, reader_type)] * 10,
                            zero_leftover_pct=pct,
                            sample_size=len(packets_data),
                        )
        return best

    return result


# ── Main ──────────────────────────────────────────────────────────────

def main():
    from ml.parsers.rofl_parser import ROFLParser
    from ml.parsers.chunk_parser import parse_payload_frames

    replay_path = sys.argv[1] if len(sys.argv) > 1 else \
        "/Users/danielngai/Documents/League of Legends/Replays/TW2-396324158.rofl"

    ciphers = load_known_ciphers()
    print(f"Loaded {len(ciphers)} cipher tables (including identity)")

    print(f"\nParsing replay: {replay_path}")
    rofl = ROFLParser(replay_path)
    frames = rofl.decompress_payload_frames()
    payload = parse_payload_frames(frames, parse_packets=True)

    # Collect packets by type
    packets_by_type: dict[int, list[bytes]] = {}
    for fr in payload.frames:
        for pkt in fr.packets:
            if pkt.size == 0:
                continue
            if pkt.packet_id not in packets_by_type:
                packets_by_type[pkt.packet_id] = []
            packets_by_type[pkt.packet_id].append(pkt.data)

    # Skip already-decoded types
    KNOWN_TYPES = {0x025B, 0x0228}

    # Top unknown types by volume
    unknown_types = sorted(
        [t for t in packets_by_type if t not in KNOWN_TYPES and len(packets_by_type[t]) > 500],
        key=lambda t: -len(packets_by_type[t])
    )[:20]

    print(f"\n{'='*70}")
    print(f"BRUTE-FORCE DECODING: {len(unknown_types)} packet types")
    print(f"{'='*70}")

    results = {}

    for pkt_type in unknown_types:
        all_data = packets_by_type[pkt_type]
        sample = all_data[:500]  # Use first 500 packets as sample
        sizes = Counter(len(d) for d in sample)

        print(f"\n--- 0x{pkt_type:04X} ({len(all_data):,} packets) ---")
        print(f"  Size distribution: {dict(sizes.most_common(5))}")

        best_result = None

        for schema_size in [1, 2, 4, 6]:
            # Skip schema sizes larger than min packet size
            min_size = min(len(d) for d in sample)
            if schema_size >= min_size:
                continue

            # Analyze schema bits
            bit_corr = analyze_schema_bits(sample, schema_size)

            # Run greedy discovery
            result = greedy_field_discovery(sample, schema_size, ciphers, max_fields=12)

            if result.zero_leftover_pct > 0:
                print(f"  schema={schema_size}B: {result.zero_leftover_pct:.1f}% zero-leftover "
                      f"with {len(result.fields)} fields")
                for i, (cn, rt) in enumerate(result.fields):
                    print(f"    f{i}: {rt:12s} cipher={cn}")

            if best_result is None or result.zero_leftover_pct > best_result.zero_leftover_pct:
                best_result = result

        if best_result and best_result.zero_leftover_pct > 0:
            results[pkt_type] = best_result
            if best_result.zero_leftover_pct >= 90:
                print(f"  >>> GOOD DECODE: {best_result.zero_leftover_pct:.1f}% <<<")

    # Summary
    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")

    good = [(t, r) for t, r in results.items() if r.zero_leftover_pct >= 90]
    partial = [(t, r) for t, r in results.items() if 30 <= r.zero_leftover_pct < 90]
    poor = [(t, r) for t, r in results.items() if 0 < r.zero_leftover_pct < 30]

    if good:
        print(f"\nGOOD (>90% zero leftover):")
        for t, r in sorted(good, key=lambda x: -x[1].zero_leftover_pct):
            n = len(packets_by_type[t])
            print(f"  0x{t:04X}: {r.zero_leftover_pct:.1f}% ({n:,} packets, "
                  f"{r.schema_size}B schema, {len(r.fields)} fields)")

    if partial:
        print(f"\nPARTIAL (30-90%):")
        for t, r in sorted(partial, key=lambda x: -x[1].zero_leftover_pct):
            n = len(packets_by_type[t])
            print(f"  0x{t:04X}: {r.zero_leftover_pct:.1f}% ({n:,} packets, "
                  f"{r.schema_size}B schema, {len(r.fields)} fields)")

    if poor:
        print(f"\nPOOR (<30%):")
        for t, r in sorted(poor, key=lambda x: -x[1].zero_leftover_pct):
            n = len(packets_by_type[t])
            print(f"  0x{t:04X}: {r.zero_leftover_pct:.1f}%")

    undecoded = [t for t in unknown_types if t not in results or results[t].zero_leftover_pct == 0]
    if undecoded:
        print(f"\nNO MATCH: {', '.join(f'0x{t:04X}' for t in undecoded)}")


if __name__ == "__main__":
    main()

"""
Universal packet decoder for League of Legends ROFL v2 replays.

Uses cipher substitution tables (from extract_ciphers.py) and handler
metadata (from find_all_handlers.py) to decode arbitrary packet types.

For each packet type, the decoder needs:
  1. Schema size (1, 2, 4, or 6 bytes)
  2. Field definitions: list of (bit_pos, bit_width, read_types, reader_kind, cipher_addr)
  3. Cipher tables for each field

This module can auto-detect schema size and field layout via brute-force
validation (the correct layout produces zero leftover bytes across many packets).

Usage:
    from ml.emulator.universal_decoder import UniversalDecoder

    decoder = UniversalDecoder("ml/data/cipher_tables.json", "ml/data/handlers.json")
    result = decoder.decode(0x025B, raw_packet_data)
"""

from __future__ import annotations

import json
import struct
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class DecodedPacket:
    """Result of decoding a single packet."""
    packet_type: int
    schema: int
    schema_size: int
    fields: dict[str, int | float | None] = field(default_factory=dict)
    has_container: bool = False
    container_data: bytes = b""
    bytes_consumed: int = 0
    total_bytes: int = 0

    @property
    def leftover(self) -> int:
        return self.total_bytes - self.bytes_consumed

    @property
    def fully_parsed(self) -> bool:
        return self.leftover == 0 or self.has_container


@dataclass
class FieldDef:
    """Definition of a single field in a packet schema."""
    index: int
    bit_pos: int
    bit_width: int
    reader: str          # "varint", "1byte", "4byte_be", "4byte_bswap", "1bit"
    cipher_table: list[int] | None  # 256-byte substitution table, or None for 1-bit
    read_types: set[int]  # type codes that trigger a read (consume bytes)


@dataclass
class PacketLayout:
    """Complete layout for a packet type."""
    packet_type: int
    schema_size: int        # bytes (1, 2, 4, or 6)
    fields: list[FieldDef]
    container_field: int | None = None  # field index for container (1-bit, type=1 means container)


# ── Stream readers ────────────────────────────────────────────────────

def _cipher_byte(table: list[int], b: int) -> int:
    return table[b & 0xFF]


def read_varint(data: bytes, pos: int, table: list[int]) -> tuple[int, int]:
    """Read a varint with per-byte cipher and btc on bit 30."""
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
    """Read 4 bytes big-endian with per-byte cipher."""
    if pos + 4 > len(data):
        return None, pos
    result = 0
    for _ in range(4):
        decoded = table[data[pos]]
        pos += 1
        result = ((result << 8) | decoded) & 0xFFFFFFFF
    return result, pos


def read_4byte_bswap(data: bytes, pos: int, table: list[int]) -> tuple[int | None, int]:
    """Read 4 bytes BE then byte-swap to LE."""
    val, pos = read_4byte_be(data, pos, table)
    if val is not None:
        val = struct.unpack("<I", struct.pack(">I", val))[0]
    return val, pos


def read_1byte(data: bytes, pos: int, table: list[int]) -> tuple[int | None, int]:
    """Read 1 byte with cipher."""
    if pos >= len(data):
        return None, pos
    return table[data[pos]], pos + 1


READERS = {
    "varint":      read_varint,
    "4byte_be":    read_4byte_be,
    "4byte_bswap": read_4byte_bswap,
    "1byte":       read_1byte,
}


# ── Decoder ───────────────────────────────────────────────────────────

class UniversalDecoder:
    """Decode any packet type using extracted cipher tables."""

    def __init__(self, cipher_tables_path: str | Path | None = None,
                 handlers_path: str | Path | None = None):
        self.cipher_tables: dict[int, list[int]] = {}  # addr -> 256-byte table
        self.handlers: dict[int, dict] = {}             # pkt_type -> handler info
        self.layouts: dict[int, PacketLayout] = {}      # pkt_type -> layout (manually or auto-configured)

        if cipher_tables_path:
            self.load_cipher_tables(cipher_tables_path)
        if handlers_path:
            self.load_handlers(handlers_path)

    def load_cipher_tables(self, path: str | Path):
        data = json.loads(Path(path).read_text())
        for key, info in data.get("tables", {}).items():
            addr = info["address_int"]
            self.cipher_tables[addr] = info["table"]
        print(f"Loaded {len(self.cipher_tables)} cipher tables")

    def load_handlers(self, path: str | Path):
        data = json.loads(Path(path).read_text())
        for key, info in data.get("handlers", {}).items():
            pkt_type = int(key, 16)
            self.handlers[pkt_type] = info
        print(f"Loaded {len(self.handlers)} handler definitions")

    def register_layout(self, layout: PacketLayout):
        """Register a known packet layout."""
        self.layouts[layout.packet_type] = layout

    def decode(self, packet_type: int, data: bytes) -> DecodedPacket | None:
        """Decode a packet using its registered layout."""
        layout = self.layouts.get(packet_type)
        if layout is None:
            return None
        if len(data) < layout.schema_size:
            return None

        # Read schema
        if layout.schema_size == 1:
            schema = data[0]
        elif layout.schema_size == 2:
            schema = struct.unpack_from('<H', data, 0)[0]
        elif layout.schema_size == 4:
            schema = struct.unpack_from('<I', data, 0)[0]
        elif layout.schema_size == 6:
            schema = int.from_bytes(data[:6], 'little')
        else:
            return None

        pos = layout.schema_size
        result = DecodedPacket(
            packet_type=packet_type,
            schema=schema,
            schema_size=layout.schema_size,
            total_bytes=len(data),
        )

        for fdef in layout.fields:
            tc = (schema >> fdef.bit_pos) & ((1 << fdef.bit_width) - 1)

            # 1-bit fields don't consume data
            if fdef.reader == "1bit":
                result.fields[f"f{fdef.index}"] = tc
                # Check for container
                if fdef.index == layout.container_field and tc == 1:
                    result.has_container = True
                    result.container_data = data[pos:]
                    pos = len(data)
                continue

            # Check if this type code triggers a read
            if tc not in fdef.read_types:
                result.fields[f"f{fdef.index}"] = None  # default value, not present
                continue

            if fdef.cipher_table is None:
                result.fields[f"f{fdef.index}"] = None
                continue

            reader_fn = READERS.get(fdef.reader)
            if reader_fn is None:
                continue

            val, pos = reader_fn(data, pos, fdef.cipher_table)
            result.fields[f"f{fdef.index}"] = val

            # Also store float interpretation for 4-byte fields
            if fdef.reader in ("4byte_be", "4byte_bswap") and val is not None:
                try:
                    fval = struct.unpack('f', struct.pack('I', val & 0xFFFFFFFF))[0]
                    result.fields[f"f{fdef.index}_float"] = fval
                except:
                    pass

        result.bytes_consumed = pos
        return result

    # ── Auto-detection ────────────────────────────────────────────────

    def auto_detect_schema_size(self, packets: list[bytes],
                                candidates: tuple[int, ...] = (1, 2, 4, 6)) -> int | None:
        """Try different schema sizes and see which gives consistent field patterns.
        The correct schema size will have the remaining bytes consistently divisible
        by common field sizes (1, 4 for 4-byte, variable for varint)."""
        if not packets:
            return None

        best_size = None
        best_score = -1

        for sz in candidates:
            valid = 0
            for pkt in packets:
                if len(pkt) < sz:
                    continue
                remainder = len(pkt) - sz
                # A valid schema size should leave a remainder that makes sense
                # (not negative, and for most packets the remainder should be > 0)
                if remainder >= 0:
                    valid += 1
            # Check if schema bytes have consistent bit patterns
            if valid > len(packets) * 0.9:
                # Count unique schema values
                schemas = set()
                for pkt in packets[:1000]:
                    if len(pkt) >= sz:
                        if sz == 1:
                            schemas.add(pkt[0])
                        elif sz == 2:
                            schemas.add(struct.unpack_from('<H', pkt, 0)[0])
                        elif sz == 4:
                            schemas.add(struct.unpack_from('<I', pkt, 0)[0])
                        elif sz == 6:
                            schemas.add(int.from_bytes(pkt[:6], 'little'))

                # Good schema sizes have moderate variety (not 1, not equal to packet count)
                variety = len(schemas)
                if 2 <= variety <= len(packets[:1000]) * 0.8:
                    score = valid * 1000 + variety
                    if score > best_score:
                        best_score = score
                        best_size = sz

        return best_size

    def brute_force_field_layout(self, packet_type: int, packets: list[bytes],
                                 schema_size: int,
                                 cipher_addrs: list[int],
                                 reader_kinds: list[str]) -> PacketLayout | None:
        """Try all combinations of cipher assignments and read_type sets
        to find the layout that produces zero leftover bytes.

        This is computationally expensive — only use for packet types
        where the layout is completely unknown.

        Parameters
        ----------
        packet_type : int
        packets : list of raw packet data
        schema_size : int (1, 2, 4, or 6)
        cipher_addrs : ordered list of cipher function addresses from BL tracing
        reader_kinds : ordered list of reader types matching cipher_addrs
        """
        # For now, this is a placeholder. The actual brute-force requires
        # knowledge of how many schema bits each field uses (3 bits for
        # most fields, 1 bit for flags). This will be filled in once
        # we have the handler disassembly data.
        print(f"[TODO] brute_force_field_layout for 0x{packet_type:04X}")
        return None


# ── Register known layouts ───────────────────────────────────────────

def register_known_layouts(decoder: UniversalDecoder):
    """Register layouts for packet types we've already reverse-engineered."""

    # ── 0x025B Movement ──
    from ml.parsers.movement_decoder import _LUT_A
    from ml.parsers.movement_decoder import (
        _make_cipher_FAD5C0, _make_cipher_FB82B0, _make_cipher_FADD60,
        _make_cipher_FAE670, _make_cipher_FAB5B0, _make_cipher_FB8FC0,
        _make_cipher_FAB410, _make_cipher_FAF080, _make_cipher_FAB3C0,
        _make_cipher_FB9A80, _make_cipher_FB6120, _make_cipher_FB3CC0,
    )

    def _table(cipher_fn):
        return [cipher_fn(i) for i in range(256)]

    layout_025B = PacketLayout(
        packet_type=0x025B,
        schema_size=6,
        container_field=17,
        fields=[
            FieldDef(1,  0x17, 3, "varint",      _table(_make_cipher_FAD5C0()),   {0, 1, 4, 5}),
            FieldDef(2,  0x1D, 1, "1bit",        None,                             set()),
            FieldDef(3,  0x04, 3, "1byte",       _table(_make_cipher_FAB3C0(_LUT_A)), {0, 1, 4, 6}),
            FieldDef(4,  0x1A, 3, "varint",      _table(_make_cipher_FB82B0()),   {1, 2, 3, 4, 5, 7}),
            FieldDef(5,  0x0D, 3, "varint",      _table(_make_cipher_FADD60(_LUT_A)), {0, 3, 5, 7}),
            FieldDef(6,  0x01, 3, "varint",      _table(_make_cipher_FAE670(_LUT_A)), {2, 4, 5, 6}),
            FieldDef(7,  0x10, 3, "1byte",       _table(_make_cipher_FAB5B0()),   {1, 5, 6, 7}),
            FieldDef(8,  0x0A, 3, "varint",      _table(_make_cipher_FB8FC0()),   {1, 2, 4, 5, 6, 7}),
            FieldDef(9,  0x1F, 3, "1byte",       _table(_make_cipher_FAB410()),   {0, 1, 2, 5}),
            FieldDef(10, 0x22, 3, "varint",      _table(_make_cipher_FAF080()),   {1, 2, 3, 7}),
            FieldDef(11, 0x1E, 1, "1bit",        None,                             set()),
            FieldDef(12, 0x25, 3, "4byte_be",    _table(_make_cipher_FB6120(_LUT_A)), {1, 4, 5, 6}),
            FieldDef(13, 0x00, 1, "1bit",        None,                             set()),
            FieldDef(14, 0x07, 3, "1byte",       _table(_make_cipher_FB9A80(_LUT_A)), {1, 2, 4, 5}),
            FieldDef(15, 0x28, 1, "1bit",        None,                             set()),
            FieldDef(16, 0x13, 3, "4byte_bswap", _table(_make_cipher_FB3CC0(_LUT_A)), {0, 2, 3, 6}),
            FieldDef(17, 0x16, 1, "1bit",        None,                             set()),
        ],
    )
    decoder.register_layout(layout_025B)

    # ── 0x0228 Entity State ──
    from ml.emulator.decode_0228 import (
        _cipher_f0, _cipher_varint_A, _cipher_4byte_A, _cipher_varint_B,
        _make_cipher_1byte_B, _cipher_varint_D, _make_cipher_1byte_A,
        _make_cipher_varint_C, _cipher_4byte_B, _LUT,
    )

    layout_0228 = PacketLayout(
        packet_type=0x0228,
        schema_size=4,
        container_field=10,
        fields=[
            FieldDef(0,  0,  3, "1byte",       _table(_cipher_f0),                {0, 1, 2, 3}),
            FieldDef(1,  3,  3, "varint",      _table(_cipher_varint_A),          {1, 2, 3, 5, 6, 7}),
            FieldDef(2,  18, 1, "1bit",        None,                               set()),
            FieldDef(3,  9,  3, "4byte_bswap", _table(_cipher_4byte_A),           {0, 1, 3, 6}),
            FieldDef(4,  6,  3, "varint",      _table(_cipher_varint_B),          {0, 2, 3, 4, 5, 6}),
            FieldDef(5,  12, 3, "1byte",       _table(_make_cipher_1byte_B(_LUT)), {0, 1, 5, 6}),
            FieldDef(6,  25, 3, "varint",      _table(_cipher_varint_D),          {0, 1, 6, 7}),
            FieldDef(7,  22, 3, "1byte",       _table(_make_cipher_1byte_A(_LUT)), {0, 1, 3, 5}),
            FieldDef(8,  15, 3, "varint",      _table(_make_cipher_varint_C(_LUT)), {0, 2, 4, 5, 6, 7}),
            FieldDef(9,  19, 3, "4byte_bswap", _table(_cipher_4byte_B),           {0, 2, 4, 6}),
            FieldDef(10, 28, 1, "1bit",        None,                               set()),
        ],
    )
    decoder.register_layout(layout_0228)


# ── Analysis tools ────────────────────────────────────────────────────

def analyze_packet_type(decoder: UniversalDecoder, packet_type: int,
                        packets: list[tuple[float, int, bytes]],
                        limit: int = 5000) -> dict:
    """Analyze decode quality for a packet type.

    packets: list of (timestamp, param, raw_data) tuples
    Returns stats dict.
    """
    total = 0
    decoded = 0
    leftover_dist = Counter()
    field_presence = Counter()

    for ts, param, data in packets[:limit]:
        result = decoder.decode(packet_type, data)
        if result is None:
            continue
        total += 1
        if result.fully_parsed:
            decoded += 1
        leftover_dist[result.leftover] += 1
        for fname, fval in result.fields.items():
            if fval is not None and not fname.endswith("_float"):
                field_presence[fname] += 1

    zero_pct = leftover_dist[0] / total * 100 if total else 0
    return {
        "total": total,
        "decoded_clean": decoded,
        "zero_leftover_pct": round(zero_pct, 1),
        "leftover_dist": dict(leftover_dist.most_common(10)),
        "field_presence": dict(field_presence.most_common()),
    }


def scan_for_positions(decoder: UniversalDecoder, packet_type: int,
                       packets: list[tuple[float, int, bytes]],
                       time_range: tuple[float, float] = (0, 5)) -> list[dict]:
    """Scan decoded fields for values that look like map coordinates (0-16383).

    Specifically looks at early-game packets (fountain spawn) where
    champions should be near (400,400) or (14300,14300).
    """
    hits = []
    for ts, param, data in packets:
        if not (time_range[0] <= ts <= time_range[1]):
            continue
        result = decoder.decode(packet_type, data)
        if result is None or not result.fully_parsed:
            continue

        for fname, val in result.fields.items():
            if val is None or fname.endswith("_float"):
                continue
            if isinstance(val, int) and 0 <= val <= 0x0FFFFFFF:
                # Try as packed 14-bit coords
                x = val & 0x3FFF
                z = (val >> 14) & 0x3FFF
                # Check if near fountain
                if ((300 < x < 600 and 300 < z < 600) or
                        (14000 < x < 14600 and 14000 < z < 14600)):
                    hits.append({
                        "time": ts,
                        "param": f"0x{param:08X}",
                        "field": fname,
                        "raw": val,
                        "x": x,
                        "z": z,
                    })
    return hits


# ── Main ──────────────────────────────────────────────────────────────

def main():
    """Demo: decode packets from a replay using known layouts."""
    from ml.parsers.rofl_parser import ROFLParser
    from ml.parsers.chunk_parser import parse_payload_frames

    replay_path = sys.argv[1] if len(sys.argv) > 1 else \
        "/Users/danielngai/Documents/League of Legends/Replays/TW2-396324158.rofl"

    cipher_tables_path = "ml/data/cipher_tables.json"
    handlers_path = "ml/data/handlers.json"

    # Initialize decoder
    decoder = UniversalDecoder()

    # Load extracted cipher tables if available
    if Path(cipher_tables_path).exists():
        decoder.load_cipher_tables(cipher_tables_path)
    if Path(handlers_path).exists():
        decoder.load_handlers(handlers_path)

    # Register known layouts (these use hardcoded cipher tables)
    register_known_layouts(decoder)

    # Parse replay
    print(f"\nParsing replay: {replay_path}")
    rofl = ROFLParser(replay_path)
    frames = rofl.decompress_payload_frames()
    payload = parse_payload_frames(frames, parse_packets=True)

    # Collect packets by type
    packets_by_type: dict[int, list[tuple[float, int, bytes]]] = {}
    for fr in payload.frames:
        for pkt in fr.packets:
            if pkt.size == 0:
                continue
            if pkt.packet_id not in packets_by_type:
                packets_by_type[pkt.packet_id] = []
            packets_by_type[pkt.packet_id].append((pkt.timestamp, pkt.param, pkt.data))

    print(f"\nPacket type distribution:")
    for pkt_type in sorted(packets_by_type, key=lambda t: -len(packets_by_type[t])):
        count = len(packets_by_type[pkt_type])
        has_layout = "DECODER" if pkt_type in decoder.layouts else ""
        has_handler = "HANDLER" if pkt_type in decoder.handlers else ""
        print(f"  0x{pkt_type:04X}: {count:>8,} packets  {has_layout}  {has_handler}")

    # Analyze known packet types
    for pkt_type in sorted(decoder.layouts):
        if pkt_type not in packets_by_type:
            continue
        print(f"\n=== 0x{pkt_type:04X} Analysis ===")
        stats = analyze_packet_type(decoder, pkt_type, packets_by_type[pkt_type])
        print(f"  Total: {stats['total']}")
        print(f"  Zero leftover: {stats['zero_leftover_pct']}%")
        print(f"  Leftover dist: {stats['leftover_dist']}")
        print(f"  Fields present: {stats['field_presence']}")

    # Scan for champion positions at game start
    for pkt_type in sorted(decoder.layouts):
        if pkt_type not in packets_by_type:
            continue
        hits = scan_for_positions(decoder, pkt_type, packets_by_type[pkt_type])
        if hits:
            print(f"\n=== Fountain Spawn Candidates (0x{pkt_type:04X}) ===")
            for h in hits[:20]:
                print(f"  t={h['time']:.1f}s {h['param']} {h['field']}: "
                      f"({h['x']}, {h['z']}) raw={h['raw']}")

    # Report on all packet types
    print("\n=== ALL PACKET TYPES ===")
    CHAMP_PARAMS = set(range(0x400000AE, 0x400000B8))
    for pkt_type in sorted(packets_by_type, key=lambda t: -len(packets_by_type[t]))[:25]:
        pkts = packets_by_type[pkt_type]
        sizes = Counter(len(d) for _, _, d in pkts[:1000])
        champ_count = sum(1 for _, p, _ in pkts if p in CHAMP_PARAMS)
        has_layout = "DECODED" if pkt_type in decoder.layouts else ""
        has_handler = "HANDLER" if pkt_type in decoder.handlers else ""
        print(f"  0x{pkt_type:04X}: {len(pkts):>8} pkts  champ={champ_count:>6}  "
              f"sizes={dict(sizes.most_common(3))}  {has_layout}  {has_handler}")


if __name__ == "__main__":
    main()

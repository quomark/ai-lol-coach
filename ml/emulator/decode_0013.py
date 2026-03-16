"""
Decode 0x0013 packets from League of Legends ROFL v2 replays.

Packet 0x0013 appears to be a periodic CHAMPION STATE UPDATE (not position).
Empirical analysis shows:
  - ~400-700 packets per champion per game (~1 every 2-5 seconds)
  - 1-byte schema at byte[0] controls field presence
  - Three packet sizes: 13, 15, 16 bytes
  - Data does NOT correlate with position (varies even at same X,Z)
  - Likely contains: HP, mana, gold, XP, level, or similar stats

Schema byte patterns:
  0x80 (10000000): size 13 — minimal update
  0x86 (10000110): size 13 — alternate minimal format
  0x94 (10010100): size 15-16 — includes stat fields
  0xA4 (10100100): size 15-16
  0xB4 (10110100): size 15-16
  0xC4 (11000100): size 15-16
  0xD4 (11010100): size 15-16
  0xE4 (11100100): size 15-16

Bit fields in schema byte:
  bit[7]:   always 1 (marker)
  bits[6:4]: 3-bit type code (varies 0-6, controls cipher selection)
  bit[3]:   always 0
  bit[2]:   1 = extended packet (adds ~2 bytes of stat data)
  bit[1]:   secondary flag
  bit[0]:   always 0

Known byte patterns (encrypted):
  - Byte at offset 6/7 (size 15/16): frequently 0x8B or 0xAF (~50/50 split)
  - Byte at offset 10/11 (size 15/16): same 0x8B/0xAF pattern
  - Last byte: almost always 0x2F (cipher of zero or constant)

Cipher: NOT the same as 0x025B or 0x0228. Uses per-field substitution cipher
with unknown constants. The cipher functions are in the macOS binary at
addresses 0x106838000-0x10685E000 (near the LUT table embeddings).

NOTE: For champion POSITION data, use 0x025B packets via MovementDecoder.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional


@dataclass
class Packet0013Data:
    """Partially decoded 0x0013 packet."""
    schema: int = 0
    schema_type_code: int = 0   # bits[6:4] — cipher selector
    schema_extended: bool = False  # bit[2] — extended data present
    schema_flag: bool = False    # bit[1] — secondary flag

    # Raw encrypted data (cipher unknown)
    raw_data: bytes = b""

    # Size info
    total_bytes: int = 0
    data_bytes: int = 0

    @property
    def is_minimal(self) -> bool:
        """Size-13 packet (0x80 or 0x86 schema)."""
        return not self.schema_extended


class Decoder0013:
    """Partial decoder for 0x0013 state update packets.

    Currently only parses the schema byte. Full field decoding requires
    the per-field cipher constants which have not yet been extracted from
    the game binary.
    """

    def decode(self, data: bytes) -> Optional[Packet0013Data]:
        if len(data) < 13:
            return None

        schema = data[0]
        result = Packet0013Data(
            schema=schema,
            schema_type_code=(schema >> 4) & 0x7,
            schema_extended=bool(schema & 0x04),
            schema_flag=bool(schema & 0x02),
            raw_data=data[1:],
            total_bytes=len(data),
            data_bytes=len(data) - 1,
        )
        return result


def main():
    """Analyze 0x0013 packets from a replay."""
    from collections import Counter
    from ml.parsers.rofl_parser import ROFLParser
    from ml.parsers.chunk_parser import parse_payload_frames

    import sys
    replay_path = sys.argv[1] if len(sys.argv) > 1 else \
        "/Users/danielngai/Documents/League of Legends/Replays/TW2-396324158.rofl"

    rofl = ROFLParser(replay_path)
    frames = rofl.decompress_payload_frames()
    payload = parse_payload_frames(frames, parse_packets=True)

    CHAMP_PARAMS = {0x400000AE, 0x400000AF, 0x400000B0, 0x400000B1, 0x400000B2,
                    0x400000B3, 0x400000B4, 0x400000B5, 0x400000B6, 0x400000B7}

    decoder = Decoder0013()
    schema_dist = Counter()
    size_dist = Counter()
    param_dist = Counter()

    for fr in payload.frames:
        for pkt in fr.packets:
            if pkt.packet_id != 0x0013 or pkt.size == 0:
                continue
            r = decoder.decode(pkt.data)
            if r:
                schema_dist[r.schema] += 1
                size_dist[r.total_bytes] += 1
                if pkt.param in CHAMP_PARAMS:
                    param_dist[pkt.param] += 1

    print(f"0x0013 Packet Analysis")
    print(f"  Total: {sum(schema_dist.values())}")
    print(f"  Champion packets: {sum(param_dist.values())}")
    print(f"\nSchema distribution:")
    for s, c in schema_dist.most_common():
        tc = (s >> 4) & 7
        ext = bool(s & 4)
        print(f"  0x{s:02X} (tc={tc}, ext={ext}): {c}")
    print(f"\nSize distribution: {dict(size_dist.most_common())}")
    print(f"\nPer-champion count:")
    for p, c in sorted(param_dist.items()):
        print(f"  0x{p:08X}: {c}")


if __name__ == "__main__":
    main()

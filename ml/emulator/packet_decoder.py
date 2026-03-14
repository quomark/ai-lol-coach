"""
Static Packet Decoder — extracts decryption parameters from the game binary
and decrypts packets in pure Python. No game context needed.

The game encrypts each packet type with a unique byte-level cipher:
  1. Arithmetic transforms (xor, ror, add, sub)
  2. Bit-pair swap: swaps adjacent bit pairs
  3. Optional 256-byte substitution table lookup

This module auto-extracts the cipher parameters from the unpacked binary
by disassembling each handler's decryption loop.
"""

from __future__ import annotations

import struct
from pathlib import Path
from dataclasses import dataclass


# ── Lookup table (extracted from binary at RVA 0x19328E0) ──

SUBST_TABLE: bytes = b""  # filled by extract_from_binary()


# ── Bit operations ──

def ror8(val: int, n: int) -> int:
    """Rotate right 8-bit."""
    n &= 7
    return ((val >> n) | (val << (8 - n))) & 0xFF

def rol8(val: int, n: int) -> int:
    """Rotate left 8-bit."""
    n &= 7
    return ((val << n) | (val >> (8 - n))) & 0xFF

def bitswap(val: int) -> int:
    """Swap adjacent bit pairs: bits (7,6,4,2,0) << 1 | bits (7,5,3,1) >> 1."""
    c = val & 0xD5
    a = (val >> 1) & 0x55
    return ((c << 1) | a) & 0xFF


@dataclass
class DecryptionStep:
    """One step in the per-byte decryption chain."""
    op: str       # 'xor', 'add', 'sub', 'ror', 'rol', 'not', 'bitswap', 'table'
    arg: int = 0  # operand (for xor/add/sub/ror/rol)


@dataclass
class HandlerInfo:
    """Decryption info for one packet type."""
    pkt_type: int
    data_offset: int       # offset in packet struct where encrypted data starts
    data_size: int         # number of bytes to decrypt
    steps: list[DecryptionStep]  # decryption operations per byte
    handler_rva: int = 0


def decrypt_byte(val: int, steps: list[DecryptionStep], table: bytes) -> int:
    """Apply the decryption chain to a single byte."""
    b = val & 0xFF
    for step in steps:
        if step.op == 'xor':
            b ^= step.arg
        elif step.op == 'add':
            b = (b + step.arg) & 0xFF
        elif step.op == 'sub':
            b = (b - step.arg) & 0xFF
        elif step.op == 'ror':
            b = ror8(b, step.arg)
        elif step.op == 'rol':
            b = rol8(b, step.arg)
        elif step.op == 'not':
            b = (~b) & 0xFF
        elif step.op == 'bitswap':
            b = bitswap(b)
        elif step.op == 'table':
            b = table[b] if b < len(table) else b
    return b


def decrypt_field(data: bytes, handler: HandlerInfo, table: bytes) -> bytes:
    """Decrypt a field from the packet using the handler's cipher chain."""
    result = bytearray(len(data))
    for i, byte in enumerate(data):
        result[i] = decrypt_byte(byte, handler.steps, table)
    return bytes(result)


# ── Known handler decryption chains (extracted from disassembly) ──

# Type 0x0D: data at +0x44, 4 bytes
# sub al, 0x66 → bitswap → xor 0x79 → sub 0x1c → xor 0xb7
HANDLER_0x0D = HandlerInfo(
    pkt_type=0x0D,
    data_offset=0x44,
    data_size=4,
    handler_rva=0x66F313,
    steps=[
        DecryptionStep('sub', 0x66),
        DecryptionStep('bitswap'),
        DecryptionStep('xor', 0x79),
        DecryptionStep('sub', 0x1C),
        DecryptionStep('xor', 0xB7),
    ],
)

# Type 0x50: data at +0x14, 4 bytes
# xor 0x50 → bitswap → sub 0x66 → ror 6 → bitswap → not → xor 9 → table
HANDLER_0x50 = HandlerInfo(
    pkt_type=0x50,
    data_offset=0x14,
    data_size=4,
    handler_rva=0x66EF0D,
    steps=[
        DecryptionStep('xor', 0x50),
        DecryptionStep('bitswap'),
        DecryptionStep('sub', 0x66),
        DecryptionStep('ror', 6),
        DecryptionStep('bitswap'),
        DecryptionStep('not'),
        DecryptionStep('xor', 9),
        DecryptionStep('table'),
    ],
)

# Type 0x43: data at +0x10, 4 bytes
# bitswap → ror 4 → not
HANDLER_0x43 = HandlerInfo(
    pkt_type=0x43,
    data_offset=0x10,
    data_size=4,
    handler_rva=0x66E7B4,
    steps=[
        DecryptionStep('bitswap'),
        DecryptionStep('ror', 4),
        DecryptionStep('not'),
    ],
)

# Type 0x2E: data at +0x10, 4 bytes
# bitswap → add 0x37 → ror 5 → xor 0x1f → bitswap → shl2/shr6 → table
HANDLER_0x2E = HandlerInfo(
    pkt_type=0x2E,
    data_offset=0x10,
    data_size=4,
    handler_rva=0x66EC59,
    steps=[
        DecryptionStep('bitswap'),
        DecryptionStep('add', 0x37),
        DecryptionStep('ror', 5),
        DecryptionStep('xor', 0x1F),
        DecryptionStep('bitswap'),
        DecryptionStep('rol', 2),  # shl 2 + shr 6 = rol 2
        DecryptionStep('table'),
    ],
)

# Type 0xD6: data varies, 4 bytes
# xor 0x46 → add 0x5a → ror 6 → not → bitswap
HANDLER_0xD6 = HandlerInfo(
    pkt_type=0xD6,
    data_offset=0x28,  # from [rsi + 0x28]
    data_size=4,
    handler_rva=0x677EEE,
    steps=[
        DecryptionStep('xor', 0x46),
        DecryptionStep('add', 0x5A),
        DecryptionStep('ror', 6),
        DecryptionStep('not'),
        DecryptionStep('bitswap'),
    ],
)

# Type 0x18: data at +0x10, 4 bytes
# add 0x80 → ror 3 → rol 6 → table → add 0x36 → ror 3 → bitswap
HANDLER_0x18 = HandlerInfo(
    pkt_type=0x18,
    data_offset=0x10,
    data_size=4,
    handler_rva=0x670C57,
    steps=[
        DecryptionStep('add', 0x80),
        DecryptionStep('ror', 3),
        DecryptionStep('rol', 6),  # shl 6 + shr 2 = rol 6
        DecryptionStep('table'),
        DecryptionStep('add', 0x36),
        DecryptionStep('ror', 3),
        DecryptionStep('bitswap'),
    ],
)

# Collected handlers
KNOWN_HANDLERS: dict[int, HandlerInfo] = {
    h.pkt_type: h for h in [
        HANDLER_0x0D, HANDLER_0x50, HANDLER_0x43,
        HANDLER_0x2E, HANDLER_0xD6, HANDLER_0x18,
    ]
}


def extract_subst_table(dump_path: str | Path = "ml/data/league_unpacked_init.bin") -> bytes:
    """Extract the 256-byte substitution table from the binary dump."""
    dump = Path(dump_path).read_bytes()
    table_rva = 0x19328E0
    return dump[table_rva:table_rva + 256]


def decode_packet_fields(pkt_type: int, raw_data: bytes,
                          table: bytes) -> dict | None:
    """
    Decrypt the first field(s) of a packet given its type.
    Returns dict with decrypted fields, or None if type is unknown.
    """
    handler = KNOWN_HANDLERS.get(pkt_type)
    if handler is None:
        return None

    # The raw_data starts from byte 1 (byte 0 is the type).
    # The handler reads from packet_struct + data_offset.
    # Our struct: +0x00 = 8 zeros, +0x08 = type, +0x10 = payload (raw_data[1:])
    # So data at struct+0x10 = raw_data[1], struct+0x14 = raw_data[5], etc.
    # Offset from struct start to payload = 0x10
    # So handler's data_offset - 0x10 = offset into payload

    payload = raw_data[1:]  # skip type byte
    payload_offset = handler.data_offset - 0x10

    if payload_offset < 0 or payload_offset + handler.data_size > len(payload):
        return None

    encrypted = payload[payload_offset:payload_offset + handler.data_size]
    decrypted = decrypt_field(encrypted, handler, table)

    return {
        "type": pkt_type,
        "type_hex": f"0x{pkt_type:02X}",
        "encrypted": encrypted.hex(),
        "decrypted": decrypted.hex(),
        "decrypted_bytes": list(decrypted),
    }


# ── CLI test ──

def main():
    import json
    from ml.parsers.rofl_parser import ROFLParser
    from ml.parsers.chunk_parser import parse_payload_frames

    table = extract_subst_table()
    print(f"Loaded substitution table ({len(table)} bytes)")

    import sys
    rofl_path = sys.argv[1] if len(sys.argv) > 1 else None
    if not rofl_path:
        print("Usage: python -m ml.emulator.packet_decoder <replay.rofl>")
        return

    parser = ROFLParser(rofl_path)
    frames = parser.decompress_payload_frames()
    payload = parse_payload_frames(frames, parse_packets=True)

    # Only process chunk frames (type 1), skip keyframes (type 2)
    chunk_frames = [f for f in payload.frames if f.header.frame_type == 1]
    print(f"Frames: {len(chunk_frames)} chunks, "
          f"{len(payload.frames) - len(chunk_frames)} keyframes")

    # Gather packets from chunks, filter obvious junk (size > 1000 is suspect)
    all_pkts = []
    for frame in chunk_frames:
        for pkt in frame.packets:
            if pkt.data and len(pkt.data) >= 2:
                all_pkts.append((frame, pkt))

    # Analyze: look at byte[0] as type, but also check byte[1] and channel
    print(f"\nTotal chunk packets: {len(all_pkts)}")

    # Group by (byte0, size_bucket) to understand the real structure
    from collections import Counter

    # Show raw hex patterns for most common byte[0] values
    byte0_groups: dict[int, list] = {}
    for frame, pkt in all_pkts:
        b0 = pkt.data[0]
        byte0_groups.setdefault(b0, []).append(pkt)

    print(f"\n── Packet structure analysis (top 15 by byte[0]) ──")
    for b0, pkts_list in sorted(byte0_groups.items(), key=lambda x: -len(x[1]))[:15]:
        small = [p for p in pkts_list if len(p.data) <= 300]
        big = [p for p in pkts_list if len(p.data) > 300]
        print(f"\n  byte[0]=0x{b0:02X} ({len(pkts_list)} pkts, {len(small)} small, {len(big)} big)")

        # Show first 3 small packets hex
        for p in small[:3]:
            hex_str = p.data[:20].hex()
            print(f"    sz={len(p.data):>5d} ch={p.channel:>3d} | {hex_str}")
        if big:
            p = big[0]
            hex_str = p.data[:20].hex()
            print(f"    sz={len(p.data):>5d} ch={p.channel:>3d} | {hex_str} (BIG)")

    # Now look at whether byte[0] really is the type
    # Check: do small (< 300B) packets have consistent structure?
    print(f"\n── Small packet (<300B) byte[0:8] patterns ──")
    small_pkts = [(f, p) for f, p in all_pkts if len(p.data) <= 300]
    print(f"  {len(small_pkts)} small packets total")

    # For small packets, check if byte[0] matches channel or has other pattern
    b0_eq_ch = sum(1 for _, p in small_pkts if p.data[0] == p.channel)
    print(f"  byte[0] == channel: {b0_eq_ch}/{len(small_pkts)}")

    # Check byte[1] patterns
    b1_counter = Counter(p.data[1] for _, p in small_pkts if len(p.data) > 1)
    print(f"  byte[1] top values: {b1_counter.most_common(10)}")

    # Check if byte[0] could be part of a u16 type with byte[1]
    b01_counter = Counter(
        struct.unpack_from("<H", p.data, 0)[0]
        for _, p in small_pkts if len(p.data) >= 2
    )
    print(f"  u16_LE[0:2] top: {b01_counter.most_common(10)}")


if __name__ == "__main__":
    main()

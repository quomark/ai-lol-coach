"""
Decode 0x025B movement packets from League of Legends ROFL v2 replays.

Reverse-engineered from the game binary (patch ~16.x, 2026).
Each movement packet contains:
  - 6-byte schema (type codes controlling which fields are present)
  - Variable-length field data (varints, 1-byte, 4-byte readers)
  - Each reader applies a per-byte cipher (Pass 1) to decrypt stream data

Field layout (17 fields, processed in order):
  f1:  varint  FAD5C0  (rarely present)
  f2:  1-bit default   (never reads)
  f3:  1-byte FAB3C0   (rarely present)
  f4:  varint  FB82B0  entity ID (always present)
  f5:  varint  FADD60  (rarely present)
  f6:  varint  FAE670  movement flags/state
  f7:  1-byte FAB5B0   waypoint count indicator
  f8:  varint  FB8FC0  (rarely present)
  f9:  1-byte FAB410   movement sub-type
  f10: varint  FAF080  packed position (14-bit X + 14-bit Z)
  f11: 1-bit default   (never reads)
  f12: 4-byte FB6120   additional data (rarely present)
  f13: 1-bit special   (type 1 reads, type 0 clears)
  f14: 1-byte FB9A80   sequence counter
  f15: 1-bit default   (never reads)
  f16: 4-byte FB3CC0   movement speed (float32, bswap)
  f17: 1-bit container (type 1 = waypoint elements, type 0 = clear)

Coordinates:
  f10 varint is packed as two 14-bit values:
    X = f10 & 0x3FFF        (range 0-16383, LoL map ~0-15000)
    Z = (f10 >> 14) & 0x3FFF

Usage:
    from ml.parsers.movement_decoder import MovementDecoder

    decoder = MovementDecoder()
    result = decoder.decode(packet_data)
    # result.x, result.z, result.entity_id, result.speed, etc.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class MovementData:
    """Decoded movement packet data."""
    entity_id: int = 0
    x: int = 0
    z: int = 0
    speed: Optional[float] = None
    waypoint_count: Optional[int] = None  # f7
    sequence: Optional[int] = None        # f14
    movement_state: Optional[int] = None  # f6 raw varint
    movement_type: Optional[int] = None   # f9

    # Raw field values for debugging
    f1: Optional[int] = None
    f3: Optional[int] = None
    f5: Optional[int] = None
    f6: Optional[int] = None
    f8: Optional[int] = None
    f10: Optional[int] = None
    f12: Optional[int] = None
    f16: Optional[int] = None

    has_container: bool = False
    container_data: bytes = b""

    bytes_consumed: int = 0
    total_bytes: int = 0

    @property
    def fully_parsed(self) -> bool:
        return self.bytes_consumed == self.total_bytes or self.has_container


# ---- Cipher primitives ----

def _ror8(v: int, n: int) -> int:
    return ((v >> n) | (v << (8 - n))) & 0xFF


def _bitswap(b: int) -> int:
    hi = (b & 0xD5) << 1
    lo = (b >> 1) & 0x55
    return (hi | lo) & 0xFF


# ---- Per-field cipher functions (Pass 1 decryption) ----

def _make_cipher_FAD5C0():
    """f1 varint cipher: ror 2, xor 0x15, bitswap, ror 7, not"""
    def cipher(b):
        b = _ror8(b, 2); b ^= 0x15; b = _bitswap(b)
        b = _ror8(b, 7); return (~b) & 0xFF
    return cipher


def _make_cipher_FB82B0():
    """f4 varint cipher: ror 2, add 3, xor 0xF5, bitswap, ror 4, bitswap, not"""
    def cipher(b):
        b = _ror8(b, 2); b = (b + 3) & 0xFF; b ^= 0xF5; b = _bitswap(b)
        b = _ror8(b, 4); b = _bitswap(b); return (~b) & 0xFF
    return cipher


def _make_cipher_FADD60(lut_a):
    """f5 varint cipher: sub 0x70, ror 5, bitswap, not, LUT_A x2, ror 2"""
    def cipher(b):
        b = (b - 0x70) & 0xFF; b = _ror8(b, 5); b = _bitswap(b)
        b = (~b) & 0xFF; b = lut_a[b]; b = lut_a[b]; b = _ror8(b, 2)
        return b
    return cipher


def _make_cipher_FAE670(lut_a):
    """f6 varint cipher: LUT_A, ror 1, sub 0x71, ror 6, xor 0x91, bitswap"""
    def cipher(b):
        b = lut_a[b]; b = _ror8(b, 1); b = (b - 0x71) & 0xFF
        b = _ror8(b, 6); b ^= 0x91; b = _bitswap(b)
        return b
    return cipher


def _make_cipher_FB8FC0():
    """f8 varint cipher: add 0x2F, bitswap, not, sub 0x57, ror 7, bitswap"""
    def cipher(b):
        b = (b + 0x2F) & 0xFF; b = _bitswap(b); b = (~b) & 0xFF
        b = (b - 0x57) & 0xFF; b = _ror8(b, 7); b = _bitswap(b)
        return b
    return cipher


def _make_cipher_FAF080():
    """f10 varint cipher: sub 0x62, bitswap, add 7"""
    def cipher(b):
        b = (b - 0x62) & 0xFF; b = _bitswap(b); b = (b + 7) & 0xFF
        return b
    return cipher


def _make_cipher_FAB3C0(lut_a):
    """f3 1-byte cipher: add 0x50, combine(shl6/shr2), LUT_A, sub 0x62, xor 0x36, add 0x62"""
    def cipher(b):
        b = (b + 0x50) & 0xFF
        idx = ((b << 6) | (b >> 2)) & 0xFF
        b = lut_a[idx]
        b = (b - 0x62) & 0xFF; b ^= 0x36; b = (b + 0x62) & 0xFF
        return b
    return cipher


def _make_cipher_FAB5B0():
    """f7 1-byte cipher: ror 3, add 0x19, ror 4, xor 0xAA, sub 0x45"""
    def cipher(b):
        b = _ror8(b, 3); b = (b + 0x19) & 0xFF; b = _ror8(b, 4)
        b ^= 0xAA; b = (b - 0x45) & 0xFF
        return b
    return cipher


def _make_cipher_FAB410():
    """f9 1-byte cipher: not, ror 2, xor 0x5A, ror 6, sub 0x34, xor 0x4D"""
    def cipher(b):
        b = (~b) & 0xFF; b = _ror8(b, 2); b ^= 0x5A; b = _ror8(b, 6)
        b = (b - 0x34) & 0xFF; b ^= 0x4D
        return b
    return cipher


def _make_cipher_FB9A80(lut_a):
    """f14 1-byte cipher: LUT_A, xor 0xD8, ror 2, sub 0x36, ror 4, add 0x21"""
    def cipher(b):
        b = lut_a[b]; b ^= 0xD8; b = _ror8(b, 2); b = (b - 0x36) & 0xFF
        b = _ror8(b, 4); b = (b + 0x21) & 0xFF
        return b
    return cipher


def _make_cipher_FB6120(lut_a):
    """f12 4-byte cipher: ror 5, add 0x6B, not, add 0x3A, combine(shl3/shr5), LUT_A, ror 3, bitswap"""
    def cipher(b):
        b = _ror8(b, 5); b = (b + 0x6B) & 0xFF; b = (~b) & 0xFF
        b = (b + 0x3A) & 0xFF
        combined = ((b << 3) | (b >> 5)) & 0xFF
        b = lut_a[combined]; b = _ror8(b, 3); b = _bitswap(b)
        return b
    return cipher


def _make_cipher_FB3CC0(lut_a):
    """f16 4-byte cipher: LUT_A, sub 0x62, ror 3, bitswap, add 0x5F, LUT_A, bitswap"""
    def cipher(b):
        b = lut_a[b]; b = (b - 0x62) & 0xFF; b = _ror8(b, 3)
        b = _bitswap(b); b = (b + 0x5F) & 0xFF; b = lut_a[b]; b = _bitswap(b)
        return b
    return cipher


# ---- Schema and field definitions ----

# (bit_position, bit_width) for each field in the 6-byte schema
_SCHEMA_FIELDS = {
    1:  (0x17, 3),  2:  (0x1D, 1),  3:  (0x04, 3),  4:  (0x1A, 3),
    5:  (0x0D, 3),  6:  (0x01, 3),  7:  (0x10, 3),  8:  (0x0A, 3),
    9:  (0x1F, 3),  10: (0x22, 3),  11: (0x1E, 1),  12: (0x25, 3),
    13: (0x00, 1),  14: (0x07, 3),  15: (0x28, 1),  16: (0x13, 3),
    17: (0x16, 1),
}

# Which type codes trigger a READ (consume bytes from stream)
_FIELD_READ_TYPES = {
    1:  {0, 1, 4, 5},
    3:  {0, 1, 4, 6},
    4:  {1, 2, 3, 4, 5, 7},
    5:  {0, 3, 5, 7},
    6:  {2, 4, 5, 6},
    7:  {1, 5, 6, 7},
    8:  {1, 2, 4, 5, 6, 7},
    9:  {0, 1, 2, 5},
    10: {1, 2, 3, 7},
    12: {1, 4, 5, 6},
    14: {1, 2, 4, 5},
    16: {0, 2, 3, 6},
}


# ---- Stream readers ----

def _read_varint(data: bytes, pos: int, cipher) -> tuple[int, int]:
    """Read a varint with per-byte cipher and btc (bit-toggle-complement) on bit 30."""
    result = 0
    shift = 0
    while pos < len(data):
        decoded = cipher(data[pos])
        pos += 1
        result |= (decoded & 0x7F) << shift
        shift += 7
        if not (decoded & 0x80):
            break
    # BTC: if bit 30 is set, negate
    if result & (1 << 30):
        result = -(result ^ (1 << 30))
    return result, pos


def _read_4byte_be(data: bytes, pos: int, cipher) -> tuple[Optional[int], int]:
    """Read 4 bytes with big-endian accumulation and per-byte cipher."""
    if pos + 4 > len(data):
        return None, pos
    result = 0
    for _ in range(4):
        decoded = cipher(data[pos])
        pos += 1
        result = ((result << 8) | decoded) & 0xFFFFFFFF
    return result, pos


def _read_4byte_bswap(data: bytes, pos: int, cipher) -> tuple[Optional[int], int]:
    """Read 4 bytes BE then byte-swap to LE (used by f16/FB3CC0)."""
    val, pos = _read_4byte_be(data, pos, cipher)
    if val is not None:
        val = struct.unpack("<I", struct.pack(">I", val))[0]
    return val, pos


def _read_1byte(data: bytes, pos: int, cipher) -> tuple[Optional[int], int]:
    """Read 1 byte with cipher."""
    if pos >= len(data):
        return None, pos
    return cipher(data[pos]), pos + 1


# ---- Decoder class ----

# LUT extracted from macOS runtime dump (256-byte permutation table, identical across platforms)
_LUT_A = [
    0xD7, 0x56, 0x82, 0xDC, 0x83, 0x02, 0x8F, 0x29, 0x35, 0x04, 0x21, 0x71, 0x79, 0x9E, 0x92, 0x7F,
    0xCB, 0x97, 0x6A, 0x51, 0x05, 0xC7, 0x6F, 0xE6, 0x40, 0x63, 0x7E, 0x34, 0x5B, 0x47, 0x07, 0x78,
    0x5A, 0x96, 0xB8, 0xB9, 0x2C, 0x99, 0x5E, 0x6E, 0xD1, 0x75, 0x41, 0x61, 0x24, 0x5F, 0x4A, 0xAA,
    0x4B, 0xCF, 0x0E, 0xD4, 0x86, 0x5D, 0xBA, 0x1D, 0x3F, 0x2B, 0xDF, 0x62, 0xF0, 0x33, 0x00, 0x55,
    0xCA, 0xFC, 0x19, 0xAC, 0xF3, 0x66, 0x23, 0x69, 0xBC, 0xEB, 0x46, 0xF8, 0x9C, 0x50, 0x87, 0x4D,
    0x6D, 0x10, 0x8E, 0x88, 0xBE, 0x1B, 0xB5, 0xDA, 0x4E, 0x1A, 0x13, 0xCC, 0x22, 0x09, 0xAD, 0xA4,
    0x9D, 0x30, 0xA6, 0xE5, 0x7D, 0xFA, 0xC9, 0x17, 0x12, 0xC2, 0xFD, 0xE1, 0xBB, 0xE7, 0x0B, 0x98,
    0xBF, 0xBD, 0x11, 0x37, 0xC0, 0x7C, 0xF7, 0x95, 0xB6, 0xDD, 0x49, 0xF4, 0x81, 0x2A, 0x9F, 0x1C,
    0xFB, 0x8D, 0x9A, 0x72, 0x7B, 0x57, 0x7A, 0x43, 0xB3, 0xA9, 0x53, 0xE4, 0x59, 0x20, 0x2F, 0xA8,
    0xF6, 0x74, 0x36, 0xA0, 0x85, 0xF1, 0xA7, 0x14, 0x70, 0x31, 0x84, 0x0C, 0xB2, 0xA5, 0xDB, 0xE8,
    0x16, 0xAE, 0x3D, 0x25, 0xB1, 0xCD, 0x9B, 0x03, 0x67, 0x15, 0x5C, 0xEA, 0x1F, 0x39, 0xA1, 0x44,
    0x0A, 0x8B, 0x76, 0xDE, 0x60, 0x65, 0x93, 0xF2, 0x64, 0xD5, 0xC1, 0xC8, 0x4C, 0x06, 0x4F, 0xB7,
    0xED, 0xFE, 0xE0, 0xF9, 0xA2, 0x18, 0x48, 0x91, 0xCE, 0x1E, 0x3C, 0xB4, 0x6C, 0x42, 0x54, 0x94,
    0xE3, 0x28, 0xE9, 0x01, 0x27, 0xEC, 0x0D, 0x45, 0xFF, 0x26, 0xEF, 0xE2, 0x8A, 0xAB, 0xD9, 0xF5,
    0x08, 0xC4, 0xAF, 0x32, 0xC5, 0x6B, 0x80, 0xC6, 0xC3, 0x58, 0xEE, 0xA3, 0x3E, 0x2D, 0x0F, 0x89,
    0x3A, 0xB0, 0xD2, 0xD3, 0x38, 0x73, 0xD8, 0xD0, 0x8C, 0x77, 0x90, 0x52, 0x3B, 0xD6, 0x2E, 0x68,
]


class MovementDecoder:
    """Decode 0x025B movement packets.

    The LUT is embedded directly (extracted from a macOS runtime dump).
    No binary dump file is needed.
    """

    def __init__(self):
        self._lut_a = _LUT_A

        # Build cipher function table
        self._ciphers = {
            1:  ("varint",       _make_cipher_FAD5C0()),
            3:  ("1byte",        _make_cipher_FAB3C0(self._lut_a)),
            4:  ("varint",       _make_cipher_FB82B0()),
            5:  ("varint",       _make_cipher_FADD60(self._lut_a)),
            6:  ("varint",       _make_cipher_FAE670(self._lut_a)),
            7:  ("1byte",        _make_cipher_FAB5B0()),
            8:  ("varint",       _make_cipher_FB8FC0()),
            9:  ("1byte",        _make_cipher_FAB410()),
            10: ("varint",       _make_cipher_FAF080()),
            12: ("4byte_be",     _make_cipher_FB6120(self._lut_a)),
            14: ("1byte",        _make_cipher_FB9A80(self._lut_a)),
            16: ("4byte_bswap",  _make_cipher_FB3CC0(self._lut_a)),
        }

    def decode(self, data: bytes) -> Optional[MovementData]:
        """Decode a single 0x025B movement packet.

        Parameters
        ----------
        data : bytes
            Raw packet payload (from ParsedPacket.data).

        Returns
        -------
        MovementData or None if the packet is too short.
        """
        if len(data) < 6:
            return None

        schema = int.from_bytes(data[:6], "little")
        pos = 6
        result = MovementData(total_bytes=len(data))

        for fnum in range(1, 18):
            dl, nbits = _SCHEMA_FIELDS[fnum]
            tc = (schema >> dl) & ((1 << nbits) - 1)

            # f17 container: handle before read_types check (f17 has no entry
            # in _FIELD_READ_TYPES, so the generic check would skip it)
            if fnum == 17:
                if tc == 1:
                    result.has_container = True
                    result.container_data = data[pos:]
                    pos = len(data)
                break  # f17 is always last

            # f13 special (type 1 reads, but we skip for now)
            if fnum == 13:
                continue

            read_types = _FIELD_READ_TYPES.get(fnum, set())
            if tc not in read_types:
                continue

            if fnum not in self._ciphers:
                continue

            rtype, cipher = self._ciphers[fnum]

            if rtype == "varint":
                val, pos = _read_varint(data, pos, cipher)
            elif rtype == "1byte":
                val, pos = _read_1byte(data, pos, cipher)
            elif rtype == "4byte_be":
                val, pos = _read_4byte_be(data, pos, cipher)
            elif rtype == "4byte_bswap":
                val, pos = _read_4byte_bswap(data, pos, cipher)
            else:
                continue

            # Store field values
            if fnum == 4:
                result.entity_id = val
            elif fnum == 6:
                result.f6 = val
                result.movement_state = val
            elif fnum == 7:
                result.waypoint_count = val
            elif fnum == 9:
                result.movement_type = val
            elif fnum == 10:
                result.f10 = val
                result.x = val & 0x3FFF
                result.z = (val >> 14) & 0x3FFF
            elif fnum == 14:
                result.sequence = val
            elif fnum == 16:
                result.f16 = val
                result.speed = struct.unpack("f", struct.pack("I", val))[0]
            elif fnum == 1:
                result.f1 = val
            elif fnum == 3:
                result.f3 = val
            elif fnum == 5:
                result.f5 = val
            elif fnum == 8:
                result.f8 = val
            elif fnum == 12:
                result.f12 = val

        result.bytes_consumed = pos
        return result

    def decode_all(self, packets, packet_id: int = 0x025B):
        """Decode all movement packets from a list of ParsedPacket objects.

        Parameters
        ----------
        packets : iterable of ParsedPacket
            Packets from chunk_parser.parse_payload_frames().
        packet_id : int
            Filter for this packet ID (default 0x025B).

        Yields
        ------
        (timestamp, MovementData) tuples for successfully decoded packets.
        """
        for pkt in packets:
            if pkt.packet_id != packet_id:
                continue
            result = self.decode(pkt.data)
            if result is not None and result.fully_parsed:
                yield pkt.timestamp, result

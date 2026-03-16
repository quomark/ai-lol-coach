"""
Decode 0x0228 packets from League of Legends ROFL v2 replays.

Reverse-engineered from the game binary (patch ~16.x, 2026).
Uses 4-byte schema + per-field ciphers, same architecture as 0x025B.

Field layout (11 fields):
  f0:  1-byte   (add 0x4f, xor 0x6c)      bits [0:3]
  f1:  varint_A (ror1,xor89,add66,ror6,bs,ror7) bits [3:6]
  f2:  1-bit                                bit 18
  f3:  4-byte_A (ror3,not,sub3F,bitswap)    bits [9:12]
  f4:  varint_B (bs,xorE1,sub12,xor28,ror3) bits [6:9]
  f5:  1-byte_B (shifts+LUT)               bits [12:15]
  f6:  varint_D (sub58,xorDA,ror6,sub7,xorC5,sub11) bits [25:28]
  f7:  1-byte_A (add50,LUTx2,sub66,xorCE)  bits [22:25]
  f8:  varint_C (bs,xor6E,77-x,xor1B,LUT,ror2,add6A) bits [15:18]
  f9:  4-byte_B (add76,xor16,add79,ror3,bs,ror5) bits [19:22]
  f10: 1-bit container                       bit 28?
"""
from __future__ import annotations
import struct
from dataclasses import dataclass, field as datafield
from pathlib import Path
from typing import Optional


@dataclass
class Packet0228Data:
    """Decoded 0x0228 packet."""
    f0: Optional[int] = None
    f1: Optional[int] = None
    f2: Optional[int] = None  # 1-bit
    f3: Optional[int] = None
    f4: Optional[int] = None
    f5: Optional[int] = None
    f6: Optional[int] = None
    f7: Optional[int] = None
    f8: Optional[int] = None
    f9: Optional[int] = None
    has_container: bool = False

    # Interpreted values (filled once we know semantics)
    f3_float: Optional[float] = None
    f9_float: Optional[float] = None

    bytes_consumed: int = 0
    total_bytes: int = 0
    schema: int = 0

    @property
    def leftover(self):
        return self.total_bytes - self.bytes_consumed


# ---- Cipher primitives ----

def _ror8(v, n):
    return ((v >> n) | (v << (8 - n))) & 0xFF

def _bitswap(b):
    hi = (b & 0xD5) << 1
    lo = (b >> 1) & 0x55
    return (hi | lo) & 0xFF


# ---- Per-field cipher functions ----

def _cipher_f0(b):
    """Field 0: add 0x4f, xor 0x6c"""
    b = (b + 0x4F) & 0xFF
    b ^= 0x6C
    return b

def _cipher_varint_A(b):
    """Field 1 varint: ror 1, xor 0x89, add 0x66, ror 6, bitswap, ror 7"""
    b = _ror8(b, 1)
    b ^= 0x89
    b = (b + 0x66) & 0xFF
    b = _ror8(b, 6)
    b = _bitswap(b)
    b = _ror8(b, 7)
    return b

def _cipher_4byte_A(b):
    """Field 3: ror 3, not, sub 0x3F, bitswap"""
    b = _ror8(b, 3)
    b = (~b) & 0xFF
    b = (b - 0x3F) & 0xFF
    # bitswap
    b = _bitswap(b)
    return b

def _cipher_varint_B(b):
    """Field 4 varint: bitswap, xor 0xE1, sub 0x12, xor 0x28, ror 3"""
    b = _bitswap(b)
    b ^= 0xE1
    b = (b - 0x12) & 0xFF
    b ^= 0x28
    b = _ror8(b, 3)
    return b

def _make_cipher_1byte_B(lut):
    """Field 5: shr 5 | shl 3, xor 0xFA, LUT, shl4|shr4, LUT, LUT, add 0x7A"""
    def cipher(b):
        combined = ((b >> 5) | (b << 3)) & 0xFF
        combined ^= 0xFA
        b2 = lut[combined]
        combined2 = ((b2 << 4) | (b2 >> 4)) & 0xFF
        b3 = lut[combined2]
        b4 = lut[b3]
        return (b4 + 0x7A) & 0xFF
    return cipher

def _cipher_varint_D(b):
    """Field 6 varint: sub 0x58, xor 0xDA, ror 6, sub 7, xor 0xC5, sub 0x11"""
    b = (b - 0x58) & 0xFF
    b ^= 0xDA
    b = _ror8(b, 6)
    b = (b - 7) & 0xFF
    b ^= 0xC5
    b = (b - 0x11) & 0xFF
    return b

def _make_cipher_1byte_A(lut):
    """Field 7: add 0x50, LUT x2, sub 0x66, xor 0xCE"""
    def cipher(b):
        b = (b + 0x50) & 0xFF
        b = lut[b]
        b = lut[b]
        b = (b - 0x66) & 0xFF
        b ^= 0xCE
        return b
    return cipher

def _make_cipher_varint_C(lut):
    """Field 8 varint: bitswap, xor 0x6E, 0x77-x, xor 0x1B, LUT, ror 2, add 0x6A"""
    def cipher(b):
        b = _bitswap(b)
        b ^= 0x6E
        b = (0x77 - b) & 0xFF
        b ^= 0x1B
        b = lut[b]
        b = _ror8(b, 2)
        b = (b + 0x6A) & 0xFF
        return b
    return cipher

def _cipher_4byte_B(b):
    """Field 9: add 0x76, xor 0x16, add 0x79, ror 3, bitswap, ror 5"""
    b = (b + 0x76) & 0xFF
    b ^= 0x16
    b = (b + 0x79) & 0xFF
    b = _ror8(b, 3)
    b = _bitswap(b)
    b = _ror8(b, 5)
    return b


# ---- Schema field definitions ----
# (bit_position, bit_width) for each field
_SCHEMA_FIELDS = {
    0:  (0, 3),
    1:  (3, 3),
    2:  (18, 1),
    3:  (9, 3),
    4:  (6, 3),
    5:  (12, 3),
    6:  (25, 3),
    7:  (22, 3),
    8:  (15, 3),
    9:  (19, 3),
    10: (28, 1),  # container bit (estimated)
}

# Read types for each field (from 0x025B patterns - need empirical validation)
# For 0x025B: varint fields read on {0,1,4,5} or similar subsets
# For 1-byte fields: read on {0,1,4,6} or similar
# Need to determine empirically
# Start with the 0x025B patterns and adjust based on leftover analysis

# Read vs Default type codes per field, derived from disassembly of
# the deserializer at 0x00E748B0. READ type codes consume data from the
# stream; DEFAULT type codes write a hard-coded constant (no data read).
_FIELD_READ_TYPES = {
    0:  {0, 1, 2, 3},        # 1-byte  (brute-force validated, 100% zero-leftover)
    1:  {1, 2, 3, 5, 6, 7},  # varint  (defaults: 0,4)
    # 2: 1-bit field, no reads
    3:  {0, 1, 3, 6},        # 4-byte  (defaults: 2,4,5,7)
    4:  {0, 2, 3, 4, 5, 6},  # varint  (brute-force validated)
    5:  {0, 1, 5, 6},        # 1-byte  (defaults: 2,3,4,7)
    6:  {0, 1, 6, 7},        # varint  (defaults: 2,3,4,5)
    7:  {0, 1, 3, 5},        # 1-byte  (defaults: 2,4,6,7)
    8:  {0, 2, 4, 5, 6, 7},  # varint  (defaults: 1,3)
    9:  {0, 2, 4, 6},        # 4-byte  (defaults: 1,3,5,7)
}


# ---- Stream readers ----

def _read_varint(data, pos, cipher):
    result = 0
    shift = 0
    while pos < len(data):
        decoded = cipher(data[pos])
        pos += 1
        result |= (decoded & 0x7F) << shift
        shift += 7
        if not (decoded & 0x80):
            break
    # BTC: if bit 30 set, negate
    if result & (1 << 30):
        result = -(result ^ (1 << 30))
    return result, pos

def _read_4byte_be(data, pos, cipher):
    if pos + 4 > len(data):
        return None, pos
    result = 0
    for _ in range(4):
        decoded = cipher(data[pos])
        pos += 1
        result = ((result << 8) | decoded) & 0xFFFFFFFF
    return result, pos

def _read_4byte_bswap(data, pos, cipher):
    val, pos = _read_4byte_be(data, pos, cipher)
    if val is not None:
        val = struct.unpack("<I", struct.pack(">I", val))[0]
    return val, pos

def _read_1byte(data, pos, cipher):
    if pos >= len(data):
        return None, pos
    return cipher(data[pos]), pos + 1


# ---- Decoder class ----

# LUT extracted from macOS runtime dump (same table used by 0x025B movement decoder)
_LUT = [
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

class Decoder0228:
    def __init__(self):
        self._lut = _LUT

        self._ciphers = {
            0:  ("1byte",    _cipher_f0),
            1:  ("varint",   _cipher_varint_A),
            3:  ("4byte_bswap", _cipher_4byte_A),
            4:  ("varint",   _cipher_varint_B),
            5:  ("1byte",    _make_cipher_1byte_B(self._lut)),
            6:  ("varint",   _cipher_varint_D),
            7:  ("1byte",    _make_cipher_1byte_A(self._lut)),
            8:  ("varint",   _make_cipher_varint_C(self._lut)),
            9:  ("4byte_bswap", _cipher_4byte_B),
        }

    def decode(self, data):
        if len(data) < 4:
            return None

        schema = struct.unpack_from('<I', data, 0)[0]
        pos = 4
        result = Packet0228Data(total_bytes=len(data), schema=schema)

        for fnum in range(11):
            if fnum == 10:
                # Container bit
                dl, nbits = _SCHEMA_FIELDS[10]
                tc = (schema >> dl) & ((1 << nbits) - 1)
                if tc == 1:
                    result.has_container = True
                break

            if fnum == 2:
                # 1-bit field, no data read
                dl, nbits = _SCHEMA_FIELDS[2]
                tc = (schema >> dl) & 1
                result.f2 = tc
                continue

            dl, nbits = _SCHEMA_FIELDS[fnum]
            tc = (schema >> dl) & ((1 << nbits) - 1)

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
            elif rtype == "4byte_bswap":
                val, pos = _read_4byte_bswap(data, pos, cipher)
            elif rtype == "4byte_be":
                val, pos = _read_4byte_be(data, pos, cipher)
            else:
                continue

            setattr(result, f'f{fnum}', val)

            # Try interpreting 4-byte values as float
            if rtype in ("4byte_bswap", "4byte_be") and val is not None:
                try:
                    fval = struct.unpack('f', struct.pack('I', val))[0]
                    if fnum == 3:
                        result.f3_float = fval
                    elif fnum == 9:
                        result.f9_float = fval
                except:
                    pass

        result.bytes_consumed = pos
        return result


def main():
    from collections import Counter, defaultdict
    from ml.parsers.rofl_parser import ROFLParser
    from ml.parsers.chunk_parser import parse_payload_frames

    decoder = Decoder0228()

    rofl = ROFLParser(r'C:\Users\ngan9\OneDrive\Documents\League of Legends\Replays\TW2-396324158.rofl')
    frames = rofl.decompress_payload_frames()
    payload = parse_payload_frames(frames, parse_packets=True)

    PLAYER_PARAMS = {
        0x400000B0: 'Jhin', 0x400000B1: 'Graves', 0x400000B2: 'Mordekaiser',
    }

    # Test decode
    leftover_counter = Counter()
    total = 0
    decoded = 0

    print('=== FIRST 20 JHIN 0x0228 PACKETS ===')
    jhin_count = 0

    for fr in payload.frames:
        for pkt in fr.packets:
            if pkt.packet_id != 0x0228 or pkt.size == 0:
                continue
            total += 1
            r = decoder.decode(pkt.data)
            if r is None:
                continue
            decoded += 1
            leftover_counter[r.leftover] += 1

            if pkt.param == 0x400000B0 and jhin_count < 20:
                f3f = f'{r.f3_float:.2f}' if r.f3_float is not None else '-'
                f9f = f'{r.f9_float:.2f}' if r.f9_float is not None else '-'
                print(f't={pkt.timestamp:8.1f} sz={pkt.size:2d} left={r.leftover:2d} '
                      f'f0={r.f0} f1={r.f1} f2={r.f2} f3={f3f} f4={r.f4} '
                      f'f5={r.f5} f6={r.f6} f7={r.f7} f8={r.f8} f9={f9f} '
                      f'schema=0x{r.schema:08X}')
                jhin_count += 1

    print(f'\nTotal: {total}, Decoded: {decoded}')
    print(f'Leftover distribution: {dict(leftover_counter.most_common(10))}')

    # If we have many packets with leftover == 0, our read types are correct
    zero_pct = leftover_counter[0] / decoded * 100 if decoded > 0 else 0
    print(f'Zero leftover: {leftover_counter[0]} ({zero_pct:.1f}%)')


if __name__ == '__main__':
    main()

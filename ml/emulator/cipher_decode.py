"""
Cipher decryption for League of Legends 0x025B movement packet struct fields.

The game's deserializer at RVA 0xFE22B0 writes to outer struct fields at
offsets +0x10 through +0x34, applying a per-field cipher transform to each
byte. This module implements the forward ciphers (as the game applies them)
and builds 256-entry inverse lookup tables for decryption.

Field layout of the decoded struct (starting at struct + 0x10):
  +0x10: 4 bytes (e.g., float or u32)
  +0x14: 1 byte
  +0x15: 1 byte
  +0x16-0x17: padding (2 bytes)
  +0x18: 4 bytes (e.g., float X position)
  +0x1C: 4 bytes (e.g., float Y position or net ID)
  +0x20: 4 bytes
  +0x24: 1 byte
  +0x25-0x27: padding (3 bytes)
  +0x28: 4 bytes
  +0x2C: 1 byte
  +0x2D-0x2F: padding (3 bytes)
  +0x30: 4 bytes
  +0x34: 1 byte

Binary: ml/data/league_unpacked_patched.bin (base 0x7FF76C300000)
S-box at file offset 0x19C11B0 (256 bytes, runtime-initialized in our dump).
"""

import struct
import os

# ---------------------------------------------------------------------------
# S-box from the binary dump at offset 0x19C11B0
# ---------------------------------------------------------------------------
SBOX = [
    0x3E, 0xD3, 0x05, 0xA7, 0x09, 0x14, 0xBD, 0x1E, 0xE0, 0x5D, 0xB0, 0x6E, 0x9B, 0xD6, 0x32, 0xEE,
    0x51, 0x72, 0x68, 0x5A, 0x97, 0xA9, 0xA0, 0x67, 0xC5, 0x42, 0x59, 0x55, 0x7F, 0x37, 0xC9, 0xAC,
    0x8D, 0x0A, 0x5C, 0x46, 0x2C, 0xA3, 0xD9, 0xD4, 0xD1, 0x07, 0x7D, 0x39, 0x24, 0xED, 0xFE, 0x8E,
    0x61, 0x99, 0xE3, 0x3D, 0x1B, 0x08, 0x92, 0x73, 0xF4, 0xAD, 0xF0, 0xFC, 0xCA, 0xA2, 0xEC, 0x38,
    0x18, 0x2A, 0xCD, 0x87, 0xAF, 0xD7, 0x4A, 0x1D, 0xC6, 0x7A, 0x2E, 0x30, 0xBC, 0x4F, 0x58, 0xBE,
    0x4D, 0x13, 0xFB, 0x8A, 0xCE, 0x3F, 0x01, 0x85, 0xE9, 0x8C, 0x20, 0x1C, 0xAA, 0x35, 0x26, 0x2D,
    0xB4, 0x2B, 0x3B, 0x19, 0xB8, 0xB5, 0x45, 0xA8, 0xFF, 0x47, 0x12, 0xE5, 0xCC, 0x50, 0x27, 0x16,
    0x98, 0x0B, 0x83, 0xF5, 0x91, 0x29, 0xB2, 0xF9, 0x1F, 0x0C, 0x86, 0x84, 0x75, 0x64, 0x1A, 0x0F,
    0xE6, 0x7C, 0x02, 0x04, 0x9A, 0x94, 0x34, 0x4E, 0x53, 0xEF, 0xDC, 0xB1, 0xF8, 0x81, 0x52, 0x06,
    0xFA, 0xC7, 0x0E, 0xB6, 0xCF, 0x77, 0x21, 0x11, 0x6F, 0x25, 0x82, 0xA6, 0x4C, 0x60, 0x0D, 0x7E,
    0x93, 0xAE, 0xC4, 0xEB, 0x5F, 0x9D, 0x62, 0x96, 0x8F, 0x89, 0x2F, 0xDD, 0x43, 0x5E, 0xA1, 0xE2,
    0xF1, 0xA4, 0x9C, 0x88, 0xCB, 0x56, 0x78, 0xBF, 0x22, 0x23, 0x36, 0x6C, 0x48, 0x71, 0x54, 0x70,
    0x74, 0xBA, 0x69, 0xE8, 0xE1, 0xE4, 0xE7, 0x15, 0xBB, 0x66, 0x40, 0x10, 0x5B, 0xA5, 0xC8, 0x31,
    0xF7, 0x28, 0xF2, 0xF3, 0x33, 0xB9, 0xFD, 0x00, 0xF6, 0xDE, 0x57, 0x9E, 0x03, 0x79, 0xB3, 0x3A,
    0xC2, 0x6B, 0xDB, 0xD0, 0x8B, 0x63, 0x17, 0x6D, 0x9F, 0xD2, 0xAB, 0x49, 0xD5, 0xC0, 0xEA, 0xDA,
    0x3C, 0x95, 0xB7, 0x44, 0x7B, 0xDF, 0x90, 0x76, 0x4B, 0xC3, 0x65, 0x80, 0x41, 0x6A, 0xC1, 0xD8,
]

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def ror8(v: int, n: int) -> int:
    """Rotate right 8-bit value by n bits."""
    return ((v >> n) | (v << (8 - n))) & 0xFF


def rol8(v: int, n: int) -> int:
    """Rotate left 8-bit value by n bits."""
    return ((v << n) | (v >> (8 - n))) & 0xFF


def bit_shuffle(v: int) -> int:
    """Bit permutation used by several ciphers.

    Splits the byte into even-position bits (mask 0xD5) and odd-position
    bits (mask 0x55 after >>1), then recombines as (evens << 1) | odds.
    Assembly pattern: movzx edx, cl; shr cl, 1; and dl, 0xD5;
                      and cl, 0x55; add dl, dl; or dl, cl
    """
    even = v & 0xD5
    odd = (v >> 1) & 0x55
    return ((even * 2) & 0xFF) | odd


# ---------------------------------------------------------------------------
# Forward cipher functions  (encrypt: plaintext byte -> ciphertext byte)
# Each corresponds to the transform the game applies when writing the field.
# ---------------------------------------------------------------------------

def cipher_0x10(b: int) -> int:
    """Field +0x10 (4 bytes). RVA 0xFE2470.
    NOT, ROR 1, bit_shuffle, XOR 0x15, ROR 6
    """
    v = (~b) & 0xFF
    v = ror8(v, 1)
    v = bit_shuffle(v)
    v = v ^ 0x15
    v = ror8(v, 6)
    return v


def cipher_0x14(b: int) -> int:
    """Field +0x14 (1 byte). RVA 0xFE25B0.
    NOT, ROR 3, XOR 0xD8, ROR 1
    """
    v = (~b) & 0xFF
    v = ror8(v, 3)
    v = v ^ 0xD8
    v = ror8(v, 1)
    return v


def cipher_0x15(b: int) -> int:
    """Field +0x15 (1 byte). RVA 0xFE2622.
    SUB 0x62, XOR 0x36, ADD 0x62, S-box lookup, ROR 6, SUB 0x50
    """
    v = (b - 0x62) & 0xFF
    v = v ^ 0x36
    v = (v + 0x62) & 0xFF
    v = SBOX[v]
    v = ror8(v, 6)
    v = (v - 0x50) & 0xFF
    return v


def cipher_0x18(b: int) -> int:
    """Field +0x18 (4 bytes). RVA 0xFE2AA0.
    NOT, bit_shuffle, ROR 4, bit_shuffle, XOR 0xF5, SUB 3, ROR 6
    """
    v = (~b) & 0xFF
    v = bit_shuffle(v)
    v = ror8(v, 4)
    v = bit_shuffle(v)
    v = v ^ 0xF5
    v = (v - 3) & 0xFF
    v = ror8(v, 6)
    return v


def cipher_0x1C(b: int) -> int:
    """Field +0x1C (4 bytes). RVA 0xFE2BD0.
    ROL 2, SBOX[x], SBOX[SBOX[x]], NOT, bit_shuffle, ROR 3, ADD 0x70
    """
    idx = rol8(b, 2)
    v = SBOX[idx]
    v = SBOX[v]
    v = (~v) & 0xFF
    v = bit_shuffle(v)
    v = ror8(v, 3)
    v = (v + 0x70) & 0xFF
    return v


def cipher_0x20(b: int) -> int:
    """Field +0x20 (4 bytes). RVA 0xFE2F50.
    bit_shuffle, XOR 0x91, ROR 2, ADD 0x71, ROR 1, ROL 2, S-box lookup
    """
    v = bit_shuffle(b)
    v = v ^ 0x91
    v = ror8(v, 2)
    v = (v + 0x71) & 0xFF
    v = ror8(v, 1)
    v = SBOX[rol8(v, 2)]
    return v


def cipher_0x24(b: int) -> int:
    """Field +0x24 (1 byte). RVA 0xFE33F0.
    ADD 0x45, XOR 0xAA, ROR 4, SUB 0x19, ROR 5
    """
    v = (b + 0x45) & 0xFF
    v = v ^ 0xAA
    v = ror8(v, 4)
    v = (v - 0x19) & 0xFF
    v = ror8(v, 5)
    return v


def cipher_0x28(b: int) -> int:
    """Field +0x28 (4 bytes). RVA 0xFE35D0.
    bit_shuffle, ROR 1, ADD 0x57, NOT, bit_shuffle, SUB 0x2F
    """
    v = bit_shuffle(b)
    v = ror8(v, 1)
    v = (v + 0x57) & 0xFF
    v = (~v) & 0xFF
    v = bit_shuffle(v)
    v = (v - 0x2F) & 0xFF
    return v


def cipher_0x2C(b: int) -> int:
    """Field +0x2C (1 byte). RVA 0xFE3830.
    XOR 0x4D, ADD 0x34, ROR 2, XOR 0x5A, ROR 6, NOT
    """
    v = b ^ 0x4D
    v = (v + 0x34) & 0xFF
    v = ror8(v, 2)
    v = v ^ 0x5A
    v = ror8(v, 6)
    v = (~v) & 0xFF
    return v


def cipher_0x30(b: int) -> int:
    """Field +0x30 (4 bytes). RVA 0xFE3BB0.
    SUB 7, bit_shuffle, ADD 0x62
    """
    v = (b - 7) & 0xFF
    v = bit_shuffle(v)
    v = (v + 0x62) & 0xFF
    return v


def cipher_0x34(b: int) -> int:
    """Field +0x34 (1 byte). RVA 0xFE3C50.
    bit_shuffle, ROR 2, SUB 0x74, ROR 3, XOR 0xD5, SUB 0x56
    """
    v = bit_shuffle(b)
    v = ror8(v, 2)
    v = (v - 0x74) & 0xFF
    v = ror8(v, 3)
    v = v ^ 0xD5
    v = (v - 0x56) & 0xFF
    return v


# ---------------------------------------------------------------------------
# Cipher registry: maps struct offset -> (cipher_fn, field_size_bytes)
# ---------------------------------------------------------------------------
CIPHER_REGISTRY = {
    0x10: (cipher_0x10, 4),
    0x14: (cipher_0x14, 1),
    0x15: (cipher_0x15, 1),
    0x18: (cipher_0x18, 4),
    0x1C: (cipher_0x1C, 4),
    0x20: (cipher_0x20, 4),
    0x24: (cipher_0x24, 1),
    0x28: (cipher_0x28, 4),
    0x2C: (cipher_0x2C, 1),
    0x30: (cipher_0x30, 4),
    0x34: (cipher_0x34, 1),
}

# ---------------------------------------------------------------------------
# Build inverse lookup tables (256-entry each)
# For each cipher c, inv[c(x)] = x for all x in 0..255
# ---------------------------------------------------------------------------

def _build_inverse_table(cipher_fn):
    """Build a 256-entry inverse table for a bijective byte cipher."""
    inv = [0] * 256
    for i in range(256):
        inv[cipher_fn(i)] = i
    return inv


INV_0x10 = _build_inverse_table(cipher_0x10)
INV_0x14 = _build_inverse_table(cipher_0x14)
INV_0x15 = _build_inverse_table(cipher_0x15)
INV_0x18 = _build_inverse_table(cipher_0x18)
INV_0x1C = _build_inverse_table(cipher_0x1C)
INV_0x20 = _build_inverse_table(cipher_0x20)
INV_0x24 = _build_inverse_table(cipher_0x24)
INV_0x28 = _build_inverse_table(cipher_0x28)
INV_0x2C = _build_inverse_table(cipher_0x2C)
INV_0x30 = _build_inverse_table(cipher_0x30)
INV_0x34 = _build_inverse_table(cipher_0x34)

# Map struct offset -> inverse table
INVERSE_TABLES = {
    0x10: INV_0x10,
    0x14: INV_0x14,
    0x15: INV_0x15,
    0x18: INV_0x18,
    0x1C: INV_0x1C,
    0x20: INV_0x20,
    0x24: INV_0x24,
    0x28: INV_0x28,
    0x2C: INV_0x2C,
    0x30: INV_0x30,
    0x34: INV_0x34,
}


# ---------------------------------------------------------------------------
# Decrypt/encrypt byte helpers
# ---------------------------------------------------------------------------

def decrypt_byte(offset: int, ciphertext_byte: int) -> int:
    """Decrypt a single byte for a given struct field offset."""
    return INVERSE_TABLES[offset][ciphertext_byte]


def encrypt_byte(offset: int, plaintext_byte: int) -> int:
    """Encrypt a single byte for a given struct field offset."""
    fn, _ = CIPHER_REGISTRY[offset]
    return fn(plaintext_byte)


def decrypt_field(offset: int, cipher_bytes: bytes) -> bytes:
    """Decrypt all bytes of a field at the given offset."""
    inv = INVERSE_TABLES[offset]
    return bytes(inv[b] for b in cipher_bytes)


def encrypt_field(offset: int, plain_bytes: bytes) -> bytes:
    """Encrypt all bytes of a field at the given offset."""
    fn, _ = CIPHER_REGISTRY[offset]
    return bytes(fn(b) for b in plain_bytes)


# ---------------------------------------------------------------------------
# Struct decoder
# ---------------------------------------------------------------------------

def decode_struct(raw_bytes: bytes) -> dict:
    """Decode the 0x28-byte region from struct+0x10 to struct+0x38.

    Parameters
    ----------
    raw_bytes : bytes
        The raw (encrypted) bytes starting at struct offset 0x10.
        Should be at least 0x25 (37) bytes to cover fields through +0x34.

    Returns
    -------
    dict with keys like 'field_0x10', 'field_0x14', etc., each containing
    the decrypted value. Multi-byte fields are returned as little-endian
    unsigned integers (u32). Single-byte fields are returned as ints.
    Also includes '_raw' sub-dict with raw decrypted bytes for each field.
    """
    if len(raw_bytes) < 0x25:
        raise ValueError(
            f"Need at least 0x25 (37) bytes, got {len(raw_bytes)}"
        )

    result = {}
    raw_fields = {}

    # Field definitions: (struct_offset, data_offset_in_raw, size)
    fields = [
        (0x10, 0x00, 4),   # raw[0:4]
        (0x14, 0x04, 1),   # raw[4]
        (0x15, 0x05, 1),   # raw[5]
        # 0x16-0x17: padding
        (0x18, 0x08, 4),   # raw[8:12]
        (0x1C, 0x0C, 4),   # raw[12:16]
        (0x20, 0x10, 4),   # raw[16:20]
        (0x24, 0x14, 1),   # raw[20]
        # 0x25-0x27: padding
        (0x28, 0x18, 4),   # raw[24:28]
        (0x2C, 0x1C, 1),   # raw[28]
        # 0x2D-0x2F: padding
        (0x30, 0x20, 4),   # raw[32:36]
        (0x34, 0x24, 1),   # raw[36]
    ]

    for offset, data_off, size in fields:
        cipher_data = raw_bytes[data_off:data_off + size]
        if len(cipher_data) < size:
            break
        decrypted = decrypt_field(offset, cipher_data)
        raw_fields[f"field_0x{offset:02X}"] = decrypted

        if size == 4:
            result[f"field_0x{offset:02X}"] = struct.unpack_from('<I', decrypted)[0]
        else:
            result[f"field_0x{offset:02X}"] = decrypted[0]

    result['_raw'] = raw_fields
    return result


def decode_struct_as_floats(raw_bytes: bytes) -> dict:
    """Like decode_struct but interprets 4-byte fields as floats where
    reasonable (0x18, 0x1C, 0x20, 0x28, 0x30 are likely coordinates)."""
    base = decode_struct(raw_bytes)
    float_fields = {0x10, 0x18, 0x1C, 0x20, 0x28, 0x30}

    result = {}
    for key, val in base.items():
        if key == '_raw':
            result[key] = val
            continue
        offset = int(key.split('_')[1], 16)
        if offset in float_fields and isinstance(val, int):
            raw = base['_raw'][key]
            fval = struct.unpack_from('<f', raw)[0]
            result[key] = fval
            result[f"{key}_u32"] = val
        else:
            result[key] = val

    return result


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _validate():
    """Run self-tests on all ciphers."""
    # 1. Check the known test vector
    assert cipher_0x10(0xFF) == 0x54, (
        f"cipher_0x10(0xFF) = 0x{cipher_0x10(0xFF):02X}, expected 0x54"
    )

    # 2. Verify all ciphers are bijective
    for offset, (fn, _) in CIPHER_REGISTRY.items():
        outputs = set(fn(i) for i in range(256))
        assert len(outputs) == 256, (
            f"cipher_0x{offset:02X} is NOT bijective! "
            f"Only {len(outputs)} unique outputs."
        )

    # 3. Verify inverse tables are correct
    for offset, inv in INVERSE_TABLES.items():
        fn, _ = CIPHER_REGISTRY[offset]
        for i in range(256):
            assert inv[fn(i)] == i, (
                f"Inverse table for 0x{offset:02X} fails at input {i}: "
                f"inv[cipher({i})] = {inv[fn(i)]}"
            )

    print("All validations passed.")
    print(f"  cipher_0x10(0xFF) = 0x{cipher_0x10(0xFF):02X} (expected 0x54)")
    print(f"  {len(CIPHER_REGISTRY)} ciphers, all bijective")
    print(f"  {len(INVERSE_TABLES)} inverse tables, all verified")


# ---------------------------------------------------------------------------
# Element-level ciphers (applied by element init at RVA 0xDDFA00)
# Element struct layout (0x28 bytes):
#   +0x00: vtable pointer (8 bytes, not encrypted)
#   +0x08: 4 bytes
#   +0x0C: 4 bytes
#   +0x10: 1 byte
#   +0x14: 4 bytes
#   +0x18: 4 bytes
#   +0x1C: 12 bytes
# ---------------------------------------------------------------------------

# S-box 2 at file offset 0x19B60F0 (used only by element +0x1C cipher)
SBOX2 = [
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


def elem_cipher_0x08(b: int) -> int:
    """Element +0x08 (4 bytes). RVA 0xDDFA30.
    SBOX[b], NOT, bit_shuffle, XOR 0x3b, SBOX[x], SUB 0x12, ROR 4
    """
    v = SBOX[b]
    v = (~v) & 0xFF
    v = bit_shuffle(v)
    v = v ^ 0x3B
    v = SBOX[v]
    v = (v - 0x12) & 0xFF
    v = ror8(v, 4)
    return v


def elem_cipher_0x0C(b: int) -> int:
    """Element +0x0C (4 bytes). RVA 0xDDFA80.
    SUB 0x1d, ROR 1, bit_shuffle, ROR 6
    """
    v = (b - 0x1D) & 0xFF
    v = ror8(v, 1)
    v = bit_shuffle(v)
    v = ror8(v, 6)
    return v


def elem_cipher_0x10(b: int) -> int:
    """Element +0x10 (1 byte). RVA 0xDDFAB2.
    SUB 0x7a, ROR 4, SUB 0x5b, ROR 3, SUB 0x32
    """
    v = (b - 0x7A) & 0xFF
    v = ror8(v, 4)
    v = (v - 0x5B) & 0xFF
    v = ror8(v, 3)
    v = (v - 0x32) & 0xFF
    return v


def elem_cipher_0x14(b: int) -> int:
    """Element +0x14 (4 bytes). RVA 0xDDFAE0.
    XOR 0x45, ROR 4, ADD 0x0f, XOR 0x56
    """
    v = b ^ 0x45
    v = ror8(v, 4)
    v = (v + 0x0F) & 0xFF
    v = v ^ 0x56
    return v


def elem_cipher_0x18(b: int) -> int:
    """Element +0x18 (4 bytes). RVA 0xDDFB10.
    SUB 0x21, ROR 4, ADD 0x36, ROL 2, XOR 0xd8, SBOX[x]
    """
    v = (b - 0x21) & 0xFF
    v = ror8(v, 4)
    v = (v + 0x36) & 0xFF
    v = rol8(v, 2)
    v = v ^ 0xD8
    v = SBOX[v]
    return v


def elem_cipher_0x1C(b: int) -> int:
    """Element +0x1C (12 bytes). RVA 0xDDFBA0 (second pass).
    ADD 8, bit_shuffle, SBOX[x], ADD 0x49, NOT
    The first pass zeroes then applies a different transform,
    but the second pass (which is the effective cipher) zeroes again
    and applies this transform.
    """
    v = (b + 8) & 0xFF
    v = bit_shuffle(v)
    v = SBOX[v]
    v = (v + 0x49) & 0xFF
    v = (~v) & 0xFF
    return v


# Element cipher registry
ELEM_CIPHER_REGISTRY = {
    0x08: (elem_cipher_0x08, 4),
    0x0C: (elem_cipher_0x0C, 4),
    0x10: (elem_cipher_0x10, 1),
    0x14: (elem_cipher_0x14, 4),
    0x18: (elem_cipher_0x18, 4),
    0x1C: (elem_cipher_0x1C, 12),
}

# Build element inverse tables
ELEM_INV_0x08 = _build_inverse_table(elem_cipher_0x08)
ELEM_INV_0x0C = _build_inverse_table(elem_cipher_0x0C)
ELEM_INV_0x10 = _build_inverse_table(elem_cipher_0x10)
ELEM_INV_0x14 = _build_inverse_table(elem_cipher_0x14)
ELEM_INV_0x18 = _build_inverse_table(elem_cipher_0x18)
ELEM_INV_0x1C = _build_inverse_table(elem_cipher_0x1C)

ELEM_INVERSE_TABLES = {
    0x08: ELEM_INV_0x08,
    0x0C: ELEM_INV_0x0C,
    0x10: ELEM_INV_0x10,
    0x14: ELEM_INV_0x14,
    0x18: ELEM_INV_0x18,
    0x1C: ELEM_INV_0x1C,
}


def decode_element(raw_bytes: bytes) -> dict:
    """Decode a 0x28-byte element (including 8-byte vtable prefix).

    Parameters
    ----------
    raw_bytes : bytes
        Full 0x28-byte element data (vtable + encrypted fields).

    Returns
    -------
    dict with decoded field values.
    """
    if len(raw_bytes) < 0x28:
        raise ValueError(f"Need 0x28 bytes, got {len(raw_bytes)}")

    vtable = struct.unpack_from('<Q', raw_bytes, 0)[0]

    result = {'vtable': vtable}
    raw_fields = {}

    # Element field definitions: (elem_offset, size)
    fields = [
        (0x08, 4),
        (0x0C, 4),
        (0x10, 1),
        # 0x11-0x13: padding
        (0x14, 4),
        (0x18, 4),
        (0x1C, 12),
    ]

    for offset, size in fields:
        cipher_data = raw_bytes[offset:offset + size]
        inv = ELEM_INVERSE_TABLES[offset]
        decrypted = bytes(inv[b] for b in cipher_data)
        raw_fields[f"elem_0x{offset:02X}"] = decrypted

        if size == 4:
            result[f"elem_0x{offset:02X}"] = struct.unpack_from('<I', decrypted)[0]
        elif size == 1:
            result[f"elem_0x{offset:02X}"] = decrypted[0]
        else:
            # 12 bytes: could be 3 floats or other
            result[f"elem_0x{offset:02X}"] = decrypted

    result['_raw'] = raw_fields
    return result


def decode_element_as_floats(raw_bytes: bytes) -> dict:
    """Like decode_element but interprets 4-byte fields as floats."""
    base = decode_element(raw_bytes)
    float_offsets = {0x08, 0x0C, 0x14, 0x18}

    result = {}
    for key, val in base.items():
        if key == '_raw':
            result[key] = val
            continue
        if key.startswith('elem_0x'):
            offset = int(key.split('_')[1], 16)
            if offset in float_offsets and isinstance(val, int):
                raw = base['_raw'][key]
                fval = struct.unpack_from('<f', raw)[0]
                result[key] = fval
                result[f"{key}_u32"] = val
            elif offset == 0x1C and isinstance(val, bytes):
                # 12 bytes: try as 3 floats
                f1 = struct.unpack_from('<f', val, 0)[0]
                f2 = struct.unpack_from('<f', val, 4)[0]
                f3 = struct.unpack_from('<f', val, 8)[0]
                result[key] = (f1, f2, f3)
            else:
                result[key] = val
        else:
            result[key] = val

    return result


if __name__ == "__main__":
    _validate()

    # Validate element ciphers
    print("\nValidating element ciphers...")
    for offset, (fn, _) in ELEM_CIPHER_REGISTRY.items():
        outputs = set(fn(i) for i in range(256))
        assert len(outputs) == 256, f"elem cipher 0x{offset:02X} not bijective!"
        inv = ELEM_INVERSE_TABLES[offset]
        for i in range(256):
            assert inv[fn(i)] == i, f"elem inv 0x{offset:02X} fails at {i}"
    print(f"  {len(ELEM_CIPHER_REGISTRY)} element ciphers, all bijective and invertible")

    # Verify element cipher-init patterns (cipher(0) for each field)
    print("\nElement cipher-init patterns (cipher(0x00)):")
    for offset, (fn, size) in sorted(ELEM_CIPHER_REGISTRY.items()):
        init_byte = fn(0)
        print(f"  elem+0x{offset:02X}: cipher(0)=0x{init_byte:02X}")

    # Demo: decode a dummy struct of all 0xFF bytes
    print("\nDemo outer struct decode (all 0xFF input):")
    dummy = b'\xff' * 0x28
    result = decode_struct(dummy)
    for key, val in sorted(result.items()):
        if key == '_raw':
            continue
        if isinstance(val, int) and val > 0xFF:
            print(f"  {key} = 0x{val:08X}")
        else:
            print(f"  {key} = 0x{val:02X}")

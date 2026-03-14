"""
ROFL → JSON: Extract movement/position data from League replays.

Replicates the ROFL tool's stub_emulator approach:
- Uses deserializer at RVA 0xF65D30 (mov_decrypt for packet 0x0425/netid 1061)
- Zeroed 0x90-byte struct (no CTOR needed)
- Patches alloc1/alloc2/skip functions
- Reads decoded payload from struct+0x18 (ptr) and +0x20 (size)
- Parses PathPacket: u16 parsing_type, u32 entity_id, f32 speed, bitpacked waypoints

Usage:
    python -m ml.emulator.rofl_to_json
"""
from __future__ import annotations

import struct as st
import time
import json
import sys
import ctypes
from pathlib import Path

from unicorn import (
    Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL,
    UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_HOOK_MEM_FETCH_UNMAPPED, UC_HOOK_CODE,
    UcError,
)
from unicorn.x86_const import *

# ── Memory layout ──────────────────────────────────────────────
BASE = 0x7FF76C300000          # Game binary base (from dump)
DESER_START = 0xF65D30         # mov_decrypt RVA start
DESER_END   = 0xF66D71         # mov_decrypt RVA end
PAYLOAD_OFF = 0x18             # Decoded payload pointer offset in struct
PAYLOAD_SZ_OFF = 0x20          # Decoded payload size offset in struct
STRUCT_SIZE = 0x90             # Zeroed struct size

ALLOC1_RVA  = 0xF605D0        # alloc1 to patch
ALLOC2_RVA  = 0x1DE550        # alloc2 to patch
SKIP_RVA    = 0xFCA950        # skip function to patch (return 1)

STACK       = 0x7FFFFFFF0000
STACK_SZ    = 0x4000
HEAP_BASE   = 0x7FFFFFFF8000   # Same as ROFL tool
HEAP_SZ     = 0x800000         # 8MB heap
PKTBUF      = 0x600000000000
STRUCT_ADDR = 0x610000000000
STOP        = 0xFF0000000000
HEAP_CURSOR = 0x0              # Address 0 stores heap offset

MAX_INSN    = 2_000_000


def sign_extend(value: int, bits: int) -> int:
    """Sign-extend a value from `bits` width to Python int."""
    if value & (1 << (bits - 1)):
        return value - (1 << bits)
    return value


def setup_emulator() -> Uc:
    """Load binary dump and set up Unicorn emulator with ROFL tool patches."""
    dump = Path("ml/data/league_unpacked_patched.bin").read_bytes()
    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    aligned = (len(dump) + 0xFFF) & ~0xFFF
    mu.mem_map(BASE, aligned, UC_PROT_ALL)
    mu.mem_write(BASE, dump)

    for addr, sz in [(STACK, STACK_SZ), (HEAP_BASE, HEAP_SZ),
                     (PKTBUF, 0x10000), (STRUCT_ADDR, 0x10000),
                     (STOP, 0x1000), (0, 0x1000)]:
        mu.mem_map(addr, sz, UC_PROT_ALL)

    mu.mem_write(STOP, b"\xCC")

    # ── Patch alloc1: bump allocator ──
    # alloc1(rcx=out_struct, edx=size): allocates, stores ptr at [rcx], size at [rcx+8]
    alloc1_code = (
        b"\x57\x56"                             # push rdi; push rsi
        + b"\x48\x89\xce\x89\xd7"               # mov rsi,rcx; mov edi,edx
        + b"\x48\x83\xc7\x0f\x48\x83\xe7\xf0"   # align size to 16
        + b"\x48\xa1" + st.pack("<Q", 0)          # mov rax, [0] (heap cursor)
        + b"\x48\x89\xc1\x48\x01\xf8"           # mov rcx,rax; add rax,rdi
        + b"\x48\xa3" + st.pack("<Q", 0)          # mov [0], rax (update cursor)
        + b"\x48\xb8" + st.pack("<Q", HEAP_BASE) # mov rax, HEAP_BASE
        + b"\x48\x01\xc8"                        # add rax, rcx
        + b"\x48\x89\x06\x89\x7e\x08"           # mov [rsi], rax; mov [rsi+8], edi
        + b"\x5e\x5f\xc3"                        # pop rsi; pop rdi; ret
    )

    # ── Patch alloc2: simple bump allocator ──
    # alloc2(rcx=size): returns pointer
    alloc2_code = (
        b"\x53"                                  # push rbx
        + b"\x48\x89\xcb\x48\x83\xc3\x0f\x48\x83\xe3\xf0"  # mov rbx,rcx; align
        + b"\x48\xa1" + st.pack("<Q", 0)          # mov rax, [0]
        + b"\x48\x89\xc1\x48\x01\xd8"           # mov rcx,rax; add rax,rbx
        + b"\x48\xa3" + st.pack("<Q", 0)          # mov [0], rax
        + b"\x48\xb8" + st.pack("<Q", HEAP_BASE) # mov rax, HEAP_BASE
        + b"\x48\x01\xc8"                        # add rax, rcx
        + b"\x5b\xc3"                            # pop rbx; ret
    )

    mu.mem_write(BASE + ALLOC1_RVA, alloc1_code)
    mu.mem_write(BASE + ALLOC2_RVA, alloc2_code)

    # skip function → return 1
    mu.mem_write(BASE + SKIP_RVA, b"\xB8\x01\x00\x00\x00\xC3")

    # Zero heap cursor
    mu.mem_write(0, st.pack("<Q", 0))

    # ── Unmapped memory hook (Sabrina trick) ──
    mapped = set()

    def hook_unmapped(uc, access, addr, size, value, data):
        page = addr & ~0xFFF
        if page in mapped:
            return False
        try:
            uc.mem_map(page, 0x1000, UC_PROT_ALL)
            from unicorn import UC_MEM_FETCH_UNMAPPED
            if access == UC_MEM_FETCH_UNMAPPED:
                # Fill with "mov eax,1; ret; nop; nop" stubs
                uc.mem_write(page, (b"\xB8\x01\x00\x00\x00\xC3\x90\x90" * (0x1000 // 8)))
            mapped.add(page)
            return True
        except:
            return False

    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
                UC_HOOK_MEM_FETCH_UNMAPPED, hook_unmapped)

    # ── Code hook: stop at STOP address, handle external calls ──
    dump_len = len(dump)

    def hook_code(uc, addr, size, data):
        rva = addr - BASE
        if 0 <= rva < dump_len:
            return  # Normal code execution
        if addr == STOP:
            uc.emu_stop()
            return
        # External call → stub return rcx (constructor pattern)
        rsp = uc.reg_read(UC_X86_REG_RSP)
        try:
            ret = st.unpack("<Q", bytes(uc.mem_read(rsp, 8)))[0]
            rcx = uc.reg_read(UC_X86_REG_RCX)
            uc.reg_write(UC_X86_REG_RAX, rcx)
            uc.reg_write(UC_X86_REG_RSP, rsp + 8)
            uc.reg_write(UC_X86_REG_RIP, ret)
        except:
            uc.emu_stop()

    mu.hook_add(UC_HOOK_CODE, hook_code)

    print(f"[EMU] Ready: binary={len(dump):,} bytes, base=0x{BASE:X}")
    return mu


def decode_packet(mu: Uc, pkt_data: bytes) -> bytes | None:
    """
    Decode a single 0x0425 packet using the mov_decrypt deserializer.

    Returns the decoded payload bytes, or None on failure.
    Uses the ROFL tool approach: zeroed struct, double-pointer payload setup.
    """
    # Reset heap
    mu.mem_write(0, st.pack("<Q", 0))

    # Zero the struct
    mu.mem_write(STRUCT_ADDR, b"\x00" * STRUCT_SIZE)

    # Set up payload with double-pointer (ROFL tool approach):
    # PKTBUF+0x00: pointer to start of payload data
    # The deserializer reads: RDX points to a location containing the payload pointer
    payload_addr = PKTBUF + 0x100
    mu.mem_write(PKTBUF, b"\x00" * 0x200)
    mu.mem_write(payload_addr, pkt_data)
    end_addr = payload_addr + len(pkt_data)

    # Double pointer: [PKTBUF] = payload_addr
    mu.mem_write(PKTBUF, st.pack("<Q", payload_addr))

    # Set up registers (Windows x64 calling convention)
    rsp = STACK + STACK_SZ - 0x100
    mu.mem_write(rsp, st.pack("<Q", STOP) + b"\x00" * 0x28)

    mu.reg_write(UC_X86_REG_RCX, STRUCT_ADDR)   # this pointer (zeroed struct)
    mu.reg_write(UC_X86_REG_RDX, PKTBUF)         # pointer to payload pointer
    mu.reg_write(UC_X86_REG_R8, end_addr)         # end of payload
    mu.reg_write(UC_X86_REG_RSP, rsp)

    for r in [UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RSI, UC_X86_REG_RDI,
              UC_X86_REG_RBP, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
              UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15]:
        mu.reg_write(r, 0)
    mu.reg_write(UC_X86_REG_RFLAGS, 0x202)

    # Run deserializer from start to end RVA
    try:
        mu.emu_start(BASE + DESER_START, BASE + DESER_END,
                     timeout=30_000_000, count=MAX_INSN)
    except UcError as e:
        return None

    # Read decoded payload from struct
    payload_ptr = st.unpack("<Q", bytes(mu.mem_read(STRUCT_ADDR + PAYLOAD_OFF, 8)))[0]
    payload_size = st.unpack("<Q", bytes(mu.mem_read(STRUCT_ADDR + PAYLOAD_SZ_OFF, 8)))[0]

    if payload_ptr == 0 or payload_size == 0 or payload_size > 0x10000:
        return None

    try:
        decoded = bytes(mu.mem_read(payload_ptr, payload_size))
        return decoded
    except:
        return None


def parse_path_packet(timestamp: float, payload: bytes) -> dict | None:
    """
    Parse a decoded movement payload into a PathPacket.

    Format (from ROFL tool's packet.rs):
      u16 parsing_type
      u32 entity_id
      f32 speed
      [optional skip byte if parsing_type & 1]
      [bitmask bytes]
      [waypoint data: pairs of u16 or u8 coordinates]

    Waypoint conversion:
      x = sign_extend(u16, 16) * 2.0 + 7358.0
      y = sign_extend(u16, 16) * 2.0 + 7412.0
    """
    if len(payload) < 10:
        return None

    offset = 0
    parsing_type = st.unpack_from("<H", payload, offset)[0]; offset += 2
    entity_id = st.unpack_from("<I", payload, offset)[0]; offset += 4
    speed = st.unpack_from("<f", payload, offset)[0]; offset += 4

    if (parsing_type & 1) != 0:
        offset += 1  # skip byte

    # Save remaining bytes for bitmask lookups
    temp_arr = payload[offset:]

    num_waypoints = (parsing_type >> 1) & 0xFFFF
    if num_waypoints == 0:
        return None

    # Skip bitmask bytes (if more than 1 waypoint)
    if num_waypoints > 1:
        bitmask_bytes = ((num_waypoints - 2) >> 2) + 1
        offset += bitmask_bytes

    # Parse waypoints
    x_coord = 0
    y_coord = 0
    waypoints = []
    v13 = 0  # bit position in bitmask

    for i in range(num_waypoints):
        v14 = 2  # x size (2 = u16, 1 = u8)
        v15 = 2  # y size

        if i != 0:
            # Read 2 bits from bitmask to determine delta encoding
            v16 = v13
            v17 = v13 & 7
            if v13 < 0:
                v16 = v13 + 7
                v17 = (v13 & 7) - 8

            byte_idx = v16 >> 3
            if byte_idx < len(temp_arr):
                v18 = temp_arr[byte_idx]
                v19 = v13 + 1
                v20 = -((1 << v17) & ctypes.c_int8(v18).value)
                v14 = 2 - (1 if v20 != 0 else 0)

                v21 = v19 & 7
                if v19 < 0:
                    v19 = v13 + 8
                    v21 = (v19 & 7) - 8

                byte_idx2 = v19 >> 3
                if byte_idx2 < len(temp_arr):
                    v15 = 2 - (1 if ((1 << v21) & temp_arr[byte_idx2]) != 0 else 0)

            v13 += 2

        if offset >= len(payload):
            break

        if v14 == 1:
            if offset < len(payload):
                x_coord = (x_coord + payload[offset]) & 0xFFFF
                offset += 1
        else:
            if offset + 2 <= len(payload):
                x_coord = st.unpack_from("<H", payload, offset)[0]
                offset += 2

        if v15 == 1:
            if offset < len(payload):
                y_coord = (y_coord + payload[offset]) & 0xFFFF
                offset += 1
        else:
            if offset + 2 <= len(payload):
                y_coord = st.unpack_from("<H", payload, offset)[0]
                offset += 2

        x = sign_extend(x_coord, 16) * 2.0 + 7358.0
        y = sign_extend(y_coord, 16) * 2.0 + 7412.0
        waypoints.append((round(x, 1), round(y, 1)))

    return {
        "t": round(timestamp, 2),
        "id": entity_id,
        "speed": round(speed, 1),
        "waypoints": waypoints,
    }


def main():
    from ml.parsers.rofl_parser import ROFLParser
    from ml.parsers.chunk_parser import parse_payload_frames

    rofl_path = r"C:\Users\ngan9\OneDrive\Documents\League of Legends\Replays\TW2-396324158.rofl"

    print("Setting up emulator...")
    mu = setup_emulator()

    print("Loading replay...")
    rofl = ROFLParser(rofl_path)
    frames = rofl.decompress_payload_frames()
    payload = parse_payload_frames(frames, parse_packets=True)

    # Collect all 0x0425 packets
    packets_0425 = []
    for fr in payload.frames:
        for p in fr.packets:
            if p.packet_id == 0x0425:
                packets_0425.append((fr.header.timestamp, p))

    print(f"Found {len(packets_0425)} packets with ID 0x0425")

    # Decode
    t0 = time.time()
    decoded_count = 0
    failed_count = 0
    paths = []

    for i, (ts, pkt) in enumerate(packets_0425):
        decoded = decode_packet(mu, pkt.data)
        if decoded:
            path = parse_path_packet(ts, decoded)
            if path:
                paths.append(path)
                decoded_count += 1
            else:
                failed_count += 1
        else:
            failed_count += 1

        if (i + 1) % 500 == 0:
            elapsed = time.time() - t0
            rate = (i + 1) / elapsed if elapsed > 0 else 0
            print(f"  [{i+1}/{len(packets_0425)}] decoded={decoded_count} "
                  f"failed={failed_count} ({elapsed:.1f}s, {rate:.0f} pkt/s)")

    elapsed = time.time() - t0
    print(f"\nDone: {decoded_count} decoded, {failed_count} failed in {elapsed:.1f}s")

    # Show sample
    if paths:
        print(f"\nFirst 5 decoded paths:")
        for p in paths[:5]:
            print(f"  t={p['t']:.1f}s id={p['id']} speed={p['speed']} "
                  f"wp={len(p['waypoints'])} → {p['waypoints'][:3]}")

        # Get unique entity IDs
        ids = set(p["id"] for p in paths)
        print(f"\nUnique entity IDs: {len(ids)}")
        from collections import Counter
        id_counts = Counter(p["id"] for p in paths)
        print("Top 20 entities by movement count:")
        for eid, cnt in id_counts.most_common(20):
            print(f"  id={eid}: {cnt} movements")

    # Save
    output_path = "ml/data/movement_data.json"
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps({
        "replay": Path(rofl_path).stem,
        "total_0425_packets": len(packets_0425),
        "decoded": decoded_count,
        "failed": failed_count,
        "decode_time_s": round(elapsed, 2),
        "paths": paths,
    }, indent=2), encoding="utf-8")
    print(f"\nSaved to {output_path}")


if __name__ == "__main__":
    main()

"""
Parse decompressed ROFL v2 payload into chunks, keyframes, and raw game packets.

ROFL v2 payload structure (after zstd decompression):
  The decompressed payload is a SINGLE byte stream containing sequential
  chunk and keyframe entries. Zstd frame boundaries do NOT align with
  chunk boundaries — you MUST concatenate all decompressed frames first.

  Each entry in the stream:
    [type:        u8 ]   1 = chunk, 2 = keyframe
    [block_id:    u32]   sequence number (0, 1, 2, ...)
    [content_len: u32]   size of the content that follows
    [timestamp:   u32]   game time in milliseconds
    [flags:       u16]   unknown / padding
    [content:     N B]   the actual game data (batched ENet packets)
    Total header: 15 bytes

  Content (inside each chunk) contains the batched game packets in
  Riot's proprietary binary format. Full decoding of individual packet
  payloads (positions, spells, etc.) requires the game engine emulator
  (see Maknee/Sabrina). We CAN extract packet boundaries if we figure
  out the inner batch format.

Usage:
    from ml.parsers.chunk_parser import parse_payload_stream

    # frames = list of decompressed zstd frame bytes
    result = parse_payload_stream(frames)
    for entry in result.entries:
        print(entry)
"""

from __future__ import annotations

import struct
from collections import Counter
from dataclasses import dataclass, field


# ── Data structures ───────────────────────────────────────────────────


CHUNK_TYPE = 1
KEYFRAME_TYPE = 2
ENTRY_HEADER_SIZE = 15


@dataclass
class PayloadEntry:
    """A single chunk or keyframe extracted from the payload stream."""
    entry_type: int          # 1 = chunk, 2 = keyframe
    block_id: int            # sequence number
    content_length: int      # declared content size
    timestamp_ms: int        # game time in ms
    flags: int               # unknown
    content: bytes           # raw content data
    stream_offset: int       # byte offset in concatenated stream

    @property
    def type_name(self) -> str:
        return {1: "chunk", 2: "keyframe"}.get(self.entry_type, f"unk({self.entry_type})")

    @property
    def time_sec(self) -> float:
        return self.timestamp_ms / 1000.0

    def __repr__(self) -> str:
        return (f"PayloadEntry({self.type_name} #{self.block_id}, "
                f"t={self.time_sec:.1f}s, {len(self.content):,}B)")


@dataclass
class PayloadParseResult:
    """Result of parsing the full payload stream."""
    entries: list[PayloadEntry]
    total_stream_size: int
    bytes_consumed: int        # how many bytes were parsed into entries
    errors: list[str] = field(default_factory=list)

    @property
    def n_chunks(self) -> int:
        return sum(1 for e in self.entries if e.entry_type == CHUNK_TYPE)

    @property
    def n_keyframes(self) -> int:
        return sum(1 for e in self.entries if e.entry_type == KEYFRAME_TYPE)

    @property
    def parse_ratio(self) -> float:
        return self.bytes_consumed / self.total_stream_size if self.total_stream_size else 0


# ── Stream parsing ───────────────────────────────────────────────────


def _read_entry_header(data: bytes, offset: int) -> tuple[int, int, int, int, int] | None:
    """
    Try to read a 15-byte entry header at the given offset.
    Returns (type, block_id, content_len, timestamp_ms, flags) or None.
    """
    if offset + ENTRY_HEADER_SIZE > len(data):
        return None

    entry_type = data[offset]
    if entry_type not in (CHUNK_TYPE, KEYFRAME_TYPE):
        return None

    block_id = struct.unpack_from("<I", data, offset + 1)[0]
    content_len = struct.unpack_from("<I", data, offset + 5)[0]
    timestamp_ms = struct.unpack_from("<I", data, offset + 9)[0]
    flags = struct.unpack_from("<H", data, offset + 13)[0]

    return entry_type, block_id, content_len, timestamp_ms, flags


def _validate_entry(entry_type: int, block_id: int, content_len: int,
                    timestamp_ms: int, remaining: int,
                    prev_entry: PayloadEntry | None) -> bool:
    """Heuristic validation of an entry header."""
    # Content must fit in remaining data
    if content_len > remaining - ENTRY_HEADER_SIZE:
        return False

    # Reasonable content size (0 to 10MB)
    if content_len > 10_000_000:
        return False

    # Game time should be reasonable (0 to 120 minutes = 7,200,000 ms)
    if timestamp_ms > 7_200_000:
        return False

    # Block IDs should be reasonable (0 to 500)
    if block_id > 500:
        return False

    # If we have a previous entry, timestamps should not decrease too much
    if prev_entry is not None:
        # Allow same or increasing time (keyframes can share timestamps with chunks)
        if timestamp_ms < prev_entry.timestamp_ms - 60000:
            return False

    return True


def parse_payload_stream(frames: list[bytes]) -> PayloadParseResult:
    """
    Concatenate decompressed frames and parse the payload stream into
    chunk/keyframe entries.

    Args:
        frames: List of decompressed zstd frame byte strings.

    Returns:
        PayloadParseResult with extracted entries.
    """
    # Concatenate all frames into one stream
    stream = b"".join(frames)
    total_size = len(stream)

    entries: list[PayloadEntry] = []
    errors: list[str] = []
    pos = 0

    while pos < total_size - ENTRY_HEADER_SIZE:
        hdr = _read_entry_header(stream, pos)

        if hdr is None:
            # Not a valid header at this position — scan forward
            # Look for next type byte (0x01 or 0x02)
            found = False
            scan_start = pos
            for scan_pos in range(pos + 1, min(pos + 1024, total_size)):
                if stream[scan_pos] in (CHUNK_TYPE, KEYFRAME_TYPE):
                    test_hdr = _read_entry_header(stream, scan_pos)
                    if test_hdr is not None:
                        remaining = total_size - scan_pos
                        prev = entries[-1] if entries else None
                        if _validate_entry(*test_hdr, remaining, prev):
                            skipped = scan_pos - pos
                            if skipped > 0:
                                errors.append(f"Skipped {skipped}B at offset {pos}")
                            pos = scan_pos
                            found = True
                            break

            if not found:
                # No valid header found in next 1KB — we're lost
                # Try jumping further
                errors.append(f"Lost sync at offset {pos}, scanning...")
                pos += 1
                continue

            # Re-read header at new position
            hdr = _read_entry_header(stream, pos)
            if hdr is None:
                pos += 1
                continue

        entry_type, block_id, content_len, timestamp_ms, flags = hdr
        remaining = total_size - pos

        if not _validate_entry(entry_type, block_id, content_len,
                               timestamp_ms, remaining,
                               entries[-1] if entries else None):
            pos += 1
            continue

        # Extract content
        content_start = pos + ENTRY_HEADER_SIZE
        content_end = content_start + content_len
        content = stream[content_start:content_end]

        entries.append(PayloadEntry(
            entry_type=entry_type,
            block_id=block_id,
            content_length=content_len,
            timestamp_ms=timestamp_ms,
            flags=flags,
            content=content,
            stream_offset=pos,
        ))

        pos = content_end

    bytes_consumed = sum(ENTRY_HEADER_SIZE + e.content_length for e in entries)

    return PayloadParseResult(
        entries=entries,
        total_stream_size=total_size,
        bytes_consumed=bytes_consumed,
        errors=errors,
    )


# ── Inner packet parsing (experimental) ──────────────────────────────


@dataclass
class RawPacket:
    """A single game packet extracted from chunk content."""
    time_delta: int       # time offset byte
    time_abs: float       # absolute time (from 0xFF marker), -1 if relative
    channel: int          # channel byte (& 0x7F)
    size: int             # payload size
    data: bytes           # raw payload
    offset: int           # offset within chunk content


def parse_chunk_packets(content: bytes) -> tuple[list[RawPacket], int, list[str]]:
    """
    Attempt to parse batched ENet packets from chunk content.

    LoL replay packet format (from community RE):
      [time_delta: u8]  (0xFF = absolute time follows as f32)
      [channel:    u8]  (bit 7 set → short packet, size in next u8)
                        (bit 7 clear → long packet, size in next u32 LE)
      [payload:    N B]

    Returns (packets, bytes_consumed, errors).
    """
    packets: list[RawPacket] = []
    errors: list[str] = []
    pos = 0

    while pos < len(content) - 2:
        pkt_start = pos

        # Time delta
        time_delta = content[pos]
        pos += 1
        time_abs = -1.0

        if time_delta == 0xFF:
            if pos + 4 > len(content):
                break
            time_abs = struct.unpack_from("<f", content, pos)[0]
            pos += 4

        # Channel
        if pos >= len(content):
            break
        channel_raw = content[pos]
        pos += 1

        short = bool(channel_raw & 0x80)
        channel = channel_raw & 0x7F

        # Size
        if short:
            if pos >= len(content):
                break
            pkt_size = content[pos]
            pos += 1
        else:
            if pos + 4 > len(content):
                break
            pkt_size = struct.unpack_from("<I", content, pos)[0]
            pos += 4

        # Validate
        if pkt_size > len(content) - pos:
            errors.append(f"size overflow ({pkt_size}) at content offset {pkt_start}")
            break

        payload = content[pos:pos + pkt_size]
        pos += pkt_size

        packets.append(RawPacket(
            time_delta=time_delta,
            time_abs=time_abs,
            channel=channel,
            size=pkt_size,
            data=payload,
            offset=pkt_start,
        ))

    return packets, pos, errors


# ── Analysis / display helpers ────────────────────────────────────────


def print_payload_summary(result: PayloadParseResult):
    """Print a summary of the parsed payload."""
    print(f"\n{'='*70}")
    print(f"Payload stream: {result.total_stream_size:,} bytes")
    print(f"Entries found:  {len(result.entries)} "
          f"({result.n_chunks} chunks + {result.n_keyframes} keyframes)")
    print(f"Bytes consumed: {result.bytes_consumed:,} / {result.total_stream_size:,} "
          f"({result.parse_ratio:.1%})")
    print(f"Errors:         {len(result.errors)}")
    print(f"{'='*70}")

    if not result.entries:
        print("  No entries found!")
        if result.errors:
            print(f"\n  First errors:")
            for e in result.errors[:10]:
                print(f"    {e}")
        return

    # Entry table
    print(f"\n{'─'*80}")
    print(f"  {'#':>4s} | {'Type':<8s} | {'BlkID':>5s} | {'Time':>10s} | "
          f"{'Content':>10s} | {'Flags':>5s} | {'Offset':>10s}")
    print(f"{'─'*80}")

    for i, e in enumerate(result.entries):
        time_str = f"{e.timestamp_ms // 60000}:{(e.timestamp_ms % 60000) // 1000:02d}.{e.timestamp_ms % 1000:03d}"
        print(f"  {i:>4d} | {e.type_name:<8s} | {e.block_id:>5d} | {time_str:>10s} | "
              f"{e.content_length:>8,} B | {e.flags:>5d} | {e.stream_offset:>8,}")

    print(f"{'─'*80}")

    # Time range
    times = [e.timestamp_ms for e in result.entries]
    print(f"\n  Time range: {min(times)/1000:.1f}s → {max(times)/1000:.1f}s "
          f"({(max(times) - min(times)) / 60000:.1f} min)")

    # Chunk vs keyframe size comparison
    chunk_sizes = [e.content_length for e in result.entries if e.entry_type == CHUNK_TYPE]
    kf_sizes = [e.content_length for e in result.entries if e.entry_type == KEYFRAME_TYPE]

    if chunk_sizes:
        print(f"\n  Chunks ({len(chunk_sizes)}): "
              f"min={min(chunk_sizes):,}  max={max(chunk_sizes):,}  "
              f"avg={sum(chunk_sizes)//len(chunk_sizes):,}  total={sum(chunk_sizes):,}")
    if kf_sizes:
        print(f"  Keyframes ({len(kf_sizes)}): "
              f"min={min(kf_sizes):,}  max={max(kf_sizes):,}  "
              f"avg={sum(kf_sizes)//len(kf_sizes):,}  total={sum(kf_sizes):,}")

    # Content hex preview of first entry
    if result.entries:
        e = result.entries[0]
        print(f"\n── Hex preview: entry 0 ({e.type_name} #{e.block_id}) first 128B ──")
        data = e.content[:128]
        for off in range(0, len(data), 16):
            chunk = data[off:off + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            print(f"  {off:04x}: {hex_part:<48s} {ascii_part}")

    # Also preview a keyframe if available
    kf_entries = [e for e in result.entries if e.entry_type == KEYFRAME_TYPE]
    if kf_entries:
        e = kf_entries[0]
        print(f"\n── Hex preview: first keyframe ({e.type_name} #{e.block_id}) first 128B ──")
        data = e.content[:128]
        for off in range(0, len(data), 16):
            chunk = data[off:off + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            print(f"  {off:04x}: {hex_part:<48s} {ascii_part}")

    # Errors
    if result.errors:
        print(f"\n── Parse errors (first 10 of {len(result.errors)}) ──")
        for e in result.errors[:10]:
            print(f"  {e}")


def try_inner_packet_parse(result: PayloadParseResult, max_entries: int = 3):
    """Try parsing packets from the first few chunk entries."""
    chunks = [e for e in result.entries if e.entry_type == CHUNK_TYPE]
    if not chunks:
        print("\n  No chunks to parse packets from.")
        return

    print(f"\n{'='*70}")
    print(f"Attempting inner packet parse on first {min(max_entries, len(chunks))} chunks...")
    print(f"{'='*70}")

    for e in chunks[:max_entries]:
        pkts, consumed, errs = parse_chunk_packets(e.content)
        ratio = consumed / len(e.content) if e.content else 0

        print(f"\n  Chunk #{e.block_id} (t={e.time_sec:.1f}s, {len(e.content):,}B):")
        print(f"    Packets: {len(pkts)}, consumed: {consumed:,}/{len(e.content):,} ({ratio:.0%})")

        if errs:
            print(f"    Errors: {errs[:3]}")

        if pkts:
            # Show first few packets
            channels = Counter(p.channel for p in pkts)
            print(f"    Channels: {dict(channels.most_common(10))}")
            print(f"    First 5 packets:")
            for i, p in enumerate(pkts[:5]):
                time_str = f"t={p.time_abs:.3f}s" if p.time_abs >= 0 else f"dt={p.time_delta}"
                hex_pre = p.data[:32].hex() if p.data else "(empty)"
                print(f"      [{i}] {time_str:<14s} ch={p.channel} size={p.size:>5d}  {hex_pre}")

    # Byte frequency analysis on first chunk content
    if chunks:
        content = chunks[0].content
        freq = Counter(content)
        top = freq.most_common(10)
        print(f"\n── Byte frequency (chunk 0, {len(content):,}B) ──")
        for byte_val, count in top:
            pct = count / len(content) * 100
            print(f"  0x{byte_val:02X} ({byte_val:>3d}): {count:>6,} ({pct:.1f}%)")

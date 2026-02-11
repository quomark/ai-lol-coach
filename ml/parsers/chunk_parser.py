"""
Parse decompressed ROFL v2 payload into chunks, keyframes, and raw game packets.

ROFL v2 payload structure:
  - Decompresses to multiple zstd frames
  - Frame 0: [15B header][content] — the header gives type, seq, timestamp, content_len
  - Frames 1+: raw chunk/keyframe content (no header)
  - Each zstd frame corresponds to one chunk OR one keyframe
  - Expected: lastGameChunkId chunks + lastKeyFrameId keyframes ≈ number of frames

  The content of each chunk/keyframe is Riot's proprietary batched game packet format.
  Full decoding requires the game engine emulator (Maknee/Sabrina).
  We can extract frame-level structure and statistics.

Usage:
    from ml.parsers.chunk_parser import parse_payload_frames, print_frame_analysis

    frames = rofl_parser.decompress_payload_frames()
    result = parse_payload_frames(frames)
    print_frame_analysis(result)
"""

from __future__ import annotations

import struct
from collections import Counter
from dataclasses import dataclass, field


# ── Data structures ───────────────────────────────────────────────────


ENTRY_HEADER_SIZE = 15


@dataclass
class FrameHeader:
    """Parsed 15-byte header (only present on frame 0)."""
    entry_type: int       # 1 = chunk, 2 = keyframe
    block_id: int         # sequence number
    content_len: int      # declared content size
    timestamp_ms: int     # game time in ms
    flags: int

    @property
    def type_name(self) -> str:
        return {1: "chunk", 2: "keyframe"}.get(self.entry_type, f"unk({self.entry_type})")


@dataclass
class FrameInfo:
    """Info about a single decompressed zstd frame."""
    index: int
    raw_size: int
    header: FrameHeader | None  # Only set if header detected
    content: bytes              # Content after stripping header (if any)
    first_bytes: bytes          # First 32 bytes of raw frame (for analysis)

    @property
    def content_size(self) -> int:
        return len(self.content)

    @property
    def has_header(self) -> bool:
        return self.header is not None


@dataclass
class PayloadParseResult:
    """Result of parsing all frames."""
    frames: list[FrameInfo]
    total_decompressed: int
    total_content: int

    @property
    def n_with_header(self) -> int:
        return sum(1 for f in self.frames if f.has_header)


# ── Frame parsing ─────────────────────────────────────────────────────


def _try_parse_header(data: bytes) -> FrameHeader | None:
    """Try to parse a 15-byte entry header from the start of a frame."""
    if len(data) < ENTRY_HEADER_SIZE:
        return None

    entry_type = data[0]
    if entry_type not in (1, 2):
        return None

    block_id = struct.unpack_from("<I", data, 1)[0]
    content_len = struct.unpack_from("<I", data, 5)[0]
    timestamp_ms = struct.unpack_from("<I", data, 9)[0]
    flags = struct.unpack_from("<H", data, 13)[0]

    # Validate: header + content should equal frame size (±small tolerance)
    expected_total = ENTRY_HEADER_SIZE + content_len
    actual_total = len(data)

    if abs(expected_total - actual_total) <= 16:
        return FrameHeader(
            entry_type=entry_type,
            block_id=block_id,
            content_len=content_len,
            timestamp_ms=timestamp_ms,
            flags=flags,
        )

    # Also try: content_len should be reasonable
    if content_len < actual_total and timestamp_ms < 7_200_000 and block_id < 500:
        return FrameHeader(
            entry_type=entry_type,
            block_id=block_id,
            content_len=content_len,
            timestamp_ms=timestamp_ms,
            flags=flags,
        )

    return None


def parse_payload_frames(frames: list[bytes]) -> PayloadParseResult:
    """
    Parse each decompressed zstd frame individually.

    Frame 0 typically has a 15-byte header. Remaining frames are raw content.
    """
    result_frames: list[FrameInfo] = []

    for i, raw in enumerate(frames):
        header = _try_parse_header(raw)

        if header is not None:
            content = raw[ENTRY_HEADER_SIZE:]
        else:
            content = raw

        result_frames.append(FrameInfo(
            index=i,
            raw_size=len(raw),
            header=header,
            content=content,
            first_bytes=raw[:32],
        ))

    total_decompressed = sum(f.raw_size for f in result_frames)
    total_content = sum(f.content_size for f in result_frames)

    return PayloadParseResult(
        frames=result_frames,
        total_decompressed=total_decompressed,
        total_content=total_content,
    )


# ── Analysis & display ────────────────────────────────────────────────


def _hex_line(data: bytes, offset: int = 0) -> str:
    """Format bytes as hex + ascii."""
    hex_part = " ".join(f"{b:02x}" for b in data)
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return f"  {offset:04x}: {hex_part:<48s} {ascii_part}"


def _hex_dump(data: bytes, max_bytes: int = 128) -> str:
    """Multi-line hex dump."""
    lines = []
    for off in range(0, min(len(data), max_bytes), 16):
        chunk = data[off:off + 16]
        lines.append(_hex_line(chunk, off))
    return "\n".join(lines)


def print_frame_analysis(result: PayloadParseResult,
                         n_chunks_expected: int = 0,
                         n_keyframes_expected: int = 0):
    """Print comprehensive analysis of parsed frames."""

    print(f"\n{'='*70}")
    print(f"Payload: {result.total_decompressed:,} bytes decompressed "
          f"→ {result.total_content:,} bytes content")
    print(f"Frames:  {len(result.frames)} "
          f"({result.n_with_header} with header)")
    if n_chunks_expected or n_keyframes_expected:
        print(f"Expected: {n_chunks_expected} chunks + {n_keyframes_expected} keyframes "
              f"= {n_chunks_expected + n_keyframes_expected}")
    print(f"{'='*70}")

    # ── Frame 0 header details ──
    f0 = result.frames[0] if result.frames else None
    if f0 and f0.header:
        h = f0.header
        print(f"\n── Frame 0 header (confirmed) ──")
        print(f"  Type:        {h.entry_type} ({h.type_name})")
        print(f"  Block ID:    {h.block_id}")
        print(f"  Content len: {h.content_len:,}")
        print(f"  Timestamp:   {h.timestamp_ms} ms ({h.timestamp_ms/1000:.1f}s)")
        print(f"  Flags:       {h.flags}")
        print(f"  Frame total: {f0.raw_size:,} (header {ENTRY_HEADER_SIZE} + content {h.content_len:,})")

    # ── Size distribution ──
    sizes = sorted([f.content_size for f in result.frames])
    print(f"\n── Frame size distribution ──")
    print(f"  Min:    {sizes[0]:>10,} B")
    print(f"  Median: {sizes[len(sizes)//2]:>10,} B")
    print(f"  Mean:   {sum(sizes)//len(sizes):>10,} B")
    print(f"  Max:    {sizes[-1]:>10,} B")

    # ── Classify frames by size into likely chunks vs keyframes ──
    # Keyframes (full state snapshots) are typically MUCH larger than chunks (delta data)
    # With 55 chunks + 27 keyframes, roughly the top 1/3 by size are keyframes
    n_kf = n_keyframes_expected or len(result.frames) // 3
    threshold = sorted(sizes, reverse=True)[min(n_kf, len(sizes) - 1)] if n_kf > 0 else sizes[-1]

    small_frames = [f for f in result.frames if f.content_size < threshold]
    large_frames = [f for f in result.frames if f.content_size >= threshold]

    if small_frames and large_frames:
        small_sizes = [f.content_size for f in small_frames]
        large_sizes = [f.content_size for f in large_frames]
        print(f"\n── Size-based classification (threshold: {threshold:,}B) ──")
        print(f"  Small (likely chunks):    {len(small_frames):>3d} frames, "
              f"avg {sum(small_sizes)//len(small_sizes):,}B")
        print(f"  Large (likely keyframes): {len(large_frames):>3d} frames, "
              f"avg {sum(large_sizes)//len(large_sizes):,}B")

    # ── First bytes pattern analysis ──
    print(f"\n── First 32 bytes of each frame (first 10 + last 3) ──")

    show_frames = result.frames[:10]
    if len(result.frames) > 13:
        show_frames += result.frames[-3:]

    for f in show_frames:
        size_label = f"({f.raw_size:>10,}B)"
        hdr_label = " [HDR]" if f.has_header else "      "
        hex_str = " ".join(f"{b:02x}" for b in f.first_bytes)
        print(f"  Frame {f.index:>3d} {size_label}{hdr_label}: {hex_str}")

    if len(result.frames) > 13:
        print(f"  ... ({len(result.frames) - 13} frames not shown)")

    # ── First-byte histogram across all frames ──
    first_bytes = Counter()
    for f in result.frames:
        if f.content:
            first_bytes[f.content[0]] += 1

    print(f"\n── First byte of content across all frames ──")
    for byte_val, count in first_bytes.most_common(10):
        print(f"  0x{byte_val:02X} ({byte_val:>3d}): {count:>3d} frames")

    # ── Byte frequency in first few frames' content ──
    print(f"\n── Byte frequency analysis (frame 0 content, {result.frames[0].content_size:,}B) ──")
    freq = Counter(result.frames[0].content)
    for byte_val, count in freq.most_common(15):
        pct = count / len(result.frames[0].content) * 100
        print(f"  0x{byte_val:02X} ({byte_val:>3d}): {count:>5,} ({pct:.1f}%)")

    # Compare with a middle frame
    mid_idx = len(result.frames) // 2
    mid_frame = result.frames[mid_idx]
    print(f"\n── Byte frequency analysis (frame {mid_idx} content, {mid_frame.content_size:,}B) ──")
    freq2 = Counter(mid_frame.content)
    for byte_val, count in freq2.most_common(15):
        pct = count / len(mid_frame.content) * 100
        print(f"  0x{byte_val:02X} ({byte_val:>3d}): {count:>5,} ({pct:.1f}%)")

    # ── Content hex preview of first 3 frames ──
    for f in result.frames[:3]:
        hdr_note = " (after header)" if f.has_header else ""
        print(f"\n── Hex: frame {f.index} content{hdr_note} ({f.content_size:,}B) ──")
        print(_hex_dump(f.content, 128))

    # ── Also show a large frame (likely keyframe) ──
    largest = max(result.frames, key=lambda f: f.content_size)
    if largest.index > 2:
        print(f"\n── Hex: frame {largest.index} (largest, {largest.content_size:,}B) ──")
        print(_hex_dump(largest.content, 128))


def print_inner_packet_attempt(result: PayloadParseResult, max_frames: int = 3):
    """
    Try several heuristic packet parsers on the first few frames' content.
    Since we don't know the exact format, try multiple approaches.
    """
    print(f"\n{'='*70}")
    print(f"Inner packet parsing attempts")
    print(f"{'='*70}")

    for f in result.frames[:max_frames]:
        content = f.content
        if len(content) < 8:
            continue

        print(f"\n  Frame {f.index} ({f.content_size:,}B):")

        # Approach 1: [time_delta:u8][channel:u8][size:u16 LE][payload]
        pkts_a, consumed_a = _try_format_a(content)
        ratio_a = consumed_a / len(content) if content else 0

        # Approach 2: [time_delta:u8][0xFF→f32 abs time][channel:u8 (bit7=short)][size:u8/u32][payload]
        pkts_b, consumed_b = _try_format_b(content)
        ratio_b = consumed_b / len(content) if content else 0

        # Approach 3: Skip first 8 bytes (possible sub-header), then format A
        pkts_c, consumed_c = _try_format_a(content[8:]) if len(content) > 8 else ([], 0)
        ratio_c = (consumed_c + 8) / len(content) if content else 0

        # Approach 4: [packet_id:u16][size:u16][payload]
        pkts_d, consumed_d = _try_format_d(content)
        ratio_d = consumed_d / len(content) if content else 0

        results = [
            ("A: [dt:u8][ch:u8][sz:u16][data]", pkts_a, consumed_a, ratio_a),
            ("B: [dt:u8/0xFF+f32][ch:u8 bit7][sz:u8/u32][data]", pkts_b, consumed_b, ratio_b),
            ("C: [8B skip]+A", pkts_c, consumed_c + 8, ratio_c),
            ("D: [id:u16][sz:u16][data]", pkts_d, consumed_d, ratio_d),
        ]

        for label, pkts, consumed, ratio in results:
            ch_dist = Counter(p[0] for p in pkts).most_common(5) if pkts else []
            sz_range = f"{min(p[1] for p in pkts)}-{max(p[1] for p in pkts)}" if pkts else "n/a"
            print(f"    {label}")
            print(f"      {len(pkts):>5d} pkts, {consumed:>8,}/{len(content):>8,}B ({ratio:.0%}), "
                  f"sizes: {sz_range}, ch: {ch_dist}")


def _try_format_a(data: bytes) -> tuple[list[tuple], int]:
    """[time_delta:u8][channel:u8][size:u16 LE][payload]"""
    pkts = []
    pos = 0
    while pos + 4 <= len(data):
        td = data[pos]
        ch = data[pos + 1]
        sz = struct.unpack_from("<H", data, pos + 2)[0]
        pos += 4
        if pos + sz > len(data):
            break
        pkts.append((ch, sz, td))
        pos += sz
    return pkts, pos


def _try_format_b(data: bytes) -> tuple[list[tuple], int]:
    """[time:u8 (0xFF→f32)][channel:u8 (bit7=short size)][size:u8/u32][payload]"""
    pkts = []
    pos = 0
    while pos < len(data) - 2:
        td = data[pos]
        pos += 1
        if td == 0xFF:
            if pos + 4 > len(data):
                break
            pos += 4  # skip f32 absolute time

        if pos >= len(data):
            break
        ch_raw = data[pos]
        pos += 1
        ch = ch_raw & 0x7F

        if ch_raw & 0x80:  # short
            if pos >= len(data):
                break
            sz = data[pos]
            pos += 1
        else:  # long
            if pos + 4 > len(data):
                break
            sz = struct.unpack_from("<I", data, pos)[0]
            pos += 4

        if pos + sz > len(data):
            break
        pkts.append((ch, sz, td))
        pos += sz
    return pkts, pos


def _try_format_d(data: bytes) -> tuple[list[tuple], int]:
    """[packet_id:u16][size:u16][payload]"""
    pkts = []
    pos = 0
    while pos + 4 <= len(data):
        pkt_id = struct.unpack_from("<H", data, pos)[0]
        sz = struct.unpack_from("<H", data, pos + 2)[0]
        pos += 4
        if pos + sz > len(data):
            break
        pkts.append((pkt_id, sz, 0))
        pos += sz
    return pkts, pos

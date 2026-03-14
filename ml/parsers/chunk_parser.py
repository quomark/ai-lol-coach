"""
Parse decompressed ROFL v2 payload frames.

ROFL v2 frame format (confirmed from hex analysis):
  EVERY zstd frame has a 15-byte header:
    [type:       u8 ]  1 = chunk, 2 = keyframe
    [timestamp: f32 ]  game time in seconds (LE)
    [field_a:   u32 ]  varies (chunk: often 2, keyframe: varies)
    [field_b:   u32 ]  varies (chunk: often 520, keyframe: often 818)
    [flags:     u16 ]  0x0000 or 0x4000

  After the header, the content contains batched game blocks.

  Inner block format (from Mowokuma/ROFL Rust parser):
    [marker: u8]  bit flags controlling field encoding:
      bit 7 (0x80): timestamp = delta (read u8 * 0.001s + acc) else absolute f32
      bit 6 (0x40): packet_id = reuse previous, else read u16
      bit 5 (0x20): param = delta (read u8 + prev), else absolute u32
      bit 4 (0x10): length = compact u8, else full u32
    [timestamp field]  either u8 delta or f32 absolute
    [length field]     either u8 or u32
    [packet_id field]  u16 or omitted (reuse prev)
    [param field]      u8 delta or u32 absolute
    [payload: length bytes]
"""

from __future__ import annotations

import struct
from collections import Counter
from dataclasses import dataclass, field


HEADER_SIZE = 15


@dataclass
class FrameHeader:
    """15-byte frame header."""
    frame_type: int       # 1=chunk, 2=keyframe
    timestamp: float      # game time seconds (f32)
    field_a: int          # u32
    field_b: int          # u32
    flags: int            # u16

    @property
    def type_name(self) -> str:
        return {1: "chunk", 2: "keyframe"}.get(self.frame_type, f"unk({self.frame_type})")

    @property
    def time_str(self) -> str:
        m = int(self.timestamp) // 60
        s = self.timestamp % 60
        return f"{m}:{s:05.2f}"


@dataclass
class ParsedPacket:
    """Single game block extracted from frame content."""
    timestamp: float     # accumulated game time in seconds
    packet_id: int       # u16 packet type ID
    param: int           # u32 param (often netID or sender)
    size: int            # payload length
    data: bytes          # raw payload bytes
    offset: int          # offset within content

    # Legacy aliases for compatibility
    @property
    def time_delta(self) -> int:
        return 0

    @property
    def channel(self) -> int:
        return self.packet_id & 0xFF


@dataclass
class FrameInfo:
    """Parsed frame with header, content, and optional inner packets."""
    index: int
    raw_size: int
    header: FrameHeader
    content: bytes
    packets: list[ParsedPacket] = field(default_factory=list)
    pkt_bytes_consumed: int = 0
    pkt_errors: list[str] = field(default_factory=list)

    @property
    def content_size(self) -> int:
        return len(self.content)

    @property
    def pkt_ratio(self) -> float:
        return self.pkt_bytes_consumed / len(self.content) if self.content else 0


@dataclass
class PayloadResult:
    frames: list[FrameInfo]

    @property
    def chunks(self) -> list[FrameInfo]:
        return [f for f in self.frames if f.header.frame_type == 1]

    @property
    def keyframes(self) -> list[FrameInfo]:
        return [f for f in self.frames if f.header.frame_type == 2]

    @property
    def total_packets(self) -> int:
        return sum(len(f.packets) for f in self.frames)


# ── Header parsing ────────────────────────────────────────────────────


def _parse_header(data: bytes) -> FrameHeader:
    """Parse 15-byte header. Always called — defaults if data too short."""
    if len(data) < HEADER_SIZE:
        return FrameHeader(0, 0.0, 0, 0, 0)

    frame_type = data[0]
    timestamp = struct.unpack_from("<f", data, 1)[0]
    field_a = struct.unpack_from("<I", data, 5)[0]
    field_b = struct.unpack_from("<I", data, 9)[0]
    flags = struct.unpack_from("<H", data, 13)[0]

    return FrameHeader(frame_type, timestamp, field_a, field_b, flags)


# ── Inner packet parsing ─────────────────────────────────────────────


def _parse_blocks(content: bytes) -> tuple[list[ParsedPacket], int, list[str]]:
    """
    Parse blocks using marker-byte format (from Mowokuma/ROFL).

    marker byte bits:
      0x80: timestamp is u8 delta (*0.001 + acc) vs f32 absolute
      0x40: packet_id reuses previous vs read u16
      0x20: param is u8 delta (+prev) vs u32 absolute
      0x10: length is u8 vs u32
    """
    pkts: list[ParsedPacket] = []
    errors: list[str] = []
    pos = 0
    acc_time = 0.0
    prev_packet_id = 0
    prev_param = 0

    while pos < len(content):
        block_start = pos

        # Read marker byte
        if pos >= len(content):
            break
        marker = content[pos]
        pos += 1

        try:
            # TIMESTAMP
            if marker & 0x80:
                if pos >= len(content):
                    errors.append(f"truncated timestamp at {block_start}")
                    break
                delta = content[pos]
                pos += 1
                acc_time += delta * 0.001
            else:
                if pos + 4 > len(content):
                    errors.append(f"truncated f32 timestamp at {block_start}")
                    break
                acc_time = struct.unpack_from("<f", content, pos)[0]
                pos += 4

            # LENGTH
            if marker & 0x10:
                if pos >= len(content):
                    errors.append(f"truncated u8 length at {block_start}")
                    break
                length = content[pos]
                pos += 1
            else:
                if pos + 4 > len(content):
                    errors.append(f"truncated u32 length at {block_start}")
                    break
                length = struct.unpack_from("<I", content, pos)[0]
                pos += 4

            # PACKET ID
            if marker & 0x40:
                packet_id = prev_packet_id
            else:
                if pos + 2 > len(content):
                    errors.append(f"truncated packet_id at {block_start}")
                    break
                packet_id = struct.unpack_from("<H", content, pos)[0]
                pos += 2

            # PARAM
            if marker & 0x20:
                if pos >= len(content):
                    errors.append(f"truncated u8 param at {block_start}")
                    break
                param_delta = content[pos]
                pos += 1
                param = param_delta + prev_param
            else:
                if pos + 4 > len(content):
                    errors.append(f"truncated u32 param at {block_start}")
                    break
                param = struct.unpack_from("<I", content, pos)[0]
                pos += 4

            # PAYLOAD
            if pos + length > len(content):
                errors.append(f"payload overflow: need {length}B at {pos}, have {len(content)-pos}")
                break

            payload = content[pos:pos + length]
            pos += length

            prev_packet_id = packet_id
            prev_param = param

            pkts.append(ParsedPacket(
                timestamp=acc_time,
                packet_id=packet_id,
                param=param,
                size=length,
                data=payload,
                offset=block_start,
            ))

        except Exception as e:
            errors.append(f"error at {block_start}: {e}")
            break

    return pkts, pos, errors


# ── Main parse function ──────────────────────────────────────────────


def parse_payload_frames(frames: list[bytes],
                         parse_packets: bool = True) -> PayloadResult:
    """Parse all decompressed zstd frames."""
    result: list[FrameInfo] = []

    for i, raw in enumerate(frames):
        # Frame header is derived from the block content (first block's timestamp)
        header = _parse_header(raw)

        # Block parser operates on the FULL decompressed frame data
        # (the first bytes are blocks, not a separate header)
        content = raw

        info = FrameInfo(
            index=i,
            raw_size=len(raw),
            header=header,
            content=content,
        )

        if parse_packets and len(content) > 4:
            pkts, consumed, errs = _parse_blocks(content)
            info.packets = pkts
            info.pkt_bytes_consumed = consumed
            info.pkt_errors = errs

        result.append(info)

    return PayloadResult(frames=result)


# ── Display ───────────────────────────────────────────────────────────


def _hex_dump(data: bytes, max_bytes: int = 128) -> str:
    lines = []
    for off in range(0, min(len(data), max_bytes), 16):
        chunk = data[off:off + 16]
        h = " ".join(f"{b:02x}" for b in chunk)
        a = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {off:04x}: {h:<48s} {a}")
    return "\n".join(lines)


def print_full_analysis(result: PayloadResult,
                        n_chunks_expected: int = 0,
                        n_keyframes_expected: int = 0):
    """Comprehensive output."""

    n_ch = len(result.chunks)
    n_kf = len(result.keyframes)
    total_pkts = result.total_packets
    total_content = sum(f.content_size for f in result.frames)
    total_pkt_bytes = sum(f.pkt_bytes_consumed for f in result.frames)

    print(f"\n{'='*75}")
    print(f"  Frames: {len(result.frames)} ({n_ch} chunks + {n_kf} keyframes)")
    if n_chunks_expected:
        print(f"  Expected: {n_chunks_expected} chunks + {n_keyframes_expected} keyframes")
    print(f"  Total content: {total_content:,} bytes")
    print(f"  Packets found: {total_pkts:,}")
    pct = total_pkt_bytes / total_content * 100 if total_content else 0
    print(f"  Packet bytes:  {total_pkt_bytes:,} / {total_content:,} ({pct:.1f}%)")
    print(f"{'='*75}")

    # ── Frame table ──
    print(f"\n── All frames (first 15, last 3) ──")
    print(f"  {'#':>3s} | {'Type':<8s} | {'Time':>8s} | {'Content':>10s} | "
          f"{'Pkts':>6s} | {'Parsed':>7s} | {'fA':>6s} | {'fB':>6s} | {'Fl':>6s}")
    print(f"  {'─'*80}")

    show = result.frames[:15]
    if len(result.frames) > 18:
        show += result.frames[-3:]

    for f in show:
        h = f.header
        ratio = f"{f.pkt_ratio:.0%}" if f.content else "n/a"
        print(f"  {f.index:>3d} | {h.type_name:<8s} | {h.time_str:>8s} | "
              f"{f.content_size:>8,} B | {len(f.packets):>6,} | {ratio:>7s} | "
              f"{h.field_a:>6d} | {h.field_b:>6d} | {h.flags:#06x}")

    if len(result.frames) > 18:
        print(f"  ... ({len(result.frames) - 18} more)")

    # ── Timestamp progression ──
    print(f"\n── Time progression ──")
    times = [(f.index, f.header.timestamp, f.header.type_name) for f in result.frames]
    # Show first 10, then last 5
    for idx, t, tn in times[:10]:
        print(f"  Frame {idx:>3d}: {t:>8.2f}s  ({tn})")
    if len(times) > 15:
        print(f"  ...")
        for idx, t, tn in times[-5:]:
            print(f"  Frame {idx:>3d}: {t:>8.2f}s  ({tn})")

    # ── Packet stats (if any) ──
    if total_pkts > 0:
        all_pkts = [p for f in result.frames for p in f.packets]

        # Channel distribution
        ch_counts = Counter(p.channel for p in all_pkts)
        print(f"\n── Channel distribution (top 15) ──")
        print(f"  {'Ch':>4s} | {'Count':>8s} | {'Hex':>5s}")
        for ch, count in ch_counts.most_common(15):
            print(f"  {ch:>4d} | {count:>8,} | 0x{ch:02X}")

        # Packet size distribution
        sizes = [p.size for p in all_pkts]
        print(f"\n── Packet size distribution ──")
        print(f"  Min: {min(sizes):,}  Max: {max(sizes):,}  "
              f"Avg: {sum(sizes)//len(sizes):,}  Median: {sorted(sizes)[len(sizes)//2]:,}")

        # Size buckets
        buckets = Counter()
        for s in sizes:
            if s == 0:
                buckets["0"] += 1
            elif s <= 10:
                buckets["1-10"] += 1
            elif s <= 50:
                buckets["11-50"] += 1
            elif s <= 200:
                buckets["51-200"] += 1
            elif s <= 1000:
                buckets["201-1K"] += 1
            elif s <= 10000:
                buckets["1K-10K"] += 1
            else:
                buckets["10K+"] += 1
        print(f"  Buckets: {dict(buckets)}")

        # Time delta distribution
        td_counts = Counter(p.time_delta for p in all_pkts)
        print(f"\n── Time delta distribution (top 10) ──")
        for td, count in td_counts.most_common(10):
            print(f"  dt={td:>3d} (0x{td:02X}): {count:>6,}")

        # First packet from first 3 frames with packets
        print(f"\n── Sample packets ──")
        shown = 0
        for f in result.frames:
            if not f.packets:
                continue
            if shown >= 3:
                break
            print(f"\n  Frame {f.index} ({f.header.type_name} @ {f.header.time_str}):")
            for p in f.packets[:5]:
                hex_pre = p.data[:24].hex() if p.data else "(empty)"
                print(f"    dt={p.time_delta:>3d} ch={p.channel:>3d} sz={p.size:>5d}  {hex_pre}")
            if len(f.packets) > 5:
                print(f"    ... ({len(f.packets) - 5} more)")
            shown += 1

    # ── Content hex for frames that had 0 packets ──
    zero_pkt_frames = [f for f in result.frames if not f.packets and f.content_size > 0]
    if zero_pkt_frames:
        print(f"\n── Frames with 0 packets ({len(zero_pkt_frames)}) ──")
        for f in zero_pkt_frames[:3]:
            print(f"\n  Frame {f.index} ({f.header.type_name} @ {f.header.time_str}, "
                  f"{f.content_size:,}B):")
            if f.pkt_errors:
                print(f"    Error: {f.pkt_errors[0]}")
            print(_hex_dump(f.content, 64))

    # ── Parse errors summary ──
    all_errs = [(f.index, e) for f in result.frames for e in f.pkt_errors]
    if all_errs:
        print(f"\n── Parse errors ({len(all_errs)}) ──")
        for idx, err in all_errs[:10]:
            print(f"  Frame {idx}: {err}")

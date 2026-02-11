"""
Parse decompressed ROFL payload frames into individual game packets.

Each decompressed zstd frame contains either a game **Chunk** (~30s of
incremental data) or a **KeyFrame** (full game state snapshot).

The binary format inside is Riot's proprietary batched-packet stream.
This parser extracts raw packets with timestamps and channel IDs.

Full payload decoding (positions, spell casts, etc.) requires running the
game engine in an emulator — see Maknee/Sabrina:
  https://maknee.github.io/blog/2025/League-Data-Scraping/

What this CAN extract:
  - Individual packet boundaries (offset, size)
  - Game timestamps per packet
  - ENet channel IDs
  - Packet type bytes (first 1-2 bytes of payload)
  - Statistics (packet counts, size distributions, channel breakdown)

What this CAN'T do without the game engine:
  - Map packet type IDs to event names (IDs change per patch)
  - Decode packet fields (positions, entity IDs, spell names)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field


# ── Data structures ───────────────────────────────────────────────────


@dataclass
class RawPacket:
    """A single game packet extracted from a frame."""
    time_delta: int      # raw time delta value (ticks)
    time_abs: float      # absolute time if available, else -1
    channel: int         # ENet channel (0-7 typical)
    size: int            # payload length
    data: bytes          # raw payload
    offset: int          # byte offset in frame content


@dataclass
class FrameHeader:
    """Header at the start of each decompressed frame."""
    frame_type: int      # raw type byte
    frame_type_name: str  # "chunk" | "keyframe" | "unknown"
    content_length: int
    header_size: int
    extra_fields: dict = field(default_factory=dict)


@dataclass
class ParsedFrame:
    """Complete parsed frame."""
    index: int
    header: FrameHeader
    packets: list[RawPacket]
    raw_size: int
    bytes_parsed: int
    errors: list[str] = field(default_factory=list)

    @property
    def parse_ratio(self) -> float:
        """Fraction of content bytes successfully parsed into packets."""
        content = self.raw_size - self.header.header_size
        return self.bytes_parsed / content if content > 0 else 0.0


# ── Frame header parsing ─────────────────────────────────────────────


def _try_header(data: bytes) -> FrameHeader | None:
    """
    Try to parse the frame header.

    ROFL v2 frame header (observed from 2026 replays):
      Byte 0:     frame_type  (u8)
      Bytes 1-4:  field_a     (u32 LE — chunk/keyframe sequence number?)
      Bytes 5-8:  content_len (u32 LE — size of remaining data)
      Bytes 9-12: field_b     (u32 LE — game time in ms? or sequence?)
      Bytes 13-14: field_c    (u16 LE — flags/padding?)
      Total: 15 bytes

    Falls back to smaller header sizes if 15-byte doesn't work.
    """
    if len(data) < 5:
        return None

    frame_type = data[0]
    type_name = {1: "chunk", 2: "keyframe"}.get(frame_type, "unknown")

    # Try 15-byte header: [type:1][seq:4][len:4][time:4][flags:2]
    if len(data) >= 15:
        seq = struct.unpack_from("<I", data, 1)[0]
        content_len = struct.unpack_from("<I", data, 5)[0]
        time_field = struct.unpack_from("<I", data, 9)[0]
        flags = struct.unpack_from("<H", data, 13)[0]

        expected_total = 15 + content_len
        if abs(expected_total - len(data)) <= 8:
            return FrameHeader(
                frame_type=frame_type,
                frame_type_name=type_name,
                content_length=content_len,
                header_size=15,
                extra_fields={"seq": seq, "time_ms": time_field, "flags": flags},
            )

    # Try 13-byte header: [type:1][seq:4][len:4][time:4]
    if len(data) >= 13:
        seq = struct.unpack_from("<I", data, 1)[0]
        content_len = struct.unpack_from("<I", data, 5)[0]
        time_field = struct.unpack_from("<I", data, 9)[0]

        expected_total = 13 + content_len
        if abs(expected_total - len(data)) <= 8:
            return FrameHeader(
                frame_type=frame_type,
                frame_type_name=type_name,
                content_length=content_len,
                header_size=13,
                extra_fields={"seq": seq, "time_ms": time_field},
            )

    # Try 9-byte header: [type:1][seq:4][len:4]
    if len(data) >= 9:
        seq = struct.unpack_from("<I", data, 1)[0]
        content_len = struct.unpack_from("<I", data, 5)[0]

        expected_total = 9 + content_len
        if abs(expected_total - len(data)) <= 8:
            return FrameHeader(
                frame_type=frame_type,
                frame_type_name=type_name,
                content_length=content_len,
                header_size=9,
                extra_fields={"seq": seq},
            )

    # No header — treat entire frame as content
    return FrameHeader(
        frame_type=0,
        frame_type_name="raw",
        content_length=len(data),
        header_size=0,
        extra_fields={},
    )


# ── Packet stream parsing ────────────────────────────────────────────


def _parse_packet_stream(data: bytes, start_offset: int = 0) -> tuple[list[RawPacket], int, list[str]]:
    """
    Parse a batched packet stream using the LoL replay format.

    Format per packet (from community RE):
      time_delta: u8
        - If 0xFF: next 4 bytes are absolute time as f32 LE
        - Otherwise: relative time in game ticks
      channel: u8
        - If bit 7 set: channel = (channel & 0x7F), size = next u8
        - If bit 7 clear: size = next u32 LE (or u16 LE in some versions)
      payload: bytes[size]

    Returns (packets, bytes_consumed, errors).
    """
    packets: list[RawPacket] = []
    errors: list[str] = []
    pos = 0

    while pos < len(data) - 2:
        pkt_start = pos

        # Time delta
        time_delta = data[pos]
        pos += 1
        time_abs = -1.0

        if time_delta == 0xFF:
            if pos + 4 > len(data):
                errors.append(f"truncated abs time at offset {pkt_start}")
                break
            time_abs = struct.unpack_from("<f", data, pos)[0]
            pos += 4

        # Channel byte
        if pos >= len(data):
            errors.append(f"truncated channel at offset {pkt_start}")
            break
        channel_byte = data[pos]
        pos += 1

        # Determine packet size based on channel encoding
        short_packet = bool(channel_byte & 0x80)
        channel = channel_byte & 0x7F

        if short_packet:
            # Short: 1-byte size
            if pos >= len(data):
                errors.append(f"truncated short size at offset {pkt_start}")
                break
            pkt_size = data[pos]
            pos += 1
        else:
            # Long: try u32 LE
            if pos + 4 > len(data):
                # Maybe u16?
                if pos + 2 <= len(data):
                    pkt_size = struct.unpack_from("<H", data, pos)[0]
                    pos += 2
                else:
                    errors.append(f"truncated long size at offset {pkt_start}")
                    break
            else:
                pkt_size = struct.unpack_from("<I", data, pos)[0]
                pos += 4

        # Sanity check size
        if pkt_size > len(data) - pos:
            # Size too large — maybe wrong format. Try u16 instead of u32.
            if not short_packet and pkt_size > 65535:
                pos = pkt_start + 1 + (5 if time_delta == 0xFF else 0) + 1
                if pos + 2 <= len(data):
                    pkt_size = struct.unpack_from("<H", data, pos)[0]
                    pos += 2
                    if pkt_size > len(data) - pos:
                        errors.append(f"size overflow ({pkt_size}) at offset {pkt_start}")
                        break
                else:
                    errors.append(f"size overflow at offset {pkt_start}")
                    break
            else:
                errors.append(f"size overflow ({pkt_size}) at offset {pkt_start}")
                break

        if pkt_size == 0:
            # Zero-length packets can happen (keepalive, etc.)
            packets.append(RawPacket(
                time_delta=time_delta, time_abs=time_abs,
                channel=channel, size=0, data=b"",
                offset=start_offset + pkt_start,
            ))
            continue

        # Extract payload
        pkt_data = data[pos : pos + pkt_size]
        pos += pkt_size

        packets.append(RawPacket(
            time_delta=time_delta, time_abs=time_abs,
            channel=channel, size=pkt_size, data=pkt_data,
            offset=start_offset + pkt_start,
        ))

    return packets, pos, errors


def _parse_packet_stream_alt(data: bytes, start_offset: int = 0) -> tuple[list[RawPacket], int, list[str]]:
    """
    Alternative parser: no time delta, just [channel:u8][size:u16 LE][data].
    Some replay formats use this simpler encoding.
    """
    packets: list[RawPacket] = []
    errors: list[str] = []
    pos = 0

    while pos < len(data) - 3:
        pkt_start = pos
        channel = data[pos]
        pos += 1
        pkt_size = struct.unpack_from("<H", data, pos)[0]
        pos += 2

        if pkt_size > len(data) - pos or pkt_size > 65535:
            errors.append(f"size overflow ({pkt_size}) at offset {pkt_start}")
            break

        pkt_data = data[pos : pos + pkt_size]
        pos += pkt_size

        packets.append(RawPacket(
            time_delta=0, time_abs=-1.0,
            channel=channel, size=pkt_size, data=pkt_data,
            offset=start_offset + pkt_start,
        ))

    return packets, pos, errors


# ── Main parse function ──────────────────────────────────────────────


def parse_frame(data: bytes, frame_index: int = 0) -> ParsedFrame:
    """
    Parse a single decompressed frame into header + packets.

    Tries multiple parsing strategies and returns the one that
    successfully parses the most bytes.
    """
    header = _try_header(data)
    if header is None:
        return ParsedFrame(
            index=frame_index, header=FrameHeader(0, "error", 0, 0),
            packets=[], raw_size=len(data), bytes_parsed=0,
            errors=["Frame too small to parse"],
        )

    content = data[header.header_size:]

    # Try strategy A: time_delta + channel (with short/long size)
    pkts_a, consumed_a, errs_a = _parse_packet_stream(content)
    # Try strategy B: simple channel + u16 size
    pkts_b, consumed_b, errs_b = _parse_packet_stream_alt(content)

    # Pick the strategy that parsed more data successfully
    if consumed_a >= consumed_b and len(pkts_a) > 0:
        return ParsedFrame(
            index=frame_index, header=header,
            packets=pkts_a, raw_size=len(data),
            bytes_parsed=consumed_a, errors=errs_a,
        )
    elif len(pkts_b) > 0:
        return ParsedFrame(
            index=frame_index, header=header,
            packets=pkts_b, raw_size=len(data),
            bytes_parsed=consumed_b, errors=errs_b,
        )
    else:
        return ParsedFrame(
            index=frame_index, header=header,
            packets=[], raw_size=len(data),
            bytes_parsed=0,
            errors=errs_a + errs_b + ["No parsing strategy succeeded"],
        )


def parse_all_frames(frames: list[bytes]) -> list[ParsedFrame]:
    """Parse all decompressed frames."""
    return [parse_frame(f, i) for i, f in enumerate(frames)]


# ── Analysis helpers ─────────────────────────────────────────────────


def frame_summary(parsed: ParsedFrame) -> str:
    """One-line summary of a parsed frame."""
    h = parsed.header
    n = len(parsed.packets)
    ratio = parsed.parse_ratio
    sizes = [p.size for p in parsed.packets] if parsed.packets else [0]
    channels = set(p.channel for p in parsed.packets)
    return (
        f"Frame {parsed.index:>3d} | {h.frame_type_name:<8s} | "
        f"{parsed.raw_size:>8,} B | "
        f"{n:>5d} pkts | "
        f"parsed {ratio:.0%} | "
        f"ch={sorted(channels)} | "
        f"sizes: {min(sizes)}-{max(sizes)}"
    )


def channel_breakdown(frames: list[ParsedFrame]) -> dict[int, dict]:
    """Aggregate packet stats by channel across all frames."""
    stats: dict[int, dict] = {}
    for f in frames:
        for p in f.packets:
            ch = p.channel
            if ch not in stats:
                stats[ch] = {"count": 0, "total_bytes": 0, "sizes": []}
            stats[ch]["count"] += 1
            stats[ch]["total_bytes"] += p.size
            stats[ch]["sizes"].append(p.size)

    for ch, s in stats.items():
        sizes = s["sizes"]
        s["min_size"] = min(sizes) if sizes else 0
        s["max_size"] = max(sizes) if sizes else 0
        s["avg_size"] = sum(sizes) // len(sizes) if sizes else 0
        del s["sizes"]  # don't keep raw list

    return dict(sorted(stats.items()))


def packet_type_histogram(frames: list[ParsedFrame]) -> dict[int, int]:
    """
    Count packets by their first byte (rough "packet type" proxy).
    The first byte of packet data is often the message type ID.
    """
    hist: dict[int, int] = {}
    for f in frames:
        for p in f.packets:
            if p.data:
                ptype = p.data[0]
                hist[ptype] = hist.get(ptype, 0) + 1
    return dict(sorted(hist.items(), key=lambda x: -x[1]))


def packet_type_histogram_u16(frames: list[ParsedFrame]) -> dict[int, int]:
    """
    Count packets by first 2 bytes as u16 LE (some packet types use 2-byte IDs).
    """
    hist: dict[int, int] = {}
    for f in frames:
        for p in f.packets:
            if len(p.data) >= 2:
                ptype = struct.unpack_from("<H", p.data, 0)[0]
                hist[ptype] = hist.get(ptype, 0) + 1
    return dict(sorted(hist.items(), key=lambda x: -x[1]))

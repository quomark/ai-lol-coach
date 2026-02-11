"""
Parse League of Legends .rofl replay files (ROFL v2 format, 2025+).

ROFL v2 layout (reverse-engineered from actual 2026 replay files):

  ┌──────────────────────────────────┐
  │ "RIOT" magic  (4 B)             │
  │ Format version (uint16le = 2)   │
  │ Header fields + game version    │  ← ~45 bytes total
  ├──────────────────────────────────┤
  │ Zstd-compressed game payload    │  ← starts at zstd magic (0x28B52FFD)
  │ (chunks & keyframes)            │
  ├──────────────────────────────────┤
  │ Metadata JSON  (uncompressed)   │  ← near end of file, ~last 200 KB
  └──────────────────────────────────┘

Usage:
    from ml.parsers.rofl_parser import ROFLParser

    parser = ROFLParser("path/to/replay.rofl")
    meta   = parser.get_metadata()       # raw metadata dict
    info   = parser.get_match_info()     # structured match info
"""

from __future__ import annotations

import io
import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Optional: zstandard for payload decompression
try:
    import zstandard

    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


# ── Data classes ───────────────────────────────────────────────────────


@dataclass
class ROFLHeader:
    format_version: int
    game_version: str
    file_size: int
    payload_offset: int  # byte offset where zstd data starts
    metadata_offset: int  # byte offset where JSON metadata starts


@dataclass
class ROFLData:
    header: ROFLHeader
    metadata: dict[str, Any]


# ── Parser ─────────────────────────────────────────────────────────────


class ROFLParser:
    """Parse .rofl replay files (v2+, 2025 onwards)."""

    def __init__(self, filepath: str | Path):
        self.filepath = Path(filepath)
        self._data: bytes | None = None
        self._parsed: ROFLData | None = None

    # -- internal helpers ------------------------------------------------

    def _read_file(self) -> bytes:
        if self._data is None:
            self._data = self.filepath.read_bytes()
        return self._data

    def _find_metadata_start(self, data: bytes) -> int:
        """Locate the opening '{' of the metadata JSON near EOF."""
        search_from = max(0, len(data) - 500_000)

        # Primary: metadata always starts with {"gameLength"
        pos = data.find(b'{"gameLength"', search_from)
        if pos >= 0:
            return pos

        # Fallbacks for slightly different key ordering
        for pat in (b'{"lastGameChunkId"', b'{"statsJson"', b'{"gameVersion"'):
            pos = data.find(pat, search_from)
            if pos >= 0:
                return pos

        raise ValueError(f"Cannot locate metadata JSON in {self.filepath}")

    def _parse_header(self, data: bytes, meta_offset: int) -> ROFLHeader:
        if data[:4] != b"RIOT":
            raise ValueError(f"Not a ROFL file (bad magic): {self.filepath}")

        fmt_version = struct.unpack_from("<H", data, 4)[0]

        # Game version string (e.g. "16.2.741.3171") lives in the first ~60 bytes
        header_ascii = data[:200].decode("ascii", errors="replace")
        m = re.search(r"\d+\.\d+\.\d+\.\d+", header_ascii)
        game_version = m.group(0) if m else ""

        # Zstd payload offset — search first 4 KB
        zstd_pos = data.find(ZSTD_MAGIC, 0, 4096)
        if zstd_pos < 0:
            zstd_pos = 0

        return ROFLHeader(
            format_version=fmt_version,
            game_version=game_version,
            file_size=len(data),
            payload_offset=zstd_pos,
            metadata_offset=meta_offset,
        )

    def _parse_metadata(self, data: bytes, offset: int) -> dict:
        text = data[offset:].decode("utf-8", errors="replace")
        decoder = json.JSONDecoder()
        obj, _ = decoder.raw_decode(text)
        return obj

    # -- public API ------------------------------------------------------

    def parse(self) -> ROFLData:
        """Parse the ROFL file. Result is cached."""
        if self._parsed:
            return self._parsed

        data = self._read_file()
        meta_offset = self._find_metadata_start(data)
        header = self._parse_header(data, meta_offset)
        metadata = self._parse_metadata(data, meta_offset)

        self._parsed = ROFLData(header=header, metadata=metadata)
        return self._parsed

    def get_metadata(self) -> dict:
        """Raw metadata dict from the replay file."""
        return self.parse().metadata

    def get_match_info(self) -> dict:
        """Structured match info extracted from metadata."""
        meta = self.get_metadata()
        hdr = self.parse().header

        # statsJson: stringified JSON array, one object per player
        stats_list = _json_field(meta, "statsJson", [])

        return {
            "game_version": hdr.game_version,
            "format_version": hdr.format_version,
            "file_size": hdr.file_size,
            "game_length_ms": meta.get("gameLength", 0),
            "last_chunk_id": meta.get("lastGameChunkId", 0),
            "last_keyframe_id": meta.get("lastKeyFrameId", 0),
            "player_count": len(stats_list),
            "player_stats": stats_list,
            "metadata_keys": sorted(meta.keys()),
        }

    def get_compressed_payload(self) -> bytes:
        """Raw zstd-compressed game data (chunks + keyframes)."""
        data = self._read_file()
        hdr = self.parse().header
        return data[hdr.payload_offset : hdr.metadata_offset]

    def decompress_payload(self) -> bytes:
        """
        Decompress game payload (multi-frame zstd).

        The payload contains many zstd frames (one per chunk/keyframe)
        possibly interleaved with non-zstd binary headers.
        We decompress greedily and tolerate errors at frame boundaries.

        Requires ``zstandard``.
        """
        if not HAS_ZSTD:
            raise ImportError("pip install zstandard")

        raw = self.get_compressed_payload()
        dctx = zstandard.ZstdDecompressor()

        # Approach 1: stream_reader with chunked reads (handles multi-frame)
        buf = io.BytesIO()
        reader = dctx.stream_reader(io.BytesIO(raw))
        try:
            while True:
                chunk = reader.read(65536)
                if not chunk:
                    break
                buf.write(chunk)
        except zstandard.ZstdError:
            pass  # hit non-zstd data after valid frames — expected

        if buf.tell() > 0:
            return buf.getvalue()

        # Approach 2: decompress individual frames by scanning for magic
        frames: list[bytes] = []
        pos = 0
        while pos < len(raw) - 4:
            idx = raw.find(ZSTD_MAGIC, pos)
            if idx < 0:
                break
            try:
                frame = dctx.decompress(raw[idx:], max_output_size=50_000_000)
                frames.append(frame)
            except zstandard.ZstdError:
                pass
            pos = idx + 4

        if frames:
            return b"".join(frames)

        raise ValueError("No decompressible zstd frames in payload")

    def payload_frame_count(self) -> int:
        """Count zstd frame magic occurrences in the payload."""
        raw = self.get_compressed_payload()
        count = 0
        pos = 0
        while True:
            idx = raw.find(ZSTD_MAGIC, pos)
            if idx < 0:
                break
            count += 1
            pos = idx + 4
        return count


# ── Helpers ────────────────────────────────────────────────────────────


def _json_field(d: dict, key: str, default: Any = None) -> Any:
    """Parse a possibly-stringified JSON value from *d[key]*."""
    val = d.get(key, default)
    if isinstance(val, str):
        try:
            return json.loads(val)
        except json.JSONDecodeError:
            return default
    return val


# ── Convenience functions ──────────────────────────────────────────────


def parse_rofl(filepath: str | Path) -> dict:
    """Quick-parse a .rofl → match-info dict."""
    return ROFLParser(filepath).get_match_info()


def batch_parse_metadata(replay_dir: str | Path) -> list[dict]:
    """Parse metadata from every .rofl in *replay_dir*."""
    results: list[dict] = []
    for f in sorted(Path(replay_dir).glob("*.rofl")):
        try:
            info = parse_rofl(f)
            info["filename"] = f.name
            results.append(info)
        except Exception as e:
            print(f"  Failed {f.name}: {e}")
    return results

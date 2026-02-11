"""
Parse League of Legends .rofl replay files.

ROFL file structure:
  ┌─────────────────────────┐
  │ Magic: "RIOT" (6 bytes) │  ← File signature
  │ Signature (256 bytes)   │  ← RSA signature
  ├─────────────────────────┤
  │ File Header (26 bytes)  │  ← Offsets to metadata/payload
  ├─────────────────────────┤
  │ Metadata (JSON string)  │  ← Match stats, players, etc. (UNENCRYPTED)
  ├─────────────────────────┤
  │ Payload Header          │  ← Encryption key, chunk info
  ├─────────────────────────┤
  │ Chunk Headers           │  ← Index of keyframes + chunks
  ├─────────────────────────┤
  │ Payload Data            │  ← Encrypted game packets (Blowfish + zlib)
  └─────────────────────────┘

Usage:
    from ml.parsers.rofl_parser import ROFLParser

    parser = ROFLParser("path/to/replay.rofl")
    metadata = parser.get_metadata()       # Match stats, players
    chunks = parser.get_decrypted_chunks()  # Raw game data chunks
"""

import json
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Optional: Blowfish for payload decryption
try:
    from Crypto.Cipher import Blowfish

    HAS_CRYPTO = True
except ImportError:
    try:
        from Cryptodome.Cipher import Blowfish

        HAS_CRYPTO = True
    except ImportError:
        HAS_CRYPTO = False


# ── ROFL Binary Format Definitions ─────────────────────────────────────

ROFL_MAGIC = b"RIOT\x00\x00"  # 6-byte magic
SIGNATURE_LENGTH = 256


@dataclass
class FileHeader:
    """26-byte file header after magic + signature."""

    head_length: int  # uint16 — total header length
    file_length: int  # uint32 — total file size
    metadata_offset: int  # uint32
    metadata_length: int  # uint32
    payload_header_offset: int  # uint32
    payload_header_length: int  # uint32
    payload_offset: int  # uint32


@dataclass
class PayloadHeader:
    """Header for the encrypted payload section."""

    game_id: int  # uint64
    game_length: int  # uint32 (milliseconds)
    keyframe_count: int  # uint32
    chunk_count: int  # uint32
    end_startup_chunk_id: int  # uint32
    start_game_chunk_id: int  # uint32
    keyframe_interval: int  # uint32 (milliseconds)
    encryption_key_length: int  # uint16
    encryption_key: bytes  # variable length


@dataclass
class ChunkHeader:
    """Header for individual chunks in the payload."""

    chunk_id: int  # uint32
    chunk_type: int  # uint8 — 1=Keyframe, 2=Chunk
    chunk_length: int  # uint32
    next_chunk_id: int  # uint32
    offset: int  # uint32


@dataclass
class ROFLData:
    """Complete parsed ROFL data."""

    file_header: FileHeader
    metadata: dict[str, Any]
    payload_header: PayloadHeader | None = None
    chunk_headers: list[ChunkHeader] = field(default_factory=list)


class ROFLParser:
    """Parse .rofl replay files."""

    def __init__(self, filepath: str | Path):
        self.filepath = Path(filepath)
        self._data: bytes | None = None
        self._parsed: ROFLData | None = None

    def _read_file(self) -> bytes:
        if self._data is None:
            self._data = self.filepath.read_bytes()
        return self._data

    def _parse_file_header(self, data: bytes, offset: int) -> FileHeader:
        """Parse the 26-byte file header."""
        fmt = "<H I I I I I I"  # little-endian: uint16 + 6x uint32
        size = struct.calcsize(fmt)
        values = struct.unpack(fmt, data[offset : offset + size])
        return FileHeader(
            head_length=values[0],
            file_length=values[1],
            metadata_offset=values[2],
            metadata_length=values[3],
            payload_header_offset=values[4],
            payload_header_length=values[5],
            payload_offset=values[6],
        )

    def _parse_metadata(self, data: bytes, header: FileHeader) -> dict:
        """Extract and parse the JSON metadata section."""
        start = header.metadata_offset
        end = start + header.metadata_length
        raw = data[start:end]
        return json.loads(raw.decode("utf-8"))

    def _parse_payload_header(self, data: bytes, header: FileHeader) -> PayloadHeader:
        """Parse the payload header (encryption key + chunk info)."""
        offset = header.payload_header_offset
        # First part: fixed fields
        fmt = "<Q I I I I I I H"
        size = struct.calcsize(fmt)
        values = struct.unpack(fmt, data[offset : offset + size])

        key_length = values[7]
        key_offset = offset + size
        encryption_key = data[key_offset : key_offset + key_length]

        return PayloadHeader(
            game_id=values[0],
            game_length=values[1],
            keyframe_count=values[2],
            chunk_count=values[3],
            end_startup_chunk_id=values[4],
            start_game_chunk_id=values[5],
            keyframe_interval=values[6],
            encryption_key_length=key_length,
            encryption_key=encryption_key,
        )

    def _parse_chunk_headers(
        self, data: bytes, payload_header: PayloadHeader, file_header: FileHeader
    ) -> list[ChunkHeader]:
        """Parse chunk header table after payload header."""
        # Chunk headers start after payload header
        offset = file_header.payload_header_offset
        # Skip payload header fixed fields + encryption key
        offset += struct.calcsize("<Q I I I I I I H") + payload_header.encryption_key_length

        total_chunks = payload_header.chunk_count + payload_header.keyframe_count
        chunk_fmt = "<I B I I I"  # id, type, length, next_id, offset
        chunk_size = struct.calcsize(chunk_fmt)

        headers = []
        for _ in range(total_chunks):
            if offset + chunk_size > len(data):
                break
            values = struct.unpack(chunk_fmt, data[offset : offset + chunk_size])
            headers.append(
                ChunkHeader(
                    chunk_id=values[0],
                    chunk_type=values[1],
                    chunk_length=values[2],
                    next_chunk_id=values[3],
                    offset=values[4],
                )
            )
            offset += chunk_size

        return headers

    def parse(self) -> ROFLData:
        """Parse the entire ROFL file."""
        if self._parsed:
            return self._parsed

        data = self._read_file()

        # Verify magic bytes
        if not data[:6] == ROFL_MAGIC:
            # Some versions use different magic
            if not data[:4] == b"RIOT":
                raise ValueError(f"Not a valid ROFL file: {self.filepath}")

        # File header starts after magic (6 bytes) + signature (256 bytes)
        header_offset = len(ROFL_MAGIC) + SIGNATURE_LENGTH
        file_header = self._parse_file_header(data, header_offset)

        # Metadata (always available, unencrypted)
        metadata = self._parse_metadata(data, file_header)

        # Payload header (may fail on newer formats)
        payload_header = None
        chunk_headers = []
        try:
            payload_header = self._parse_payload_header(data, file_header)
            chunk_headers = self._parse_chunk_headers(data, payload_header, file_header)
        except Exception as e:
            print(f"  Warning: Could not parse payload header: {e}")

        self._parsed = ROFLData(
            file_header=file_header,
            metadata=metadata,
            payload_header=payload_header,
            chunk_headers=chunk_headers,
        )
        return self._parsed

    def get_metadata(self) -> dict:
        """Get parsed metadata (match stats, players, etc.)."""
        parsed = self.parse()
        return parsed.metadata

    def get_match_info(self) -> dict:
        """
        Extract structured match info from metadata.
        Similar to what match-v5 would return.
        """
        meta = self.get_metadata()
        payload = self.parse().payload_header

        # Parse statsJson from each player if present
        players = []
        stats_json_raw = meta.get("statsJson", "[]")
        if isinstance(stats_json_raw, str):
            try:
                stats_list = json.loads(stats_json_raw)
            except json.JSONDecodeError:
                stats_list = []
        else:
            stats_list = stats_json_raw

        # Also get player list from metadata
        player_list = meta.get("players", [])
        if isinstance(player_list, str):
            try:
                player_list = json.loads(player_list)
            except json.JSONDecodeError:
                player_list = []

        for p in player_list:
            player_stats = p.get("statsJson", "{}")
            if isinstance(player_stats, str):
                try:
                    player_stats = json.loads(player_stats)
                except json.JSONDecodeError:
                    player_stats = {}

            players.append(
                {
                    "name": p.get("NAME", p.get("name", "")),
                    "champion": p.get("SKIN", p.get("skin", "")),
                    "team": p.get("TEAM", p.get("team", "")),
                    "stats": player_stats,
                }
            )

        result = {
            "game_length_ms": meta.get("gameLength", 0),
            "game_version": meta.get("gameVersion", ""),
            "players": players,
        }

        if payload:
            result["game_id"] = payload.game_id
            result["keyframe_count"] = payload.keyframe_count
            result["chunk_count"] = payload.chunk_count
            result["keyframe_interval_ms"] = payload.keyframe_interval

        return result

    def get_raw_chunks(self) -> list[tuple[ChunkHeader, bytes]]:
        """
        Get raw (encrypted) chunk data.
        Returns list of (header, raw_bytes) tuples.
        """
        parsed = self.parse()
        if not parsed.payload_header or not parsed.chunk_headers:
            return []

        data = self._read_file()
        payload_offset = parsed.file_header.payload_offset

        chunks = []
        for ch in parsed.chunk_headers:
            start = payload_offset + ch.offset
            end = start + ch.chunk_length
            if end <= len(data):
                chunks.append((ch, data[start:end]))

        return chunks

    def get_decrypted_chunks(self) -> list[tuple[ChunkHeader, bytes]]:
        """
        Decrypt and decompress payload chunks.
        Requires pycryptodome: pip install pycryptodome

        Returns list of (header, decompressed_bytes) tuples.
        """
        if not HAS_CRYPTO:
            raise ImportError(
                "pycryptodome required for chunk decryption: pip install pycryptodome"
            )

        parsed = self.parse()
        if not parsed.payload_header:
            return []

        # Decode the encryption key (base64)
        import base64

        try:
            key = base64.b64decode(parsed.payload_header.encryption_key)
        except Exception:
            key = parsed.payload_header.encryption_key

        raw_chunks = self.get_raw_chunks()
        decrypted = []

        for header, raw_data in raw_chunks:
            try:
                # Blowfish ECB decrypt
                cipher = Blowfish.new(key, Blowfish.MODE_ECB)

                # Pad to block size (8 bytes)
                padded = raw_data
                pad_len = 8 - (len(raw_data) % 8)
                if pad_len != 8:
                    padded = raw_data + b"\x00" * pad_len

                decrypted_data = cipher.decrypt(padded)

                # Decompress (zlib)
                try:
                    decompressed = zlib.decompress(decrypted_data, 15 + 32)
                except zlib.error:
                    # Try without gzip header
                    try:
                        decompressed = zlib.decompress(decrypted_data)
                    except zlib.error:
                        # Try raw deflate
                        try:
                            decompressed = zlib.decompress(decrypted_data, -15)
                        except zlib.error:
                            # Store raw decrypted data if decompression fails
                            decompressed = decrypted_data

                decrypted.append((header, decompressed))
            except Exception as e:
                print(f"  Warning: Failed to decrypt chunk {header.chunk_id}: {e}")

        return decrypted


# ── Convenience Functions ──────────────────────────────────────────────


def parse_rofl(filepath: str | Path) -> dict:
    """Quick parse: return metadata dict from a .rofl file."""
    parser = ROFLParser(filepath)
    return parser.get_match_info()


def batch_parse_metadata(replay_dir: str | Path) -> list[dict]:
    """Parse metadata from all .rofl files in a directory."""
    replay_dir = Path(replay_dir)
    results = []
    for rofl_file in sorted(replay_dir.glob("*.rofl")):
        try:
            info = parse_rofl(rofl_file)
            info["filename"] = rofl_file.name
            results.append(info)
        except Exception as e:
            print(f"  Failed to parse {rofl_file.name}: {e}")
    return results

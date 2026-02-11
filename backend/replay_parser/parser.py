"""
League of Legends .rofl replay file parser.

.rofl file format (reverse-engineered):
┌─────────────────────────────────────┐
│ Magic bytes: "RIOT" + version bytes │  (6 bytes)
│ Signature + header length info      │  (variable)
│ File metadata (JSON)                │  (variable)
│ Payload header                      │  (variable)
│ Payload: chunks + keyframes         │  (bulk of file)
└─────────────────────────────────────┘

The payload contains ENet packets that represent the spectator protocol.
Chunks are sequential game state deltas; keyframes are full snapshots.

The metadata JSON contains match info: game version, players, stats, etc.
That alone is gold for coaching — we get full end-game stats per player.

References:
- https://github.com/leeanchu/ROFL-Player (C# parser)
- https://huggingface.co/datasets/maknee/league-of-legends-decoded-replay-packets
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class PlayerStats:
    champion: str = ""
    summoner_name: str = ""
    team: str = ""  # "100" = blue, "200" = red
    role: str = ""
    kills: int = 0
    deaths: int = 0
    assists: int = 0
    cs: int = 0
    gold_earned: int = 0
    damage_dealt: int = 0
    damage_taken: int = 0
    vision_score: float = 0.0
    wards_placed: int = 0
    wards_killed: int = 0
    level: int = 0
    items: list[int] = field(default_factory=list)
    # raw stats dict for anything else
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ReplayData:
    """Structured data extracted from a .rofl replay file."""

    game_version: str = ""
    game_length_seconds: int = 0
    map_id: int = 0
    game_mode: str = ""
    winning_team: str = ""  # "100" or "200"
    players: list[PlayerStats] = field(default_factory=list)
    raw_metadata: dict[str, Any] = field(default_factory=dict)
    # We'll add timeline data here when we decode payload packets
    timeline_events: list[dict[str, Any]] = field(default_factory=list)

    def to_prompt_context(self) -> str:
        """Convert replay data to a text representation for LLM input."""
        lines = []
        lines.append(f"Game Version: {self.game_version}")
        lines.append(f"Game Length: {self.game_length_seconds // 60}m {self.game_length_seconds % 60}s")
        lines.append(f"Game Mode: {self.game_mode}")
        lines.append(f"Winning Team: {'Blue' if self.winning_team == '100' else 'Red'}")
        lines.append("")

        for team_id, team_name in [("100", "Blue Team"), ("200", "Red Team")]:
            team_players = [p for p in self.players if p.team == team_id]
            lines.append(f"=== {team_name} ===")
            for p in team_players:
                lines.append(
                    f"  {p.summoner_name} - {p.champion} ({p.role}): "
                    f"{p.kills}/{p.deaths}/{p.assists} | "
                    f"CS: {p.cs} | Gold: {p.gold_earned:,} | "
                    f"Damage: {p.damage_dealt:,} | "
                    f"Vision: {p.vision_score:.0f} | "
                    f"Wards: {p.wards_placed}/{p.wards_killed}"
                )
            lines.append("")

        return "\n".join(lines)


class RoflParser:
    """
    Parse .rofl replay files to extract match metadata and player stats.

    The .rofl format stores:
    1. A header with magic bytes and lengths
    2. JSON metadata with full match stats
    3. Binary payload with game state packets (chunks/keyframes)

    For coaching, the JSON metadata alone gives us everything we need:
    full end-game stats, items, runes, summoner spells, etc.
    """

    ROFL_MAGIC = b"RIOT"

    def parse(self, file_path: str | Path) -> ReplayData:
        """Parse a .rofl file and return structured replay data."""
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"Replay file not found: {file_path}")
        if not file_path.suffix.lower() == ".rofl":
            raise ValueError(f"Expected .rofl file, got: {file_path.suffix}")

        with open(file_path, "rb") as f:
            data = f.read()

        # Validate magic bytes
        if not data[:4] == self.ROFL_MAGIC:
            raise ValueError("Invalid .rofl file: missing RIOT magic bytes")

        # Extract metadata JSON from the file
        metadata = self._extract_metadata(data)
        return self._build_replay_data(metadata)

    def parse_bytes(self, data: bytes) -> ReplayData:
        """Parse .rofl file from bytes (for upload handling)."""
        if not data[:4] == self.ROFL_MAGIC:
            raise ValueError("Invalid .rofl file: missing RIOT magic bytes")

        metadata = self._extract_metadata(data)
        return self._build_replay_data(metadata)

    def _extract_metadata(self, data: bytes) -> dict[str, Any]:
        """
        Extract the JSON metadata block from .rofl binary data.

        .rofl header structure (approximate, varies by version):
        Offset 0:    "RIOT" magic (4 bytes)
        Offset 4-5:  signature bytes (2 bytes)
        Offset 6:    Header length fields that tell us where metadata lives

        The metadata JSON is typically found by scanning for the first '{' 
        after the header region and parsing the JSON block.

        Different .rofl versions have slightly different header layouts,
        so we use a robust scan approach.
        """
        # Strategy: .rofl files embed a JSON metadata block.
        # We find it by looking for the JSON object pattern after the header.

        # Try the structured approach first (newer .rofl format)
        try:
            return self._extract_metadata_structured(data)
        except Exception:
            pass

        # Fallback: scan for JSON metadata block
        return self._extract_metadata_scan(data)

    def _extract_metadata_structured(self, data: bytes) -> dict[str, Any]:
        """
        Parse .rofl with known header structure.

        Modern .rofl layout:
        [0:4]     - "RIOT" magic
        [4:6]     - signature
        [6:262]   - 256-byte file signature
        [262:264] - header length (uint16 LE)
        Then header contains: file length, metadata offset, metadata length,
        payload header offset, payload header length, payload offset, payload length
        """
        # Read header length at offset 262
        if len(data) < 264:
            raise ValueError("File too small for structured parse")

        header_len = struct.unpack_from("<H", data, 262)[0]

        # After the 264-byte preamble, read the header fields
        offset = 264
        if len(data) < offset + header_len:
            raise ValueError("Header extends beyond file")

        # Header fields (each uint32 or uint64, layout varies)
        # Common layout: metadata_offset(8), metadata_length(4), ...
        # We'll read key fields
        try:
            metadata_offset = struct.unpack_from("<Q", data, offset)[0]
            metadata_length = struct.unpack_from("<I", data, offset + 8)[0]

            meta_start = metadata_offset
            meta_end = meta_start + metadata_length

            if meta_end > len(data):
                raise ValueError("Metadata extends beyond file")

            meta_json = data[meta_start:meta_end].decode("utf-8")
            return json.loads(meta_json)
        except (json.JSONDecodeError, UnicodeDecodeError, struct.error):
            raise ValueError("Failed structured metadata extraction")

    def _extract_metadata_scan(self, data: bytes) -> dict[str, Any]:
        """
        Fallback: scan the binary for embedded JSON metadata.
        
        The metadata block starts with '{' and contains known keys like
        "gameLength", "statsJson", etc.
        """
        # Look for JSON-like patterns
        text = data.decode("utf-8", errors="ignore")

        # Find potential JSON blocks
        candidates = []
        i = 0
        while i < len(text):
            if text[i] == "{":
                # Try to find matching closing brace
                depth = 0
                for j in range(i, min(i + 500_000, len(text))):
                    if text[j] == "{":
                        depth += 1
                    elif text[j] == "}":
                        depth -= 1
                        if depth == 0:
                            candidates.append(text[i : j + 1])
                            break
                break  # only need first major JSON block
            i += 1

        # Try parsing candidates, look for the one with game data
        for candidate in candidates:
            try:
                parsed = json.loads(candidate)
                # Validate it looks like LoL match metadata
                if isinstance(parsed, dict) and any(
                    k in parsed
                    for k in ["gameLength", "statsJson", "players", "gameVersion"]
                ):
                    return parsed
            except json.JSONDecodeError:
                continue

        raise ValueError(
            "Could not find valid metadata JSON in .rofl file. "
            "The file may be corrupted or use an unsupported format version."
        )

    def _build_replay_data(self, metadata: dict[str, Any]) -> ReplayData:
        """Convert raw metadata dict to structured ReplayData."""
        replay = ReplayData(raw_metadata=metadata)

        replay.game_version = metadata.get("gameVersion", "")
        replay.game_length_seconds = metadata.get("gameLength", 0) // 1000  # ms -> s
        replay.map_id = metadata.get("mapId", 0)
        replay.game_mode = metadata.get("gameMode", "")

        # Parse player stats
        stats_json = metadata.get("statsJson", "[]")
        if isinstance(stats_json, str):
            try:
                player_stats_list = json.loads(stats_json)
            except json.JSONDecodeError:
                player_stats_list = []
        else:
            player_stats_list = stats_json

        for ps in player_stats_list:
            player = PlayerStats(
                champion=ps.get("SKIN", ps.get("champion", "")),
                summoner_name=ps.get("NAME", ps.get("summonerName", "")),
                team=str(ps.get("TEAM", ps.get("teamId", ""))),
                role=ps.get("INDIVIDUAL_POSITION", ps.get("role", "")),
                kills=int(ps.get("CHAMPIONS_KILLED", ps.get("kills", 0))),
                deaths=int(ps.get("NUM_DEATHS", ps.get("deaths", 0))),
                assists=int(ps.get("ASSISTS", ps.get("assists", 0))),
                cs=int(ps.get("MINIONS_KILLED", 0)) + int(ps.get("NEUTRAL_MINIONS_KILLED", 0)),
                gold_earned=int(ps.get("GOLD_EARNED", ps.get("goldEarned", 0))),
                damage_dealt=int(
                    ps.get(
                        "TOTAL_DAMAGE_DEALT_TO_CHAMPIONS",
                        ps.get("totalDamageDealtToChampions", 0),
                    )
                ),
                damage_taken=int(
                    ps.get(
                        "TOTAL_DAMAGE_TAKEN",
                        ps.get("totalDamageTaken", 0),
                    )
                ),
                vision_score=float(ps.get("VISION_SCORE", ps.get("visionScore", 0))),
                wards_placed=int(ps.get("WARD_PLACED", ps.get("wardsPlaced", 0))),
                wards_killed=int(ps.get("WARD_KILLED", ps.get("wardsKilled", 0))),
                level=int(ps.get("LEVEL", ps.get("champLevel", 0))),
                items=self._extract_items(ps),
                raw=ps,
            )
            replay.players.append(player)

        # Determine winning team
        if replay.players:
            for ps in player_stats_list:
                if str(ps.get("WIN", "")).lower() in ("win", "true", "1"):
                    replay.winning_team = str(ps.get("TEAM", ps.get("teamId", "")))
                    break

        return replay

    def _extract_items(self, stats: dict) -> list[int]:
        """Extract item IDs from player stats."""
        items = []
        for i in range(7):
            item_key = f"ITEM{i}"
            if item_key in stats:
                items.append(int(stats[item_key]))
            elif f"item{i}" in stats:
                items.append(int(stats[f"item{i}"]))
        return items

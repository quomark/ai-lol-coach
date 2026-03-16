"""
Reconstruct game state from decoded ROFL packets.

Combines 0x025B (movement) and 0x0228 (entity state) decoders
to build a per-champion timeline of positions, stats, and events.

Usage:
    from ml.parsers.game_state import GameStateBuilder

    builder = GameStateBuilder("ml/data/league_unpacked_patched.bin")
    game = builder.build_from_rofl("path/to/replay.rofl")

    for champ in game.champions.values():
        print(f"{champ.entity_id}: {len(champ.positions)} positions, "
              f"{len(champ.state_updates)} state updates")
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ml.parsers.rofl_parser import ROFLParser
from ml.parsers.chunk_parser import parse_payload_frames
from ml.parsers.movement_decoder import MovementDecoder
from ml.emulator.decode_0228 import Decoder0228


# LoL map constants (Summoner's Rift)
MAP_MIN = 0
MAP_MAX = 15000  # approximate map size in game units


@dataclass
class PositionEvent:
    """A single position update from 0x025B."""
    timestamp: float
    x: int
    z: int
    speed: Optional[float] = None
    movement_type: Optional[int] = None
    waypoint_count: Optional[int] = None


@dataclass
class StateUpdate:
    """A single state update from 0x0228."""
    timestamp: float
    f0: Optional[int] = None
    f1: Optional[int] = None  # entity_id
    f3_float: Optional[float] = None
    f4: Optional[int] = None
    f5: Optional[int] = None  # appears during death
    f6: Optional[int] = None
    f7: Optional[int] = None
    f8: Optional[int] = None  # gold/XP/HP (increases over time, resets on death)
    f9_float: Optional[float] = None


@dataclass
class DeathEvent:
    """Detected champion death."""
    timestamp: float
    x: Optional[int] = None
    z: Optional[int] = None
    f8_before: Optional[int] = None
    f8_after: Optional[int] = None


@dataclass
class ChampionTimeline:
    """All decoded data for a single champion entity."""
    entity_id: int
    param: int  # network ID (0x400000AE-0x400000B7 for champions)

    positions: list[PositionEvent] = field(default_factory=list)
    state_updates: list[StateUpdate] = field(default_factory=list)
    deaths: list[DeathEvent] = field(default_factory=list)

    @property
    def position_count(self) -> int:
        return len(self.positions)

    @property
    def last_position(self) -> Optional[PositionEvent]:
        return self.positions[-1] if self.positions else None

    def position_at(self, timestamp: float) -> Optional[PositionEvent]:
        """Get the most recent position at or before the given timestamp."""
        best = None
        for p in self.positions:
            if p.timestamp <= timestamp:
                best = p
            else:
                break
        return best

    def f8_at(self, timestamp: float) -> Optional[int]:
        """Get the most recent f8 value at or before the given timestamp."""
        best = None
        for s in self.state_updates:
            if s.timestamp <= timestamp:
                if s.f8 is not None:
                    best = s.f8
            else:
                break
        return best


@dataclass
class GameState:
    """Full reconstructed game state from a replay."""
    replay_path: str
    duration: float = 0.0

    # entity_id -> ChampionTimeline
    champions: dict[int, ChampionTimeline] = field(default_factory=dict)

    # All entities (including non-champions)
    entities: dict[int, list[PositionEvent]] = field(default_factory=dict)

    # Stats
    total_movement_packets: int = 0
    total_state_packets: int = 0
    total_frames: int = 0

    def get_champion_by_param(self, param: int) -> Optional[ChampionTimeline]:
        for c in self.champions.values():
            if c.param == param:
                return c
        return None


# Champion entity IDs are typically in a small range (e.g., 174-183)
CHAMPION_ENTITY_RANGE = range(170, 190)
CHAMPION_PARAM_RANGE = range(0x400000A0, 0x400000C0)


class GameStateBuilder:
    """Build game state from ROFL replay using decoded packets."""

    def __init__(self):
        self._mov_decoder = MovementDecoder()
        self._state_decoder = Decoder0228()

    def build_from_rofl(self, rofl_path: str | Path) -> GameState:
        """Parse a ROFL file and reconstruct game state."""
        rofl_path = str(rofl_path)
        rofl = ROFLParser(rofl_path)
        frames = rofl.decompress_payload_frames()
        payload = parse_payload_frames(frames, parse_packets=True)

        game = GameState(replay_path=rofl_path)
        game.total_frames = len(payload.frames)

        # Collect champion params from 0x025B and 0x0228 packets
        champion_params: set[int] = set()

        for fr in payload.frames:
            for pkt in fr.packets:
                if pkt.packet_id in (0x025B, 0x0228):
                    if pkt.param in CHAMPION_PARAM_RANGE:
                        champion_params.add(pkt.param)

        # Process all packets
        for fr in payload.frames:
            for pkt in fr.packets:
                if pkt.packet_id == 0x025B:
                    self._process_movement(game, pkt, champion_params)
                elif pkt.packet_id == 0x0228:
                    self._process_state(game, pkt, champion_params)

        # Filter to real champions: exactly 10 entities with most positions
        # that span most of the game duration
        if game.champions:
            candidates = sorted(
                game.champions.values(),
                key=lambda c: c.position_count,
                reverse=True,
            )
            real_ids = {c.entity_id for c in candidates[:10]}
            real_champions = {
                eid: c for eid, c in game.champions.items()
                if eid in real_ids
            }
        game.champions = real_champions

        # Detect deaths from f8 drops
        for champ in game.champions.values():
            self._detect_deaths(champ)

        # Sort everything by timestamp
        for champ in game.champions.values():
            champ.positions.sort(key=lambda p: p.timestamp)
            champ.state_updates.sort(key=lambda s: s.timestamp)

        # Set duration
        if game.champions:
            all_times = []
            for c in game.champions.values():
                if c.positions:
                    all_times.append(c.positions[-1].timestamp)
                if c.state_updates:
                    all_times.append(c.state_updates[-1].timestamp)
            if all_times:
                game.duration = max(all_times)

        return game

    def _process_movement(self, game: GameState, pkt, champion_params: set[int]):
        result = self._mov_decoder.decode(pkt.data)
        if result is None or not result.fully_parsed:
            return

        game.total_movement_packets += 1

        pos = PositionEvent(
            timestamp=pkt.timestamp,
            x=result.x,
            z=result.z,
            speed=result.speed,
            movement_type=result.movement_type,
            waypoint_count=result.waypoint_count,
        )

        entity_id = result.entity_id

        # Track all entities
        if entity_id not in game.entities:
            game.entities[entity_id] = []
        game.entities[entity_id].append(pos)

        # Track champion entities
        if pkt.param in champion_params:
            if entity_id not in game.champions:
                game.champions[entity_id] = ChampionTimeline(
                    entity_id=entity_id,
                    param=pkt.param,
                )
            game.champions[entity_id].positions.append(pos)

    def _process_state(self, game: GameState, pkt, champion_params: set[int]):
        result = self._state_decoder.decode(pkt.data)
        if result is None or result.leftover != 0:
            return

        game.total_state_packets += 1

        update = StateUpdate(
            timestamp=pkt.timestamp,
            f0=result.f0,
            f1=result.f1,
            f3_float=result.f3_float,
            f4=result.f4,
            f5=result.f5,
            f6=result.f6,
            f7=result.f7,
            f8=result.f8,
            f9_float=result.f9_float,
        )

        # Match to champion by param
        if pkt.param in champion_params:
            entity_id = result.f1 if result.f1 is not None else 0
            # Try to find existing champion by param
            champ = game.get_champion_by_param(pkt.param)
            if champ is None:
                # Create champion timeline using entity_id from 0x0228 f1
                if entity_id not in game.champions:
                    game.champions[entity_id] = ChampionTimeline(
                        entity_id=entity_id,
                        param=pkt.param,
                    )
                champ = game.champions[entity_id]
            champ.state_updates.append(update)

    def _detect_deaths(self, champ: ChampionTimeline):
        """Detect deaths from sustained f8 drops to entity-ID-like values.

        When a champion dies, f8 drops from a large value (gold/XP/stats)
        to a small value in the entity-ID range (likely the killer's ID)
        and STAYS low for the duration of the death timer (>= 5 seconds).
        Momentary blips (< 1s) are filtered out as false positives.
        """
        updates_with_f8 = [(s.timestamp, s.f8) for s in champ.state_updates
                           if s.f8 is not None]
        last_death_time = -999.0

        i = 0
        while i < len(updates_with_f8):
            ts, f8 = updates_with_f8[i]

            if f8 < 200 and ts > 90.0:
                # Check if a recent prior value was large
                prev_large = None
                for j in range(i - 1, max(i - 5, -1), -1):
                    if updates_with_f8[j][1] > 500:
                        prev_large = updates_with_f8[j][1]
                        break

                if prev_large is not None:
                    # Check how long f8 stays low (< 200)
                    stay_until = ts
                    for k in range(i + 1, min(i + 20, len(updates_with_f8))):
                        if updates_with_f8[k][1] > 300:
                            stay_until = updates_with_f8[k][0]
                            break

                    low_duration = stay_until - ts
                    if low_duration >= 5.0 and ts - last_death_time > 30.0:
                        pos = champ.position_at(ts)
                        death = DeathEvent(
                            timestamp=ts,
                            x=pos.x if pos else None,
                            z=pos.z if pos else None,
                            f8_before=prev_large,
                            f8_after=f8,
                        )
                        champ.deaths.append(death)
                        last_death_time = ts
            i += 1


def main():
    """Demo: build game state from a replay and print summary."""
    import sys

    binary_path = "ml/data/league_unpacked_patched.bin"
    replay_path = r"C:\Users\ngan9\OneDrive\Documents\League of Legends\Replays\TW2-396324158.rofl"

    if len(sys.argv) > 1:
        replay_path = sys.argv[1]

    builder = GameStateBuilder(binary_path)
    game = builder.build_from_rofl(replay_path)

    print(f"Replay: {game.replay_path}")
    print(f"Duration: {game.duration:.1f}s ({game.duration / 60:.1f}min)")
    print(f"Frames: {game.total_frames}")
    print(f"Movement packets decoded: {game.total_movement_packets:,}")
    print(f"State packets decoded: {game.total_state_packets:,}")
    print(f"Total entities tracked: {len(game.entities)}")
    print(f"Champions identified: {len(game.champions)}")

    print(f"\n{'Entity':<8} {'Param':<12} {'Positions':<12} {'States':<10} {'Deaths':<8} {'Duration'}")
    print("-" * 70)
    for eid, champ in sorted(game.champions.items()):
        dur = ""
        if champ.positions:
            t0 = champ.positions[0].timestamp
            t1 = champ.positions[-1].timestamp
            dur = f"{t0:.0f}s - {t1:.0f}s"

        print(f"{eid:<8} 0x{champ.param:08X}  {champ.position_count:<12} "
              f"{len(champ.state_updates):<10} {len(champ.deaths):<8} {dur}")

    # Show deaths
    all_deaths = []
    for eid, champ in game.champions.items():
        for d in champ.deaths:
            all_deaths.append((d.timestamp, eid, d))
    all_deaths.sort()

    if all_deaths:
        print(f"\nDeaths detected: {len(all_deaths)}")
        for ts, eid, d in all_deaths[:20]:
            pos_str = f"({d.x}, {d.z})" if d.x is not None else "(?)"
            print(f"  t={ts:7.1f}s  entity={eid}  pos={pos_str}  "
                  f"f8: {d.f8_before} -> {d.f8_after}")

    # Show f8 progression for first champion
    if game.champions:
        first_champ = list(game.champions.values())[0]
        f8_vals = [(s.timestamp, s.f8) for s in first_champ.state_updates
                   if s.f8 is not None]
        if f8_vals:
            print(f"\nEntity {first_champ.entity_id} f8 progression (first/last 5):")
            for ts, val in f8_vals[:5]:
                print(f"  t={ts:7.1f}s  f8={val}")
            if len(f8_vals) > 10:
                print(f"  ...")
            for ts, val in f8_vals[-5:]:
                print(f"  t={ts:7.1f}s  f8={val}")


if __name__ == "__main__":
    main()

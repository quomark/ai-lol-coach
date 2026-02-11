"""
Game state data structures for replay observations.

Each observation captures a snapshot of the full game state at a point in time.
This is what gets serialized to JSON during replay scraping.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Position:
    x: float = 0.0
    y: float = 0.0
    z: float = 0.0


@dataclass
class ChampionState:
    """State of a single champion at an observation tick."""
    champion_name: str = ""
    summoner_name: str = ""
    team: str = ""  # "ORDER" (blue) or "CHAOS" (red)
    level: int = 0
    position: Position = field(default_factory=Position)

    # Resources
    current_health: float = 0.0
    max_health: float = 0.0
    current_mana: float = 0.0
    max_mana: float = 0.0
    health_pct: float = 0.0

    # Stats
    attack_damage: float = 0.0
    ability_power: float = 0.0
    armor: float = 0.0
    magic_resist: float = 0.0
    move_speed: float = 0.0
    attack_speed: float = 0.0

    # Combat
    is_dead: bool = False
    respawn_timer: float = 0.0
    cs: int = 0  # creep score

    # Economy
    current_gold: float = 0.0

    # Items (6 slots)
    items: list[dict] = field(default_factory=list)

    # Abilities
    abilities: dict[str, dict] = field(default_factory=dict)

    # Scores
    kills: int = 0
    deaths: int = 0
    assists: int = 0

    # Buffs
    buffs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


@dataclass
class ObjectiveState:
    """State of a map objective (dragon, baron, tower, etc.)."""
    name: str = ""
    team: str = ""
    position: Position = field(default_factory=Position)
    current_health: float = 0.0
    max_health: float = 0.0
    is_alive: bool = True


@dataclass
class GameEvent:
    """A game event (kill, dragon, baron, tower, etc.)."""
    event_type: str = ""
    time: float = 0.0
    data: dict = field(default_factory=dict)


@dataclass
class GameObservation:
    """
    Full game state at a single point in time.
    This is the primary data structure for training.
    """
    # Metadata
    game_id: str = ""
    game_time: float = 0.0  # seconds
    observation_index: int = 0

    # Players (10 total: 5 blue + 5 red)
    champions: list[ChampionState] = field(default_factory=list)

    # Map objects
    turrets: list[ObjectiveState] = field(default_factory=list)
    inhibitors: list[ObjectiveState] = field(default_factory=list)

    # Events that happened since last observation
    events: list[GameEvent] = field(default_factory=list)

    # Team-level stats
    blue_team_gold: float = 0.0
    red_team_gold: float = 0.0
    blue_team_kills: int = 0
    red_team_kills: int = 0
    blue_team_dragons: int = 0
    red_team_dragons: int = 0
    blue_team_barons: int = 0
    red_team_barons: int = 0

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        import json
        return json.dumps(self.to_dict(), separators=(",", ":"))


def parse_live_client_data(game_data: dict, game_id: str = "",
                           obs_index: int = 0) -> GameObservation:
    """
    Parse the Live Client Data API response into a GameObservation.
    This is the primary data source during replay scraping.

    Live Client Data API endpoints:
      GET /liveclientdata/allgamedata      → full game state
      GET /liveclientdata/activeplayer     → focused player
      GET /liveclientdata/playerlist       → all players
      GET /liveclientdata/eventdata        → events
      GET /liveclientdata/gamestats        → game-level stats
    """
    obs = GameObservation(
        game_id=game_id,
        observation_index=obs_index,
    )

    # Game stats
    game_stats = game_data.get("gameData", {})
    obs.game_time = game_stats.get("gameTime", 0.0)

    # Players
    all_players = game_data.get("allPlayers", [])
    for p in all_players:
        champ = ChampionState(
            champion_name=p.get("championName", ""),
            summoner_name=p.get("riotIdGameName", p.get("summonerName", "")),
            team=p.get("team", ""),
            level=p.get("level", 0),
            is_dead=p.get("isDead", False),
            respawn_timer=p.get("respawnTimer", 0.0),
        )

        # Scores
        scores = p.get("scores", {})
        champ.kills = scores.get("kills", 0)
        champ.deaths = scores.get("deaths", 0)
        champ.assists = scores.get("assists", 0)
        champ.cs = scores.get("creepScore", 0)

        # Items
        champ.items = p.get("items", [])

        # Position (from Live Client Data — may not have x,y,z in spectator)
        # Position comes from the memory reader instead

        obs.champions.append(champ)

    # Events
    events_data = game_data.get("events", {}).get("Events", [])
    for ev in events_data:
        obs.events.append(GameEvent(
            event_type=ev.get("EventName", ""),
            time=ev.get("EventTime", 0.0),
            data=ev,
        ))

    # Team totals
    blue_kills = red_kills = 0
    for ch in obs.champions:
        if ch.team == "ORDER":
            blue_kills += ch.kills
        else:
            red_kills += ch.kills
    obs.blue_team_kills = blue_kills
    obs.red_team_kills = red_kills

    return obs

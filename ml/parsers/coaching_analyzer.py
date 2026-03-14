"""
Coaching analysis from decoded ROFL game state.

Generates actionable coaching insights from champion positions,
deaths, and state updates. Designed to analyze the USER's own
replay and provide personalized feedback.

Usage:
    from ml.parsers.coaching_analyzer import CoachingAnalyzer

    analyzer = CoachingAnalyzer(game, player_name="SummonerName")
    report = analyzer.analyze()
    print(report.summary())
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from ml.parsers.game_state import GameState, ChampionTimeline


# Summoner's Rift approximate landmarks (game units)
BLUE_FOUNTAIN = (400, 400)
RED_FOUNTAIN = (14600, 14600)
MAP_CENTER = (7500, 7500)

# Lane corridors (approximate bounding boxes)
# Top lane: left edge, going from blue to red
TOP_LANE = {"x_range": (0, 4000), "z_range": (4000, 16000)}
# Bot lane: bottom edge
BOT_LANE = {"x_range": (4000, 16000), "z_range": (0, 4000)}
# Mid lane: diagonal corridor
MID_LANE_WIDTH = 3000  # distance from diagonal

# Time windows
EARLY_GAME = (90, 900)      # 1:30 - 15:00
MID_GAME = (900, 1500)      # 15:00 - 25:00
LATE_GAME = (1500, 3600)    # 25:00+


@dataclass
class TeamInfo:
    entity_ids: list[int]
    side: str  # "blue" or "red"


@dataclass
class DeathAnalysis:
    total_deaths: int
    early_deaths: int  # before 15 min
    solo_deaths: int  # no ally death within 30s
    death_positions: list[tuple[float, int, int]]  # (time, x, z)
    avg_death_time_gap: float  # average seconds between deaths


@dataclass
class PositionAnalysis:
    avg_x: float
    avg_z: float
    time_in_base_pct: float  # % time near fountain
    time_in_enemy_half_pct: float
    roam_score: float  # how much the player moves around the map


@dataclass
class CoachingReport:
    player_entity: Optional[int]
    champion_name: Optional[str]
    team: Optional[str]
    game_duration: float

    deaths: DeathAnalysis
    positioning: PositionAnalysis

    # Coaching tips generated from analysis
    tips: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = []
        champ = self.champion_name or f"Entity {self.player_entity}"
        lines.append(f"=== Coaching Report: {champ} ===")
        lines.append(f"Duration: {self.game_duration / 60:.1f} min")
        lines.append("")

        lines.append(f"Deaths: {self.deaths.total_deaths}")
        lines.append(f"  Early game (<15min): {self.deaths.early_deaths}")
        lines.append(f"  Solo deaths: {self.deaths.solo_deaths}")
        if self.deaths.avg_death_time_gap > 0:
            lines.append(f"  Avg time between deaths: {self.deaths.avg_death_time_gap:.0f}s")
        lines.append("")

        lines.append(f"Positioning:")
        lines.append(f"  Time in base: {self.positioning.time_in_base_pct:.1f}%")
        lines.append(f"  Time in enemy half: {self.positioning.time_in_enemy_half_pct:.1f}%")
        lines.append(f"  Roam score: {self.positioning.roam_score:.1f}")
        lines.append("")

        if self.tips:
            lines.append("Coaching Tips:")
            for i, tip in enumerate(self.tips, 1):
                lines.append(f"  {i}. {tip}")

        return "\n".join(lines)


def _distance(x1, z1, x2, z2):
    return ((x1 - x2) ** 2 + (z1 - z2) ** 2) ** 0.5


def _is_near_fountain(x, z, side):
    if side == "blue":
        return _distance(x, z, *BLUE_FOUNTAIN) < 2500
    return _distance(x, z, *RED_FOUNTAIN) < 2500


def _in_enemy_half(x, z, side):
    if side == "blue":
        return x + z > 15000
    return x + z < 15000


class CoachingAnalyzer:
    """Generate coaching insights from a reconstructed game state."""

    def __init__(self, game: GameState, player_name: Optional[str] = None):
        self.game = game
        self.player_name = player_name
        self._teams = self._determine_teams()
        self._player_meta = self._load_player_meta()

    def _determine_teams(self) -> tuple[TeamInfo, TeamInfo]:
        """Split champions into two teams using kill graph."""
        kill_edges = []
        for champ in self.game.champions.values():
            for d in champ.deaths:
                killer = d.f8_after
                if killer is not None and killer in self.game.champions:
                    kill_edges.append((killer, champ.entity_id))

        if not kill_edges:
            ids = sorted(self.game.champions.keys())
            mid = len(ids) // 2
            return (
                TeamInfo(ids[:mid], "blue"),
                TeamInfo(ids[mid:], "red"),
            )

        # BFS graph coloring
        adj: dict[int, set[int]] = defaultdict(set)
        for k, v in kill_edges:
            adj[k].add(v)
            adj[v].add(k)

        teams: dict[int, int] = {}
        start = min(self.game.champions.keys())
        teams[start] = 0
        queue = [start]
        while queue:
            node = queue.pop(0)
            for neighbor in adj[node]:
                if neighbor not in teams:
                    teams[neighbor] = 1 - teams[node]
                    queue.append(neighbor)

        # Assign any uncolored entities
        for eid in self.game.champions:
            if eid not in teams:
                teams[eid] = 0

        group0 = sorted(e for e, t in teams.items() if t == 0)
        group1 = sorted(e for e, t in teams.items() if t == 1)

        # Determine which group is blue by checking early positions
        # Blue side starts at lower coordinates
        def avg_early_pos(ids):
            total_x, total_z, n = 0, 0, 0
            for eid in ids:
                champ = self.game.champions.get(eid)
                if champ:
                    early = [p for p in champ.positions if p.timestamp < 30]
                    for p in early:
                        total_x += p.x
                        total_z += p.z
                        n += 1
            return (total_x / n, total_z / n) if n > 0 else (7500, 7500)

        pos0 = avg_early_pos(group0)
        pos1 = avg_early_pos(group1)

        if pos0[0] + pos0[1] <= pos1[0] + pos1[1]:
            return TeamInfo(group0, "blue"), TeamInfo(group1, "red")
        return TeamInfo(group1, "blue"), TeamInfo(group0, "red")

    def _load_player_meta(self) -> Optional[dict]:
        """Load ROFL metadata to match player names to champions."""
        try:
            from ml.parsers.rofl_parser import ROFLParser
            rofl = ROFLParser(self.game.replay_path)
            info = rofl.get_match_info()
            return info
        except Exception:
            return None

    def _find_player_entity(self) -> tuple[Optional[int], Optional[str]]:
        """Find the player's entity ID and champion name."""
        if self._player_meta and self.player_name:
            stats = self._player_meta.get("player_stats", [])
            for i, p in enumerate(stats):
                name = p.get("NAME", "") or p.get("PUUID", "")
                if name and self.player_name.lower() in name.lower():
                    # Map metadata index to entity
                    entities = sorted(self.game.champions.keys())
                    if i < len(entities):
                        return entities[i], p.get("SKIN", "Unknown")

        # Default: first champion
        if self.game.champions:
            first = min(self.game.champions.keys())
            return first, None
        return None, None

    def _get_team_side(self, entity_id: int) -> str:
        blue, red = self._teams
        if entity_id in blue.entity_ids:
            return "blue"
        return "red"

    def _analyze_deaths(self, champ: ChampionTimeline, side: str) -> DeathAnalysis:
        total = len(champ.deaths)
        early = sum(1 for d in champ.deaths if d.timestamp < EARLY_GAME[1])

        # Solo deaths: no ally died within 30 seconds
        ally_team = self._teams[0] if side == "blue" else self._teams[1]
        ally_deaths = []
        for eid in ally_team.entity_ids:
            if eid == champ.entity_id:
                continue
            ally = self.game.champions.get(eid)
            if ally:
                ally_deaths.extend(d.timestamp for d in ally.deaths)

        solo = 0
        for d in champ.deaths:
            nearby_ally_death = any(
                abs(d.timestamp - at) < 30 for at in ally_deaths
            )
            if not nearby_ally_death:
                solo += 1

        positions = [
            (d.timestamp, d.x or 0, d.z or 0) for d in champ.deaths
        ]

        if total >= 2:
            gaps = [
                champ.deaths[i].timestamp - champ.deaths[i - 1].timestamp
                for i in range(1, total)
            ]
            avg_gap = sum(gaps) / len(gaps)
        else:
            avg_gap = 0

        return DeathAnalysis(
            total_deaths=total,
            early_deaths=early,
            solo_deaths=solo,
            death_positions=positions,
            avg_death_time_gap=avg_gap,
        )

    def _analyze_positioning(self, champ: ChampionTimeline, side: str) -> PositionAnalysis:
        if not champ.positions:
            return PositionAnalysis(0, 0, 0, 0, 0)

        positions = champ.positions
        total = len(positions)

        avg_x = sum(p.x for p in positions) / total
        avg_z = sum(p.z for p in positions) / total

        in_base = sum(1 for p in positions if _is_near_fountain(p.x, p.z, side))
        in_enemy = sum(1 for p in positions if _in_enemy_half(p.x, p.z, side))

        base_pct = in_base / total * 100
        enemy_pct = in_enemy / total * 100

        # Roam score: average distance between consecutive positions
        if total >= 2:
            total_dist = sum(
                _distance(positions[i].x, positions[i].z,
                          positions[i - 1].x, positions[i - 1].z)
                for i in range(1, total)
            )
            roam_score = total_dist / total
        else:
            roam_score = 0

        return PositionAnalysis(
            avg_x=avg_x,
            avg_z=avg_z,
            time_in_base_pct=base_pct,
            time_in_enemy_half_pct=enemy_pct,
            roam_score=roam_score,
        )

    def _generate_tips(self, deaths: DeathAnalysis, positioning: PositionAnalysis,
                       champ: ChampionTimeline) -> list[str]:
        tips = []

        if deaths.early_deaths >= 3:
            tips.append(
                f"You died {deaths.early_deaths} times before 15 minutes. "
                "Focus on safer laning - ward river and play around cooldowns."
            )

        if deaths.solo_deaths > deaths.total_deaths * 0.5 and deaths.solo_deaths >= 2:
            tips.append(
                f"{deaths.solo_deaths} of your {deaths.total_deaths} deaths were solo. "
                "Avoid overextending without vision or team backup."
            )

        if positioning.time_in_base_pct > 15:
            tips.append(
                f"You spent {positioning.time_in_base_pct:.0f}% of the game in base. "
                "Try to reduce recall frequency by managing HP/mana better."
            )

        if positioning.time_in_enemy_half_pct < 10 and self.game.duration > 1200:
            tips.append(
                "You spent very little time in the enemy half of the map. "
                "Look for opportunities to push advantages and pressure objectives."
            )

        if deaths.avg_death_time_gap > 0 and deaths.avg_death_time_gap < 120 and deaths.total_deaths >= 3:
            tips.append(
                f"Your deaths were only {deaths.avg_death_time_gap:.0f}s apart on average. "
                "After dying, play safer to avoid giving up consecutive kills."
            )

        if not tips:
            tips.append("Solid game! Keep focusing on consistent positioning and map awareness.")

        return tips

    def analyze(self, entity_id: Optional[int] = None) -> CoachingReport:
        """Run full coaching analysis for a player."""
        if entity_id is None:
            entity_id, champ_name = self._find_player_entity()
        else:
            champ_name = None

        if entity_id is None or entity_id not in self.game.champions:
            raise ValueError(f"Entity {entity_id} not found in game state")

        champ = self.game.champions[entity_id]
        side = self._get_team_side(entity_id)

        deaths = self._analyze_deaths(champ, side)
        positioning = self._analyze_positioning(champ, side)
        tips = self._generate_tips(deaths, positioning, champ)

        return CoachingReport(
            player_entity=entity_id,
            champion_name=champ_name,
            team=side,
            game_duration=self.game.duration,
            deaths=deaths,
            positioning=positioning,
            tips=tips,
        )

    def analyze_all(self) -> list[CoachingReport]:
        """Run coaching analysis for all champions."""
        reports = []
        for eid in sorted(self.game.champions.keys()):
            champ_name = None
            if self._player_meta:
                stats = self._player_meta.get("player_stats", [])
                entities = sorted(self.game.champions.keys())
                idx = entities.index(eid) if eid in entities else -1
                if 0 <= idx < len(stats):
                    champ_name = stats[idx].get("SKIN", None)

            report = self.analyze(entity_id=eid)
            report.champion_name = champ_name
            reports.append(report)
        return reports


def main():
    """Demo: analyze a replay and print coaching report."""
    import sys
    from ml.parsers.game_state import GameStateBuilder

    binary_path = "ml/data/league_unpacked_patched.bin"
    replay_path = r"C:\Users\ngan9\OneDrive\Documents\League of Legends\Replays\TW2-396324158.rofl"

    if len(sys.argv) > 1:
        replay_path = sys.argv[1]

    player_name = None
    if len(sys.argv) > 2:
        player_name = sys.argv[2]

    builder = GameStateBuilder(binary_path)
    game = builder.build_from_rofl(replay_path)

    analyzer = CoachingAnalyzer(game, player_name=player_name)

    # Print team info
    blue, red = analyzer._teams
    print(f"Blue team: entities {blue.entity_ids}")
    print(f"Red team:  entities {red.entity_ids}")
    print()

    # Analyze all players
    reports = analyzer.analyze_all()
    for report in reports:
        print(report.summary())
        print()


if __name__ == "__main__":
    main()

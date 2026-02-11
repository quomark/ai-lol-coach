"""
Build the "optimal play" training dataset from high-elo match timelines.

This processes Riot API timeline data into training pairs:
  Input:  game state at frame N
  Output: what the high-elo player did at frame N+1

The model learns "what would a Challenger player do in this exact situation?"

Then at inference time:
  1. Parse the user's replay
  2. At each key moment, ask the model "what's optimal here?"
  3. Compare what the user DID vs what the model says is OPTIMAL
  4. The GAP is the coaching advice

Usage:
    # After fetching high-elo matches:
    python -m ml.scripts.build_optimal_play_dataset \
        --input ./ml/data/raw/high_elo \
        --output ./ml/data/processed/optimal_play.jsonl
"""

import argparse
import json
from pathlib import Path
from typing import Any


# ─── Game state extraction from timeline frames ─────────────────────────────

def extract_frame_state(frame: dict, participant_id: int, all_participants: dict) -> dict:
    """
    Extract a structured game state from a timeline frame for one player.

    A timeline frame contains:
    - participantFrames: position, gold, CS, XP, level for each player
    - events: kills, items, wards, objectives, etc.
    - timestamp: milliseconds into the game
    """
    pframes = frame.get("participantFrames", {})
    pf = pframes.get(str(participant_id), {})
    position = pf.get("position", {})

    # Get all player positions for context
    all_positions = {}
    for pid, pdata in pframes.items():
        pos = pdata.get("position", {})
        all_positions[int(pid)] = {
            "x": pos.get("x", 0),
            "y": pos.get("y", 0),
            "gold": pdata.get("totalGold", 0),
            "cs": pdata.get("minionsKilled", 0) + pdata.get("jungleMinionsKilled", 0),
            "xp": pdata.get("xp", 0),
            "level": pdata.get("level", 1),
            "current_gold": pdata.get("currentGold", 0),
        }

    # Get participant info (champion, team, role)
    participant_info = all_participants.get(participant_id, {})

    state = {
        "timestamp_ms": frame.get("timestamp", 0),
        "timestamp_min": frame.get("timestamp", 0) / 60000,
        # Focus player state
        "player": {
            "participant_id": participant_id,
            "champion": participant_info.get("champion", ""),
            "role": participant_info.get("role", ""),
            "team": participant_info.get("team", ""),
            "x": position.get("x", 0),
            "y": position.get("y", 0),
            "gold": pf.get("totalGold", 0),
            "current_gold": pf.get("currentGold", 0),
            "cs": pf.get("minionsKilled", 0) + pf.get("jungleMinionsKilled", 0),
            "xp": pf.get("xp", 0),
            "level": pf.get("level", 1),
            "damage_done": pf.get("damageStats", {}).get("totalDamageDoneToChampions", 0),
        },
        # All player positions (for map awareness context)
        "all_players": all_positions,
        # Team gold totals
        "team_gold": {
            "blue": sum(
                d["gold"] for pid, d in all_positions.items() if pid <= 5
            ),
            "red": sum(
                d["gold"] for pid, d in all_positions.items() if pid > 5
            ),
        },
    }

    return state


def extract_events_in_window(
    events: list[dict],
    start_ms: int,
    end_ms: int,
    participant_id: int,
) -> list[dict]:
    """Extract events relevant to a player in a time window."""
    relevant = []
    for event in events:
        ts = event.get("timestamp", 0)
        if ts < start_ms or ts > end_ms:
            continue

        etype = event.get("type", "")

        # Events involving this player
        if event.get("participantId") == participant_id:
            relevant.append({"type": etype, "timestamp": ts, **event})
        elif event.get("killerId") == participant_id:
            relevant.append({"type": etype, "role": "killer", "timestamp": ts, **event})
        elif event.get("victimId") == participant_id:
            relevant.append({"type": etype, "role": "victim", "timestamp": ts, **event})
        elif participant_id in event.get("assistingParticipantIds", []):
            relevant.append({"type": etype, "role": "assist", "timestamp": ts, **event})

        # Objective events (relevant to everyone)
        if etype in (
            "DRAGON_SOUL_GIVEN",
            "ELITE_MONSTER_KILL",
            "BUILDING_KILL",
            "GAME_END",
        ):
            relevant.append({"type": etype, "timestamp": ts, **event})

    return relevant


def classify_action(
    current_state: dict,
    next_state: dict,
    events: list[dict],
) -> dict:
    """
    Classify what the player DID between two frames.

    Returns a structured action description:
    - movement: where they moved (and how far)
    - combat: did they fight, kill, die, assist?
    - economy: did they buy items, farm?
    - objectives: did they take/contest objectives?
    - map_control: did they ward, clear wards?
    """
    player_now = current_state["player"]
    player_next = next_state["player"]

    # Movement
    dx = player_next["x"] - player_now["x"]
    dy = player_next["y"] - player_now["y"]
    distance = (dx**2 + dy**2) ** 0.5

    # Classify position on map (rough zones)
    zone = _classify_map_zone(player_next["x"], player_next["y"])

    # Event-based actions
    kills = [e for e in events if e.get("type") == "CHAMPION_KILL" and e.get("role") == "killer"]
    deaths = [e for e in events if e.get("type") == "CHAMPION_KILL" and e.get("role") == "victim"]
    assists = [e for e in events if e.get("type") == "CHAMPION_KILL" and e.get("role") == "assist"]
    items_bought = [e for e in events if e.get("type") == "ITEM_PURCHASED"]
    wards_placed = [e for e in events if e.get("type") == "WARD_PLACED"]
    wards_killed = [e for e in events if e.get("type") == "WARD_KILL"]
    objectives = [e for e in events if e.get("type") == "ELITE_MONSTER_KILL"]
    buildings = [e for e in events if e.get("type") == "BUILDING_KILL"]

    action = {
        "movement": {
            "distance": distance,
            "direction": {"dx": dx, "dy": dy},
            "zone": zone,
        },
        "combat": {
            "kills": len(kills),
            "deaths": len(deaths),
            "assists": len(assists),
        },
        "economy": {
            "cs_gained": player_next["cs"] - player_now["cs"],
            "gold_gained": player_next["gold"] - player_now["gold"],
            "items_bought": len(items_bought),
        },
        "vision": {
            "wards_placed": len(wards_placed),
            "wards_cleared": len(wards_killed),
        },
        "objectives": {
            "monsters_killed": [e.get("monsterType", "") for e in objectives],
            "buildings_killed": len(buildings),
        },
    }

    return action


def _classify_map_zone(x: int, y: int) -> str:
    """
    Rough map zone classification based on coordinates.
    Summoner's Rift coordinates: roughly 0-15000 on both axes.
    """
    # Normalize to 0-1
    nx = x / 15000
    ny = y / 15000

    if nx < 0.3 and ny < 0.3:
        return "blue_base"
    elif nx > 0.7 and ny > 0.7:
        return "red_base"
    elif nx < 0.4 and ny > 0.6:
        return "top_lane"
    elif nx > 0.6 and ny < 0.4:
        return "bot_lane"
    elif 0.35 < nx < 0.65 and 0.35 < ny < 0.65:
        return "mid_lane"
    elif nx < 0.5 and ny < 0.5:
        return "blue_jungle"
    elif nx > 0.5 and ny > 0.5:
        return "red_jungle"
    elif 0.4 < nx < 0.6 and ny < 0.4:
        return "dragon_pit"
    elif 0.4 < nx < 0.6 and ny > 0.6:
        return "baron_pit"
    else:
        return "river"


# ─── Build training examples ────────────────────────────────────────────────

def process_match(match_file: str, timeline_file: str) -> list[dict]:
    """
    Process a single match + timeline into training examples.

    For each player, for each frame pair:
      (game_state_at_T, action_taken_T_to_T+1)

    This teaches the model: "in this situation, a Challenger player did X"
    """
    with open(match_file) as f:
        match = json.load(f)
    with open(timeline_file) as f:
        timeline = json.load(f)

    info = match.get("info", {})
    participants = {}
    for p in info.get("participants", []):
        participants[p["participantId"]] = {
            "champion": p.get("championName", ""),
            "role": p.get("individualPosition", ""),
            "team": "blue" if p.get("teamId") == 100 else "red",
            "win": p.get("win", False),
        }

    frames = timeline.get("info", {}).get("frames", [])
    if len(frames) < 2:
        return []

    examples = []

    for participant_id, pinfo in participants.items():
        for i in range(len(frames) - 1):
            current_frame = frames[i]
            next_frame = frames[i + 1]

            # Skip early game (first 2 min is just walking to lane)
            if current_frame.get("timestamp", 0) < 120000:
                continue

            # Extract state
            state = extract_frame_state(current_frame, participant_id, participants)

            # Extract events between frames
            events = extract_events_in_window(
                next_frame.get("events", []),
                current_frame.get("timestamp", 0),
                next_frame.get("timestamp", 0),
                participant_id,
            )

            # Extract next state
            next_state = extract_frame_state(next_frame, participant_id, participants)

            # Classify what they did
            action = classify_action(state, next_state, events)

            example = {
                "state": state,
                "action": action,
                "events": [
                    {"type": e.get("type"), "timestamp": e.get("timestamp")}
                    for e in events
                ],
                "player_info": pinfo,
                "match_id": match.get("metadata", {}).get("matchId", ""),
            }
            examples.append(example)

    return examples


def main():
    parser = argparse.ArgumentParser(description="Build optimal play dataset")
    parser.add_argument("--input", type=str, default="./ml/data/raw/high_elo")
    parser.add_argument("--output", type=str, default="./ml/data/processed/optimal_play.jsonl")
    args = parser.parse_args()

    input_dir = Path(args.input)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    match_dir = input_dir / "matches"
    timeline_dir = input_dir / "timelines"

    if not match_dir.exists():
        print(f"No matches found in {match_dir}")
        print("Run fetch_high_elo_matches.py first!")
        return

    match_files = sorted(match_dir.glob("*.json"))
    print(f"Processing {len(match_files)} matches...")

    total_examples = 0

    with open(output_path, "w") as out:
        for i, match_file in enumerate(match_files):
            match_id = match_file.stem
            timeline_file = timeline_dir / f"{match_id}_timeline.json"

            if not timeline_file.exists():
                continue

            try:
                examples = process_match(str(match_file), str(timeline_file))
                for ex in examples:
                    out.write(json.dumps(ex) + "\n")
                total_examples += len(examples)

                if (i + 1) % 50 == 0:
                    print(f"  [{i+1}/{len(match_files)}] {total_examples} examples so far")
            except Exception as e:
                print(f"  Failed to process {match_id}: {e}")

    print(f"\nDone! {total_examples} training examples → {output_path}")
    print(f"  {total_examples // max(len(match_files), 1)} examples per match avg")


if __name__ == "__main__":
    main()

"""
Convert scraped observation JSON files → SQLite database.

Input:  ml/data/raw/observations/*.jsonl  (one file per game)
Output: ml/data/processed/replays.db

Tables:
  games        — one row per game
  observations — one row per observation tick
  champions    — one row per champion per tick (10 per observation)
  events       — game events (kills, dragons, etc.)

Usage:
    python -m ml.scraper.convert_to_sqlite \\
        --input ml/data/raw/observations \\
        --output ml/data/processed/replays.db
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path


DEFAULT_INPUT = "ml/data/raw/observations"
DEFAULT_OUTPUT = "ml/data/processed/replays.db"


def create_tables(conn: sqlite3.Connection):
    """Create the schema."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS games (
            game_id TEXT PRIMARY KEY,
            total_observations INTEGER,
            max_game_time REAL,
            source_file TEXT
        );

        CREATE TABLE IF NOT EXISTS observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            game_id TEXT NOT NULL,
            obs_index INTEGER NOT NULL,
            game_time REAL NOT NULL,
            blue_team_kills INTEGER,
            red_team_kills INTEGER,
            blue_team_gold REAL,
            red_team_gold REAL,
            blue_team_dragons INTEGER,
            red_team_dragons INTEGER,
            blue_team_barons INTEGER,
            red_team_barons INTEGER,
            FOREIGN KEY (game_id) REFERENCES games(game_id)
        );

        CREATE TABLE IF NOT EXISTS champions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            game_id TEXT NOT NULL,
            obs_index INTEGER NOT NULL,
            game_time REAL NOT NULL,
            champion_name TEXT,
            summoner_name TEXT,
            team TEXT,
            level INTEGER,
            pos_x REAL,
            pos_y REAL,
            pos_z REAL,
            current_health REAL,
            max_health REAL,
            health_pct REAL,
            current_mana REAL,
            max_mana REAL,
            attack_damage REAL,
            ability_power REAL,
            armor REAL,
            magic_resist REAL,
            move_speed REAL,
            attack_speed REAL,
            is_dead INTEGER,
            cs INTEGER,
            current_gold REAL,
            kills INTEGER,
            deaths INTEGER,
            assists INTEGER,
            items_json TEXT,
            FOREIGN KEY (game_id) REFERENCES games(game_id)
        );

        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            game_id TEXT NOT NULL,
            event_type TEXT,
            event_time REAL,
            data_json TEXT,
            FOREIGN KEY (game_id) REFERENCES games(game_id)
        );

        CREATE INDEX IF NOT EXISTS idx_obs_game ON observations(game_id);
        CREATE INDEX IF NOT EXISTS idx_obs_time ON observations(game_time);
        CREATE INDEX IF NOT EXISTS idx_champ_game ON champions(game_id);
        CREATE INDEX IF NOT EXISTS idx_champ_time ON champions(game_time);
        CREATE INDEX IF NOT EXISTS idx_champ_name ON champions(champion_name);
        CREATE INDEX IF NOT EXISTS idx_events_game ON events(game_id);
        CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
    """)


def insert_observation(conn: sqlite3.Connection, obs: dict):
    """Insert a single observation into the database."""
    game_id = obs.get("game_id", "")
    obs_idx = obs.get("observation_index", 0)
    game_time = obs.get("game_time", 0.0)

    # Insert observation row
    conn.execute("""
        INSERT INTO observations (
            game_id, obs_index, game_time,
            blue_team_kills, red_team_kills,
            blue_team_gold, red_team_gold,
            blue_team_dragons, red_team_dragons,
            blue_team_barons, red_team_barons
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        game_id, obs_idx, game_time,
        obs.get("blue_team_kills", 0), obs.get("red_team_kills", 0),
        obs.get("blue_team_gold", 0), obs.get("red_team_gold", 0),
        obs.get("blue_team_dragons", 0), obs.get("red_team_dragons", 0),
        obs.get("blue_team_barons", 0), obs.get("red_team_barons", 0),
    ))

    # Insert champion rows
    for champ in obs.get("champions", []):
        pos = champ.get("position", {})
        conn.execute("""
            INSERT INTO champions (
                game_id, obs_index, game_time,
                champion_name, summoner_name, team, level,
                pos_x, pos_y, pos_z,
                current_health, max_health, health_pct,
                current_mana, max_mana,
                attack_damage, ability_power, armor, magic_resist,
                move_speed, attack_speed,
                is_dead, cs, current_gold,
                kills, deaths, assists, items_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            game_id, obs_idx, game_time,
            champ.get("champion_name", ""),
            champ.get("summoner_name", ""),
            champ.get("team", ""),
            champ.get("level", 0),
            pos.get("x", 0), pos.get("y", 0), pos.get("z", 0),
            champ.get("current_health", 0), champ.get("max_health", 0),
            champ.get("health_pct", 0),
            champ.get("current_mana", 0), champ.get("max_mana", 0),
            champ.get("attack_damage", 0), champ.get("ability_power", 0),
            champ.get("armor", 0), champ.get("magic_resist", 0),
            champ.get("move_speed", 0), champ.get("attack_speed", 0),
            1 if champ.get("is_dead", False) else 0,
            champ.get("cs", 0),
            champ.get("current_gold", 0),
            champ.get("kills", 0), champ.get("deaths", 0), champ.get("assists", 0),
            json.dumps(champ.get("items", []), separators=(",", ":")),
        ))


def process_file(conn: sqlite3.Connection, jsonl_path: Path) -> tuple[int, float]:
    """Process a single .jsonl file. Returns (obs_count, max_game_time)."""
    game_id = jsonl_path.stem
    obs_count = 0
    max_time = 0.0
    seen_events = set()

    with open(jsonl_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obs = json.loads(line)
            except json.JSONDecodeError:
                continue

            insert_observation(conn, obs)
            obs_count += 1
            gt = obs.get("game_time", 0.0)
            if gt > max_time:
                max_time = gt

            # Insert events (deduplicated by event_type + time)
            for ev in obs.get("events", []):
                key = (ev.get("event_type", ""), ev.get("time", 0))
                if key not in seen_events:
                    seen_events.add(key)
                    conn.execute("""
                        INSERT INTO events (game_id, event_type, event_time, data_json)
                        VALUES (?, ?, ?, ?)
                    """, (
                        game_id,
                        ev.get("event_type", ""),
                        ev.get("time", 0.0),
                        json.dumps(ev.get("data", {}), separators=(",", ":")),
                    ))

    # Insert game summary
    conn.execute("""
        INSERT OR REPLACE INTO games (game_id, total_observations, max_game_time, source_file)
        VALUES (?, ?, ?, ?)
    """, (game_id, obs_count, max_time, jsonl_path.name))

    return obs_count, max_time


def convert(input_dir: str, output_db: str):
    """Convert all JSONL files to SQLite."""
    input_path = Path(input_dir)
    output_path = Path(output_db)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    jsonl_files = sorted(input_path.glob("*.jsonl"))
    if not jsonl_files:
        print(f"No .jsonl files found in {input_path}")
        return

    print(f"Converting {len(jsonl_files)} files → {output_path}")

    conn = sqlite3.connect(str(output_path))
    create_tables(conn)

    total_obs = 0
    for i, f in enumerate(jsonl_files, 1):
        n, max_t = process_file(conn, f)
        total_obs += n
        mins = max_t / 60
        print(f"  [{i}/{len(jsonl_files)}] {f.stem}: {n:,} obs, {mins:.1f}m")

        # Commit every 10 files
        if i % 10 == 0:
            conn.commit()

    conn.commit()

    # Print summary
    cursor = conn.execute("SELECT COUNT(*) FROM games")
    n_games = cursor.fetchone()[0]
    cursor = conn.execute("SELECT COUNT(*) FROM observations")
    n_obs = cursor.fetchone()[0]
    cursor = conn.execute("SELECT COUNT(*) FROM champions")
    n_champs = cursor.fetchone()[0]
    cursor = conn.execute("SELECT COUNT(*) FROM events")
    n_events = cursor.fetchone()[0]

    print(f"\n{'='*50}")
    print(f"Database: {output_path}")
    print(f"  Games:        {n_games:>10,}")
    print(f"  Observations: {n_obs:>10,}")
    print(f"  Champion rows: {n_champs:>10,}")
    print(f"  Events:       {n_events:>10,}")
    db_size = output_path.stat().st_size
    print(f"  Size:         {db_size / 1024 / 1024:.1f} MB")
    print(f"{'='*50}")

    conn.close()


def main():
    ap = argparse.ArgumentParser(description="Convert observation JSONL → SQLite")
    ap.add_argument("--input", default=DEFAULT_INPUT, help="Input dir with .jsonl files")
    ap.add_argument("--output", default=DEFAULT_OUTPUT, help="Output SQLite database path")
    args = ap.parse_args()
    convert(args.input, args.output)


if __name__ == "__main__":
    main()

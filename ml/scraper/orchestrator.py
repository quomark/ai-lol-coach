"""
Replay scraping orchestrator.

Automates the full pipeline:
  1. Find .rofl files to process
  2. For each replay:
     a. Launch it in the LoL client via LCU API
     b. Set playback speed (8x or 16x)
     c. Poll game state via Live Client Data API (+ memory reader for positions)
     d. Save observations as JSON
  3. Convert JSON → SQLite

The Live Client Data API provides:
  - Player stats (kills, deaths, assists, items, level, CS)
  - Game events (kills, dragons, barons, turrets)
  - Game time

The memory reader (Windows-only) adds:
  - Champion x,y positions
  - Health/mana values in real-time
  - More granular data

Usage:
    python -m ml.scraper.orchestrator \\
        --replay-dir ml/data/raw/high_elo/replays \\
        --output-dir ml/data/raw/observations \\
        --speed 8
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from ml.scraper.lcu_api import LCUClient
from ml.scraper.game_state import GameObservation, parse_live_client_data


# ── Configuration ────────────────────────────────────────────────────

DEFAULT_REPLAY_DIR = "ml/data/raw/high_elo/replays"
DEFAULT_OUTPUT_DIR = "ml/data/raw/observations"
DEFAULT_SPEED = 8
OBS_PER_SECOND = 4  # Target observations per real second of game time
REPLAY_LOAD_TIMEOUT = 60  # Seconds to wait for replay to load
MAX_GAME_TIME = 60 * 60  # 1 hour max (safety)


# ── Memory reader (optional, Windows only) ────────────────────────────

def try_import_memory_reader():
    """Try to import the memory reader. Returns None on Mac/Linux."""
    if sys.platform != "win32":
        return None
    try:
        from ml.scraper.memory_reader import LoLMemoryReader
        return LoLMemoryReader
    except ImportError:
        return None


# ── Scraping logic ────────────────────────────────────────────────────

def scrape_single_replay(
    lcu: LCUClient,
    rofl_path: Path,
    output_dir: Path,
    speed: float = 8,
    max_game_minutes: float = 0,  # 0 = full game
    use_memory_reader: bool = True,
) -> int:
    """
    Scrape a single replay file.

    Returns the number of observations captured.
    """
    game_id = rofl_path.stem.replace(".replay", "")
    obs_file = output_dir / f"{game_id}.jsonl"

    # Skip if already scraped
    if obs_file.exists():
        lines = obs_file.read_text().strip().count("\n") + 1
        print(f"  [SKIP] {game_id} — already have {lines} observations")
        return 0

    print(f"\n  [LOAD] {game_id}")

    # Launch replay
    abs_path = str(rofl_path.resolve())
    launched = lcu.launch_replay_from_file(abs_path)
    if not launched:
        print(f"  [FAIL] Could not launch replay: {abs_path}")
        return 0

    # Wait for it to load
    print(f"  [WAIT] Loading replay (timeout={REPLAY_LOAD_TIMEOUT}s)...")
    if not lcu.wait_for_replay_loaded(timeout=REPLAY_LOAD_TIMEOUT):
        print(f"  [FAIL] Replay did not load within {REPLAY_LOAD_TIMEOUT}s")
        return 0

    # Set speed
    time.sleep(2)  # Brief pause after load
    lcu.set_replay_speed(speed)
    print(f"  [PLAY] Speed={speed}x")

    # Optional: attach memory reader
    mem_reader = None
    if use_memory_reader:
        MemReaderClass = try_import_memory_reader()
        if MemReaderClass:
            mem_reader = MemReaderClass()
            if not mem_reader.attach():
                print(f"  [WARN] Memory reader failed to attach, using API only")
                mem_reader = None

    # Calculate polling interval
    # At 8x speed, 1 real second = 8 game seconds
    # We want OBS_PER_SECOND observations per game-second
    # So poll every: 1 / (OBS_PER_SECOND * speed) real seconds
    poll_interval = 1.0 / (OBS_PER_SECOND * speed)
    # But clamp to reasonable bounds
    poll_interval = max(poll_interval, 0.05)  # Min 50ms
    poll_interval = min(poll_interval, 0.5)   # Max 500ms

    # Scrape loop
    observations: list[str] = []
    obs_count = 0
    last_game_time = 0.0
    stall_count = 0
    max_game_seconds = max_game_minutes * 60 if max_game_minutes > 0 else MAX_GAME_TIME

    print(f"  [SCRAPE] Polling every {poll_interval*1000:.0f}ms "
          f"(target: {OBS_PER_SECOND}/game-sec)...")

    try:
        while True:
            # Get game data from Live Client Data API
            game_data = lcu.get_game_data()
            if not game_data:
                stall_count += 1
                if stall_count > 30:  # 30 consecutive failures
                    print(f"  [END] Game data unavailable — replay ended?")
                    break
                time.sleep(0.5)
                continue

            stall_count = 0

            # Parse into observation
            obs = parse_live_client_data(game_data, game_id=game_id, obs_index=obs_count)

            # Enrich with memory reader data (positions)
            if mem_reader:
                try:
                    positions = mem_reader.get_champion_positions()
                    # Match positions to champions by name
                    pos_by_name = {p["name"]: p for p in positions}
                    for champ in obs.champions:
                        if champ.champion_name in pos_by_name:
                            p = pos_by_name[champ.champion_name]
                            champ.position.x = p["x"]
                            champ.position.y = p["y"]
                            champ.position.z = p["z"]
                            champ.current_health = p["health"]
                            champ.max_health = p["max_health"]
                            if champ.max_health > 0:
                                champ.health_pct = champ.current_health / champ.max_health
                except Exception:
                    pass  # Memory read failures are non-fatal

            # Check if game progressed
            if obs.game_time <= last_game_time and obs.game_time > 0:
                stall_count += 1
                if stall_count > 50:
                    print(f"  [END] Game time stalled at {obs.game_time:.1f}s")
                    break
            else:
                stall_count = 0
                last_game_time = obs.game_time

            # Save observation
            observations.append(obs.to_json())
            obs_count += 1

            # Progress
            if obs_count % 100 == 0:
                mins = obs.game_time / 60
                print(f"    {obs_count:>5d} obs | game time: {mins:.1f}m")

            # Check time limit
            if obs.game_time >= max_game_seconds:
                print(f"  [END] Reached time limit ({max_game_minutes}m)")
                break

            time.sleep(poll_interval)

    except KeyboardInterrupt:
        print(f"\n  [INTERRUPT] Saving {obs_count} observations...")

    # Clean up memory reader
    if mem_reader:
        mem_reader.detach()

    # Save to file
    if observations:
        output_dir.mkdir(parents=True, exist_ok=True)
        obs_file.write_text("\n".join(observations) + "\n")
        print(f"  [SAVE] {obs_count} observations → {obs_file}")
    else:
        print(f"  [WARN] No observations captured")

    return obs_count


def run_scraper(
    replay_dir: str,
    output_dir: str,
    speed: float = DEFAULT_SPEED,
    max_game_minutes: float = 0,
    max_games: int = 0,
    use_memory_reader: bool = True,
):
    """Main scraping loop."""
    replay_path = Path(replay_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Find .rofl files
    rofl_files = sorted(replay_path.glob("*.rofl"))
    if not rofl_files:
        print(f"No .rofl files found in {replay_path}")
        return

    # Filter already-scraped
    already_done = set()
    for f in output_path.glob("*.jsonl"):
        already_done.add(f.stem)

    remaining = [f for f in rofl_files if f.stem.replace(".replay", "") not in already_done]

    if max_games > 0:
        remaining = remaining[:max_games]

    print(f"{'='*60}")
    print(f"Replay Scraper")
    print(f"{'='*60}")
    print(f"  Replay dir:  {replay_path}")
    print(f"  Output dir:  {output_path}")
    print(f"  Total .rofl: {len(rofl_files)}")
    print(f"  Already done: {len(already_done)}")
    print(f"  Remaining:   {len(remaining)}")
    print(f"  Speed:       {speed}x")
    if max_game_minutes:
        print(f"  Max time:    {max_game_minutes}m per game")
    print(f"{'='*60}")

    if not remaining:
        print("Nothing to scrape!")
        return

    # Connect to LCU
    print("\nConnecting to League Client...")
    try:
        lcu = LCUClient()
    except FileNotFoundError as e:
        print(f"\n[ERROR] {e}")
        print("\nMake sure:")
        print("  1. League of Legends client is running")
        print("  2. You are logged in")
        print("  3. Set LOL_LOCKFILE env var if non-standard install path")
        return

    # Process each replay
    total_obs = 0
    for i, rofl_file in enumerate(remaining, 1):
        print(f"\n[{i}/{len(remaining)}] {rofl_file.name}")
        n = scrape_single_replay(
            lcu=lcu,
            rofl_path=rofl_file,
            output_dir=output_path,
            speed=speed,
            max_game_minutes=max_game_minutes,
            use_memory_reader=use_memory_reader,
        )
        total_obs += n

        # Brief pause between games for client to clean up
        if i < len(remaining):
            time.sleep(3)

    print(f"\n{'='*60}")
    print(f"Done! Scraped {len(remaining)} games, {total_obs:,} total observations")
    print(f"Output: {output_path}")
    print(f"{'='*60}")


# ── CLI ──────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Scrape game state from LoL replays")
    ap.add_argument("--replay-dir", default=DEFAULT_REPLAY_DIR,
                    help="Directory containing .rofl files")
    ap.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR,
                    help="Output directory for observation JSON files")
    ap.add_argument("--speed", type=float, default=DEFAULT_SPEED,
                    help="Replay playback speed (default: 8)")
    ap.add_argument("--max-minutes", type=float, default=0,
                    help="Only scrape first N minutes of each game (0=all)")
    ap.add_argument("--max-games", type=int, default=0,
                    help="Maximum number of games to scrape (0=all)")
    ap.add_argument("--no-memory", action="store_true",
                    help="Disable memory reader (API-only mode)")

    # Quick test modes
    ap.add_argument("--test-lcu", action="store_true",
                    help="Just test LCU connection and exit")
    ap.add_argument("--test-api", action="store_true",
                    help="Test Live Client Data API and exit")
    ap.add_argument("--test-launch", type=str, default=None, metavar="ROFL_PATH",
                    help="Test launching a single .rofl file and exit")
    ap.add_argument("--test-endpoints", action="store_true",
                    help="Dump available LCU replay endpoints")

    args = ap.parse_args()

    if args.test_lcu:
        try:
            lcu = LCUClient()
            print("[OK] LCU connected!")
            state = lcu.get_replay_state()
            print(f"Replay state: {json.dumps(state, indent=2) if state else 'No active replay'}")

            # Also show replay dir
            replay_dir = lcu.get_replay_dir()
            print(f"Replay dir: {replay_dir}")

            # Show available replays
            status = lcu.get_replay_status()
            if status:
                print(f"Replay status: {json.dumps(status, indent=2)[:1000]}")
        except FileNotFoundError as e:
            print(f"[FAIL] {e}")
        return

    if args.test_endpoints:
        try:
            lcu = LCUClient()
            print("[OK] LCU connected! Probing replay endpoints...\n")

            endpoints = [
                ("GET", "/lol-replays/v1/configuration"),
                ("GET", "/lol-replays/v1/rofls"),
                ("GET", "/lol-replays/v2/metadata"),
                ("GET", "/replay/playback"),
                ("GET", "/riotclient/region-locale"),
                ("GET", "/lol-patch/v1/game-path"),
                ("GET", "/lol-gameflow/v1/session"),
            ]
            for method, ep in endpoints:
                try:
                    if method == "GET":
                        data = lcu._get(ep)
                    else:
                        data = lcu._post(ep)
                    status = "OK" if data is not None else "null/404"
                    preview = json.dumps(data, indent=2)[:300] if data else "null"
                    print(f"  {method} {ep}: [{status}]")
                    print(f"    {preview}\n")
                except Exception as e:
                    print(f"  {method} {ep}: ERROR {e}\n")
        except FileNotFoundError as e:
            print(f"[FAIL] {e}")
        return

    if args.test_api:
        try:
            lcu = LCUClient()
            data = lcu.get_game_data()
            if data:
                print(f"[OK] Game data: {json.dumps(data, indent=2)[:2000]}")
            else:
                print("[FAIL] No game data — is a replay running?")
        except FileNotFoundError as e:
            print(f"[FAIL] {e}")
        return

    if args.test_launch:
        try:
            lcu = LCUClient()
            from pathlib import Path
            rofl = Path(args.test_launch)
            if not rofl.exists():
                print(f"[FAIL] File not found: {rofl}")
                return
            print(f"Attempting to launch: {rofl}")
            ok = lcu.launch_replay_from_file(str(rofl))
            if ok:
                print("\n[OK] Launch command sent. Waiting for replay to load...")
                if lcu.wait_for_replay_loaded(timeout=90):
                    print("[OK] Replay is playing!")
                    data = lcu.get_game_data()
                    if data:
                        print(f"[OK] Live Client Data API working ({len(json.dumps(data))} bytes)")
                    else:
                        print("[INFO] Live Client Data API not responding yet")
                else:
                    print("[WARN] Replay didn't start within 90s")
            else:
                print("[FAIL] All launch strategies failed")
        except FileNotFoundError as e:
            print(f"[FAIL] {e}")
        return

    run_scraper(
        replay_dir=args.replay_dir,
        output_dir=args.output_dir,
        speed=args.speed,
        max_game_minutes=args.max_minutes,
        max_games=args.max_games,
        use_memory_reader=not args.no_memory,
    )


if __name__ == "__main__":
    main()

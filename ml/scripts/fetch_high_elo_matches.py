"""
Fetch high-elo (Challenger/GM/Master) match data from Riot API.

Split into independent steps that save intermediate results:
  Step 1: players   — fetch player list + PUUIDs
  Step 2: matchids  — fetch match IDs from those players
  Step 3: download  — download match data + timelines (macro data)
  Step 4: replays   — download .rofl replay files (micro data)

Each step is fully resumable. Re-running skips already-completed work.

Usage:
    # Run all steps (except replays):
    python -m ml.scripts.fetch_high_elo_matches --region na1 --tier challenger --count 200

    # Run individual steps:
    python -m ml.scripts.fetch_high_elo_matches --region na1 --tier challenger --step players
    python -m ml.scripts.fetch_high_elo_matches --region na1 --tier challenger --step matchids
    python -m ml.scripts.fetch_high_elo_matches --region na1 --tier challenger --step download --count 200
    python -m ml.scripts.fetch_high_elo_matches --region na1 --tier challenger --step replays --count 200
"""

import argparse
import json
import time
from pathlib import Path

import httpx

RATE_LIMIT_DELAY = 0.05  # Personal key: 2000 req/10s. Use 1.3 for dev keys.

PLATFORM_TO_REGION = {
    "na1": "americas",
    "br1": "americas",
    "la1": "americas",
    "la2": "americas",
    "euw1": "europe",
    "eun1": "europe",
    "tr1": "europe",
    "ru": "europe",
    "kr": "asia",
    "jp1": "asia",
    "oc1": "sea",
    "ph2": "sea",
    "sg2": "sea",
    "th2": "sea",
    "tw2": "sea",
    "vn2": "sea",
}


class RiotAPIClient:
    def __init__(self, api_key: str, platform: str = "na1"):
        self.api_key = api_key
        self.platform = platform
        self.region = PLATFORM_TO_REGION.get(platform, "americas")
        self.headers = {"X-Riot-Token": api_key}
        self.client = httpx.Client(timeout=30)

    def _get(self, url: str, retries: int = 3) -> dict | list | None:
        time.sleep(RATE_LIMIT_DELAY)
        resp = self.client.get(url, headers=self.headers)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", 10))
            print(f"  Rate limited, waiting {retry_after}s...")
            time.sleep(retry_after)
            return self._get(url, retries)
        elif resp.status_code >= 500 and retries > 0:
            wait = (4 - retries) * 5
            print(f"  Server error {resp.status_code}, retrying in {wait}s...")
            time.sleep(wait)
            return self._get(url, retries - 1)
        else:
            print(f"  API error {resp.status_code}: {resp.text[:200]}")
            return None

    def get_high_elo_players(self, tier: str = "challenger", queue: str = "RANKED_SOLO_5x5") -> list[dict]:
        url = f"https://{self.platform}.api.riotgames.com/lol/league/v4/{tier}leagues/by-queue/{queue}"
        data = self._get(url)
        if data and "entries" in data:
            entries = sorted(data["entries"], key=lambda x: x.get("leaguePoints", 0), reverse=True)
            return entries
        return []

    def get_puuid(self, summoner_id: str) -> str | None:
        url = f"https://{self.platform}.api.riotgames.com/lol/summoner/v4/summoners/{summoner_id}"
        data = self._get(url)
        return data.get("puuid") if data else None

    def get_match_ids(self, puuid: str, count: int = 20, queue: int = 420) -> list[str]:
        url = (
            f"https://{self.region}.api.riotgames.com/lol/match/v5/matches/by-puuid/{puuid}/ids"
            f"?queue={queue}&count={count}&type=ranked"
        )
        data = self._get(url)
        return data if isinstance(data, list) else []

    def get_match_data(self, match_id: str) -> dict | None:
        url = f"https://{self.region}.api.riotgames.com/lol/match/v5/matches/{match_id}"
        return self._get(url)

    def get_match_timeline(self, match_id: str) -> dict | None:
        url = f"https://{self.region}.api.riotgames.com/lol/match/v5/matches/{match_id}/timeline"
        return self._get(url)

    def get_player_replays(self, puuid: str) -> list[str]:
        """Get .rofl replay file URLs for a player's recent matches."""
        url = f"https://{self.region}.api.riotgames.com/lol/match/v5/matches/by-puuid/{puuid}/replays"
        data = self._get(url)
        if data and isinstance(data, dict):
            return data.get("matchFileURLs", [])
        return []

    def download_file(self, url: str, dest: Path) -> bool:
        """Download a file (e.g. .rofl) to disk."""
        try:
            with self.client.stream("GET", url) as resp:
                if resp.status_code != 200:
                    return False
                with open(dest, "wb") as f:
                    for chunk in resp.iter_bytes(chunk_size=8192):
                        f.write(chunk)
            return True
        except Exception as e:
            print(f"  Download error: {e}")
            return False


# ── Step 1: Fetch players ─────────────────────────────────────────────

def step_players(client: RiotAPIClient, tier: str, output_dir: Path):
    """Fetch player list and save with PUUIDs."""
    players_file = output_dir / "players.json"

    if players_file.exists():
        players = json.loads(players_file.read_text())
        print(f"  Already have {len(players)} players cached in {players_file}")
        print(f"  (delete {players_file} to re-fetch)")
        return players

    print(f"\n=== Step 1: Fetching {tier} players from {client.platform} ===")
    players = client.get_high_elo_players(tier)
    if not players:
        print("No players found!")
        return []

    print(f"  Found {len(players)} {tier} players")

    # Check how many already have puuid from league endpoint
    with_puuid = sum(1 for p in players if p.get("puuid"))
    print(f"  {with_puuid}/{len(players)} already have PUUID from league endpoint")

    # Save
    players_file.write_text(json.dumps(players, indent=2))
    print(f"  Saved to {players_file}")
    return players


# ── Step 2: Fetch match IDs ───────────────────────────────────────────

def step_matchids(client: RiotAPIClient, output_dir: Path, matches_per_player: int = 5):
    """Fetch match IDs for each player. Resumable — skips already-fetched players."""
    players_file = output_dir / "players.json"
    match_ids_file = output_dir / "match_ids.json"

    if not players_file.exists():
        print("  ERROR: Run --step players first!")
        return []

    players = json.loads(players_file.read_text())

    # Load existing progress
    progress = {}
    if match_ids_file.exists():
        progress = json.loads(match_ids_file.read_text())

    fetched_puuids = set(progress.get("fetched_puuids", []))
    all_match_ids = set(progress.get("match_ids", []))
    print(f"\n=== Step 2: Fetching match IDs ===")
    print(f"  Progress: {len(fetched_puuids)} players done, {len(all_match_ids)} match IDs collected")

    new_this_run = 0
    for i, player in enumerate(players):
        puuid = player.get("puuid")
        if not puuid:
            summoner_id = player.get("summonerId")
            puuid = client.get_puuid(summoner_id) if summoner_id else None
        if not puuid:
            continue

        if puuid in fetched_puuids:
            continue  # Already done

        name = player.get("summonerName", "???")
        lp = player.get("leaguePoints", 0)
        print(f"  [{i+1}/{len(players)}] {name} ({lp} LP)...", end=" ")

        match_ids = client.get_match_ids(puuid, count=matches_per_player)
        new_matches = [m for m in match_ids if m not in all_match_ids]
        all_match_ids.update(new_matches)
        fetched_puuids.add(puuid)
        new_this_run += len(new_matches)
        print(f"{len(new_matches)} new matches (total: {len(all_match_ids)})")

        # Save progress every 10 players
        if len(fetched_puuids) % 10 == 0:
            _save_match_ids(match_ids_file, all_match_ids, fetched_puuids)

    _save_match_ids(match_ids_file, all_match_ids, fetched_puuids)
    print(f"\n  Done! {new_this_run} new match IDs this run. Total: {len(all_match_ids)}")
    return list(all_match_ids)


def _save_match_ids(path: Path, match_ids: set, fetched_puuids: set):
    path.write_text(json.dumps({
        "match_ids": sorted(match_ids),
        "fetched_puuids": sorted(fetched_puuids),
    }, indent=2))


# ── Step 3: Download match data + timelines ───────────────────────────

def step_download(client: RiotAPIClient, output_dir: Path, max_matches: int):
    """Download match data and timelines. Resumable — skips already-downloaded."""
    match_ids_file = output_dir / "match_ids.json"
    meta_file = output_dir / "metadata.jsonl"

    if not match_ids_file.exists():
        print("  ERROR: Run --step matchids first!")
        return

    data = json.loads(match_ids_file.read_text())
    all_match_ids = data.get("match_ids", [])

    (output_dir / "matches").mkdir(parents=True, exist_ok=True)
    (output_dir / "timelines").mkdir(parents=True, exist_ok=True)

    # Check what's already downloaded
    existing = set()
    if meta_file.exists():
        with open(meta_file) as f:
            for line in f:
                try:
                    existing.add(json.loads(line)["match_id"])
                except (json.JSONDecodeError, KeyError):
                    pass

    remaining = [m for m in all_match_ids if m not in existing]
    if max_matches:
        remaining = remaining[:max_matches - len(existing)] if len(existing) < max_matches else []

    print(f"\n=== Step 3: Downloading match data ===")
    print(f"  Already downloaded: {len(existing)}")
    print(f"  Remaining: {len(remaining)}")
    if not remaining:
        print("  Nothing to download!")
        return

    downloaded = 0
    failed = 0

    for i, match_id in enumerate(remaining):
        print(f"  [{i+1}/{len(remaining)}] {match_id}...", end=" ")

        match_data = client.get_match_data(match_id)
        if not match_data:
            failed += 1
            print("failed (match)")
            continue

        timeline = client.get_match_timeline(match_id)
        if not timeline:
            failed += 1
            print("failed (timeline)")
            continue

        # Save match
        with open(output_dir / "matches" / f"{match_id}.json", "w") as f:
            json.dump(match_data, f)

        # Save timeline
        with open(output_dir / "timelines" / f"{match_id}_timeline.json", "w") as f:
            json.dump(timeline, f)

        # Append metadata
        info = match_data.get("info", {})
        meta_entry = {
            "match_id": match_id,
            "platform": client.platform,
            "game_duration": info.get("gameDuration", 0),
            "game_version": info.get("gameVersion", ""),
            "participants": [
                {
                    "puuid": p.get("puuid"),
                    "champion": p.get("championName"),
                    "role": p.get("individualPosition"),
                    "win": p.get("win"),
                    "kills": p.get("kills"),
                    "deaths": p.get("deaths"),
                    "assists": p.get("assists"),
                }
                for p in info.get("participants", [])
            ],
        }
        with open(meta_file, "a") as f:
            f.write(json.dumps(meta_entry) + "\n")

        downloaded += 1
        duration = info.get("gameDuration", 0) // 60
        print(f"ok ({duration}min)")

    print(f"\n  Done! Downloaded {downloaded}, failed {failed}")
    print(f"  Total in {output_dir}: {len(existing) + downloaded}")


# ── Step 4: Download .rofl replays ─────────────────────────────────────

def step_replays(client: RiotAPIClient, output_dir: Path, max_replays: int):
    """Download .rofl replay files for players. Resumable."""
    players_file = output_dir / "players.json"
    replays_dir = output_dir / "replays"
    replays_dir.mkdir(parents=True, exist_ok=True)
    replay_log = output_dir / "replays_log.jsonl"

    if not players_file.exists():
        print("  ERROR: Run --step players first!")
        return

    players = json.loads(players_file.read_text())

    # Track already-downloaded replays
    downloaded_urls = set()
    if replay_log.exists():
        with open(replay_log) as f:
            for line in f:
                try:
                    downloaded_urls.add(json.loads(line)["url"])
                except (json.JSONDecodeError, KeyError):
                    pass

    print(f"\n=== Step 4: Downloading .rofl replays ===")
    print(f"  Already downloaded: {len(downloaded_urls)}")

    total_downloaded = len(downloaded_urls)
    failed = 0

    for i, player in enumerate(players):
        if total_downloaded >= max_replays:
            break

        puuid = player.get("puuid")
        if not puuid:
            continue

        name = player.get("summonerName", "???")
        lp = player.get("leaguePoints", 0)
        print(f"  [{i+1}/{len(players)}] {name} ({lp} LP)...", end=" ")

        replay_urls = client.get_player_replays(puuid)
        if not replay_urls:
            print("no replays")
            continue

        new_urls = [u for u in replay_urls if u not in downloaded_urls]
        print(f"{len(new_urls)} new replays")

        for url in new_urls:
            if total_downloaded >= max_replays:
                break

            # Extract match ID from URL path, ignore query params
            url_path = url.split("?")[0]
            fname = url_path.split("/")[-1]
            if not fname.endswith(".rofl"):
                fname += ".rofl"
            # Fallback if filename is still weird
            if len(fname) > 200:
                fname = f"{puuid[:16]}_{total_downloaded}.rofl"
            dest = replays_dir / fname

            if dest.exists():
                total_downloaded += 1
                continue

            print(f"    Downloading {fname}...", end=" ")
            if client.download_file(url, dest):
                # Log it
                with open(replay_log, "a") as f:
                    f.write(json.dumps({
                        "url": url,
                        "file": str(dest),
                        "puuid": puuid,
                        "player": name,
                    }) + "\n")
                total_downloaded += 1
                size_mb = dest.stat().st_size / (1024 * 1024)
                print(f"ok ({size_mb:.1f} MB)")
            else:
                failed += 1
                print("failed")

    print(f"\n  Done! Total replays: {total_downloaded}, failed: {failed}")
    print(f"  Saved to: {replays_dir}")


# ── CLI ────────────────────────────────────────────────────────────────

def load_api_key(args_key: str | None) -> str:
    if args_key:
        return args_key
    import os
    for env_path in ["backend/.env", ".env"]:
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("RIOT_API_KEY=") and not line.startswith("#"):
                        return line.split("=", 1)[1].strip().strip('"').strip("'")
    return os.environ.get("RIOT_API_KEY", "")


def main():
    parser = argparse.ArgumentParser(description="Fetch high-elo LoL matches from Riot API")
    parser.add_argument("--api-key", type=str, help="Riot API key (or set RIOT_API_KEY)")
    parser.add_argument("--region", type=str, default="na1")
    parser.add_argument("--tier", type=str, default="challenger",
                        choices=["challenger", "grandmaster", "master"])
    parser.add_argument("--count", type=int, default=500, help="Max matches to download")
    parser.add_argument("--matches-per-player", type=int, default=5)
    parser.add_argument("--output", type=str, default="./ml/data/raw/high_elo")
    parser.add_argument("--step", type=str, default="all",
                        choices=["all", "players", "matchids", "download", "replays", "debug"],
                        help="Run a specific step (default: all)")
    args = parser.parse_args()

    api_key = load_api_key(args.api_key)
    if not api_key:
        print("Error: Set --api-key or RIOT_API_KEY in backend/.env")
        return

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    client = RiotAPIClient(api_key, args.region)

    if args.step in ("all", "players"):
        step_players(client, args.tier, output_dir)

    if args.step in ("all", "matchids"):
        step_matchids(client, output_dir, args.matches_per_player)

    if args.step in ("all", "download"):
        step_download(client, output_dir, args.count)

    if args.step == "replays":
        step_replays(client, output_dir, args.count)

    if args.step == "debug":
        step_debug(client, output_dir)


def step_debug(client: RiotAPIClient, output_dir: Path):
    """Debug: test each endpoint individually."""
    import json as _json

    match_ids_file = output_dir / "match_ids.json"
    players_file = output_dir / "players.json"

    print("=== DEBUG: Testing API endpoints ===\n")

    # 1. Test league endpoint
    print("1. League-v4 (get challengers)...")
    url = f"https://{client.platform}.api.riotgames.com/lol/league/v4/challengerleagues/by-queue/RANKED_SOLO_5x5"
    resp = client.client.get(url, headers=client.headers)
    print(f"   URL: {url}")
    print(f"   Status: {resp.status_code}")
    print(f"   Rate headers: {dict((k,v) for k,v in resp.headers.items() if 'rate' in k.lower())}")
    print()

    # 2. Get a PUUID
    puuid = None
    if players_file.exists():
        players = _json.loads(players_file.read_text())
        puuid = players[0].get("puuid")
        print(f"2. Using PUUID from players.json: {puuid[:20]}...")
    if not puuid:
        print("2. No PUUID available, skipping remaining tests")
        return

    # 3. Test match list endpoint
    print("\n3. Match-v5 match list (by puuid)...")
    url = f"https://{client.region}.api.riotgames.com/lol/match/v5/matches/by-puuid/{puuid}/ids?count=3&type=ranked"
    resp = client.client.get(url, headers=client.headers)
    print(f"   URL: {url}")
    print(f"   Status: {resp.status_code}")
    print(f"   Body: {resp.text[:300]}")
    print()

    match_ids = []
    if resp.status_code == 200:
        match_ids = resp.json()

    # Also try from saved match_ids.json
    if not match_ids and match_ids_file.exists():
        data = _json.loads(match_ids_file.read_text())
        match_ids = data.get("match_ids", [])[:3]
        print(f"   (Using saved match IDs instead: {match_ids})")

    if not match_ids:
        print("   No match IDs to test with")
        return

    # 4. Test match data endpoint
    test_id = match_ids[0]
    print(f"\n4. Match-v5 match data ({test_id})...")
    url = f"https://{client.region}.api.riotgames.com/lol/match/v5/matches/{test_id}"
    resp = client.client.get(url, headers=client.headers)
    print(f"   URL: {url}")
    print(f"   Status: {resp.status_code}")
    print(f"   Headers: {dict((k,v) for k,v in resp.headers.items() if 'rate' in k.lower() or 'retry' in k.lower())}")
    print(f"   Body: {resp.text[:500]}")
    print()

    # 5. Test timeline endpoint
    print(f"\n5. Match-v5 timeline ({test_id})...")
    url = f"https://{client.region}.api.riotgames.com/lol/match/v5/matches/{test_id}/timeline"
    resp = client.client.get(url, headers=client.headers)
    print(f"   URL: {url}")
    print(f"   Status: {resp.status_code}")
    print(f"   Body: {resp.text[:500]}")
    print()

    # 6. Try multiple match IDs to see if it's specific matches
    print("\n6. Testing first 5 match IDs...")
    for mid in match_ids[:5]:
        url = f"https://{client.region}.api.riotgames.com/lol/match/v5/matches/{mid}"
        resp = client.client.get(url, headers=client.headers)
        print(f"   {mid} → {resp.status_code}")
        time.sleep(0.1)


if __name__ == "__main__":
    main()

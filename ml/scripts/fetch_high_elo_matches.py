"""
Fetch high-elo (Challenger/GM/Master) match data from Riot API.

This gives us the "ground truth" of what optimal play looks like.
We train our model on what these players DO, then compare user replays against it.

Flow:
  1. Get Challenger/GM/Master player list from LEAGUE-V4
  2. Get their PUUIDs from SUMMONER-V4
  3. Get recent match IDs from MATCH-V5
  4. Download match timelines (tick-by-tick events) from MATCH-V5

Requirements:
  - Riot API key (get from https://developer.riotgames.com)
  - Set RIOT_API_KEY in .env

Usage:
    python -m ml.scripts.fetch_high_elo_matches --region na1 --tier challenger --count 500
    python -m ml.scripts.fetch_high_elo_matches --region kr --tier grandmaster --count 1000
"""

import argparse
import json
import time
from pathlib import Path

import httpx

# Riot API rate limits: 20 requests per 1 second, 100 per 2 minutes
# We'll be conservative
RATE_LIMIT_DELAY = 1.3  # seconds between requests

# Region routing
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

    def _get(self, url: str) -> dict | list | None:
        """Make a rate-limited GET request."""
        time.sleep(RATE_LIMIT_DELAY)
        resp = self.client.get(url, headers=self.headers)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 429:
            # Rate limited — wait and retry
            retry_after = int(resp.headers.get("Retry-After", 10))
            print(f"  Rate limited, waiting {retry_after}s...")
            time.sleep(retry_after)
            return self._get(url)
        else:
            print(f"  API error {resp.status_code}: {resp.text[:200]}")
            return None

    def get_high_elo_players(self, tier: str = "challenger", queue: str = "RANKED_SOLO_5x5") -> list[dict]:
        """
        Get players from a specific tier.
        tier: challenger, grandmaster, master
        """
        url = f"https://{self.platform}.api.riotgames.com/lol/league/v4/{tier}leagues/by-queue/{queue}"
        data = self._get(url)
        if data and "entries" in data:
            # Sort by LP descending — highest LP = best players
            entries = sorted(data["entries"], key=lambda x: x.get("leaguePoints", 0), reverse=True)
            print(f"  Found {len(entries)} {tier} players")
            return entries
        return []

    def get_puuid(self, summoner_id: str) -> str | None:
        """Get PUUID from summoner ID."""
        url = f"https://{self.platform}.api.riotgames.com/lol/summoner/v4/summoners/{summoner_id}"
        data = self._get(url)
        return data.get("puuid") if data else None

    def get_match_ids(self, puuid: str, count: int = 20, queue: int = 420) -> list[str]:
        """
        Get recent ranked match IDs for a player.
        queue 420 = Ranked Solo/Duo
        """
        url = (
            f"https://{self.region}.api.riotgames.com/lol/match/v5/matches/by-puuid/{puuid}/ids"
            f"?queue={queue}&count={count}&type=ranked"
        )
        data = self._get(url)
        return data if isinstance(data, list) else []

    def get_match_data(self, match_id: str) -> dict | None:
        """Get full match data including participant stats."""
        url = f"https://{self.region}.api.riotgames.com/lol/match/v5/matches/{match_id}"
        return self._get(url)

    def get_match_timeline(self, match_id: str) -> dict | None:
        """
        Get match timeline — tick-by-tick events.
        This is the GOLD data: positions, kills, objectives, items, etc.
        at every frame (usually 1 per minute).
        """
        url = f"https://{self.region}.api.riotgames.com/lol/match/v5/matches/{match_id}/timeline"
        return self._get(url)


def fetch_and_save(
    api_key: str,
    platform: str,
    tier: str,
    max_matches: int,
    output_dir: str,
    matches_per_player: int = 5,
):
    """
    Fetch high-elo matches and save them.

    Output structure:
      output_dir/
        matches/
          NA1_12345.json         # full match data
        timelines/
          NA1_12345_timeline.json # tick-by-tick timeline
        metadata.jsonl            # index of all fetched matches
    """
    output_dir = Path(output_dir)
    (output_dir / "matches").mkdir(parents=True, exist_ok=True)
    (output_dir / "timelines").mkdir(parents=True, exist_ok=True)

    client = RiotAPIClient(api_key, platform)

    # Step 1: Get high-elo player list
    print(f"\n=== Fetching {tier} players from {platform} ===")
    players = client.get_high_elo_players(tier)
    if not players:
        print("No players found!")
        return

    # Step 2: Get match IDs from top players
    all_match_ids = set()
    metadata = []

    # Track existing matches to skip duplicates
    existing = set()
    meta_file = output_dir / "metadata.jsonl"
    if meta_file.exists():
        with open(meta_file) as f:
            for line in f:
                d = json.loads(line)
                existing.add(d["match_id"])
        print(f"  {len(existing)} matches already downloaded, skipping duplicates")

    print(f"\nFetching match IDs from top players...")
    for i, player in enumerate(players):
        if len(all_match_ids) >= max_matches:
            break

        summoner_id = player.get("summonerId")
        summoner_name = player.get("summonerName", "???")
        lp = player.get("leaguePoints", 0)

        print(f"  [{i+1}/{len(players)}] {summoner_name} ({lp} LP)...", end=" ")

        puuid = client.get_puuid(summoner_id)
        if not puuid:
            print("failed to get PUUID")
            continue

        match_ids = client.get_match_ids(puuid, count=matches_per_player)
        new_matches = [m for m in match_ids if m not in all_match_ids and m not in existing]
        all_match_ids.update(new_matches)
        print(f"{len(new_matches)} new matches")

    print(f"\nTotal unique match IDs: {len(all_match_ids)}")

    # Step 3: Download match data + timelines
    print(f"\nDownloading match data and timelines...")
    downloaded = 0

    for i, match_id in enumerate(all_match_ids):
        if downloaded >= max_matches:
            break

        print(f"  [{i+1}/{len(all_match_ids)}] {match_id}...", end=" ")

        # Get match data
        match_data = client.get_match_data(match_id)
        if not match_data:
            print("failed")
            continue

        # Get timeline
        timeline = client.get_match_timeline(match_id)
        if not timeline:
            print("no timeline")
            continue

        # Save match
        match_file = output_dir / "matches" / f"{match_id}.json"
        with open(match_file, "w") as f:
            json.dump(match_data, f)

        # Save timeline
        timeline_file = output_dir / "timelines" / f"{match_id}_timeline.json"
        with open(timeline_file, "w") as f:
            json.dump(timeline, f)

        # Save metadata entry
        info = match_data.get("info", {})
        meta_entry = {
            "match_id": match_id,
            "platform": platform,
            "tier": tier,
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
        print(f"ok ({info.get('gameDuration', 0) // 60}min)")

    print(f"\n=== Done! Downloaded {downloaded} matches to {output_dir} ===")
    print(f"  Matches:   {output_dir / 'matches'}")
    print(f"  Timelines: {output_dir / 'timelines'}")
    print(f"  Metadata:  {meta_file}")


def main():
    parser = argparse.ArgumentParser(description="Fetch high-elo LoL matches from Riot API")
    parser.add_argument("--api-key", type=str, help="Riot API key (or set RIOT_API_KEY env var)")
    parser.add_argument("--region", type=str, default="na1", help="Platform (na1, kr, euw1, etc.)")
    parser.add_argument(
        "--tier",
        type=str,
        default="challenger",
        choices=["challenger", "grandmaster", "master"],
    )
    parser.add_argument("--count", type=int, default=500, help="Max matches to fetch")
    parser.add_argument("--matches-per-player", type=int, default=5)
    parser.add_argument("--output", type=str, default="./ml/data/raw/high_elo")
    args = parser.parse_args()

    api_key = args.api_key
    if not api_key:
        import os
        api_key = os.environ.get("RIOT_API_KEY", "")

    if not api_key:
        print("Error: Set --api-key or RIOT_API_KEY environment variable")
        print("Get your key at: https://developer.riotgames.com")
        return

    fetch_and_save(
        api_key=api_key,
        platform=args.region,
        tier=args.tier,
        max_matches=args.count,
        output_dir=args.output,
        matches_per_player=args.matches_per_player,
    )


if __name__ == "__main__":
    main()

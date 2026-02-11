"""
League Client Update (LCU) API connector.

The LoL client runs a local HTTPS server on a random port.
Auth credentials are in the lockfile at:
  - Windows: C:/Riot Games/League of Legends/lockfile
  - Mac:     /Applications/League of Legends.app/Contents/LoL/lockfile

Format: process_name:pid:port:password:protocol

This module auto-discovers the lockfile, connects to the LCU,
and provides methods to control replay playback.
"""

from __future__ import annotations

import base64
import json
import os
import platform
import re
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx


# ── Default LoL install paths ────────────────────────────────────────

_LOCKFILE_PATHS = {
    "Windows": [
        Path("C:/Riot Games/League of Legends/lockfile"),
        Path("D:/Riot Games/League of Legends/lockfile"),
        Path(os.path.expanduser("~/Riot Games/League of Legends/lockfile")),
    ],
    "Darwin": [
        Path("/Applications/League of Legends.app/Contents/LoL/lockfile"),
    ],
}


@dataclass
class LCUConnection:
    pid: int
    port: int
    password: str
    protocol: str  # "https"

    @property
    def base_url(self) -> str:
        return f"{self.protocol}://127.0.0.1:{self.port}"

    @property
    def auth_header(self) -> str:
        token = base64.b64encode(f"riot:{self.password}".encode()).decode()
        return f"Basic {token}"


def find_lockfile() -> Path | None:
    """Auto-detect the LoL lockfile."""
    system = platform.system()
    candidates = _LOCKFILE_PATHS.get(system, [])

    # Also check environment variable
    env_path = os.environ.get("LOL_LOCKFILE")
    if env_path:
        candidates.insert(0, Path(env_path))

    for p in candidates:
        if p.exists():
            return p

    # Windows: try to find via running process
    if system == "Windows":
        try:
            import psutil
            for proc in psutil.process_iter(["name", "exe"]):
                if proc.info["name"] and "LeagueClient" in proc.info["name"]:
                    exe_path = Path(proc.info["exe"])
                    lockfile = exe_path.parent / "lockfile"
                    if lockfile.exists():
                        return lockfile
        except ImportError:
            pass

    return None


def parse_lockfile(lockfile_path: Path) -> LCUConnection:
    """Parse the lockfile to get LCU connection info."""
    content = lockfile_path.read_text().strip()
    parts = content.split(":")
    if len(parts) < 5:
        raise ValueError(f"Invalid lockfile format: {content}")

    return LCUConnection(
        pid=int(parts[1]),
        port=int(parts[2]),
        password=parts[3],
        protocol=parts[4],
    )


class LCUClient:
    """Client for the League Client Update (LCU) API."""

    def __init__(self, connection: LCUConnection | None = None):
        if connection is None:
            lockfile = find_lockfile()
            if lockfile is None:
                raise FileNotFoundError(
                    "LoL lockfile not found. Is the client running?\n"
                    "Set LOL_LOCKFILE env var if non-standard install path."
                )
            connection = parse_lockfile(lockfile)

        self.conn = connection
        # LCU uses self-signed cert — disable verification
        self.client = httpx.Client(
            base_url=self.conn.base_url,
            headers={
                "Authorization": self.conn.auth_header,
                "Accept": "application/json",
            },
            verify=False,
            timeout=30,
        )
        print(f"[LCU] Connected to {self.conn.base_url} (pid={self.conn.pid})")

    def _get(self, endpoint: str) -> Any:
        resp = self.client.get(endpoint)
        if resp.status_code == 200:
            return resp.json()
        return None

    def _post(self, endpoint: str, data: Any = None) -> Any:
        resp = self.client.post(endpoint, json=data)
        if resp.status_code in (200, 204):
            try:
                return resp.json()
            except Exception:
                return True
        return None

    # ── Replay API ────────────────────────────────────────────────────

    def get_replay_state(self) -> dict | None:
        """Get current replay playback state."""
        return self._get("/replay/playback")

    def set_replay_speed(self, speed: float) -> bool:
        """Set replay playback speed (1, 2, 4, 8, or custom via POST)."""
        result = self._post("/replay/playback", {"speed": speed})
        return result is not None

    def set_replay_paused(self, paused: bool) -> bool:
        """Pause or unpause replay."""
        result = self._post("/replay/playback", {"paused": paused})
        return result is not None

    def seek_replay(self, time_seconds: float) -> bool:
        """Seek to a specific time in the replay."""
        result = self._post("/replay/playback", {"time": time_seconds})
        return result is not None

    def get_game_data(self) -> dict | None:
        """Get live game data (works during replay)."""
        # This hits the Live Client Data API (separate from LCU)
        try:
            resp = httpx.get("https://127.0.0.1:2999/liveclientdata/allgamedata", verify=False, timeout=5)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None

    def get_active_player(self) -> dict | None:
        """Get active player data from Live Client Data API."""
        try:
            resp = httpx.get("https://127.0.0.1:2999/liveclientdata/activeplayer", verify=False, timeout=5)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None

    def get_all_players(self) -> list[dict] | None:
        """Get all players data from Live Client Data API."""
        try:
            resp = httpx.get("https://127.0.0.1:2999/liveclientdata/playerlist", verify=False, timeout=5)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None

    def get_game_events(self) -> dict | None:
        """Get game events from Live Client Data API."""
        try:
            resp = httpx.get("https://127.0.0.1:2999/liveclientdata/eventdata", verify=False, timeout=5)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None

    # ── Launch replay ─────────────────────────────────────────────────

    def launch_replay(self, game_id: str | int) -> bool:
        """Tell the client to download and launch a replay by game ID."""
        result = self._post(f"/lol-replays/v1/rofls/{game_id}/watch")
        return result is not None

    def launch_replay_from_file(self, rofl_path: str) -> bool:
        """Launch a local .rofl file."""
        # The LCU can launch local files via the replay-ux endpoint
        result = self._post("/lol-replays/v2/replay/watch", {"filePath": str(rofl_path)})
        if result is None:
            # Fallback: try v1
            result = self._post("/lol-replays/v1/replay/watch", {"filePath": str(rofl_path)})
        return result is not None

    def get_replay_status(self) -> str | None:
        """Get replay download/launch status."""
        data = self._get("/lol-replays/v1/rofls")
        return data

    # ── Utility ───────────────────────────────────────────────────────

    def wait_for_replay_loaded(self, timeout: int = 60) -> bool:
        """Wait until a replay is loaded and playing."""
        start = time.time()
        while time.time() - start < timeout:
            state = self.get_replay_state()
            if state and not state.get("paused", True):
                return True
            # Also check Live Client Data API
            game = self.get_game_data()
            if game:
                return True
            time.sleep(1)
        return False

    def is_replay_active(self) -> bool:
        """Check if a replay is currently running."""
        game = self.get_game_data()
        return game is not None

    def get_game_time(self) -> float:
        """Get current game time in seconds."""
        state = self.get_replay_state()
        if state:
            return state.get("time", 0.0)
        return 0.0


# ── Quick test ────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    try:
        lcu = LCUClient()
        print(f"\n[OK] LCU connected: port={lcu.conn.port}")

        state = lcu.get_replay_state()
        if state:
            print(f"[Replay] State: {json.dumps(state, indent=2)}")
        else:
            print("[Replay] No active replay")

        game = lcu.get_game_data()
        if game:
            print(f"[Game] Active game data available ({len(json.dumps(game))} bytes)")
        else:
            print("[Game] No active game/replay")

    except FileNotFoundError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

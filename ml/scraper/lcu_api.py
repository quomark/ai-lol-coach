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
import subprocess
import ssl
import sys
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
        """Tell the client to download and watch a replay by game ID."""
        # Try multiple endpoints — varies by client version
        endpoints = [
            f"/lol-replays/v1/rofls/{game_id}/watch",
            f"/lol-replays/v2/rofls/{game_id}/watch",
        ]
        for ep in endpoints:
            result = self._post(ep)
            if result is not None:
                return True
        return False

    def launch_replay_from_file(self, rofl_path: str) -> bool:
        """
        Launch a local .rofl file.

        Strategy 1: Extract game ID, use LCU watch endpoint
        Strategy 2: Launch game executable directly with .rofl as argument
        Strategy 3: Use /lol-replays/v1/rofls/{id}/watch/download then watch
        """
        from pathlib import Path
        import subprocess
        import re

        rofl = Path(rofl_path)
        if not rofl.exists():
            print(f"  [ERROR] File not found: {rofl_path}")
            return False

        # Extract game ID from filename (e.g., "NA1_5480593641.replay.rofl" → "NA1_5480593641")
        # or "TW2-388023029.rofl" → "TW2_388023029"
        stem = rofl.stem.replace(".replay", "")
        # Normalize: TW2-388023029 → TW2_388023029
        game_id = stem.replace("-", "_")
        game_id_dash = stem  # Keep original for some endpoints

        print(f"  [INFO] Game ID: {game_id} | File: {rofl.name}")

        # Strategy 1: Try LCU download + watch endpoint with game ID
        for gid in (game_id_dash, game_id, stem):
            # First try to "create" the replay entry by POSTing the path
            self._post(f"/lol-replays/v1/rofls/{gid}/download", {
                "gameId": gid,
                "filePath": str(rofl.resolve()),
            })
            # Then watch it
            result = self._post(f"/lol-replays/v1/rofls/{gid}/watch")
            if result is not None:
                print(f"  [OK] Launched via LCU watch endpoint")
                return True

        # Strategy 2: POST with componentType replay
        result = self._post("/riotclient/launch-ux", {
            "args": [str(rofl.resolve())],
        })
        if result is not None:
            print(f"  [OK] Launched via riotclient/launch-ux")
            return True

        # Strategy 3: Find game executable and launch directly
        game_exe = self._find_game_exe()
        if game_exe:
            try:
                abs_path = str(rofl.resolve())
                print(f"  [INFO] Launching directly: {game_exe} \"{abs_path}\"")
                subprocess.Popen(
                    [str(game_exe), abs_path],
                    cwd=str(game_exe.parent),
                )
                print(f"  [OK] Launched game process directly")
                return True
            except Exception as e:
                print(f"  [WARN] Direct launch failed: {e}")

        # Strategy 4: Open file with OS default handler (double-click equivalent)
        try:
            if sys.platform == "win32":
                os.startfile(str(rofl.resolve()))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(rofl.resolve())])
            else:
                subprocess.Popen(["xdg-open", str(rofl.resolve())])
            print(f"  [OK] Launched via OS file handler (double-click)")
            return True
        except Exception as e:
            print(f"  [WARN] OS handler failed: {e}")

        print(f"  [FAIL] All launch strategies failed")
        return False

    def _find_game_exe(self) -> Path | None:
        """Find the League of Legends game executable."""
        from pathlib import Path
        candidates = [
            Path("C:/Riot Games/League of Legends/Game/League of Legends.exe"),
            Path("D:/Riot Games/League of Legends/Game/League of Legends.exe"),
            Path(os.path.expanduser("~/Riot Games/League of Legends/Game/League of Legends.exe")),
        ]
        # Also try to get install path from LCU
        install_dir = self._get("/lol-patch/v1/game-path")
        if install_dir and isinstance(install_dir, str):
            candidates.insert(0, Path(install_dir) / "League of Legends.exe")

        for p in candidates:
            if p.exists():
                return p
        return None

    def get_replay_dir(self) -> str | None:
        """Get the client's replay directory."""
        data = self._get("/lol-replays/v1/configuration")
        if data and isinstance(data, dict):
            return data.get("replaysPath")
        # Fallback
        data = self._get("/lol-game-data/assets/v1/default-configuration")
        if data and isinstance(data, dict):
            return data.get("ReplayConfig", {}).get("ReplayFolderPath")
        return None

    def get_replay_status(self) -> Any:
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

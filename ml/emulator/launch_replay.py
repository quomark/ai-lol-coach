"""
Launch a .rofl replay with detailed logging.

Diagnoses why the game crashes on startup by logging each step
and checking the process status.
"""

from __future__ import annotations

import subprocess
import time
import sys
import os
from pathlib import Path


def find_game_exe() -> Path | None:
    candidates = [
        Path("C:/Riot Games/League of Legends/Game/League of Legends.exe"),
        Path("D:/Riot Games/League of Legends/Game/League of Legends.exe"),
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def is_process_running(name: str) -> list[str]:
    """Check if a process is running, return matching lines."""
    result = subprocess.run(
        ["tasklist"], capture_output=True, text=True
    )
    return [l for l in result.stdout.splitlines() if name.lower() in l.lower()]


def stop_vanguard():
    print("[1/6] Stopping Vanguard...")

    # Kill tray icon
    r = subprocess.run(["taskkill", "/IM", "vgtray.exe", "/F"],
                       capture_output=True, text=True)
    print(f"  vgtray: {r.stdout.strip() or r.stderr.strip()}")

    # Stop services
    r = subprocess.run(["sc", "stop", "vgc"], capture_output=True, text=True)
    print(f"  vgc service: {r.stdout.strip().splitlines()[0] if r.stdout.strip() else r.stderr.strip()}")

    r = subprocess.run(["sc", "stop", "vgk"], capture_output=True, text=True)
    print(f"  vgk service: {r.stdout.strip().splitlines()[0] if r.stdout.strip() else r.stderr.strip()}")

    time.sleep(2)

    # Verify
    vg_procs = is_process_running("vg")
    if vg_procs:
        print(f"  WARNING: Vanguard processes still running:")
        for l in vg_procs:
            print(f"    {l}")
    else:
        print("  OK: Vanguard stopped")


def start_vanguard():
    print("[6/6] Restarting Vanguard...")
    r = subprocess.run(["sc", "start", "vgc"], capture_output=True, text=True)
    print(f"  vgc: {r.stdout.strip().splitlines()[0] if r.stdout.strip() else r.stderr.strip()}")

    vgtray = Path(r"C:\Program Files\Riot Vanguard\vgtray.exe")
    if vgtray.exists():
        subprocess.Popen([str(vgtray)], creationflags=0x00000008)
        print("  vgtray: started")


def launch_replay(rofl_path: str, region: str = "TW2", locale: str = "zh_TW"):
    rofl = Path(rofl_path)
    if not rofl.exists():
        print(f"ERROR: File not found: {rofl_path}")
        return

    game_exe = find_game_exe()
    if not game_exe:
        print("ERROR: League of Legends.exe not found")
        return

    print("=" * 60)
    print("  Replay Launcher (with diagnostics)")
    print("=" * 60)
    print(f"  Replay:   {rofl.name} ({rofl.stat().st_size // 1024 // 1024} MB)")
    print(f"  Game exe: {game_exe}")
    print(f"  Region:   {region}")
    print()

    # Step 1: Stop Vanguard
    stop_vanguard()

    # Step 2: Check for existing League processes
    print("\n[2/6] Checking existing League processes...")
    league_procs = is_process_running("League")
    if league_procs:
        print(f"  Found {len(league_procs)} existing process(es):")
        for l in league_procs:
            print(f"    {l}")
        print("  Killing them...")
        subprocess.run(["taskkill", "/IM", "League of Legends.exe", "/F"],
                       capture_output=True)
        time.sleep(2)
    else:
        print("  None found (good)")

    # Step 3: Build command
    abs_path = str(rofl.resolve())
    cmd = [
        str(game_exe),
        abs_path,
        "-GameBaseDir=..",
        f"-Region={region}",
        f"-PlatformID={region}",
        f"-Locale={locale}",
        "-SkipBuild",
        "-EnableCrashpad=true",
        "-EnableLNP",
        "-UseDX11=1:1",
        "-UseMetal=0:1",
        "-UseNewX3D",
        "-UseNewX3DFramebuffers",
    ]

    print(f"\n[3/6] Launch command:")
    print(f"  exe:  {cmd[0]}")
    print(f"  rofl: {cmd[1]}")
    print(f"  args: {' '.join(cmd[2:])}")

    # Step 4: Launch
    print(f"\n[4/6] Launching game process...")
    env = os.environ.copy()
    env["riot_launched"] = "true"

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(game_exe.parent),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        print(f"  PID: {proc.pid}")
    except Exception as e:
        print(f"  FAILED: {e}")
        start_vanguard()
        return

    # Step 5: Monitor the process
    print(f"\n[5/6] Monitoring process (waiting up to 30s)...")
    for i in range(30):
        time.sleep(1)
        ret = proc.poll()

        # Check if process is still running
        league_procs = is_process_running("League of Legends")
        status = f"t={i+1:2d}s | "

        if ret is not None:
            # Process exited
            stdout = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
            stderr = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
            print(f"  {status}EXITED with code {ret}")
            if stdout.strip():
                print(f"  stdout: {stdout[:500]}")
            if stderr.strip():
                print(f"  stderr: {stderr[:500]}")

            # Check for crash dumps
            crash_dir = game_exe.parent / "Logs"
            if crash_dir.exists():
                logs = sorted(crash_dir.glob("*.log"), key=lambda f: f.stat().st_mtime, reverse=True)
                if logs:
                    latest_log = logs[0]
                    age = time.time() - latest_log.stat().st_mtime
                    if age < 30:  # log modified in last 30 seconds
                        print(f"\n  Recent log: {latest_log.name}")
                        try:
                            content = latest_log.read_text(errors="replace")
                            # Print last 20 lines
                            lines = content.strip().splitlines()
                            for line in lines[-20:]:
                                print(f"    {line}")
                        except Exception:
                            pass

            # Also check BugSplat / crash dumps
            for crash_pattern in ["*.dmp", "*.mdmp"]:
                game_dir = game_exe.parent
                dumps = sorted(game_dir.glob(crash_pattern), key=lambda f: f.stat().st_mtime, reverse=True)
                if dumps and (time.time() - dumps[0].stat().st_mtime < 60):
                    print(f"  Crash dump found: {dumps[0].name}")

            break
        else:
            proc_count = len(league_procs)
            print(f"  {status}running (pid={proc.pid}, {proc_count} League process(es))")

            if i >= 10 and proc_count > 0:
                print(f"\n  Game appears to be running successfully!")
                print(f"  You can now run the dumper:")
                print(f"    .venv\\Scripts\\python.exe -m ml.emulator.dump_unpacked")
                break
    else:
        print(f"  Process still running after 30s — looks good!")

    # Step 6: Restart Vanguard (delayed)
    print()
    start_vanguard()


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("rofl", nargs="?",
                   default="C:/Users/ngan9/OneDrive/Documents/League of Legends/Replays/TW2-396324158.rofl")
    p.add_argument("--region", default="TW2")
    p.add_argument("--locale", default="zh_TW")
    args = p.parse_args()

    launch_replay(args.rofl, args.region, args.locale)

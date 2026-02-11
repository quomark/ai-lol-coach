"""
Parse downloaded .rofl replay files into structured data.

Modes:
  inspect  — Dump one .rofl file's structure / metadata
  metadata — Extract metadata from all replays (fast, no decryption)
  events   — Decompress payload and probe for game events (experimental)
  packets  — Decode decompressed frames into raw game packets

Usage:
    python -m ml.scripts.parse_replays --mode inspect
    python -m ml.scripts.parse_replays --mode metadata
    python -m ml.scripts.parse_replays --mode events
    python -m ml.scripts.parse_replays --mode packets [--file X.rofl]
"""

import argparse
import json
from pathlib import Path

from ml.parsers.rofl_parser import ROFLParser, batch_parse_metadata


# ── inspect ────────────────────────────────────────────────────────────


def mode_inspect(filepath: str):
    """Inspect a single .rofl file — show header + full metadata."""
    p = ROFLParser(filepath)
    parsed = p.parse()
    hdr = parsed.header
    meta = parsed.metadata

    size_mb = Path(filepath).stat().st_size / 1024 / 1024

    print(f"\n{'='*60}")
    print(f"File:             {filepath}")
    print(f"Size:             {size_mb:.1f} MB")
    print(f"Format version:   {hdr.format_version}")
    print(f"Game version:     {hdr.game_version}")
    print(f"Payload offset:   {hdr.payload_offset} (0x{hdr.payload_offset:X})")
    print(f"Metadata offset:  {hdr.metadata_offset} (0x{hdr.metadata_offset:X})")
    payload_size = hdr.metadata_offset - hdr.payload_offset
    meta_size = hdr.file_size - hdr.metadata_offset
    print(f"Payload size:     {payload_size:,} bytes ({payload_size/1024/1024:.1f} MB)")
    print(f"Metadata size:    {meta_size:,} bytes ({meta_size/1024:.0f} KB)")
    print(f"{'='*60}")

    # Metadata summary
    game_ms = meta.get("gameLength", 0)
    print(f"\n── Metadata ──")
    print(f"  gameLength:        {game_ms} ms  ({game_ms // 60000}m {(game_ms % 60000) // 1000}s)")
    print(f"  lastGameChunkId:   {meta.get('lastGameChunkId')}")
    print(f"  lastKeyFrameId:    {meta.get('lastKeyFrameId')}")
    print(f"  All keys:          {sorted(meta.keys())}")

    # Zstd frame count
    try:
        n_frames = p.payload_frame_count()
        print(f"  Zstd frames in payload: {n_frames}")
    except Exception:
        pass

    # Stats per player
    stats_raw = meta.get("statsJson", "[]")
    if isinstance(stats_raw, str):
        try:
            stats_list = json.loads(stats_raw)
        except json.JSONDecodeError:
            stats_list = []
    else:
        stats_list = stats_raw if isinstance(stats_raw, list) else []

    # ── Coaching-relevant stat keys (show for first player) ──
    COACHING_KEYS = [
        # Identity
        "NAME", "SKIN", "TEAM", "WIN", "ID",
        "INDIVIDUAL_POSITION", "TEAM_POSITION",
        # Core
        "CHAMPIONS_KILLED", "NUM_DEATHS", "ASSISTS", "LEVEL", "EXP",
        "GOLD_EARNED", "GOLD_SPENT", "MINIONS_KILLED",
        "NEUTRAL_MINIONS_KILLED", "NEUTRAL_MINIONS_KILLED_YOUR_JUNGLE",
        "NEUTRAL_MINIONS_KILLED_ENEMY_JUNGLE",
        # Damage
        "TOTAL_DAMAGE_DEALT", "TOTAL_DAMAGE_DEALT_TO_CHAMPIONS",
        "PHYSICAL_DAMAGE_DEALT_TO_CHAMPIONS", "MAGIC_DAMAGE_DEALT_TO_CHAMPIONS",
        "TRUE_DAMAGE_DEALT_TO_CHAMPIONS", "TOTAL_DAMAGE_TAKEN",
        "PHYSICAL_DAMAGE_TAKEN", "MAGIC_DAMAGE_TAKEN", "TRUE_DAMAGE_TAKEN",
        "TOTAL_DAMAGE_DEALT_TO_BUILDINGS", "TOTAL_DAMAGE_DEALT_TO_OBJECTIVES",
        "LARGEST_CRITICAL_STRIKE",
        # Combat
        "DOUBLE_KILLS", "TRIPLE_KILLS", "QUADRA_KILLS", "PENTA_KILLS",
        "KILLING_SPREES", "LARGEST_KILLING_SPREE", "LARGEST_MULTI_KILL",
        "TIME_CCING_OTHERS", "TOTAL_TIME_CROWD_CONTROL_DEALT",
        "TOTAL_HEAL", "TOTAL_UNITS_HEALED",
        # Vision
        "WARD_PLACED", "WARD_KILLED", "SIGHT_WARDS_BOUGHT_IN_GAME",
        "VISION_WARDS_BOUGHT_IN_GAME", "VISION_SCORE",
        # Objectives
        "DRAGON_KILLS", "BARON_KILLS", "RIFT_HERALD_KILLS",
        "TURRET_KILLED", "TURRET_TAKEDOWNS", "HQ_KILLED",
        "BARRACKS_KILLED", "ATAKHAN_KILLS",
        # Economy / Items
        "ITEM0", "ITEM1", "ITEM2", "ITEM3", "ITEM4", "ITEM5", "ITEM6",
        "ITEMS_PURCHASED", "CONSUMABLES_PURCHASED",
        "KEYSTONE_ID",
        # Survival
        "LONGEST_TIME_SPENT_LIVING", "TOTAL_TIME_SPENT_DEAD",
        # Game outcome
        "GAME_ENDED_IN_SURRENDER", "GAME_ENDED_IN_EARLY_SURRENDER",
        "FRIENDLY_TURRET_LOST", "FRIENDLY_HQ_LOST",
    ]

    if stats_list:
        print(f"\n── Player Stats ({len(stats_list)} players) ──")

        # Show ALL coaching-relevant keys for player 1
        p1 = stats_list[0] if isinstance(stats_list[0], dict) else {}
        print(f"\n  [Player 1] — All coaching-relevant stats:")
        for k in COACHING_KEYS:
            if k in p1:
                print(f"    {k}: {p1[k]}")

        # Summary table for all players
        print(f"\n  ┌─────┬──────────────────┬──────┬───┬───┬───┬───────┬─────┬──────┐")
        print(f"  │  #  │ Champion (SKIN)   │ Pos  │ K │ D │ A │ Gold  │  CS │ Win? │")
        print(f"  ├─────┼──────────────────┼──────┼───┼───┼───┼───────┼─────┼──────┤")
        for i, ps in enumerate(stats_list):
            if not isinstance(ps, dict):
                continue
            skin = ps.get("SKIN", ps.get("skin", "?"))
            pos = ps.get("INDIVIDUAL_POSITION", ps.get("TEAM_POSITION", "?"))
            k = ps.get("CHAMPIONS_KILLED", "?")
            d = ps.get("NUM_DEATHS", "?")
            a = ps.get("ASSISTS", "?")
            gold = ps.get("GOLD_EARNED", "?")
            cs = ps.get("MINIONS_KILLED", "?")
            win = ps.get("WIN", "?")
            hq_lost = ps.get("FRIENDLY_HQ_LOST", "?")
            win_display = win if win != "?" else ("L" if hq_lost == "1" else "W" if hq_lost == "0" else "?")
            print(f"  │ {i+1:>3} │ {str(skin):<16s} │ {str(pos):<4s} │{str(k):>2s} │{str(d):>2s} │{str(a):>2s} │{str(gold):>6s} │{str(cs):>4s} │ {str(win_display):<4s} │")
        print(f"  └─────┴──────────────────┴──────┴───┴───┴───┴───────┴─────┴──────┘")

        # Show all unique stat key categories (filter out seasonal/skin junk)
        all_keys = sorted(p1.keys())
        gameplay_keys = [k for k in all_keys if not k.startswith(("2026_", "Event_", "Missions_",
                         "ActMission_", "DemonsHand_", "HoL_"))]
        print(f"\n  All gameplay stat keys ({len(gameplay_keys)}/{len(all_keys)} non-event):")
        for k in gameplay_keys:
            print(f"    {k}: {p1[k]}")
    else:
        print(f"\n  No player stats found in statsJson")

    # Payload decompression — frame by frame
    try:
        frames = p.decompress_payload_frames()
        total = sum(len(f) for f in frames)
        print(f"\n── Decompressed Payload ──")
        print(f"  Frames decompressed: {len(frames)} / {n_frames}")
        print(f"  Total decompressed:  {total:,} bytes ({total/1024/1024:.1f} MB)")
        if frames:
            sizes = [len(f) for f in frames]
            print(f"  Frame sizes: min={min(sizes):,}  max={max(sizes):,}  avg={sum(sizes)//len(sizes):,}")
            print(f"\n  Frame 0 ({len(frames[0]):,} B) first 200 hex:")
            print(f"    {frames[0][:200].hex()}")
            if len(frames) > 1:
                print(f"\n  Frame 1 ({len(frames[1]):,} B) first 200 hex:")
                print(f"    {frames[1][:200].hex()}")
            # Check the biggest frame (likely a keyframe)
            biggest_idx = sizes.index(max(sizes))
            biggest = frames[biggest_idx]
            print(f"\n  Biggest frame #{biggest_idx} ({len(biggest):,} B) first 200 hex:")
            print(f"    {biggest[:200].hex()}")
    except ImportError:
        print(f"\n  (Install zstandard to decompress payload: pip install zstandard)")
    except Exception as e:
        print(f"\n  Payload decompression failed: {e}")


# ── metadata ───────────────────────────────────────────────────────────


def mode_metadata(replay_dir: str, output: str):
    """Extract metadata from all .rofl files and save as JSON."""
    replay_dir_p = Path(replay_dir)
    output_p = Path(output)
    output_p.parent.mkdir(parents=True, exist_ok=True)

    rofl_files = sorted(replay_dir_p.glob("*.rofl"))
    print(f"\n=== Parsing metadata from {len(rofl_files)} .rofl files ===")

    results = []
    for i, f in enumerate(rofl_files):
        print(f"  [{i+1}/{len(rofl_files)}] {f.name}...", end=" ", flush=True)
        try:
            parser = ROFLParser(f)
            info = parser.get_match_info()
            info["filename"] = f.name
            info["file_size_mb"] = round(f.stat().st_size / 1024 / 1024, 1)
            results.append(info)
            dur = info.get("game_length_ms", 0) // 60000
            print(f"ok ({dur}min, {info.get('player_count', '?')} players)")
        except Exception as e:
            print(f"failed: {e}")

    with open(output_p, "w") as fh:
        json.dump(results, fh, indent=2, default=str)

    print(f"\nDone! Parsed {len(results)}/{len(rofl_files)} files")
    print(f"Saved to: {output_p}")

    if results:
        durations = [r["game_length_ms"] // 60000 for r in results if r.get("game_length_ms")]
        if durations:
            print(f"  Durations: min={min(durations)}m  max={max(durations)}m  avg={sum(durations)//len(durations)}m")


# ── events (experimental) ─────────────────────────────────────────────


def mode_events(replay_dir: str, output_dir: str):
    """Decompress payloads and save for further analysis."""
    replay_dir_p = Path(replay_dir)
    output_dir_p = Path(output_dir)
    output_dir_p.mkdir(parents=True, exist_ok=True)

    rofl_files = sorted(replay_dir_p.glob("*.rofl"))
    print(f"\n=== Decompressing payloads from {len(rofl_files)} files ===")

    for i, f in enumerate(rofl_files):
        print(f"  [{i+1}/{len(rofl_files)}] {f.name}...", end=" ", flush=True)
        try:
            parser = ROFLParser(f)
            payload = parser.decompress_payload()
            out_file = output_dir_p / f"{f.stem}.bin"
            out_file.write_bytes(payload)
            print(f"ok ({len(payload)/1024/1024:.1f} MB decompressed)")
        except ImportError:
            print("skip (pip install zstandard)")
            break
        except Exception as e:
            print(f"failed: {e}")

    print("Done!")


# ── packets ────────────────────────────────────────────────────────────


def mode_packets(filepath: str, max_frames: int = 10):
    """
    Decompress frames, concatenate into one stream, and parse
    chunk/keyframe entries from the payload.
    """
    from ml.parsers.chunk_parser import (
        parse_payload_stream,
        print_payload_summary,
        try_inner_packet_parse,
    )

    p = ROFLParser(filepath)
    parsed = p.parse()
    meta = parsed.metadata

    game_ms = meta.get("gameLength", 0)
    n_chunks = meta.get("lastGameChunkId", 0)
    n_keyframes = meta.get("lastKeyFrameId", 0)

    print(f"\n{'='*70}")
    print(f"File:        {filepath}")
    print(f"Game:        {game_ms // 60000}m {(game_ms % 60000) // 1000}s")
    print(f"Expected:    {n_chunks} chunks + {n_keyframes} keyframes = {n_chunks + n_keyframes} frames")
    print(f"{'='*70}")

    # Decompress all zstd frames
    print(f"\nDecompressing payload frames...")
    try:
        frames = p.decompress_payload_frames()
    except Exception as e:
        print(f"  FAILED: {e}")
        return

    total_decompressed = sum(len(f) for f in frames)
    print(f"  Got {len(frames)} zstd frames, {total_decompressed:,} bytes total")

    if not frames:
        print("  No frames to parse!")
        return

    # Parse the concatenated stream
    print(f"\nConcatenating and parsing payload stream...")
    result = parse_payload_stream(frames)

    # Print full summary
    print_payload_summary(result)

    # Try inner packet parsing on first few chunks
    try_inner_packet_parse(result, max_entries=3)


# ── main ───────────────────────────────────────────────────────────────


def main():
    ap = argparse.ArgumentParser(description="Parse .rofl replay files")
    ap.add_argument("--mode", default="inspect", choices=["inspect", "metadata", "events", "packets"])
    ap.add_argument("--file", type=str, help="Single file (inspect/packets mode)")
    ap.add_argument("--replay-dir", default="./ml/data/raw/high_elo/replays")
    ap.add_argument("--output", default="./ml/data/processed/replay_metadata.json",
                    help="Output file (metadata) or dir (events)")
    ap.add_argument("--max-frames", type=int, default=10,
                    help="Max frames to show in packets mode")
    args = ap.parse_args()

    # Auto-select file for single-file modes
    if args.mode in ("inspect", "packets") and not args.file:
        replay_dir = Path(args.replay_dir)
        files = sorted(replay_dir.glob("*.rofl"))
        if not files:
            print(f"No .rofl files in {replay_dir}")
            return
        args.file = str(files[0])
        print(f"  (Auto-selected: {args.file})")

    if args.mode == "inspect":
        mode_inspect(args.file)
    elif args.mode == "metadata":
        mode_metadata(args.replay_dir, args.output)
    elif args.mode == "events":
        mode_events(args.replay_dir, args.output)
    elif args.mode == "packets":
        mode_packets(args.file, max_frames=args.max_frames)


if __name__ == "__main__":
    main()

"""
Parse downloaded .rofl replay files into structured data.

Modes:
  inspect  — Dump one .rofl file's structure / metadata
  metadata — Extract metadata from all replays (fast, no decryption)
  events   — Decompress payload and probe for game events (experimental)

Usage:
    python -m ml.scripts.parse_replays --mode inspect
    python -m ml.scripts.parse_replays --mode metadata
    python -m ml.scripts.parse_replays --mode events
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

    # Stats per player
    stats_raw = meta.get("statsJson", "[]")
    if isinstance(stats_raw, str):
        try:
            stats_list = json.loads(stats_raw)
        except json.JSONDecodeError:
            stats_list = []
    else:
        stats_list = stats_raw if isinstance(stats_raw, list) else []

    if stats_list:
        print(f"\n── Player Stats ({len(stats_list)} players) ──")
        for i, ps in enumerate(stats_list):
            # Show first 10 keys as sample
            keys = sorted(ps.keys()) if isinstance(ps, dict) else []
            print(f"  [Player {i+1}]  {len(keys)} stat keys")
            if keys:
                print(f"    Sample keys: {keys[:12]}")
                # Try to find some recognisable stats
                for prefix in ("CHAMPIONS_KILLED", "NUM_DEATHS", "ASSISTS",
                               "GOLD_EARNED", "MINIONS_KILLED"):
                    if prefix in ps:
                        print(f"    {prefix}: {ps[prefix]}")
    else:
        print(f"\n  No player stats found in statsJson")

    # Print the full raw metadata (pretty, truncated)
    print(f"\n── Raw Metadata (first 5000 chars) ──")
    pretty = json.dumps(meta, indent=2, ensure_ascii=False)
    print(pretty[:5000])
    if len(pretty) > 5000:
        print(f"  ... ({len(pretty)} total chars)")

    # Optionally try decompressing payload
    try:
        payload = p.decompress_payload()
        print(f"\n── Decompressed Payload ──")
        print(f"  Size: {len(payload):,} bytes ({len(payload)/1024/1024:.1f} MB)")
        print(f"  First 200 bytes (hex): {payload[:200].hex()}")
        # Look for recognizable structures
        for marker in (b"KeyFrame", b"Chunk", b"gameData", b"player"):
            idx = payload.find(marker)
            if idx >= 0:
                print(f"  Found '{marker.decode()}' at offset {idx}")
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


# ── main ───────────────────────────────────────────────────────────────


def main():
    ap = argparse.ArgumentParser(description="Parse .rofl replay files")
    ap.add_argument("--mode", default="inspect", choices=["inspect", "metadata", "events"])
    ap.add_argument("--file", type=str, help="Single file (inspect mode)")
    ap.add_argument("--replay-dir", default="./ml/data/raw/high_elo/replays")
    ap.add_argument("--output", default="./ml/data/processed/replay_metadata.json",
                    help="Output file (metadata) or dir (events)")
    args = ap.parse_args()

    if args.mode == "inspect":
        if not args.file:
            replay_dir = Path(args.replay_dir)
            files = sorted(replay_dir.glob("*.rofl"))
            if not files:
                print(f"No .rofl files in {replay_dir}")
                return
            args.file = str(files[0])
            print(f"  (Auto-selected: {args.file})")
        mode_inspect(args.file)

    elif args.mode == "metadata":
        mode_metadata(args.replay_dir, args.output)

    elif args.mode == "events":
        mode_events(args.replay_dir, args.output)


if __name__ == "__main__":
    main()

"""
Parse downloaded .rofl replay files into structured data.

Three modes:
  1. inspect  — Look at one .rofl file to see what's inside
  2. metadata — Extract metadata from all replays (fast, no decryption)
  3. full     — Decrypt chunks and extract game events (needs pycryptodome)

Usage:
    # Inspect a single file
    python -m ml.scripts.parse_replays --mode inspect --file ml/data/raw/high_elo/replays/NA1_5483551531.replay.rofl

    # Extract metadata from all downloaded replays
    python -m ml.scripts.parse_replays --mode metadata

    # Full extraction with chunk decryption
    python -m ml.scripts.parse_replays --mode full
"""

import argparse
import json
from pathlib import Path

from ml.parsers.rofl_parser import ROFLParser, batch_parse_metadata


def mode_inspect(filepath: str):
    """Inspect a single .rofl file — show structure and contents."""
    parser = ROFLParser(filepath)
    parsed = parser.parse()

    print(f"\n{'='*60}")
    print(f"ROFL File: {filepath}")
    print(f"File size: {Path(filepath).stat().st_size / 1024 / 1024:.1f} MB")
    print(f"{'='*60}")

    # File header
    fh = parsed.file_header
    print(f"\n── File Header ──")
    print(f"  Head length:           {fh.head_length}")
    print(f"  File length:           {fh.file_length}")
    print(f"  Metadata offset:       {fh.metadata_offset}")
    print(f"  Metadata length:       {fh.metadata_length}")
    print(f"  Payload header offset: {fh.payload_header_offset}")
    print(f"  Payload header length: {fh.payload_header_length}")
    print(f"  Payload offset:        {fh.payload_offset}")

    # Metadata
    meta = parsed.metadata
    print(f"\n── Metadata ──")
    print(f"  Game version:  {meta.get('gameVersion', '?')}")
    print(f"  Game length:   {meta.get('gameLength', 0)}ms ({meta.get('gameLength', 0) // 60000}min)")

    # Show metadata keys
    print(f"\n  Metadata keys: {sorted(meta.keys())}")

    # Show raw metadata for a few key fields
    for key in ["gameVersion", "gameLength", "lastGameChunkId", "lastKeyFrameId"]:
        if key in meta:
            print(f"  {key}: {meta[key]}")

    # Players
    players = meta.get("players", [])
    if isinstance(players, str):
        try:
            players = json.loads(players)
        except json.JSONDecodeError:
            players = []

    if players:
        print(f"\n── Players ({len(players)}) ──")
        for i, p in enumerate(players):
            name = p.get("NAME", p.get("name", "?"))
            skin = p.get("SKIN", p.get("skin", "?"))
            team = p.get("TEAM", p.get("team", "?"))
            print(f"  [{i+1}] {name} — {skin} (team {team})")

            # Show player stats keys
            stats_raw = p.get("statsJson", p.get("STATS", "{}"))
            if isinstance(stats_raw, str):
                try:
                    stats = json.loads(stats_raw)
                    if stats:
                        print(f"       Stats keys ({len(stats)}): {sorted(stats.keys())[:15]}...")
                        # Show a few key stats
                        for sk in ["CHAMPIONS_KILLED", "NUM_DEATHS", "ASSISTS", "GOLD_EARNED",
                                   "MINIONS_KILLED", "VISION_WARDS_BOUGHT_IN_GAME", "WARD_PLACED"]:
                            if sk in stats:
                                print(f"       {sk}: {stats[sk]}")
                except json.JSONDecodeError:
                    pass
    else:
        print(f"\n  No player data in metadata")
        # Print raw metadata sample
        meta_str = json.dumps(meta, indent=2)
        print(f"\n  Raw metadata (first 2000 chars):\n{meta_str[:2000]}")

    # Payload header
    ph = parsed.payload_header
    if ph:
        print(f"\n── Payload Header ──")
        print(f"  Game ID:            {ph.game_id}")
        print(f"  Game length:        {ph.game_length}ms ({ph.game_length // 60000}min)")
        print(f"  Keyframe count:     {ph.keyframe_count}")
        print(f"  Chunk count:        {ph.chunk_count}")
        print(f"  Keyframe interval:  {ph.keyframe_interval}ms")
        print(f"  Encryption key len: {ph.encryption_key_length}")
        print(f"  Start game chunk:   {ph.start_game_chunk_id}")
        print(f"  End startup chunk:  {ph.end_startup_chunk_id}")

    # Chunk headers summary
    if parsed.chunk_headers:
        keyframes = [c for c in parsed.chunk_headers if c.chunk_type == 1]
        data_chunks = [c for c in parsed.chunk_headers if c.chunk_type == 2]
        print(f"\n── Chunks ──")
        print(f"  Total:     {len(parsed.chunk_headers)}")
        print(f"  Keyframes: {len(keyframes)}")
        print(f"  Data:      {len(data_chunks)}")
        if parsed.chunk_headers:
            sizes = [c.chunk_length for c in parsed.chunk_headers]
            print(f"  Chunk sizes: min={min(sizes)}, max={max(sizes)}, avg={sum(sizes)//len(sizes)}")

    # Try decrypting one chunk to see if it works
    try:
        decrypted = parser.get_decrypted_chunks()
        if decrypted:
            ch, data = decrypted[0]
            print(f"\n── Sample Decrypted Chunk ──")
            print(f"  Chunk ID: {ch.chunk_id}, Type: {ch.chunk_type}")
            print(f"  Decrypted size: {len(data)} bytes")
            print(f"  First 100 bytes (hex): {data[:100].hex()}")
            print(f"  First 100 bytes (repr): {repr(data[:100])}")
    except ImportError:
        print(f"\n  (Install pycryptodome to decrypt chunks: pip install pycryptodome)")
    except Exception as e:
        print(f"\n  Chunk decryption failed: {e}")


def mode_metadata(replay_dir: str, output: str):
    """Extract metadata from all .rofl files and save."""
    replay_dir = Path(replay_dir)
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rofl_files = sorted(replay_dir.glob("*.rofl"))
    print(f"\n=== Parsing metadata from {len(rofl_files)} .rofl files ===")

    results = []
    for i, rofl_file in enumerate(rofl_files):
        print(f"  [{i+1}/{len(rofl_files)}] {rofl_file.name}...", end=" ")
        try:
            parser = ROFLParser(rofl_file)
            info = parser.get_match_info()
            info["filename"] = rofl_file.name
            info["file_size_mb"] = round(rofl_file.stat().st_size / 1024 / 1024, 1)
            results.append(info)
            duration = info.get("game_length_ms", 0) // 60000
            n_players = len(info.get("players", []))
            print(f"ok ({duration}min, {n_players} players)")
        except Exception as e:
            print(f"failed: {e}")

    # Save results
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\n  Done! Parsed {len(results)}/{len(rofl_files)} files")
    print(f"  Saved to: {output_path}")

    # Summary stats
    if results:
        durations = [r["game_length_ms"] // 60000 for r in results if r.get("game_length_ms")]
        if durations:
            print(f"\n  Game durations: min={min(durations)}min, max={max(durations)}min, avg={sum(durations)//len(durations)}min")

        # Champion frequency
        champ_count: dict[str, int] = {}
        for r in results:
            for p in r.get("players", []):
                champ = p.get("champion", "?")
                champ_count[champ] = champ_count.get(champ, 0) + 1
        if champ_count:
            top = sorted(champ_count.items(), key=lambda x: x[1], reverse=True)[:10]
            print(f"\n  Top champions: {', '.join(f'{c}({n})' for c, n in top)}")


def mode_full(replay_dir: str, output_dir: str):
    """Full extraction: metadata + decrypted chunks."""
    replay_dir = Path(replay_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    rofl_files = sorted(replay_dir.glob("*.rofl"))
    print(f"\n=== Full parsing of {len(rofl_files)} .rofl files ===")

    for i, rofl_file in enumerate(rofl_files):
        print(f"\n  [{i+1}/{len(rofl_files)}] {rofl_file.name}")
        try:
            parser = ROFLParser(rofl_file)
            info = parser.get_match_info()

            # Save metadata
            match_dir = output_dir / rofl_file.stem
            match_dir.mkdir(exist_ok=True)

            with open(match_dir / "metadata.json", "w") as f:
                json.dump(info, f, indent=2, default=str)

            # Decrypt chunks
            try:
                chunks = parser.get_decrypted_chunks()
                print(f"    Decrypted {len(chunks)} chunks")

                # Save chunks as binary
                for ch, data in chunks:
                    chunk_type = "keyframe" if ch.chunk_type == 1 else "chunk"
                    chunk_file = match_dir / f"{chunk_type}_{ch.chunk_id:04d}.bin"
                    chunk_file.write_bytes(data)

                # Also save a chunks index
                chunk_index = [
                    {
                        "id": ch.chunk_id,
                        "type": "keyframe" if ch.chunk_type == 1 else "chunk",
                        "size": len(data),
                        "file": f"{'keyframe' if ch.chunk_type == 1 else 'chunk'}_{ch.chunk_id:04d}.bin",
                    }
                    for ch, data in chunks
                ]
                with open(match_dir / "chunks_index.json", "w") as f:
                    json.dump(chunk_index, f, indent=2)

                print(f"    Saved to {match_dir}")

            except ImportError:
                print(f"    Skipping chunk decryption (install pycryptodome)")
            except Exception as e:
                print(f"    Chunk decryption failed: {e}")

        except Exception as e:
            print(f"    Failed: {e}")


def main():
    parser = argparse.ArgumentParser(description="Parse .rofl replay files")
    parser.add_argument(
        "--mode",
        type=str,
        default="inspect",
        choices=["inspect", "metadata", "full"],
        help="Parse mode",
    )
    parser.add_argument(
        "--file",
        type=str,
        help="Single .rofl file to inspect (for --mode inspect)",
    )
    parser.add_argument(
        "--replay-dir",
        type=str,
        default="./ml/data/raw/high_elo/replays",
        help="Directory with .rofl files",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="./ml/data/processed/replay_metadata.json",
        help="Output file (metadata mode) or directory (full mode)",
    )
    args = parser.parse_args()

    if args.mode == "inspect":
        if not args.file:
            # Auto-pick first .rofl file
            replay_dir = Path(args.replay_dir)
            rofl_files = sorted(replay_dir.glob("*.rofl"))
            if not rofl_files:
                print(f"No .rofl files found in {replay_dir}")
                return
            args.file = str(rofl_files[0])
            print(f"  (Auto-selected: {args.file})")
        mode_inspect(args.file)

    elif args.mode == "metadata":
        mode_metadata(args.replay_dir, args.output)

    elif args.mode == "full":
        mode_full(args.replay_dir, args.output)


if __name__ == "__main__":
    main()

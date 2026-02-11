"""
Download Maknee's decoded League of Legends replay packet dataset from HuggingFace.

This dataset contains 1.4M+ replays already decoded to structured JSON events:
  - CreateSummoner, CastSpell, BasicAttackAtTarget, UpdateState
  - Death, BecomeVisibleInFogOfWar, CreateEntity, etc.
  - Millisecond-precision positions, spell casts, state changes

Source: https://maknee.github.io/blog/2025/League-Data-Scraping/
HuggingFace: https://huggingface.co/Maknee

Usage:
    # List available datasets from Maknee
    python -m ml.scripts.download_hf_replays --list

    # Download a specific dataset (streaming mode — inspect first)
    python -m ml.scripts.download_hf_replays --dataset Maknee/league-of-legends-replays --peek 5

    # Download full dataset to disk
    python -m ml.scripts.download_hf_replays --dataset Maknee/league-of-legends-replays --download

    # Download raw .rofl files (if dataset contains them)
    python -m ml.scripts.download_hf_replays --dataset Maknee/league-of-legends-replays --download-files
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Optional imports — fail gracefully with install instructions
try:
    from huggingface_hub import HfApi, hf_hub_download, list_repo_files
    HAS_HF = True
except ImportError:
    HAS_HF = False

try:
    from datasets import load_dataset
    HAS_DATASETS = True
except ImportError:
    HAS_DATASETS = False


OUTPUT_DIR = Path("ml/data/raw/hf_replays")

# Known Maknee dataset IDs (update if URLs change)
KNOWN_DATASETS = [
    "Maknee/league-of-legends-replays",
    "Maknee/league-of-legends-replays-2",
    "Maknee/league-of-legends-decoded-replay-packets",
]


def cmd_list():
    """List Maknee's datasets on HuggingFace."""
    if not HAS_HF:
        print("pip install huggingface-hub")
        return

    api = HfApi()
    print("Searching for Maknee's League datasets on HuggingFace...\n")

    try:
        # Search by author
        datasets = list(api.list_datasets(author="Maknee"))
        if datasets:
            print(f"Found {len(datasets)} dataset(s) by Maknee:")
            for ds in datasets:
                size = ""
                if hasattr(ds, "size_categories") and ds.size_categories:
                    size = f" [{ds.size_categories}]"
                print(f"  {ds.id}{size}")
                if hasattr(ds, "description") and ds.description:
                    print(f"    {ds.description[:120]}")
        else:
            print("No datasets found by author 'Maknee'.")
            print("Trying known dataset IDs...")

        # Also try known IDs
        print(f"\nChecking known dataset IDs:")
        for ds_id in KNOWN_DATASETS:
            try:
                info = api.dataset_info(ds_id)
                size_str = ""
                if hasattr(info, "cardData") and info.cardData:
                    size_str = f" (card data available)"
                print(f"  ✓ {ds_id}{size_str}")
                # List files
                try:
                    files = list(api.list_repo_files(ds_id, repo_type="dataset"))
                    print(f"    Files: {len(files)} — {files[:5]}{'...' if len(files) > 5 else ''}")
                except Exception:
                    pass
            except Exception:
                print(f"  ✗ {ds_id} — not found or private")

    except Exception as e:
        print(f"Error: {e}")
        print("\nYou may need to set HF_TOKEN or log in:")
        print("  huggingface-cli login")


def cmd_peek(dataset_id: str, count: int = 5):
    """Stream a few samples from the dataset to inspect the format."""
    if not HAS_DATASETS:
        print("pip install datasets")
        return

    print(f"Streaming {count} samples from {dataset_id}...\n")

    try:
        ds = load_dataset(dataset_id, streaming=True, split="train")
        for i, sample in enumerate(ds):
            if i >= count:
                break
            print(f"── Sample {i} ──")
            # Pretty-print keys and truncated values
            if isinstance(sample, dict):
                for k, v in sample.items():
                    v_str = str(v)
                    if len(v_str) > 200:
                        v_str = v_str[:200] + "..."
                    print(f"  {k}: {v_str}")
            else:
                print(f"  {str(sample)[:500]}")
            print()
    except Exception as e:
        print(f"Error loading dataset: {e}")
        print("\nTroubleshooting:")
        print("  1. Check dataset ID is correct: huggingface.co/datasets/" + dataset_id)
        print("  2. May need auth: huggingface-cli login")
        print("  3. May need: pip install datasets")


def cmd_download(dataset_id: str, max_samples: int | None = None):
    """Download the full dataset to disk as JSONL."""
    if not HAS_DATASETS:
        print("pip install datasets")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_file = OUTPUT_DIR / f"{dataset_id.replace('/', '_')}.jsonl"

    print(f"Downloading {dataset_id} → {out_file}")
    if max_samples:
        print(f"  (limited to {max_samples} samples)")

    try:
        ds = load_dataset(dataset_id, streaming=True, split="train")
        count = 0
        with open(out_file, "w") as f:
            for sample in ds:
                f.write(json.dumps(sample, default=str) + "\n")
                count += 1
                if count % 1000 == 0:
                    print(f"  {count:,} samples...", flush=True)
                if max_samples and count >= max_samples:
                    break

        size_mb = out_file.stat().st_size / 1024 / 1024
        print(f"\nDone! {count:,} samples → {out_file} ({size_mb:.1f} MB)")

    except Exception as e:
        print(f"Error: {e}")


def cmd_download_files(dataset_id: str, pattern: str = "*.json"):
    """Download raw files from a HuggingFace dataset repo."""
    if not HAS_HF:
        print("pip install huggingface-hub")
        return

    api = HfApi()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Listing files in {dataset_id}...")
    try:
        files = list(api.list_repo_files(dataset_id, repo_type="dataset"))
        print(f"  Found {len(files)} files")

        # Filter by pattern
        from fnmatch import fnmatch
        matched = [f for f in files if fnmatch(f, pattern)]
        print(f"  Matched {len(matched)} files with pattern '{pattern}'")

        if not matched:
            print(f"\n  All files: {files[:20]}")
            return

        for i, fname in enumerate(matched):
            print(f"  [{i+1}/{len(matched)}] {fname}...", end=" ", flush=True)
            try:
                local_path = hf_hub_download(
                    dataset_id, fname, repo_type="dataset",
                    local_dir=str(OUTPUT_DIR / dataset_id.replace("/", "_")),
                )
                print(f"ok → {local_path}")
            except Exception as e:
                print(f"failed: {e}")

        print(f"\nDone! Files in: {OUTPUT_DIR}")

    except Exception as e:
        print(f"Error: {e}")


def main():
    ap = argparse.ArgumentParser(description="Download Maknee's decoded LoL replay dataset")
    ap.add_argument("--list", action="store_true", help="List available datasets")
    ap.add_argument("--dataset", type=str, default=KNOWN_DATASETS[0],
                    help=f"HuggingFace dataset ID (default: {KNOWN_DATASETS[0]})")
    ap.add_argument("--peek", type=int, default=0,
                    help="Stream N samples to inspect format")
    ap.add_argument("--download", action="store_true",
                    help="Download full dataset as JSONL")
    ap.add_argument("--download-files", action="store_true",
                    help="Download raw files from repo")
    ap.add_argument("--max-samples", type=int, default=None,
                    help="Max samples to download (for testing)")
    ap.add_argument("--pattern", type=str, default="*.json",
                    help="File pattern for --download-files")
    args = ap.parse_args()

    if args.list:
        cmd_list()
    elif args.peek > 0:
        cmd_peek(args.dataset, args.peek)
    elif args.download:
        cmd_download(args.dataset, args.max_samples)
    elif args.download_files:
        cmd_download_files(args.dataset, args.pattern)
    else:
        # Default: list + peek
        cmd_list()
        print("\n" + "="*60)
        print("Use --peek N to inspect samples, --download to save to disk")


if __name__ == "__main__":
    main()

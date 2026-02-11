"""
Download the decoded LoL replay packets dataset from HuggingFace.

Dataset: maknee/league-of-legends-decoded-replay-packets
Contains decoded spectator protocol packets from real LoL games.

Usage:
    python -m ml.scripts.download_dataset
    python -m ml.scripts.download_dataset --output ./ml/data/raw
"""

import argparse
from pathlib import Path

from datasets import load_dataset
from huggingface_hub import login


def main():
    parser = argparse.ArgumentParser(description="Download LoL replay dataset")
    parser.add_argument(
        "--output", type=str, default="./ml/data/raw", help="Output directory"
    )
    parser.add_argument(
        "--dataset",
        type=str,
        default="maknee/league-of-legends-decoded-replay-packets",
        help="HuggingFace dataset ID",
    )
    parser.add_argument("--token", type=str, default=None, help="HuggingFace token")
    parser.add_argument(
        "--max-samples",
        type=int,
        default=None,
        help="Max samples to download (for testing)",
    )
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.token:
        login(token=args.token)

    print(f"Downloading dataset: {args.dataset}")
    print(f"Output directory: {output_dir}")

    # Load dataset
    ds = load_dataset(args.dataset, trust_remote_code=True)

    if args.max_samples:
        for split in ds:
            ds[split] = ds[split].select(range(min(args.max_samples, len(ds[split]))))

    # Save to disk
    ds.save_to_disk(str(output_dir / "replay_packets"))
    print(f"Dataset saved to {output_dir / 'replay_packets'}")
    print(f"Splits: {list(ds.keys())}")
    for split in ds:
        print(f"  {split}: {len(ds[split])} samples")


if __name__ == "__main__":
    main()

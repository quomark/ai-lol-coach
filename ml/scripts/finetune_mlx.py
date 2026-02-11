"""
Fine-tune a language model on LoL coaching data using MLX (Apple Silicon).

MLX is Apple's ML framework — optimized for unified memory on M-series chips.
This replaces the CUDA-based QLoRA approach for Mac users.

Requirements:
    pip install mlx mlx-lm

Usage:
    # 1. Generate training data first
    python -m ml.scripts.prepare_training_data --synthetic --output ./ml/data/processed/train.jsonl

    # 2. Convert JSONL to MLX format
    python -m ml.scripts.finetune_mlx --prepare-data \
        --train-data ./ml/data/processed/train.jsonl \
        --output-dir ./ml/data/processed/mlx

    # 3. Fine-tune
    python -m ml.scripts.finetune_mlx \
        --train \
        --model mlx-community/Mistral-7B-Instruct-v0.3-4bit \
        --data-dir ./ml/data/processed/mlx \
        --output-dir ./ml/models/lol-coach-v1 \
        --epochs 3

    # Smaller model if 7B is too slow:
    python -m ml.scripts.finetune_mlx \
        --train \
        --model mlx-community/Llama-3.2-3B-Instruct-4bit \
        --data-dir ./ml/data/processed/mlx \
        --output-dir ./ml/models/lol-coach-v1 \
        --epochs 3

Memory usage (approximate):
    Mistral-7B-4bit:  ~14GB during training (fits 24GB Mac Mini)
    Llama-3.2-3B-4bit: ~8GB during training (comfortable on 24GB)
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path


def prepare_data(train_jsonl: str, output_dir: str, val_split: float = 0.1):
    """
    Convert our JSONL training data to the format MLX expects.

    MLX fine-tuning expects JSONL files with a "text" field containing
    the full chat formatted as a single string, OR a "messages" field
    in OpenAI chat format (which our data already uses).

    It needs: train.jsonl, valid.jsonl in a directory.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load all examples
    examples = []
    with open(train_jsonl) as f:
        for line in f:
            if line.strip():
                examples.append(json.loads(line))

    # Split into train/val
    split_idx = int(len(examples) * (1 - val_split))
    train_examples = examples[:split_idx]
    val_examples = examples[split_idx:]

    # Write in chat format (MLX supports "messages" key directly)
    for filename, data in [("train.jsonl", train_examples), ("valid.jsonl", val_examples)]:
        filepath = output_dir / filename
        with open(filepath, "w") as f:
            for ex in data:
                # MLX expects each line to have "messages" with role/content pairs
                f.write(json.dumps(ex) + "\n")

        print(f"  {filename}: {len(data)} examples → {filepath}")

    print(f"\nData prepared in {output_dir}")
    print(f"  Train: {len(train_examples)} examples")
    print(f"  Valid: {len(val_examples)} examples")


def finetune(
    model: str,
    data_dir: str,
    output_dir: str,
    epochs: int = 3,
    batch_size: int = 4,
    learning_rate: float = 1e-5,
    lora_rank: int = 16,
    steps_per_eval: int = 50,
    max_seq_length: int = 2048,
):
    """
    Run MLX LoRA fine-tuning.

    Uses `mlx_lm.lora` which handles:
    - Loading the 4-bit quantized model
    - Setting up LoRA adapters
    - Training loop with gradient accumulation
    - Saving the adapter weights
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Model: {model}")
    print(f"Data:  {data_dir}")
    print(f"Output: {output_dir}")
    print(f"Epochs: {epochs}, Batch: {batch_size}, LR: {learning_rate}")
    print(f"LoRA rank: {lora_rank}")
    print()

    # Build mlx_lm.lora command
    cmd = [
        sys.executable, "-m", "mlx_lm.lora",
        "--model", model,
        "--data", data_dir,
        "--adapter-path", str(output_dir),
        "--train",
        "--iters", str(_estimate_iters(data_dir, epochs, batch_size)),
        "--batch-size", str(batch_size),
        "--learning-rate", str(learning_rate),
        "--lora-rank", str(lora_rank),
        "--steps-per-eval", str(steps_per_eval),
        "--max-seq-length", str(max_seq_length),
        "--seed", "42",
    ]

    print(f"Running: {' '.join(cmd)}\n")
    result = subprocess.run(cmd)

    if result.returncode == 0:
        print(f"\n✅ Training complete! Adapter saved to {output_dir}")
        print(f"\nTo test inference:")
        print(f"  python -m mlx_lm.generate \\")
        print(f"    --model {model} \\")
        print(f"    --adapter-path {output_dir} \\")
        print(f'    --prompt "Analyze this LoL game..."')
        print(f"\nTo use in the app, set in .env:")
        print(f"  LORA_ADAPTER_PATH={output_dir}")

        # Save training config
        config = {
            "base_model": model,
            "lora_rank": lora_rank,
            "epochs": epochs,
            "batch_size": batch_size,
            "learning_rate": learning_rate,
            "framework": "mlx",
        }
        with open(output_dir / "training_config.json", "w") as f:
            json.dump(config, f, indent=2)
    else:
        print(f"\n❌ Training failed with exit code {result.returncode}")
        sys.exit(1)


def _estimate_iters(data_dir: str, epochs: int, batch_size: int) -> int:
    """Estimate total training iterations from data size."""
    train_file = Path(data_dir) / "train.jsonl"
    num_examples = sum(1 for _ in open(train_file))
    iters = (num_examples * epochs) // batch_size
    print(f"  {num_examples} examples × {epochs} epochs ÷ {batch_size} batch = {iters} iterations")
    return max(iters, 1)


def test_generation(model: str, adapter_path: str, prompt: str | None = None):
    """Quick test of the fine-tuned model."""
    if prompt is None:
        prompt = (
            "Analyze this League of Legends game for player 'TestPlayer'.\n\n"
            "Game Version: 14.24\nGame Length: 28m 15s\nGame Mode: CLASSIC\n"
            "Winning Team: Blue\n\n"
            "=== Blue Team ===\n"
            "  TestPlayer - Jinx (BOTTOM): 8/4/6 | CS: 215 | Gold: 13,200 | "
            "Damage: 24,500 | Vision: 22 | Wards: 8/2\n"
        )

    cmd = [
        sys.executable, "-m", "mlx_lm.generate",
        "--model", model,
        "--adapter-path", adapter_path,
        "--prompt", prompt,
        "--max-tokens", "512",
        "--temp", "0.7",
    ]

    print(f"Testing model: {model} + adapter: {adapter_path}\n")
    subprocess.run(cmd)


def main():
    parser = argparse.ArgumentParser(description="Fine-tune LoL Coach on Apple Silicon (MLX)")

    # Mode
    parser.add_argument("--prepare-data", action="store_true", help="Prepare data for MLX format")
    parser.add_argument("--train", action="store_true", help="Run fine-tuning")
    parser.add_argument("--test", action="store_true", help="Test the fine-tuned model")

    # Data
    parser.add_argument("--train-data", type=str, help="Input JSONL (for --prepare-data)")
    parser.add_argument("--data-dir", type=str, default="./ml/data/processed/mlx", help="MLX data directory")

    # Model
    parser.add_argument(
        "--model", type=str,
        default="mlx-community/Mistral-7B-Instruct-v0.3-4bit",
        help="MLX model ID (use mlx-community/ models for pre-quantized)",
    )
    parser.add_argument("--output-dir", type=str, default="./ml/models/lol-coach-v1")
    parser.add_argument("--adapter-path", type=str, help="Adapter path for --test")

    # Training hyperparameters
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=4)
    parser.add_argument("--learning-rate", type=float, default=1e-5)
    parser.add_argument("--lora-rank", type=int, default=16)
    parser.add_argument("--max-seq-length", type=int, default=2048)

    args = parser.parse_args()

    if args.prepare_data:
        if not args.train_data:
            print("Error: --train-data required for --prepare-data")
            sys.exit(1)
        prepare_data(args.train_data, args.data_dir)

    elif args.train:
        finetune(
            model=args.model,
            data_dir=args.data_dir,
            output_dir=args.output_dir,
            epochs=args.epochs,
            batch_size=args.batch_size,
            learning_rate=args.learning_rate,
            lora_rank=args.lora_rank,
            max_seq_length=args.max_seq_length,
        )

    elif args.test:
        adapter = args.adapter_path or args.output_dir
        test_generation(args.model, adapter)

    else:
        parser.print_help()
        print("\nExample full workflow:")
        print("  # Step 1: Generate training data")
        print("  python -m ml.scripts.prepare_training_data --synthetic --output ./ml/data/processed/train.jsonl")
        print()
        print("  # Step 2: Prepare for MLX")
        print("  python -m ml.scripts.finetune_mlx --prepare-data --train-data ./ml/data/processed/train.jsonl")
        print()
        print("  # Step 3: Fine-tune (pick one model)")
        print("  python -m ml.scripts.finetune_mlx --train --model mlx-community/Mistral-7B-Instruct-v0.3-4bit")
        print("  python -m ml.scripts.finetune_mlx --train --model mlx-community/Llama-3.2-3B-Instruct-4bit  # faster")
        print()
        print("  # Step 4: Test")
        print("  python -m ml.scripts.finetune_mlx --test")


if __name__ == "__main__":
    main()

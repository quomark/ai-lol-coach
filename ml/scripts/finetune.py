"""
Fine-tune a language model on LoL coaching data using LoRA (QLoRA).

This uses PEFT/LoRA to fine-tune efficiently on consumer hardware:
- 7B model with 4-bit quantization fits in ~6GB VRAM
- LoRA only trains ~0.1% of parameters
- Full fine-tune quality with fraction of compute

Usage:
    # Generate synthetic data first
    python -m ml.scripts.prepare_training_data --synthetic --output ./ml/data/processed/train.jsonl

    # Fine-tune
    python -m ml.scripts.finetune \
        --train-data ./ml/data/processed/train.jsonl \
        --output-dir ./ml/models/lol-coach-v1 \
        --epochs 3 \
        --batch-size 4

    # With real .rofl data
    python -m ml.scripts.prepare_training_data --rofl-dir ./replays --output ./ml/data/processed/train.jsonl
    python -m ml.scripts.finetune --train-data ./ml/data/processed/train.jsonl --output-dir ./ml/models/lol-coach-v1
"""

import argparse
import json
from pathlib import Path

import torch
from datasets import Dataset
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    TrainingArguments,
)
from trl import SFTTrainer


def load_training_data(path: str) -> Dataset:
    """Load JSONL training data into a HuggingFace Dataset."""
    examples = []
    with open(path) as f:
        for line in f:
            if line.strip():
                examples.append(json.loads(line))

    # Convert chat messages to single text strings
    texts = []
    for ex in examples:
        # Format as chat template
        texts.append(ex["messages"])

    return Dataset.from_dict({"messages": texts})


def main():
    parser = argparse.ArgumentParser(description="Fine-tune LoL Coach model")
    parser.add_argument(
        "--train-data",
        type=str,
        required=True,
        help="Path to training JSONL file",
    )
    parser.add_argument(
        "--base-model",
        type=str,
        default="mistralai/Mistral-7B-Instruct-v0.3",
        help="Base model to fine-tune",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./ml/models/lol-coach-v1",
        help="Output directory for fine-tuned adapter",
    )
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=4)
    parser.add_argument("--learning-rate", type=float, default=2e-4)
    parser.add_argument("--max-seq-length", type=int, default=2048)
    parser.add_argument("--lora-r", type=int, default=16, help="LoRA rank")
    parser.add_argument("--lora-alpha", type=int, default=32, help="LoRA alpha")
    parser.add_argument("--lora-dropout", type=float, default=0.05)
    parser.add_argument(
        "--gradient-accumulation-steps",
        type=int,
        default=4,
        help="Gradient accumulation steps",
    )
    parser.add_argument("--use-4bit", action="store_true", default=True)
    parser.add_argument("--no-4bit", action="store_true")
    args = parser.parse_args()

    use_4bit = args.use_4bit and not args.no_4bit

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Base model: {args.base_model}")
    print(f"Training data: {args.train_data}")
    print(f"Output: {args.output_dir}")
    print(f"4-bit quantization: {use_4bit}")

    # ─── Load model ──────────────────────────────────────────────────────

    bnb_config = None
    if use_4bit:
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_use_double_quant=True,
        )

    print("Loading model...")
    model = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        quantization_config=bnb_config,
        device_map="auto",
        torch_dtype=torch.float16,
    )

    tokenizer = AutoTokenizer.from_pretrained(args.base_model)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
        model.config.pad_token_id = tokenizer.eos_token_id

    # ─── LoRA config ─────────────────────────────────────────────────────

    if use_4bit:
        model = prepare_model_for_kbit_training(model)

    lora_config = LoraConfig(
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=[
            "q_proj",
            "k_proj",
            "v_proj",
            "o_proj",
            "gate_proj",
            "up_proj",
            "down_proj",
        ],
    )

    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    # ─── Load data ───────────────────────────────────────────────────────

    print("Loading training data...")
    dataset = load_training_data(args.train_data)
    print(f"Training examples: {len(dataset)}")

    # ─── Training ────────────────────────────────────────────────────────

    training_args = TrainingArguments(
        output_dir=str(output_dir / "checkpoints"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.gradient_accumulation_steps,
        learning_rate=args.learning_rate,
        weight_decay=0.01,
        warmup_ratio=0.03,
        lr_scheduler_type="cosine",
        logging_steps=10,
        save_strategy="epoch",
        fp16=True,
        optim="paged_adamw_8bit" if use_4bit else "adamw_torch",
        max_grad_norm=0.3,
        group_by_length=True,
        report_to="none",  # set to "wandb" if you want logging
    )

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        args=training_args,
        max_seq_length=args.max_seq_length,
    )

    print("Starting training...")
    trainer.train()

    # ─── Save ────────────────────────────────────────────────────────────

    print(f"Saving adapter to {output_dir}")
    model.save_pretrained(str(output_dir))
    tokenizer.save_pretrained(str(output_dir))

    # Save config for easy loading
    config = {
        "base_model": args.base_model,
        "lora_r": args.lora_r,
        "lora_alpha": args.lora_alpha,
        "epochs": args.epochs,
        "learning_rate": args.learning_rate,
    }
    with open(output_dir / "training_config.json", "w") as f:
        json.dump(config, f, indent=2)

    print("Done! To use the model, set LORA_ADAPTER_PATH in .env")
    print(f"  LORA_ADAPTER_PATH={output_dir}")


if __name__ == "__main__":
    main()

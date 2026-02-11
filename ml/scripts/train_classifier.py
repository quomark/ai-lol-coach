"""
Train the game state classifier.

This trains the REAL model — the one that learns game patterns from data.
Not an LLM. A purpose-built neural net.

Input: labeled game moments (from label_with_claude.py or rule-based)
Output: trained model that detects mistakes in any game state

Usage:
    # With Claude-labeled data:
    python -m ml.scripts.train_classifier \
        --data ./ml/data/processed/claude_labeled.jsonl \
        --output ./ml/models/classifier-v1 \
        --epochs 50

    # With rule-labeled data (bootstrap):
    python -m ml.scripts.train_classifier \
        --data ./ml/data/processed/rule_labeled.jsonl \
        --output ./ml/models/classifier-v1 \
        --epochs 50

Memory: ~1-2GB. Trains in 5-30 min on Mac Mini depending on data size.
"""

import argparse
import json
from pathlib import Path

import numpy as np
import torch
from torch.utils.data import DataLoader, Dataset, random_split

from ml.models.classifier import GameStateClassifier, create_model
from ml.models.features import (
    FEATURE_DIM,
    LABEL_TO_IDX,
    IDX_TO_LABEL,
    NUM_LABELS,
    extract_features,
    GameContext,
)


# ─── Dataset ─────────────────────────────────────────────────────────────────

class GameMomentDataset(Dataset):
    """
    Dataset of labeled game moments.

    Each sample is a window of consecutive frames + a label for the last frame.
    """

    def __init__(self, data_path: str, window_size: int = 5):
        self.window_size = window_size
        self.samples = []  # list of (features_window, label_idx, severity)

        data_path = Path(data_path)
        print(f"Loading data from {data_path}...")

        if data_path.suffix == ".jsonl":
            self._load_jsonl(data_path)
        elif data_path.suffix == ".npz":
            self._load_npz(data_path)
        else:
            raise ValueError(f"Unknown data format: {data_path.suffix}")

        print(f"  Loaded {len(self.samples)} samples")

    def _load_jsonl(self, path: Path):
        """Load from labeled JSONL (Claude or rule-based labels)."""
        # Group examples by match_id to build windows
        matches: dict[str, list] = {}

        with open(path) as f:
            for line in f:
                if not line.strip():
                    continue
                ex = json.loads(line)

                # Handle both formats:
                # Format 1: raw game states with labels (from build_optimal_play_dataset + labeling)
                # Format 2: Claude-labeled with metadata

                if "state" in ex:
                    # Raw game state format
                    match_id = ex.get("match_id", "unknown")
                    if match_id not in matches:
                        matches[match_id] = []
                    matches[match_id].append(ex)

                elif "metadata" in ex:
                    # Claude-labeled format
                    meta = ex["metadata"]
                    claude = meta.get("claude_analysis", {})
                    match_id = meta.get("match_id", "unknown")
                    if match_id not in matches:
                        matches[match_id] = []

                    # Map Claude's category to our label system
                    label = self._map_claude_label(claude)
                    severity = claude.get("decision_rating", 5) / 10.0

                    matches[match_id].append({
                        "state": ex.get("state", {}),
                        "action": ex.get("action", {}),
                        "events": ex.get("events", []),
                        "label": label,
                        "severity": severity,
                    })

        # Build windowed samples from each match
        for match_id, moments in matches.items():
            # Sort by timestamp
            moments.sort(key=lambda x: x.get("state", {}).get("timestamp_min", 0))

            # Extract features for all frames
            context = GameContext()
            frame_features = []
            for moment in moments:
                feat = extract_features(
                    moment.get("state", {}),
                    moment.get("action"),
                    moment.get("events"),
                    context,
                )
                frame_features.append(feat)

            # Build windows
            for i in range(len(frame_features)):
                # Get window ending at frame i
                start = max(0, i - self.window_size + 1)
                window = frame_features[start : i + 1]

                # Pad if window is shorter than window_size
                while len(window) < self.window_size:
                    window.insert(0, np.zeros(FEATURE_DIM, dtype=np.float32))

                window = np.stack(window)  # (window_size, feature_dim)

                # Get label for this frame
                label_str = moments[i].get("label", "no_mistake")
                label_idx = LABEL_TO_IDX.get(label_str, 0)
                severity = moments[i].get("severity", 0.5)

                self.samples.append((window, label_idx, severity))

    def _load_npz(self, path: Path):
        """Load pre-processed numpy data."""
        data = np.load(path)
        features = data["features"]  # (N, window_size, feature_dim)
        labels = data["labels"]  # (N,)
        severities = data.get("severities", np.full(len(labels), 0.5))

        for i in range(len(labels)):
            self.samples.append((features[i], int(labels[i]), float(severities[i])))

    def _map_claude_label(self, claude_analysis: dict) -> str:
        """Map Claude's free-text category to our label enum."""
        category = claude_analysis.get("category", "other").lower()
        was_optimal = claude_analysis.get("was_optimal", True)
        rating = claude_analysis.get("decision_rating", 5)

        if was_optimal or rating >= 7:
            # Good play
            if "objective" in category:
                return "good_objective_call"
            elif "rotation" in category:
                return "good_rotation"
            elif "vision" in category:
                return "good_vision_setup"
            else:
                return "no_mistake"

        # Bad play — map to specific mistake
        mapping = {
            "objective_control": "missed_objective_baron",
            "macro_rotation": "wrong_rotation",
            "vision": "no_vision_control",
            "farming": "missed_cs_opportunity",
            "wave_management": "missed_cs_opportunity",
            "backing_timing": "bad_recall_timing",
            "teamfighting": "not_grouping",
            "trading": "bad_positioning_danger",
        }

        return mapping.get(category, "no_mistake")

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        window, label, severity = self.samples[idx]
        return (
            torch.tensor(window, dtype=torch.float32),
            torch.tensor(label, dtype=torch.long),
            torch.tensor(severity, dtype=torch.float32),
        )


# ─── Rule-based auto-labeler ────────────────────────────────────────────────

def auto_label_game_state(state: dict, action: dict, events: list) -> tuple[str, float]:
    """
    Automatically label a game moment using rules.
    
    This is the BOOTSTRAP labeler — good enough to start training,
    then you improve with Claude labels or human labels later.

    Returns: (label_str, severity_0_to_1)
    """
    player = state.get("player", {})
    all_players = state.get("all_players", {})
    team_gold = state.get("team_gold", {})
    timestamp_min = state.get("timestamp_min", 0)
    combat = action.get("combat", {})
    movement = action.get("movement", {})
    objectives = action.get("objectives", {})
    vision = action.get("vision", {})
    economy = action.get("economy", {})

    px, py = player.get("x", 0), player.get("y", 0)
    pid = player.get("participant_id", 1)
    is_blue = pid <= 5

    # Check for deaths
    if combat.get("deaths", 0) > 0:
        # Was player isolated?
        ally_range = range(1, 6) if is_blue else range(6, 11)
        ally_dists = []
        for apid in ally_range:
            if apid != pid and apid in all_players:
                ap = all_players[apid]
                dx = px - ap.get("x", 0)
                dy = py - ap.get("y", 0)
                ally_dists.append((dx**2 + dy**2) ** 0.5)

        if ally_dists and min(ally_dists) > 4000:
            return "died_overextended", 0.8
        
        if vision.get("wards_placed", 0) == 0:
            return "died_no_vision", 0.7

    # Check for objective takes (positive)
    monsters = objectives.get("monsters_killed", [])
    if "BARON_NASHOR" in monsters:
        return "good_objective_call", 0.9
    if "DRAGON" in monsters or "RIFTHERALD" in monsters:
        return "good_objective_call", 0.7

    # Check for missed objectives
    if timestamp_min >= 20:
        # Baron phase — is player far from baron when they have numbers?
        from ml.models.features import BARON_PIT, distance
        dist_to_baron = distance((px, py), BARON_PIT)

        blue_alive = sum(1 for i in range(1, 6)
                         if i in all_players and all_players[i].get("level", 0) > 0)
        red_alive = sum(1 for i in range(6, 11)
                         if i in all_players and all_players[i].get("level", 0) > 0)

        team_alive = blue_alive if is_blue else red_alive
        enemy_alive = red_alive if is_blue else blue_alive

        if team_alive >= enemy_alive + 2 and dist_to_baron > 5000:
            return "missed_objective_baron", 0.7

    # Check for low CS
    cs = player.get("cs", 0)
    if timestamp_min > 5:
        cs_per_min = cs / timestamp_min
        role = player.get("role", "")
        if role in ("TOP", "MID", "BOTTOM") and cs_per_min < 5:
            return "missed_cs_opportunity", 0.4

    # Check for no vision around objectives
    if vision.get("wards_placed", 0) == 0 and timestamp_min > 10:
        from ml.models.features import DRAGON_PIT, BARON_PIT, distance
        near_objective = (
            distance((px, py), DRAGON_PIT) < 4000
            or distance((px, py), BARON_PIT) < 4000
        )
        if near_objective:
            return "no_vision_control", 0.5

    # Check for good rotation
    if movement.get("distance", 0) > 4000 and combat.get("kills", 0) > 0:
        return "good_rotation", 0.6

    return "no_mistake", 0.3


def auto_label_dataset(input_path: str, output_path: str):
    """Apply rule-based labels to raw game state data."""
    input_path = Path(input_path)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    label_counts = {}
    total = 0

    with open(input_path) as f_in, open(output_path, "w") as f_out:
        for line in f_in:
            if not line.strip():
                continue
            ex = json.loads(line)

            label, severity = auto_label_game_state(
                ex.get("state", {}),
                ex.get("action", {}),
                ex.get("events", []),
            )

            ex["label"] = label
            ex["severity"] = severity
            f_out.write(json.dumps(ex) + "\n")

            label_counts[label] = label_counts.get(label, 0) + 1
            total += 1

    print(f"Auto-labeled {total} examples → {output_path}")
    print("Label distribution:")
    for label, count in sorted(label_counts.items(), key=lambda x: -x[1]):
        print(f"  {label}: {count} ({count/total:.1%})")


# ─── Training loop ───────────────────────────────────────────────────────────

def train(
    model: GameStateClassifier,
    train_loader: DataLoader,
    val_loader: DataLoader,
    epochs: int = 50,
    lr: float = 1e-3,
    device: str = "mps",  # Apple Silicon
    output_dir: str = "./ml/models/classifier-v1",
):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    model = model.to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)
    criterion = model.get_loss_fn().to(device)
    severity_criterion = torch.nn.MSELoss()

    best_val_acc = 0
    best_epoch = 0

    for epoch in range(epochs):
        # ─── Train ───
        model.train()
        train_loss = 0
        train_correct = 0
        train_total = 0

        for batch_features, batch_labels, batch_severity in train_loader:
            batch_features = batch_features.to(device)
            batch_labels = batch_labels.to(device)
            batch_severity = batch_severity.to(device)

            optimizer.zero_grad()
            output = model(batch_features)

            # Classification loss
            cls_loss = criterion(output["logits"], batch_labels)

            # Severity loss
            sev_loss = severity_criterion(
                output["severity"].squeeze(-1), batch_severity
            )

            loss = cls_loss + 0.3 * sev_loss
            loss.backward()

            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()

            train_loss += loss.item() * batch_features.size(0)
            _, predicted = output["logits"].max(dim=1)
            train_correct += (predicted == batch_labels).sum().item()
            train_total += batch_labels.size(0)

        scheduler.step()

        train_loss /= max(train_total, 1)
        train_acc = train_correct / max(train_total, 1)

        # ─── Validate ───
        model.eval()
        val_loss = 0
        val_correct = 0
        val_total = 0
        label_correct = {}
        label_total = {}

        with torch.no_grad():
            for batch_features, batch_labels, batch_severity in val_loader:
                batch_features = batch_features.to(device)
                batch_labels = batch_labels.to(device)
                batch_severity = batch_severity.to(device)

                output = model(batch_features)
                loss = criterion(output["logits"], batch_labels)

                val_loss += loss.item() * batch_features.size(0)
                _, predicted = output["logits"].max(dim=1)
                val_correct += (predicted == batch_labels).sum().item()
                val_total += batch_labels.size(0)

                # Per-label accuracy
                for pred, true in zip(predicted.cpu().numpy(), batch_labels.cpu().numpy()):
                    label = IDX_TO_LABEL[true]
                    label_total[label] = label_total.get(label, 0) + 1
                    if pred == true:
                        label_correct[label] = label_correct.get(label, 0) + 1

        val_loss /= max(val_total, 1)
        val_acc = val_correct / max(val_total, 1)

        # Log
        print(
            f"Epoch {epoch+1:3d}/{epochs} | "
            f"Train Loss: {train_loss:.4f} Acc: {train_acc:.3f} | "
            f"Val Loss: {val_loss:.4f} Acc: {val_acc:.3f} | "
            f"LR: {scheduler.get_last_lr()[0]:.6f}"
        )

        # Save best model
        if val_acc > best_val_acc:
            best_val_acc = val_acc
            best_epoch = epoch + 1
            torch.save({
                "model_state_dict": model.state_dict(),
                "epoch": epoch,
                "val_acc": val_acc,
                "val_loss": val_loss,
            }, output_dir / "best_model.pt")

        # Save latest
        torch.save({
            "model_state_dict": model.state_dict(),
            "epoch": epoch,
            "val_acc": val_acc,
        }, output_dir / "latest_model.pt")

    print(f"\nBest validation accuracy: {best_val_acc:.3f} at epoch {best_epoch}")
    print(f"Model saved to {output_dir}")

    # Print per-label accuracy
    print("\nPer-label accuracy:")
    for label in sorted(label_total.keys()):
        correct = label_correct.get(label, 0)
        total = label_total[label]
        print(f"  {label:30s}: {correct}/{total} = {correct/total:.1%}")

    # Save config
    config = {
        "feature_dim": model.feature_dim,
        "num_labels": model.num_labels,
        "d_model": model.d_model,
        "window_size": model.window_size,
        "best_val_acc": best_val_acc,
        "best_epoch": best_epoch,
        "epochs": epochs,
        "lr": lr,
    }
    with open(output_dir / "config.json", "w") as f:
        json.dump(config, f, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Train game state classifier")
    parser.add_argument("--data", type=str, required=True, help="Labeled data JSONL")
    parser.add_argument("--output", type=str, default="./ml/models/classifier-v1")
    parser.add_argument("--model-size", type=str, default="medium", choices=["small", "medium", "large"])
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--val-split", type=float, default=0.15)
    parser.add_argument("--window-size", type=int, default=5)
    parser.add_argument("--device", type=str, default="mps", help="mps for Mac, cuda for NVIDIA, cpu for fallback")

    # Auto-labeling mode
    parser.add_argument("--auto-label", action="store_true", help="Auto-label raw data with rules first")
    parser.add_argument("--raw-data", type=str, help="Raw data to auto-label (for --auto-label)")

    args = parser.parse_args()

    # Check device
    if args.device == "mps" and not torch.backends.mps.is_available():
        print("MPS not available, falling back to CPU")
        args.device = "cpu"
    elif args.device == "cuda" and not torch.cuda.is_available():
        print("CUDA not available, falling back to CPU")
        args.device = "cpu"

    print(f"Device: {args.device}")

    # Auto-label if requested
    if args.auto_label:
        if not args.raw_data:
            print("Error: --raw-data required with --auto-label")
            return
        auto_label_dataset(args.raw_data, args.data)

    # Load dataset
    dataset = GameMomentDataset(args.data, window_size=args.window_size)

    if len(dataset) == 0:
        print("No training data! Run the labeling pipeline first.")
        return

    # Split
    val_size = int(len(dataset) * args.val_split)
    train_size = len(dataset) - val_size
    train_ds, val_ds = random_split(dataset, [train_size, val_size])

    print(f"Train: {train_size}, Val: {val_size}")

    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True, num_workers=0)
    val_loader = DataLoader(val_ds, batch_size=args.batch_size, shuffle=False, num_workers=0)

    # Create model
    model = create_model(args.model_size)

    # Train
    train(
        model=model,
        train_loader=train_loader,
        val_loader=val_loader,
        epochs=args.epochs,
        lr=args.lr,
        device=args.device,
        output_dir=args.output,
    )


if __name__ == "__main__":
    main()

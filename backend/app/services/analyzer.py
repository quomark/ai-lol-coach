"""
Game state analyzer — uses the trained classifier to detect mistakes.

This is the bridge between the ML model and the coaching service.
It takes parsed replay data, runs it through the classifier, 
and returns structured findings that the text generator (Claude/LLM) 
turns into coaching advice.

Flow:
  .rofl → parser → analyzer (THIS) → findings → text generator → advice
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import numpy as np
import torch

logger = logging.getLogger(__name__)


class GameAnalyzer:
    """
    Analyzes game states using the trained classifier model.

    Falls back to rule-based analysis if no model is loaded.
    """

    def __init__(self):
        self.model = None
        self.device = "cpu"
        self._loaded = False

    def load_model(self, model_dir: str):
        """Load trained classifier from disk."""
        try:
            from ml.models.classifier import GameStateClassifier

            model_dir = Path(model_dir)
            config_path = model_dir / "config.json"
            model_path = model_dir / "best_model.pt"

            if not model_path.exists():
                logger.warning(f"No model found at {model_path}")
                return

            # Load config
            with open(config_path) as f:
                config = json.load(f)

            # Create model with saved config
            self.model = GameStateClassifier(
                d_model=config.get("d_model", 128),
                window_size=config.get("window_size", 5),
            )

            # Load weights
            if torch.backends.mps.is_available():
                self.device = "mps"
            elif torch.cuda.is_available():
                self.device = "cuda"

            checkpoint = torch.load(model_path, map_location=self.device)
            self.model.load_state_dict(checkpoint["model_state_dict"])
            self.model.to(self.device)
            self.model.eval()
            self._loaded = True

            logger.info(
                f"Classifier loaded from {model_dir} "
                f"(val_acc={checkpoint.get('val_acc', '?'):.3f}, device={self.device})"
            )

        except Exception as e:
            logger.warning(f"Failed to load classifier: {e}")
            self._loaded = False

    def analyze_timeline(
        self,
        timeline_states: list[dict],
        focus_participant_id: int = 1,
    ) -> list[dict[str, Any]]:
        """
        Analyze a sequence of game states from a timeline.

        Returns a list of findings (mistakes and good plays detected).
        """
        if not self._loaded:
            return self._rule_based_analysis(timeline_states, focus_participant_id)

        from ml.models.features import extract_features, IDX_TO_LABEL, GameContext

        findings = []
        context = GameContext()
        feature_buffer = []  # rolling window

        for state_data in timeline_states:
            state = state_data.get("state", state_data)
            action = state_data.get("action", {})
            events = state_data.get("events", [])

            # Extract features
            feat = extract_features(state, action, events, context, focus_participant_id)
            feature_buffer.append(feat)

            # Keep window size
            window_size = self.model.window_size
            if len(feature_buffer) > window_size:
                feature_buffer = feature_buffer[-window_size:]

            # Pad if needed
            window = list(feature_buffer)
            while len(window) < window_size:
                window.insert(0, np.zeros_like(feat))

            # Run inference
            x = torch.tensor(np.stack(window), dtype=torch.float32).unsqueeze(0).to(self.device)
            prediction = self.model.predict(x)

            # Only report non-trivial findings
            if prediction["label"] != "no_mistake" and prediction["confidence"] > 0.5:
                findings.append({
                    "timestamp_min": state.get("timestamp_min", 0),
                    "label": prediction["label"],
                    "confidence": prediction["confidence"],
                    "severity": prediction["severity"],
                    "all_probs": prediction["all_probs"],
                    "game_state_summary": self._summarize_state(state),
                })
            elif prediction["label"] in ("good_objective_call", "good_rotation", "good_vision_setup"):
                if prediction["confidence"] > 0.6:
                    findings.append({
                        "timestamp_min": state.get("timestamp_min", 0),
                        "label": prediction["label"],
                        "confidence": prediction["confidence"],
                        "severity": prediction["severity"],
                        "game_state_summary": self._summarize_state(state),
                    })

        return findings

    def _summarize_state(self, state: dict) -> str:
        """Quick text summary of a game state for context."""
        player = state.get("player", {})
        team_gold = state.get("team_gold", {})
        t = state.get("timestamp_min", 0)

        return (
            f"{t:.0f}min | {player.get('champion', '?')} "
            f"at ({player.get('x', 0)}, {player.get('y', 0)}) | "
            f"Gold: {player.get('gold', 0):,} | "
            f"Team gold diff: {team_gold.get('blue', 0) - team_gold.get('red', 0):+,}"
        )

    def _rule_based_analysis(
        self,
        timeline_states: list[dict],
        focus_participant_id: int,
    ) -> list[dict[str, Any]]:
        """Fallback rule-based analysis when no classifier is loaded."""
        from ml.scripts.train_classifier import auto_label_game_state

        findings = []
        for state_data in timeline_states:
            state = state_data.get("state", state_data)
            action = state_data.get("action", {})
            events = state_data.get("events", [])

            label, severity = auto_label_game_state(state, action, events)

            if label != "no_mistake":
                findings.append({
                    "timestamp_min": state.get("timestamp_min", 0),
                    "label": label,
                    "confidence": 0.8,  # rules are binary, assign decent confidence
                    "severity": severity * 10,
                    "game_state_summary": self._summarize_state(state),
                })

        return findings

    def findings_to_text(self, findings: list[dict]) -> str:
        """
        Convert findings to text that can be sent to Claude/LLM for 
        generating human-readable coaching advice.
        """
        if not findings:
            return "No significant issues detected. Solid gameplay overall."

        lines = ["Detected issues and notable plays:\n"]

        # Sort by timestamp
        findings.sort(key=lambda f: f.get("timestamp_min", 0))

        mistakes = [f for f in findings if not f["label"].startswith("good_")]
        good_plays = [f for f in findings if f["label"].startswith("good_")]

        if mistakes:
            lines.append("MISTAKES:")
            for f in mistakes:
                severity_stars = "★" * int(f["severity"])
                lines.append(
                    f"  [{f['timestamp_min']:.0f}min] {f['label'].replace('_', ' ').upper()} "
                    f"(severity: {severity_stars}, confidence: {f['confidence']:.0%})"
                )
                lines.append(f"    Context: {f.get('game_state_summary', '')}")
            lines.append("")

        if good_plays:
            lines.append("GOOD PLAYS:")
            for f in good_plays:
                lines.append(
                    f"  [{f['timestamp_min']:.0f}min] {f['label'].replace('_', ' ').upper()} "
                    f"(confidence: {f['confidence']:.0%})"
                )
            lines.append("")

        return "\n".join(lines)


# Singleton
game_analyzer = GameAnalyzer()

"""
Coaching service — takes parsed replay data and generates advice.

Two modes:
1. **LLM mode** (default): Uses a fine-tuned or base LLM to generate coaching advice
   from structured replay data. This is the target for fine-tuning.
2. **Rule-based fallback**: Heuristic analysis when no model is loaded.
"""

from __future__ import annotations

import logging
from typing import Any

from backend.replay_parser import ReplayData, PlayerStats

logger = logging.getLogger(__name__)

# ─── Prompt templates ────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an expert League of Legends coach with deep knowledge of macro strategy, micro mechanics, itemization, vision control, wave management, and team composition. 

Analyze the provided game data and give specific, actionable coaching advice. Focus on:
1. What the player did well (be specific with stats)
2. Key areas for improvement (backed by data)  
3. Concrete actionable tips they can apply next game

Be direct. No fluff. Reference actual numbers from the game."""

USER_PROMPT_TEMPLATE = """Analyze this League of Legends game and provide coaching advice{focus_clause}.

{game_data}

{extra_instructions}

Provide your analysis in this structure:
**Game Summary**: Brief overview of how the game went
**Strengths**: What went well (cite specific stats)
**Weaknesses**: Areas that need work (cite specific stats)
**Actionable Tips**: 3-5 concrete things to do differently next game"""


# ─── Rule-based analysis (fallback / baseline) ──────────────────────────────

def _analyze_vision(player: PlayerStats, game_length_s: int) -> list[str]:
    """Analyze vision control."""
    tips = []
    minutes = max(game_length_s / 60, 1)
    wards_per_min = player.wards_placed / minutes

    if wards_per_min < 0.5:
        tips.append(
            f"Vision is critically low ({player.wards_placed} wards in {minutes:.0f}min = "
            f"{wards_per_min:.1f}/min). Aim for 1+ ward/min. "
            "Buy control wards every back."
        )
    elif wards_per_min < 0.75:
        tips.append(
            f"Vision could improve ({wards_per_min:.1f} wards/min). "
            "Try to ward river/jungle entrances before objectives spawn."
        )

    if player.wards_killed < 3:
        tips.append(
            f"Only cleared {player.wards_killed} wards. Buy sweeper after laning phase "
            "and actively deny enemy vision around objectives."
        )

    return tips


def _analyze_cs(player: PlayerStats, game_length_s: int) -> list[str]:
    """Analyze CS efficiency."""
    tips = []
    minutes = max(game_length_s / 60, 1)
    cs_per_min = player.cs / minutes

    if player.role in ("TOP", "MID", "BOTTOM"):
        if cs_per_min < 6:
            tips.append(
                f"CS is low at {cs_per_min:.1f}/min ({player.cs} total). "
                f"Practice last-hitting in practice tool. Aim for 7+ CS/min."
            )
        elif cs_per_min < 7:
            tips.append(
                f"CS is decent at {cs_per_min:.1f}/min but can improve. "
                "Focus on not missing CS during roams — shove wave first."
            )
    elif player.role == "JUNGLE":
        if cs_per_min < 5:
            tips.append(
                f"Jungle CS is low ({cs_per_min:.1f}/min). "
                "Make sure you're clearing camps between ganks — don't let them sit."
            )

    return tips


def _analyze_kda(player: PlayerStats) -> list[str]:
    """Analyze KDA and deaths."""
    tips = []
    kda = (player.kills + player.assists) / max(player.deaths, 1)

    if player.deaths > 7:
        tips.append(
            f"Died {player.deaths} times — that's too many. "
            "Review your deaths: were they from bad positioning, "
            "overextending without vision, or getting caught out?"
        )
    if kda < 2.0 and player.deaths > 5:
        tips.append(
            f"KDA of {kda:.1f} suggests too many risky plays. "
            "Focus on staying alive — a dead player contributes nothing."
        )

    return tips


def _analyze_damage(player: PlayerStats, teammates: list[PlayerStats]) -> list[str]:
    """Analyze damage contribution."""
    tips = []
    team_total = sum(p.damage_dealt for p in teammates) or 1
    dmg_share = player.damage_dealt / team_total

    if player.role in ("MID", "BOTTOM") and dmg_share < 0.2:
        tips.append(
            f"Damage share is only {dmg_share:.0%} of team total. "
            f"As {player.role}, you should be a primary damage source. "
            "Look for more opportunities to deal damage in fights."
        )

    return tips


def rule_based_analysis(
    replay: ReplayData,
    focus_player: str | None = None,
) -> dict[str, Any]:
    """
    Generate coaching advice using heuristic rules.
    Used as fallback when no ML model is loaded, and also
    useful for generating training data labels.
    """
    # Find the focus player
    player = None
    if focus_player:
        for p in replay.players:
            if p.summoner_name.lower() == focus_player.lower():
                player = p
                break

    if not player and replay.players:
        player = replay.players[0]

    if not player:
        return {"error": "No player data found"}

    # Get teammates
    teammates = [p for p in replay.players if p.team == player.team]

    # Run analyses
    strengths = []
    weaknesses = []
    tips = []

    # Vision
    vision_tips = _analyze_vision(player, replay.game_length_seconds)
    if vision_tips:
        weaknesses.append("Vision control needs improvement")
        tips.extend(vision_tips)
    else:
        strengths.append(f"Good vision control ({player.wards_placed} wards, {player.wards_killed} cleared)")

    # CS
    cs_tips = _analyze_cs(player, replay.game_length_seconds)
    if cs_tips:
        weaknesses.append("CS efficiency could be better")
        tips.extend(cs_tips)
    else:
        minutes = max(replay.game_length_seconds / 60, 1)
        strengths.append(f"Solid CS ({player.cs / minutes:.1f}/min)")

    # KDA
    kda_tips = _analyze_kda(player)
    if kda_tips:
        weaknesses.append("Too many deaths")
        tips.extend(kda_tips)
    else:
        kda = (player.kills + player.assists) / max(player.deaths, 1)
        strengths.append(f"Good KDA ({player.kills}/{player.deaths}/{player.assists} = {kda:.1f})")

    # Damage
    dmg_tips = _analyze_damage(player, teammates)
    if dmg_tips:
        weaknesses.append("Low damage output")
        tips.extend(dmg_tips)
    else:
        strengths.append(f"Good damage output ({player.damage_dealt:,})")

    # Game summary
    won = player.team == replay.winning_team
    summary = (
        f"{'Victory' if won else 'Defeat'} — {replay.game_length_seconds // 60}min game. "
        f"{player.summoner_name} played {player.champion} {player.role}. "
        f"KDA: {player.kills}/{player.deaths}/{player.assists}, "
        f"CS: {player.cs}, Gold: {player.gold_earned:,}"
    )

    return {
        "game_summary": summary,
        "focus_player": player.summoner_name,
        "strengths": strengths,
        "weaknesses": weaknesses,
        "actionable_tips": tips,
        "coaching_advice": "\n".join(tips) if tips else "Solid game overall! Keep it up.",
    }


# ─── LLM-based analysis ─────────────────────────────────────────────────────

class CoachingService:
    """
    Main coaching service. Uses LLM when available, falls back to rules.
    """

    def __init__(self):
        self.model = None
        self.tokenizer = None
        self._model_loaded = False
        self._backend = None  # "mlx" or "pytorch"

    def load_model(self, model_path: str | None = None):
        """
        Load the fine-tuned model for inference.
        Tries MLX first (Apple Silicon), falls back to PyTorch (NVIDIA).
        """
        from backend.app.core.config import settings
        adapter_path = model_path or settings.LORA_ADAPTER_PATH

        # Try MLX first (Apple Silicon)
        if self._try_load_mlx(settings.BASE_MODEL, adapter_path):
            return

        # Fall back to PyTorch (NVIDIA GPU)
        self._try_load_pytorch(settings.BASE_MODEL, adapter_path)

    def _try_load_mlx(self, base_model: str, adapter_path: str) -> bool:
        """Load model using MLX (Apple Silicon)."""
        try:
            from mlx_lm import load

            # MLX models use mlx-community/ prefix for pre-quantized
            mlx_model_name = base_model
            if not mlx_model_name.startswith("mlx-community/"):
                # Try to map to mlx-community equivalent
                model_short = base_model.split("/")[-1]
                mlx_model_name = f"mlx-community/{model_short}-4bit"

            logger.info(f"Loading MLX model: {mlx_model_name}")

            if adapter_path:
                self.model, self.tokenizer = load(
                    mlx_model_name, adapter_path=adapter_path
                )
            else:
                self.model, self.tokenizer = load(mlx_model_name)

            self._model_loaded = True
            self._backend = "mlx"
            logger.info("MLX model loaded successfully")
            return True

        except ImportError:
            logger.info("MLX not available, trying PyTorch")
            return False
        except Exception as e:
            logger.warning(f"MLX load failed: {e}")
            return False

    def _try_load_pytorch(self, base_model: str, adapter_path: str) -> bool:
        """Load model using PyTorch (NVIDIA GPU)."""
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
            from backend.app.core.config import settings
            import torch

            logger.info(f"Loading PyTorch model: {base_model}")

            load_kwargs = {"device_map": "auto", "torch_dtype": torch.float16}
            if settings.USE_4BIT:
                from transformers import BitsAndBytesConfig
                load_kwargs["quantization_config"] = BitsAndBytesConfig(
                    load_in_4bit=True,
                    bnb_4bit_compute_dtype=torch.float16,
                    bnb_4bit_quant_type="nf4",
                )

            self.tokenizer = AutoTokenizer.from_pretrained(base_model)
            self.model = AutoModelForCausalLM.from_pretrained(base_model, **load_kwargs)

            if adapter_path:
                from peft import PeftModel
                logger.info(f"Loading LoRA adapter: {adapter_path}")
                self.model = PeftModel.from_pretrained(self.model, adapter_path)

            self._model_loaded = True
            self._backend = "pytorch"
            logger.info("PyTorch model loaded successfully")
            return True

        except Exception as e:
            logger.warning(f"Failed to load model: {e}. Using rule-based fallback.")
            self._model_loaded = False
            return False

    def analyze(
        self,
        replay: ReplayData,
        summoner_name: str | None = None,
        focus_areas: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Analyze a replay and generate coaching advice.
        Uses LLM if loaded, otherwise falls back to rule-based analysis.
        """
        # Always run rule-based for structured data
        rule_result = rule_based_analysis(replay, summoner_name)

        if not self._model_loaded:
            return rule_result

        # LLM analysis
        try:
            llm_advice = self._generate_llm_advice(replay, summoner_name, focus_areas)
            rule_result["coaching_advice"] = llm_advice
        except Exception as e:
            logger.error(f"LLM inference failed: {e}")

        return rule_result

    def _generate_llm_advice(
        self,
        replay: ReplayData,
        summoner_name: str | None,
        focus_areas: list[str] | None,
    ) -> str:
        """Generate coaching advice using the loaded LLM (MLX or PyTorch)."""
        focus_clause = ""
        if summoner_name:
            focus_clause = f" for player '{summoner_name}'"

        extra = ""
        if focus_areas:
            extra = f"Focus especially on: {', '.join(focus_areas)}"

        prompt = USER_PROMPT_TEMPLATE.format(
            focus_clause=focus_clause,
            game_data=replay.to_prompt_context(),
            extra_instructions=extra,
        )

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]

        if self._backend == "mlx":
            return self._generate_mlx(messages)
        else:
            return self._generate_pytorch(messages)

    def _generate_mlx(self, messages: list[dict]) -> str:
        """Generate with MLX backend."""
        from mlx_lm import generate

        input_text = self.tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )
        response = generate(
            self.model,
            self.tokenizer,
            prompt=input_text,
            max_tokens=1024,
            temp=0.7,
            top_p=0.9,
        )
        return response.strip()

    def _generate_pytorch(self, messages: list[dict]) -> str:
        """Generate with PyTorch backend."""
        import torch

        input_text = self.tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )
        inputs = self.tokenizer(input_text, return_tensors="pt").to(self.model.device)

        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=1024,
                temperature=0.7,
                top_p=0.9,
                do_sample=True,
                repetition_penalty=1.1,
            )

        response = self.tokenizer.decode(
            outputs[0][inputs["input_ids"].shape[1] :], skip_special_tokens=True
        )
        return response.strip()


# Singleton
coaching_service = CoachingService()

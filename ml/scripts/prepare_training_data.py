"""
Prepare training data for fine-tuning.

Converts raw replay data into instruction-tuning format:
    System: You are an expert LoL coach...
    User: <game state data>
    Assistant: <coaching analysis>

Two data sources:
1. HuggingFace decoded replay packets → extract game states
2. .rofl files parsed locally → extract match metadata + use rule-based 
   analysis to generate initial labels (then refine with human feedback)

Usage:
    python -m ml.scripts.prepare_training_data
"""

import argparse
import json
import random
from pathlib import Path

from backend.app.services.coach import SYSTEM_PROMPT, rule_based_analysis
from backend.replay_parser import ReplayData, PlayerStats, RoflParser


def rofl_to_training_examples(rofl_dir: str, output_path: str):
    """
    Convert a directory of .rofl files into training examples.
    Uses rule-based analysis to generate initial coaching labels.
    
    This is a bootstrap approach — you'd later refine with:
    - Human expert annotations
    - RLHF / DPO on the generated advice
    """
    rofl_dir = Path(rofl_dir)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    parser = RoflParser()
    examples = []

    rofl_files = list(rofl_dir.glob("*.rofl"))
    print(f"Found {len(rofl_files)} .rofl files")

    for rofl_file in rofl_files:
        try:
            replay = parser.parse(rofl_file)
        except Exception as e:
            print(f"  Failed to parse {rofl_file.name}: {e}")
            continue

        # Generate training examples — one per player
        for player in replay.players:
            result = rule_based_analysis(replay, player.summoner_name)

            # Build the coaching response text
            advice_parts = []
            advice_parts.append(f"**Game Summary**: {result['game_summary']}")
            advice_parts.append("")

            if result["strengths"]:
                advice_parts.append("**Strengths**:")
                for s in result["strengths"]:
                    advice_parts.append(f"- {s}")
                advice_parts.append("")

            if result["weaknesses"]:
                advice_parts.append("**Weaknesses**:")
                for w in result["weaknesses"]:
                    advice_parts.append(f"- {w}")
                advice_parts.append("")

            if result["actionable_tips"]:
                advice_parts.append("**Actionable Tips**:")
                for t in result["actionable_tips"]:
                    advice_parts.append(f"- {t}")

            coaching_text = "\n".join(advice_parts)

            example = {
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {
                        "role": "user",
                        "content": (
                            f"Analyze this League of Legends game for player "
                            f"'{player.summoner_name}'.\n\n{replay.to_prompt_context()}"
                        ),
                    },
                    {"role": "assistant", "content": coaching_text},
                ]
            }
            examples.append(example)

    # Shuffle and save
    random.shuffle(examples)

    with open(output_path, "w") as f:
        for ex in examples:
            f.write(json.dumps(ex) + "\n")

    print(f"Generated {len(examples)} training examples → {output_path}")
    return examples


def create_synthetic_training_data(output_path: str, num_examples: int = 500):
    """
    Generate synthetic training examples for bootstrapping.
    Creates varied game scenarios with coaching advice.
    
    This gets you started before you have real replay data.
    Replace with real data ASAP.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    champions = [
        "Aatrox", "Ahri", "Akali", "Alistar", "Amumu", "Anivia", "Annie",
        "Aphelios", "Ashe", "AurelionSol", "Azir", "Bard", "Blitzcrank",
        "Brand", "Braum", "Caitlyn", "Camille", "Cassiopeia", "ChoGath",
        "Corki", "Darius", "Diana", "DrMundo", "Draven", "Ekko", "Elise",
        "Evelynn", "Ezreal", "Fiddlesticks", "Fiora", "Fizz", "Galio",
        "Gangplank", "Garen", "Gnar", "Gragas", "Graves", "Gwen",
        "Hecarim", "Heimerdinger", "Illaoi", "Irelia", "Ivern", "Janna",
        "JarvanIV", "Jax", "Jayce", "Jhin", "Jinx", "KaiSa", "Kalista",
        "Karma", "Karthus", "Kassadin", "Katarina", "Kayle", "Kayn",
        "Kennen", "KhaZix", "Kindred", "Kled", "KogMaw", "LeBlanc",
        "LeeSin", "Leona", "Lillia", "Lissandra", "Lucian", "Lulu", "Lux",
        "Malphite", "Malzahar", "Maokai", "MasterYi", "MissFortune",
        "Mordekaiser", "Morgana", "Nami", "Nasus", "Nautilus", "Neeko",
        "Nidalee", "Nocturne", "Nunu", "Olaf", "Orianna", "Ornn",
        "Pantheon", "Poppy", "Pyke", "Qiyana", "Quinn", "Rakan",
        "Rammus", "RekSai", "Rell", "Renata", "Renekton", "Rengar",
        "Riven", "Rumble", "Ryze", "Samira", "Sejuani", "Senna",
        "Seraphine", "Sett", "Shaco", "Shen", "Shyvana", "Singed",
        "Sion", "Sivir", "Skarner", "Sona", "Soraka", "Swain", "Sylas",
        "Syndra", "TahmKench", "Taliyah", "Talon", "Taric", "Teemo",
        "Thresh", "Tristana", "Trundle", "Tryndamere", "TwistedFate",
        "Twitch", "Udyr", "Urgot", "Varus", "Vayne", "Veigar", "VelKoz",
        "Vex", "Vi", "Viego", "Viktor", "Vladimir", "Volibear", "Warwick",
        "Wukong", "Xayah", "Xerath", "XinZhao", "Yasuo", "Yone",
        "Yorick", "Yuumi", "Zac", "Zed", "Zeri", "Ziggs", "Zilean",
        "Zoe", "Zyra",
    ]
    roles = ["TOP", "JUNGLE", "MID", "BOTTOM", "UTILITY"]

    examples = []

    for i in range(num_examples):
        # Random game scenario
        game_length = random.randint(15 * 60, 45 * 60)
        winning_team = random.choice(["100", "200"])

        players = []
        used_champs = set()
        for team_id in ["100", "200"]:
            for role in roles:
                champ = random.choice([c for c in champions if c not in used_champs])
                used_champs.add(champ)

                # Generate stats based on win/loss and some variance
                is_winning = team_id == winning_team
                base_kills = random.randint(3, 12) if is_winning else random.randint(1, 8)
                base_deaths = random.randint(1, 6) if is_winning else random.randint(3, 10)

                player = PlayerStats(
                    champion=champ,
                    summoner_name=f"Player{len(players)+1}",
                    team=team_id,
                    role=role,
                    kills=base_kills,
                    deaths=base_deaths,
                    assists=random.randint(2, 15),
                    cs=int(random.gauss(7, 2) * (game_length / 60))
                    if role != "UTILITY"
                    else random.randint(20, 60),
                    gold_earned=random.randint(8000, 18000),
                    damage_dealt=random.randint(8000, 35000),
                    damage_taken=random.randint(10000, 40000),
                    vision_score=random.uniform(10, 80),
                    wards_placed=random.randint(3, 25),
                    wards_killed=random.randint(0, 12),
                    level=random.randint(12, 18),
                )
                players.append(player)

        replay = ReplayData(
            game_version="14.24",
            game_length_seconds=game_length,
            map_id=11,
            game_mode="CLASSIC",
            winning_team=winning_team,
            players=players,
        )

        # Pick a random player to analyze
        focus_player = random.choice(players)
        result = rule_based_analysis(replay, focus_player.summoner_name)

        advice_parts = []
        advice_parts.append(f"**Game Summary**: {result['game_summary']}")
        advice_parts.append("")
        if result["strengths"]:
            advice_parts.append("**Strengths**:")
            for s in result["strengths"]:
                advice_parts.append(f"- {s}")
            advice_parts.append("")
        if result["weaknesses"]:
            advice_parts.append("**Weaknesses**:")
            for w in result["weaknesses"]:
                advice_parts.append(f"- {w}")
            advice_parts.append("")
        if result["actionable_tips"]:
            advice_parts.append("**Actionable Tips**:")
            for t in result["actionable_tips"]:
                advice_parts.append(f"- {t}")

        example = {
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Analyze this League of Legends game for player "
                        f"'{focus_player.summoner_name}'.\n\n{replay.to_prompt_context()}"
                    ),
                },
                {"role": "assistant", "content": "\n".join(advice_parts)},
            ]
        }
        examples.append(example)

    random.shuffle(examples)

    with open(output_path, "w") as f:
        for ex in examples:
            f.write(json.dumps(ex) + "\n")

    print(f"Generated {len(examples)} synthetic training examples → {output_path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rofl-dir", type=str, help="Directory with .rofl files")
    ap.add_argument("--output", type=str, default="./ml/data/processed/train.jsonl")
    ap.add_argument(
        "--synthetic",
        action="store_true",
        help="Generate synthetic data for bootstrapping",
    )
    ap.add_argument("--num-synthetic", type=int, default=500)
    args = ap.parse_args()

    if args.synthetic:
        create_synthetic_training_data(args.output, args.num_synthetic)
    elif args.rofl_dir:
        rofl_to_training_examples(args.rofl_dir, args.output)
    else:
        print("Specify --rofl-dir or --synthetic")
        print("Example: python -m ml.scripts.prepare_training_data --synthetic")


if __name__ == "__main__":
    main()

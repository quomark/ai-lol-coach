"""
Use Claude API as the "coaching brain" to generate training labels.

Flow:
  1. Load Challenger match timelines (from fetch_high_elo_matches.py)
  2. For each key game moment, ask Claude to evaluate:
     - Was the player's action optimal?
     - What should they have done instead?
     - Why?
  3. Save Claude's analysis as training data
  4. Fine-tune local model on this data (distillation)

After fine-tuning, the local model replicates Claude's coaching ability
without needing the API. Claude is the teacher, local model is the student.

Usage:
    # Set your API key
    export ANTHROPIC_API_KEY=sk-ant-xxx

    # Generate labels from Challenger match data
    python -m ml.scripts.label_with_claude \
        --input ./ml/data/processed/optimal_play.jsonl \
        --output ./ml/data/processed/claude_labeled.jsonl \
        --max-samples 500

    # Then fine-tune on Claude's labels
    python -m ml.scripts.finetune_mlx \
        --prepare-data --train-data ./ml/data/processed/claude_labeled.jsonl
    python -m ml.scripts.finetune_mlx --train

Cost estimate:
    ~500 game moments × ~2K tokens each ≈ 1M input + 500K output tokens
    Claude Sonnet: ~$5 total
    Claude Opus:   ~$30 total (better quality)
"""

import argparse
import json
import os
import time
from pathlib import Path

import httpx

CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"

SYSTEM_PROMPT = """You are an elite League of Legends coach (Challenger tier) analyzing game moments.

For each game state snapshot, you will:
1. Evaluate what the player did
2. Determine if it was optimal
3. Explain what the best play would be and why
4. Rate the decision (1-10)

Be extremely specific. Reference exact numbers, timings, and conditions.
Think about wave state, objective timers, cooldowns, vision, and team compositions.
Never give generic advice — every response must be specific to THIS game state."""

ANALYSIS_PROMPT = """Analyze this game moment:

**Time:** {timestamp}
**Player:** {champion} ({role}) — {team} team
**Player Position:** {zone}
**Player State:** {gold} gold, {cs} CS, Level {level}

**Team Gold:** Blue {blue_gold:,} | Red {red_gold:,} ({"Blue" if blue_gold > red_gold else "Red"} leads by {abs(blue_gold - red_gold):,})

**What happened next (between this frame and the next):**
{events_summary}

**Actions taken:**
- Movement: {movement_summary}
- Combat: {combat_summary}
- Economy: {economy_summary}
- Vision: {vision_summary}
- Objectives: {objectives_summary}

Analyze this decision. Respond in EXACTLY this JSON format:
{{
  "decision_rating": <1-10>,
  "was_optimal": <true/false>,
  "what_player_did": "<one sentence>",
  "what_optimal_play_was": "<one sentence>",
  "why": "<2-3 sentences explaining the reasoning>",
  "category": "<one of: macro_rotation, objective_control, vision, farming, trading, teamfighting, wave_management, backing_timing, other>",
  "severity": "<one of: critical, major, minor, good_play, excellent_play>"
}}"""


def format_game_moment(example: dict) -> str:
    """Format a game state example into a prompt for Claude."""
    state = example.get("state", {})
    action = example.get("action", {})
    events = example.get("events", [])
    player_info = example.get("player_info", {})
    player = state.get("player", {})
    team_gold = state.get("team_gold", {})

    # Summarize events
    event_types = [e.get("type", "unknown") for e in events]
    if not event_types:
        events_summary = "Nothing notable happened"
    else:
        events_summary = ", ".join(event_types)

    # Summarize actions
    movement = action.get("movement", {})
    combat = action.get("combat", {})
    economy = action.get("economy", {})
    vision = action.get("vision", {})
    objectives = action.get("objectives", {})

    movement_summary = f"Moved to {movement.get('zone', 'unknown')} (distance: {movement.get('distance', 0):.0f})"

    kills, deaths, assists = combat.get("kills", 0), combat.get("deaths", 0), combat.get("assists", 0)
    if kills or deaths or assists:
        combat_summary = f"{kills} kills, {deaths} deaths, {assists} assists"
    else:
        combat_summary = "No combat"

    cs_gained = economy.get("cs_gained", 0)
    gold_gained = economy.get("gold_gained", 0)
    economy_summary = f"+{cs_gained} CS, +{gold_gained} gold"

    wards_p = vision.get("wards_placed", 0)
    wards_c = vision.get("wards_cleared", 0)
    vision_summary = f"{wards_p} placed, {wards_c} cleared" if (wards_p or wards_c) else "No vision activity"

    monsters = objectives.get("monsters_killed", [])
    buildings = objectives.get("buildings_killed", 0)
    if monsters or buildings:
        objectives_summary = f"Monsters: {', '.join(monsters) if monsters else 'none'}, Buildings: {buildings}"
    else:
        objectives_summary = "None"

    return ANALYSIS_PROMPT.format(
        timestamp=f"{state.get('timestamp_min', 0):.1f} min",
        champion=player_info.get("champion", "Unknown"),
        role=player_info.get("role", "Unknown"),
        team=player_info.get("team", "Unknown"),
        zone=movement.get("zone", "unknown"),
        gold=player.get("gold", 0),
        cs=player.get("cs", 0),
        level=player.get("level", 1),
        blue_gold=team_gold.get("blue", 0),
        red_gold=team_gold.get("red", 0),
        events_summary=events_summary,
        movement_summary=movement_summary,
        combat_summary=combat_summary,
        economy_summary=economy_summary,
        vision_summary=vision_summary,
        objectives_summary=objectives_summary,
    )


def call_claude(
    api_key: str,
    prompt: str,
    model: str = "claude-sonnet-4-20250514",
    max_retries: int = 3,
) -> str | None:
    """Call Claude API and return the response text."""
    headers = {
        "x-api-key": api_key,
        "content-type": "application/json",
        "anthropic-version": "2023-06-01",
    }

    payload = {
        "model": model,
        "max_tokens": 1024,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,  # Low temp for consistent labels
    }

    for attempt in range(max_retries):
        try:
            resp = httpx.post(
                CLAUDE_API_URL,
                headers=headers,
                json=payload,
                timeout=60,
            )

            if resp.status_code == 200:
                data = resp.json()
                return data["content"][0]["text"]
            elif resp.status_code == 429:
                wait = 2 ** (attempt + 1)
                print(f"    Rate limited, waiting {wait}s...")
                time.sleep(wait)
            else:
                print(f"    API error {resp.status_code}: {resp.text[:200]}")
                return None

        except Exception as e:
            print(f"    Request failed: {e}")
            time.sleep(2)

    return None


def parse_claude_response(response: str) -> dict | None:
    """Extract JSON from Claude's response."""
    # Claude usually wraps JSON in ```json ... ``` or returns raw JSON
    text = response.strip()

    # Strip markdown code fences if present
    if "```" in text:
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            text = text[start:end]

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to find JSON object in the text
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                return None
    return None


def build_training_example(
    game_state: dict,
    claude_analysis: dict,
    prompt: str,
) -> dict:
    """
    Convert Claude's analysis into a training example.

    Format: chat messages that teach the local model to analyze like Claude.
    """
    # Build the coaching response from Claude's structured analysis
    rating = claude_analysis.get("decision_rating", 5)
    severity = claude_analysis.get("severity", "minor")
    category = claude_analysis.get("category", "other")

    coaching_text = []
    coaching_text.append(f"**Decision Rating:** {rating}/10 ({severity})")
    coaching_text.append(f"**Category:** {category}")
    coaching_text.append("")

    if claude_analysis.get("was_optimal"):
        coaching_text.append(f"✓ **Good play:** {claude_analysis.get('what_player_did', '')}")
    else:
        coaching_text.append(f"✗ **What you did:** {claude_analysis.get('what_player_did', '')}")
        coaching_text.append(f"✓ **Optimal play:** {claude_analysis.get('what_optimal_play_was', '')}")

    coaching_text.append("")
    coaching_text.append(f"**Why:** {claude_analysis.get('why', '')}")

    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
            {"role": "assistant", "content": "\n".join(coaching_text)},
        ],
        "metadata": {
            "claude_analysis": claude_analysis,
            "match_id": game_state.get("match_id", ""),
            "timestamp": game_state.get("state", {}).get("timestamp_min", 0),
        },
    }


def is_interesting_moment(example: dict) -> bool:
    """
    Filter for moments worth labeling — skip boring frames.
    Don't waste Claude API calls on "player farmed 3 CS and nothing happened."
    """
    action = example.get("action", {})
    events = example.get("events", [])
    combat = action.get("combat", {})
    objectives = action.get("objectives", {})
    movement = action.get("movement", {})

    # Keep if: kills, deaths, objectives, or big rotations
    if combat.get("kills", 0) > 0 or combat.get("deaths", 0) > 0:
        return True
    if objectives.get("monsters_killed") or objectives.get("buildings_killed", 0) > 0:
        return True
    if movement.get("distance", 0) > 3000:  # Big rotation
        return True

    # Keep some event-heavy frames
    if len(events) >= 3:
        return True

    # Keep every 5th frame for general macro evaluation
    timestamp = example.get("state", {}).get("timestamp_min", 0)
    if int(timestamp) % 5 == 0 and int(timestamp) > 3:
        return True

    return False


def main():
    parser = argparse.ArgumentParser(description="Label game moments with Claude")
    parser.add_argument("--input", type=str, default="./ml/data/processed/optimal_play.jsonl")
    parser.add_argument("--output", type=str, default="./ml/data/processed/claude_labeled.jsonl")
    parser.add_argument("--api-key", type=str, help="Anthropic API key (or set ANTHROPIC_API_KEY)")
    parser.add_argument("--model", type=str, default="claude-sonnet-4-20250514",
                        help="Claude model (claude-sonnet-4-20250514 = cheap, claude-opus-4-20250514 = best)")
    parser.add_argument("--max-samples", type=int, default=500, help="Max moments to label")
    parser.add_argument("--delay", type=float, default=0.5, help="Seconds between API calls")
    args = parser.parse_args()

    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        print("Error: Set --api-key or ANTHROPIC_API_KEY environment variable")
        print("Get your key at: https://console.anthropic.com")
        return

    input_path = Path(args.input)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not input_path.exists():
        print(f"Input file not found: {input_path}")
        print("Run build_optimal_play_dataset.py first!")
        return

    # Load game moments
    print(f"Loading game moments from {input_path}...")
    all_examples = []
    with open(input_path) as f:
        for line in f:
            if line.strip():
                all_examples.append(json.loads(line))

    print(f"  Total moments: {len(all_examples)}")

    # Filter for interesting moments
    interesting = [ex for ex in all_examples if is_interesting_moment(ex)]
    print(f"  Interesting moments: {len(interesting)}")

    # Cap at max_samples
    samples = interesting[: args.max_samples]
    print(f"  Labeling: {len(samples)} moments")

    # Estimate cost
    est_input_tokens = len(samples) * 800  # ~800 tokens per prompt
    est_output_tokens = len(samples) * 200  # ~200 tokens per response
    if "sonnet" in args.model:
        est_cost = (est_input_tokens * 3 + est_output_tokens * 15) / 1_000_000
    else:  # opus
        est_cost = (est_input_tokens * 15 + est_output_tokens * 75) / 1_000_000
    print(f"  Estimated cost: ${est_cost:.2f}")
    print()

    # Label each moment
    labeled = 0
    failed = 0

    with open(output_path, "w") as out:
        for i, example in enumerate(samples):
            print(f"  [{i + 1}/{len(samples)}]", end=" ")

            # Format the prompt
            prompt = format_game_moment(example)

            # Call Claude
            response = call_claude(api_key, prompt, model=args.model)
            if not response:
                print("❌ no response")
                failed += 1
                continue

            # Parse Claude's response
            analysis = parse_claude_response(response)
            if not analysis:
                print(f"❌ couldn't parse: {response[:100]}...")
                failed += 1
                continue

            # Build training example
            training_ex = build_training_example(example, analysis, prompt)
            out.write(json.dumps(training_ex) + "\n")

            rating = analysis.get("decision_rating", "?")
            severity = analysis.get("severity", "?")
            print(f"✅ rating={rating}/10 severity={severity}")

            labeled += 1
            time.sleep(args.delay)

    print(f"\n=== Done ===")
    print(f"  Labeled: {labeled}")
    print(f"  Failed:  {failed}")
    print(f"  Output:  {output_path}")
    print(f"\nNext steps:")
    print(f"  python -m ml.scripts.finetune_mlx --prepare-data --train-data {output_path}")
    print(f"  python -m ml.scripts.finetune_mlx --train")


if __name__ == "__main__":
    main()

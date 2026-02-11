# Windows Replay Scraper Setup

## Prerequisites

1. **League of Legends** installed and updated to current patch
2. **Python 3.11+** installed (python.org or winget)
3. This repo cloned on your Windows machine

## Setup

```bash
cd ai-lol-coach
python -m venv .venv
.venv\Scripts\activate
pip install httpx psutil pywin32
```

## How it works

1. **Start LoL client** and log in to your account
2. The scraper auto-detects the LCU port + auth token from the lockfile
3. It loads replays one by one via the LCU Replay API
4. While each replay plays at high speed (8-16x), the memory reader captures game state
5. Observations are saved as JSON, then converted to SQLite

## Usage

```bash
# Step 1: Make sure you have .rofl files downloaded
# (from fetch_high_elo_matches.py --step replays)

# Step 2: Start LoL client and log in

# Step 3: Run the scraper
python -m ml.scraper.orchestrator --replay-dir ml/data/raw/high_elo/replays --speed 8

# Step 4: Convert to SQLite
python -m ml.scraper.convert_to_sqlite --input ml/data/raw/observations --output ml/data/processed/replays.db
```

## Architecture

```
ml/scraper/
  lcu_api.py         - LCU (League Client Update) API connector
  orchestrator.py    - Loads replays, controls playback speed
  memory_reader.py   - Reads game state from process memory (Windows)
  game_state.py      - Game state data structures
  convert_to_sqlite.py - JSON observations → SQLite dataset
```

## Notes

- Replay scraping only works on the **current patch** replays
- LCU API is localhost-only, requires the client to be running
- Memory offsets may need updating each patch (check community resources)
- Running at 8x speed with JSON serialization: ~130 games/day
- Running at 16x speed: ~260 games/day (fewer observations per second)

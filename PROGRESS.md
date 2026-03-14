# ROFL Decoding Progress & Next Steps

## Current State (2026-03-14)

### What Works
| Component | Status | File |
|-----------|--------|------|
| ROFL v2 parser | Working | `ml/parsers/rofl_parser.py` |
| Frame/packet parser | Working | `ml/parsers/chunk_parser.py` |
| 0x025B movement decoder | 100% (32,037/32,037) | `ml/parsers/movement_decoder.py` |
| 0x0228 state decoder | 100% (57,523/57,523) | `ml/emulator/decode_0228.py` |
| Game state reconstruction | Working | `ml/parsers/game_state.py` |
| Coaching analyzer | Draft | `ml/parsers/coaching_analyzer.py` |
| Cipher extraction tool | Working | `ml/tools/extract_ciphers.py` |
| Runtime dump script (Win) | Created, untested | `ml/emulator/dump_runtime.py` |

### What's BROKEN: Position Coordinates
**This is the #1 blocker.** Movement packets decode with 0 leftover (structure is correct), but the x,z coordinates are WRONG:
- At t=0, all 10 champions show identical positions (should be at fountain)
- Blue and red team members appear at same coordinates
- X values roughly scale to Maknee's range, but Z is completely off
- **Root cause**: The binary dump (`ml/data/league_unpacked_patched.bin`) was captured via `CREATE_SUSPENDED` — the game hadn't initialized yet, so LUT tables and cipher constants may contain pre-init values

### Coordinate System Reference (from Maknee's decoded data)
- Grid coordinates centered at (0,0), range ±7300
- Values are even numbers (grid × 2)
- Blue fountain: (-6754, -6800), Red fountain: (6710, 6688)
- Our decoder outputs unsigned 14-bit values (0-16383): `x = f10 & 0x3FFF, z = (f10 >> 14) & 0x3FFF`

### Binary Dump Problem
- Current dump: `ml/data/league_unpacked_patched.bin` (33MB)
- Method: `CREATE_SUSPENDED` → DllMain runs (unpacks code) → dump before entry point
- Problem: LUT at RVA `0x19B60F0` and other cipher tables may not be populated until runtime init
- Need: A **runtime dump** after the game has fully initialized

## Next Step: macOS Runtime Dump

macOS is the best path because:
1. Vanguard on macOS is **user-mode only** (no kernel driver blocking memory reads)
2. Can freely attach `lldb` to running League process
3. Cipher tables / LUT values are **identical** across platforms (same server protocol)
4. Only the RVAs (offsets in the binary) differ between Windows PE and macOS Mach-O

### macOS Dump Procedure

```bash
# 1. Install League on Mac, open a replay
#    Double-click a .rofl file or: open -a "League of Legends" replay.rofl

# 2. Wait for game to load (10-15 seconds after you see the game)

# 3. Find the process
ps aux | grep -i league
# or
pgrep -f LeagueofLegends

# 4. Attach lldb
lldb -p <PID>

# 5. In lldb, find the main module
(lldb) image list
# Look for LeagueofLegends — note the base address and size

# 6. Dump the entire binary
(lldb) memory read --outfile ~/league_macos_dump.bin --binary --force --count <SIZE> <BASE_ADDR>

# 7. Detach
(lldb) detach
```

### After Getting the macOS Dump

The LUT and cipher constants need to be found at macOS-specific offsets. Run the scanning script:

```bash
python ml/tools/scan_macos_dump.py ~/league_macos_dump.bin
```

This will:
1. Find 256-byte permutation tables (LUTs) — each byte appears exactly once
2. Find cipher constant patterns matching known Windows values
3. Extract the actual initialized values
4. Validate by decoding packets with the new values

## Key RVAs (Windows Binary — for reference)

| What | RVA | Notes |
|------|-----|-------|
| Packet dispatcher | 0x0066E5F0 | Entry point for all packet processing |
| 0x025B deserializer | 0x00DE3410 | Movement packet decoder |
| 0x0228 deserializer | 0x00E748B0 | State/entity packet decoder |
| LUT (used by 0x0228) | 0x19B60F0 | 256-byte lookup table |
| Function pointer table | 0x019B6200 | 776 entries, stride 48 bytes |
| VARINT_DEC function | 0x01150B40 | Shared varint reader |
| f10 cipher (0x025B) | 0x00FAF080 | Position field: `sub 0x62, bitswap, add 7` |

## Architecture Overview

```
.rofl file
  → ROFLParser (decompress payload frames)
    → chunk_parser (extract packets: id, param, timestamp, data)
      → MovementDecoder (0x025B packets → entity_id, x, z, speed)
      → Decoder0228 (0x0228 packets → entity state: f0-f9)
        → GameStateBuilder (combine into per-champion timelines)
          → CoachingAnalyzer (generate insights)
```

### Packet Format
- Each packet: 4-byte schema (little-endian) + encrypted payload
- Schema bits select "type code" per field → determines if field is read or default
- Each field has its own cipher (combinations of add, xor, ror, bitswap, LUT)
- Varints use protobuf-like encoding (7-bit chunks, MSB continuation)

### Key Decoded Fields
**0x025B (movement):** entity_id, x, z, speed, movement_type, waypoint_count
**0x0228 (state):** f0 (1-byte), f1 (entity_id), f3 (float), f4 (varint), f5 (death-related), f6-f7, f8 (gold/XP or killer_id on death), f9 (float)

### Death Detection
- f8 normally increases over time (cumulative stat)
- On death: f8 drops from >500 to <200 (value = killer's entity_id)
- Stays low for death timer duration (≥5 seconds)
- Currently ~2x overcount (102 detected vs ~47 actual)

### Team Detection
- Kill graph from f8_after values: kills always cross-team
- BFS graph coloring splits entities into two teams
- Early position average determines blue (lower coords) vs red (upper coords)

## File Inventory

### Core Pipeline (keep these)
- `ml/parsers/rofl_parser.py` — ROFL v2 file format parser
- `ml/parsers/chunk_parser.py` — Payload frame + packet extractor
- `ml/parsers/movement_decoder.py` — 0x025B movement packet decoder
- `ml/emulator/decode_0228.py` — 0x0228 state packet decoder
- `ml/parsers/game_state.py` — Game state reconstruction
- `ml/parsers/coaching_analyzer.py` — Coaching insights generator
- `ml/tools/extract_ciphers.py` — Auto-extract cipher params from binary dumps

### Dump Tools
- `ml/emulator/dump_via_suspended.py` — CREATE_SUSPENDED dump (Windows)
- `ml/emulator/dump_runtime.py` — Runtime dump (Windows, needs Vanguard bypass)

### Binary Data
- `ml/data/league_unpacked_patched.bin` — 33MB Windows binary dump (CREATE_SUSPENDED, possibly uninitialized LUTs)

### Research/Analysis Scripts (in ml/emulator/)
Many analysis scripts were created during reverse engineering. Most are one-off experiments.
Key ones: `find_all_deserializers.py`, `find_decrypt_rvas.py`, `unicorn_emulator.py`
